import errno
import json
import logging
import socket
import ssl
import struct
import sys
import threading
import time
import traceback
import zlib
from typing import List, Optional, TYPE_CHECKING, Tuple

from dmoj import sysinfo
from dmoj.judgeenv import get_runtime_versions, get_supported_problems
from dmoj.result import Result
from dmoj.utils.unicode import utf8bytes, utf8text

if TYPE_CHECKING:
    from dmoj.judge import Judge

log = logging.getLogger(__name__)


class JudgeAuthenticationFailed(Exception):
    pass


class ApiManager(object):
    transport = None

    def __init__(
        self,
        host: str,
        port: int,
        judge: 'Judge',
        name: str,
        key: str,
        transport=None,
        **kwargs
    ):
        self.judge = judge

        self.host = host
        self.port = port
        self.id = name
        self.key = key

        self._testcase_queue_lock = threading.Lock()
        self._testcase_queue: List[Tuple[int, Result]] = []

        if not transport:
            raise ValueError('No transport provided for ApiManager')
        self.transport = transport(host, port, name, key, api=self, **kwargs)
        self.transport.start()

    def run(self):
        threading.Thread(target=self._periodically_flush_testcase_queue).start()
        self.transport.run()

    def run_async(self):
        self.transport.run_async()

    def disconnect(self):
        self.transport.disconnect()
        self.judge.terminate_grading()
        sys.exit(0)

    def close(self):
        self.transport.close()

    def _send_packet(self, packet, rewrite=True):
        if rewrite and 'submission-id' in packet and self.judge.get_process_type() != 'submission':
            packet['%s-id' % self.judge.get_process_type()] = packet['submission-id']
            del packet['submission-id']

    def _flush_testcase_queue(self):
        with self._testcase_queue_lock:
            if not self._testcase_queue:
                return

            self._send_packet(
                {
                    'name': 'test-case-status',
                    'submission-id': self.judge.current_submission_id,
                    'cases': [
                        {
                            'position': position,
                            'status': result.result_flag,
                            'time': result.execution_time,
                            'points': result.points,
                            'total-points': result.total_points,
                            'memory': result.max_memory,
                            'output': result.output,
                            'extended-feedback': result.extended_feedback,
                            'feedback': result.feedback,
                        }
                        for position, result in self._testcase_queue
                    ],
                }
            )

            self._testcase_queue.clear()

    def _periodically_flush_testcase_queue(self):
        while not self.transport._closed:
            try:
                time.sleep(0.25)
                # It is okay if we flush the testcase queue even while the connection is not open or there's nothing
                # grading, since the only thing that can queue testcases is a currently-grading submission.
                self._flush_testcase_queue()
            except KeyboardInterrupt:
                break
            except Exception:
                traceback.print_exc()

    def _send_packet(self, packet: dict, rewrite: Optional[bool] = False):
        for k, v in packet.items():
            if isinstance(v, bytes):
                # Make sure we don't have any garbage utf-8 from e.g. weird compilers
                # *cough* fpc *cough* that could cause this routine to crash
                # We cannot use utf8text because it may not be text.
                packet[k] = v.decode('utf-8', 'replace')

        return self.transport.send_packet(packet, rewrite=rewrite)

    def receive_packet(self, packet: dict):
        name = packet['name']
        if name == 'ping':
            self.ping_packet(packet['when'])
        elif name == 'get-current-submission':
            self.current_submission_packet()
        elif name == 'submission-request':
            self.submission_acknowledged_packet(packet['submission-id'])
            self.judge.begin_grading(
                packet['submission-id'],
                packet['problem-id'],
                packet['language'],
                packet['source'],
                float(packet['time-limit']),
                int(packet['memory-limit']),
                packet['short-circuit'],
                packet['meta'],
            )
            self._batch = 0
            log.info(
                'Accept submission: %d: executor: %s, code: %s',
                packet['submission-id'],
                packet['language'],
                packet['problem-id'],
            )
        elif name == 'terminate-submission':
            log.info('Received abortion request for %s', self.judge.current_submission_id)
            self.judge.terminate_grading()
        elif name == 'disconnect':
            log.info('Received disconnect request, shutting down...')
            self.disconnect()
        else:
            log.error('Unknown packet %s, payload %s', name, packet)

    def handshake(self):
        problems = get_supported_problems()
        runtimes = get_runtime_versions()
        response = self._send_packet({'name': 'handshake', 'problems': problems, 'executors': runtimes, 'id': self.id, 'key': self.key})

        log.info('Awaiting handshake response: [%s]:%s', self.host, self.port)
        # TODO
        try:
            resp = self.transport.get_handshake_response(response)
        except Exception:
            log.exception('Cannot understand handshake response: [%s]:%s', self.host, self.port)
            raise JudgeAuthenticationFailed('Handshake failed.')
        else:
            if 'name' not in resp or resp['name'] != 'handshake-success':
                raise JudgeAuthenticationFailed('Handshake failed.')

    def supported_problems_packet(self, problems: List[Tuple[str, int]]):
        log.info('Update problems')
        self._send_packet({'name': 'supported-problems', 'problems': problems})

    def test_case_status_packet(self, position: int, result: Result):
        log.info(
            'Test case on %d: #%d, %s [%.3fs | %.2f MB], %.1f/%.0f',
            self.judge.current_submission_id,
            position,
            ', '.join(result.readable_codes()),
            result.execution_time,
            result.max_memory / 1024.0,
            result.points,
            result.total_points,
        )
        with self._testcase_queue_lock:
            self._testcase_queue.append((position, result))

    def compile_error_packet(self, message: str):
        log.info('Compile error: %d', self.judge.current_submission_id)
        self.fallback = 4
        self._send_packet({'name': 'compile-error', 'submission-id': self.judge.current_submission_id, 'log': message})

    def compile_message_packet(self, message: str):
        log.info('Compile message: %d', self.judge.current_submission_id)
        self._send_packet(
            {'name': 'compile-message', 'submission-id': self.judge.current_submission_id, 'log': message}
        )

    def internal_error_packet(self, message: str):
        log.info('Internal error: %d', self.judge.current_submission_id)
        self._flush_testcase_queue()
        self._send_packet(
            {'name': 'internal-error', 'submission-id': self.judge.current_submission_id, 'message': message}
        )

    def begin_grading_packet(self, is_pretested: bool):
        log.info('Begin grading: %d', self.judge.current_submission_id)
        self._send_packet(
            {'name': 'grading-begin', 'submission-id': self.judge.current_submission_id, 'pretested': is_pretested}
        )

    def grading_end_packet(self):
        log.info('End grading: %d', self.judge.current_submission_id)
        self.fallback = 4
        self._flush_testcase_queue()
        self._send_packet({'name': 'grading-end', 'submission-id': self.judge.current_submission_id})

    def batch_begin_packet(self):
        self._batch += 1
        log.info('Enter batch number %d: %d', self._batch, self.judge.current_submission_id)
        self._flush_testcase_queue()
        self._send_packet({'name': 'batch-begin', 'submission-id': self.judge.current_submission_id})

    def batch_end_packet(self):
        log.info('Exit batch number %d: %d', self._batch, self.judge.current_submission_id)
        self._flush_testcase_queue()
        self._send_packet({'name': 'batch-end', 'submission-id': self.judge.current_submission_id})

    def current_submission_packet(self):
        log.info('Current submission query: %d', self.judge.current_submission_id)
        self._send_packet({'name': 'current-submission-id', 'submission-id': self.judge.current_submission_id})

    def submission_terminated_packet(self):
        log.info('Submission aborted: %d', self.judge.current_submission_id)
        self._flush_testcase_queue()
        self._send_packet({'name': 'submission-terminated', 'submission-id': self.judge.current_submission_id})

    def ping_packet(self, when: float):
        data = {'name': 'ping-response', 'when': when, 'time': time.time()}
        for fn in sysinfo.report_callbacks:
            key, value = fn()
            data[key] = value
        self._send_packet(data)

    def submission_acknowledged_packet(self, sub_id: int):
        self._send_packet({'name': 'submission-acknowledged', 'submission-id': sub_id})
