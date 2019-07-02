from __future__ import print_function

import errno
import json
import logging
import os
import socket
import struct
import sys
import threading
import time
import traceback
import zlib

import six

from dmoj import sysinfo
from dmoj.judgeenv import get_supported_problems, get_runtime_versions
from dmoj.utils.unicode import utf8text, utf8bytes

try:
    import ssl
except ImportError:
    ssl = None

log = logging.getLogger(__name__)
timer = time.clock if os.name == 'nt' else time.time


class JudgeAuthenticationFailed(Exception):
    pass


class ApiManager(object):
    transport = None

    def __init__(self, host, port, judge, name, key, transport=None, **kwargs):
        self.judge = judge
        self.host = host
        self.port = port
        self.id = name
        self.key = key

        if not transport:
            raise ValueError('No transport provided for ApiManager')
        self.transport = transport(host, port, name, key, api=self, **kwargs)
        self.transport.start()

    def run(self):
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

        for k, v in packet.items():
            if isinstance(v, six.binary_type):
                # Make sure we don't have any garbage utf-8 from e.g. weird compilers
                # *cough* fpc *cough* that could cause this routine to crash
                # We cannot use utf8text because it may not be text.
                packet[k] = v.decode('utf-8', 'replace')

        return self.transport.send_packet(packet, rewrite=rewrite)

    def receive_packet(self, packet):
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
                packet['meta']
            )
            self._batch = 0
            log.info('Accept submission: %d: executor: %s, code: %s',
                     packet['submission-id'], packet['language'], packet['problem-id'])
        elif name == 'invocation-request':
            self.invocation_acknowledged_packet(packet['invocation-id'])
            self.judge.custom_invocation(
                packet['invocation-id'],
                packet['language'],
                packet['source'],
                float(packet['time-limit']),
                int(packet['memory-limit']),
                packet['input-data']
            )
            log.info('Accept invocation: %d: executor: %s', packet['invocation-id'], packet['language'])
        elif name == 'terminate-submission':
            log.info('Received abortion request for %s', self.judge.current_submission)
            self.judge.terminate_grading()
        elif name == 'disconnect':
            log.info('Received disconnect request, shutting down...')
            self.disconnect()
        else:
            log.error('Unknown packet %s, payload %s', name, packet)

    def handshake(self):
        problems = get_supported_problems()
        versions = get_runtime_versions()
        response = self._send_packet({'name': 'handshake',
                           'problems': problems,
                           'executors': versions,
                           'id': self.id,
                           'key': self.key})
        log.info('Awaiting handshake response: [%s]:%s', self.host, self.port)
        # TODO
        try:
            resp = self.transport.get_handshake_response(response)
        except Exception:
            log.exception('Cannot understand handshake response: [%s]:%s', self.host, self.port)
            raise JudgeAuthenticationFailed()
        else:
            if resp['name'] != 'handshake-success':
                log.error('Handshake failed.')
                raise JudgeAuthenticationFailed()

    def invocation_begin_packet(self):
        log.info('Begin invoking: %d', self.judge.current_submission)
        self._send_packet({'name': 'invocation-begin',
                           'invocation-id': self.judge.current_submission})

    def invocation_end_packet(self, result):
        log.info('End invoking: %d', self.judge.current_submission)
        self.fallback = 4
        self._send_packet({'name': 'invocation-end',
                           'output': result.proc_output,
                           'status': result.status_flag,
                           'time': result.execution_time,
                           'memory': result.max_memory,
                           'feedback': result.feedback,
                           'invocation-id': self.judge.current_submission})

    def supported_problems_packet(self, problems):
        log.info('Update problems')
        self._send_packet({'name': 'supported-problems',
                           'problems': problems})

    def test_case_status_packet(self, position, result):
        log.info('Test case on %d: #%d, %s [%.3fs | %.2f MB], %.1f/%.0f',
                 self.judge.current_submission, position,
                 ', '.join(result.readable_codes()),
                 result.execution_time, result.max_memory / 1024.0,
                 result.points, result.total_points)
        self._send_packet({'name': 'test-case-status',
                           'submission-id': self.judge.current_submission,
                           'position': position,
                           'status': result.result_flag,
                           'time': result.execution_time,
                           'points': result.points,
                           'total-points': result.total_points,
                           'memory': result.max_memory,
                           'output': result.output,
                           'extended-feedback': result.extended_feedback,
                           'feedback': result.feedback})

    def compile_error_packet(self, message):
        log.info('Compile error: %d', self.judge.current_submission)
        self.fallback = 4
        self._send_packet({'name': 'compile-error',
                           'submission-id': self.judge.current_submission,
                           'log': message})

    def compile_message_packet(self, message):
        log.info('Compile message: %d', self.judge.current_submission)
        self._send_packet({'name': 'compile-message',
                           'submission-id': self.judge.current_submission,
                           'log': message})

    def internal_error_packet(self, message):
        log.info('Internal error: %d', self.judge.current_submission)
        self._send_packet({'name': 'internal-error',
                           'submission-id': self.judge.current_submission,
                           'message': message})

    def begin_grading_packet(self, is_pretested):
        log.info('Begin grading: %d', self.judge.current_submission)
        self._send_packet({'name': 'grading-begin',
                           'submission-id': self.judge.current_submission,
                           'pretested': is_pretested})

    def grading_end_packet(self):
        log.info('End grading: %d', self.judge.current_submission)
        self.fallback = 4
        self._send_packet({'name': 'grading-end',
                           'submission-id': self.judge.current_submission})

    def batch_begin_packet(self):
        self._batch += 1
        log.info('Enter batch number %d: %d', self._batch, self.judge.current_submission)
        self._send_packet({'name': 'batch-begin',
                           'submission-id': self.judge.current_submission})

    def batch_end_packet(self):
        log.info('Exit batch number %d: %d', self._batch, self.judge.current_submission)
        self._send_packet({'name': 'batch-end',
                           'submission-id': self.judge.current_submission})

    def current_submission_packet(self):
        log.info('Current submission query: %d', self.judge.current_submission)
        self._send_packet({'name': 'current-submission-id',
                           'submission-id': self.judge.current_submission})

    def submission_terminated_packet(self):
        log.info('Submission aborted: %d', self.judge.current_submission)
        self._send_packet({'name': 'submission-terminated',
                           'submission-id': self.judge.current_submission})

    def ping_packet(self, when):
        data = {'name': 'ping-response',
                'when': when,
                'time': time.time()}
        for fn in sysinfo.report_callbacks:
            key, value = fn()
            data[key] = value
        self._send_packet(data)

    def submission_acknowledged_packet(self, sub_id):
        self._send_packet({'name': 'submission-acknowledged',
                           'submission-id': sub_id}, rewrite=False)

    def invocation_acknowledged_packet(self, sub_id):
        self._send_packet({'name': 'submission-acknowledged',
                           'invocation-id': sub_id}, rewrite=False)
