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
import requests

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


class HTTPSTransport(object):
    def __init__(self, host, port, name, key, path='/', api=None, interval=5):
        self.host = host
        self.port = port
        self.name = name
        self.key = key
        self.interval = interval
        self.api = api
        self.path = path
        self._closed = False
        self.api_url = '%s:%s%s' % (host, port, path)
        self.session = requests.Session()

        log.info('Preparing to connect to [%s]:%s as: %s', host, port, name)

        # TODO What?
        self._lock = threading.RLock()
        self._batch = 0
        # Exponential backoff: starting at 4 seconds.
        # Certainly hope it won't stack overflow, since it will take days if not years.
        self.fallback = 4

        self.conn = None

    def start(self):
        self._do_reconnect()

    def _connect(self):
        log.info('HTTP(S) Transport initiation for: [%s]:%s', self.host, self.port)

        log.info('Starting handshake with: [%s]:%s', self.host, self.port)
        self.api.handshake()
        log.info('Judge "%s" online: [%s]:%s', self.name, self.host, self.port)

    def _reconnect(self):
        if self.fallback > 86400:
            # Return 0 to avoid supervisor restart.
            raise SystemExit(0)

        log.warning('Attempting reconnection in %.0fs: [%s]:%s', self.fallback, self.host, self.port)

        time.sleep(self.fallback)
        self.fallback *= 1.5
        self._do_reconnect()

    def _do_reconnect(self):
        try:
            self._connect()
        except JudgeAuthenticationFailed:
            log.error('Authentication as "%s" failed on: [%s]:%s', self.name, self.host, self.port)
            self._reconnect()
        except socket.error:
            log.exception('Connection failed due to socket error: [%s]:%s', self.host, self.port)
            self._reconnect()

    def __del__(self):
        self.close()

    def close(self):
        pass

    def _read_async(self):
        try:
            while True:
                self._receive_packet(self._read_single())
                time.sleep(self.interval)
        except KeyboardInterrupt:
            pass
        except requests.exceptions.RequestException:
            # TODO Do something
            traceback.print_exc()
            pass
        except Exception:
            traceback.print_exc()
            raise SystemExit(1)

    def _prepare_request(self, data):
        if 'key' in data:
            del data['key']

        request = requests.Request('POST', url=self.api_url, headers={
            'X-DMOJ-Key': self.key
        }, json=data)
        return request.prepare()

    def _read_single(self):
        # TODO Exceptions?
        prepared = self._prepare_request({})
        response = self.session.send(prepared)
        return response

    def run(self):
        self._read_async()

    def run_async(self):
        threading.Thread(target=self._read_async).start()

    def send_packet(self, packet, rewrite=True):
        prepared = self._prepare_request(packet)
        response = self.session.send(prepared)
        return response

    def _receive_packet(self, response):
        response = response.json()
        # Ignore empty payloads
        if 'name' in response:
            self.api.receive_packet(response)

    def get_handshake_response(self, response):
        return response.json()

