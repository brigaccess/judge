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


class SocketTransport(object):
    SIZE_PACK = struct.Struct('!I')

    def __init__(self, host, port, name, key, api=None, secure=False, no_cert_check=False, cert_store=None):
        self.host = host
        self.port = port
        self.name = name
        self.api = api
        self._closed = False

        log.info('Preparing to connect to [%s]:%s as: %s', host, port, name)
        if secure and ssl:
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.ssl_context.options |= ssl.OP_NO_SSLv2
            self.ssl_context.options |= ssl.OP_NO_SSLv3

            if not no_cert_check:
                self.ssl_context.verify_mode = ssl.CERT_REQUIRED
                self.ssl_context.check_hostname = True

            if cert_store is None:
                self.ssl_context.load_default_certs()
            else:
                self.ssl_context.load_verify_locations(cafile=cert_store)
            log.info('Configured to use TLS.')
        else:
            self.ssl_context = None
            log.info('TLS not enabled.')

        self.secure = secure
        self.no_cert_check = no_cert_check
        self.cert_store = cert_store

        self._lock = threading.RLock()
        self._batch = 0
        # Exponential backoff: starting at 4 seconds.
        # Certainly hope it won't stack overflow, since it will take days if not years.
        self.fallback = 4

        self.conn = None

    def start(self):
        self._do_reconnect()

    def _connect(self):
        log.info('Opening connection to: [%s]:%s', self.host, self.port)

        while True:
            try:
                self.conn = socket.create_connection((self.host, self.port), timeout=5)
            except OSError as e:
                if e.errno != errno.EINTR:
                    raise
            else:
                break

        self.conn.settimeout(300)
        self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        if self.ssl_context:
            log.info('Starting TLS on: [%s]:%s', self.host, self.port)
            self.conn = self.ssl_context.wrap_socket(self.conn, server_hostname=self.host)

        log.info('Starting handshake with: [%s]:%s', self.host, self.port)
        self.input = self.conn.makefile('rb')
        self.output = self.conn.makefile('wb', 0)
        self.api.handshake()
        log.info('Judge "%s" online: [%s]:%s', self.name, self.host, self.port)

    def _reconnect(self):
        if self.fallback > 86400:
            # Return 0 to avoid supervisor restart.
            raise SystemExit(0)

        log.warning('Attempting reconnection in %.0fs: [%s]:%s', self.fallback, self.host, self.port)

        if self.conn is not None:
            log.info('Dropping old connection.')
            self.conn.close()
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
        if self.conn and not self._closed:
            self.conn.shutdown(socket.SHUT_RDWR)
        self._closed = True

    def _read_async(self):
        try:
            while True:
                self._receive_packet(self._read_single())
        except KeyboardInterrupt:
            pass
        except Exception:  # connection reset by peer
            traceback.print_exc()
            raise SystemExit(1)

    def _read_single(self):
        try:
            data = self.input.read(SocketTransport.SIZE_PACK.size)
        except socket.error:
            self._reconnect()
            return self._read_single()
        if not data:
            self._reconnect()
            return self._read_single()
        size = SocketTransport.SIZE_PACK.unpack(data)[0]
        try:
            packet = zlib.decompress(self.input.read(size))
        except zlib.error:
            self._reconnect()
            return self._read_single()
        else:
            return json.loads(utf8text(packet))

    def run(self):
        self._read_async()

    def run_async(self):
        threading.Thread(target=self._read_async).start()

    def send_packet(self, packet, rewrite=True):
        raw = zlib.compress(utf8bytes(json.dumps(packet)))
        with self._lock:
            self.output.writelines((SocketTransport.SIZE_PACK.pack(len(raw)), raw))

    def _receive_packet(self, packet):
        self.api.receive_packet(packet)

    def get_handshake_response(self, response):
        data = self.input.read(SocketTransport.SIZE_PACK.size)
        size = SocketTransport.SIZE_PACK.unpack(data)[0]
        packet = utf8text(zlib.decompress(self.input.read(size)))
        resp = json.loads(packet)
        return resp

