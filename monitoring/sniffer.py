#!/usr/bin/env python3.8

import threading
import subprocess
from time import sleep, time
import logging as log
import os
from contextlib import suppress
from collections import namedtuple, defaultdict
from collections.abc import Callable
import struct
import math

__all__ = ['Sniffer', 'BtbrProcessor', 'BtleProcessor', 'BtleAdvProcessor',
           'BtbrFingerprint', 'mac_bytes_to_str']

__author__ = "Severin Marti <severin.marti@ost.ch"
__status__  = "development"
#__version__ = "0.1"
#__date__    = ""

def mac_bytes_to_str(mac: bytes) -> str:
    return ':'.join(f'{byte:02x}' for byte in reversed(mac))

class Std:
    def __init__(self):
        self.mean = 0
        self._n = 0
        self.std = 0

    def update_std(self, value: int):
        if self._n == 0:
            self.mean = value
            self.std = 0
            self._n += 1
            return

        new_mean = (self._n*self.mean + value) / (self._n+1)
        new_std = math.sqrt((self._n*(self.std**2 + (new_mean-self.mean) ** 2) +
                            (new_mean-value)**2) / (self._n+1))
        self.mean = new_mean
        self.std = new_std
        self._n += 1

class BtFingerprint:
    def __init__(self):
        self.first_seen = int(time())
        self.last_seen = self.first_seen

class BtbrFingerprint(BtFingerprint):

    def __init__(self):
        BtFingerprint.__init__(self)
        self.uap = None
        self.lap = None
        self.nap = None

    def update(self, packet):
        if packet.flags & 0b1:
            self.uap = packet.uap

        if new := self.lap is None:
            self.lap = packet.lap

        self.last_seen = packet.timestamp

        return new

    def __str__(self):
        return f'{(self.uap if self.uap else 0):02x}{self.lap:06x}' \
               f'first_seen: {self.first_seen} last_seen: {self.last_seen}'

class BtleFingerprint(BtFingerprint, Std):
    def __init__(self):
        Std.__init__(self)
        BtFingerprint.__init__(self)
        self.aa = None
        self.times_seen = 0
        self.rssi = None

    def update(self, packet):
        if self.aa is None:
            self.aa = packet.aa

        self.rssi = packet.rssi
        self.update_std(packet.rssi)

        self.times_seen += 1

        self.last_seen = packet.timestamp

        return self.times_seen

    def __str__(self):
        return f'{self.aa:06x} seen {self.times_seen} times, last_seen {self.last_seen}, '\
               f'rssi: {self.rssi}, mean: {self.mean}, std: {self.std}'

class BtleAdvFingerprint(BtFingerprint, Std):
    def __init__(self):
        Std.__init__(self)
        BtFingerprint.__init__(self)
        self.type = None
        self.random = None
        self.mac = None
        self.rssi = None
        self.service_uuid = None
        self.company_id = None

    def update(self, packet):
        if new := self.mac is None:
            self.mac = packet.mac
            self.service_uuid = packet.service_uuid
            self.company_id = packet.company_id
            self.random = packet.random


        self.rssi = packet.rssi
        self.update_std(packet.rssi)

        self.last_seen = packet.timestamp

        return new

    def __str__(self):
        return f'{mac_bytes_to_str(self.mac)} random: {self.random} first_seen: {self.first_seen} '\
               f'last_seen: {self.last_seen} rssi: {self.rssi} mean: {self.mean} std: {self.std} '\
               f'service_uuid: {hex(self.service_uuid)} company_id: {hex(self.company_id)}'

class Processor:

    default_pipe = 'pipes/pipe'
    name = 'base'

    def __init__(self, *, pipe_path = "", callback=None, ut_id=0):
        self._pipe = self._create_pipe(pipe_path)
        self._lock = threading.Lock()
        self._processing_thread = None
        self._running = False
        self._callback = callback
        self._ut_id = ut_id
        self._fingerprints = None
        self._last_reported = int(time())

    def _create_pipe(self, path: str) -> str:

        path = self.default_pipe if not path else path

        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)

        with suppress(OSError):
            os.remove(path)

        os.mkfifo(path)

        return path

    def start(self):
        raise NotImplementedError('Method not implemented in base class.')

    def process(self):
        raise NotImplementedError('Method not implemented in base class.')

    def stop(self):
        self._running = False
        self._processing_thread.join()

    def __del__(self):
        self.stop()

class BtleAdvProcessor(Processor):
    default_pipe = 'pipes/btle-adv'
    name = 'btle-adv'
    _packet_length = 20
    _fmt = 'B?6sIiHH'
    _Packet = namedtuple('Packet', ['type', 'random', 'mac', 'timestamp', 'rssi', 'service_uuid', 'company_id'])


    def __init__(self, *, pipe_path='', callback=None, ut_id=0, seen_for=60):
        Processor.__init__(self, pipe_path=pipe_path, callback=callback, ut_id=ut_id)
        self.cmd = f'ubertooth-btle -M {self._pipe} -U {ut_id}'.split(' ')
        self._fingerprints = defaultdict(BtleAdvFingerprint)
        self.seen_for = seen_for

    def start(self):
        self._running = True
        self._processing_thread = threading.Thread(target=BtleAdvProcessor.process,
                                                args=[self],
                                                name=f'{self.name}.processor')
        self._processing_thread.start()

    def process(self):
        log.debug("Started processing.")
        with open(self._pipe, 'rb') as pipe:
            while self._running:

                try:
                    packet = pipe.read(self._packet_length)
                    data = self._Packet._make(struct.unpack(self._fmt, packet))
                except struct.error:
                    if not self._running:
                        break

                    raise

                with self._lock:
                    if self._fingerprints[data.mac].update(data):
                        pass#if self._callback: self._callback(self._fingerprints[data.mac])

    @property
    def result(self):
        with self._lock:

            now = int(time())

            self._fingerprints = defaultdict(BtleAdvFingerprint, { key: value
                                    for key, value in self._fingerprints.items()
                                    if value.last_seen >= self._last_reported })

            self._last_reported = now

            return [ value
                    for value in self._fingerprints.values()
                    if value.last_seen-value.first_seen > self.seen_for]

    def __str__(self):
        with self._lock:
            return '=== BTLE ADVERTISEMENT ===\n' + \
                '\n'.join(f'{":".join(hex(int(byte)).replace("0x", "") for byte in reversed(k))}'+ \
                    f': {v}'\
                     for k, v in self._fingerprints.items() if v.last_seen-v.first_seen > self.seen_for)+ \
                f'\n{len(self._fingerprints)} results.'

class BtleProcessor(Processor):
    default_pipe = 'pipes/btle'
    name = 'btle'
    _packet_length = 12
    _fmt = 'IIi'
    _Packet = namedtuple('Packet', ['aa', 'timestamp', 'rssi'])

    def __init__(self, *, pipe_path='', callback: Callable=None, seen_threshold=5, ut_id=0):
        Processor.__init__(self, pipe_path=pipe_path, callback=callback, ut_id=ut_id)
        self.cmd = f'ubertooth-btle -m {self._pipe} -U {ut_id}'.split(' ')
        self._fingerprints = defaultdict(BtleFingerprint)
        self.seen_threshold = seen_threshold

    def start(self):
        self._running = True
        self._processing_thread = threading.Thread(target=BtleProcessor.process,
                                                args=[self],
                                                name=f'{self.name}.processor')
        self._processing_thread.start()

    def process(self):
        log.debug("Started processing.")

        with open(self._pipe, 'rb') as pipe:
            while self._running:

                try:
                    packet = pipe.read(self._packet_length)
                    data = self._Packet._make(struct.unpack(self._fmt, packet))
                except struct.error:
                    if not self._running:
                        break

                    raise

                with self._lock:
                    if self._fingerprints[data.aa].update(data) >= self.seen_threshold:
                        pass#if self._callback: self._callback(self._fingerprints[data.aa])
    @property
    def result(self):
        with self._lock:
            now = int(time())

            self._fingerprints = defaultdict(BtleFingerprint, { key: value
                                    for key, value in self._fingerprints.items()
                                    if value.last_seen >= self._last_reported })

            self._last_reported = now

            return [ value
                    for value in self._fingerprints.values()
                    if value.times_seen >= self.seen_threshold ]

    def __str__(self):
        with self._lock:
            return '=== BTLE ===\n'+'\n'.join(f'{k:06x}: {v}' \
                for k, v in self._fingerprints.items()\
                if v.times_seen >= self.seen_threshold)+f'\n{len(self._fingerprints)} results.'

class BtbrProcessor(Processor):
    default_pipe = 'pipes/btbr'
    name = 'btbr'
    _packet_length = 12
    _fmt = 'HBII'
    _Packet = namedtuple('Packet', ['flags', 'uap', 'lap', 'timestamp'])

    def __init__(self, *, pipe_path='', callback: Callable=None, ut_id: int=0, seen_for: int=60):
        Processor.__init__(self, pipe_path=pipe_path, ut_id=ut_id)
        self.cmd = f'ubertooth-rx -m {self._pipe} -U {ut_id}'.split(' ')
        self._fingerprints = defaultdict(BtbrFingerprint)
        self._callback = callback
        self.seen_for = seen_for

    def start(self):
        self._running = True
        self._processing_thread = threading.Thread(target=BtbrProcessor.process,
                                                args=[self],
                                                name=f'{self.name}.processor')

        self._processing_thread.start()

    def process(self):
        log.debug("Started processing.")
        while self._running:
            with open(self._pipe, 'rb') as pipe:
                while self._running:

                    try:
                        packet = pipe.read(self._packet_length)
                        data = self._Packet._make(struct.unpack(self._fmt, packet))
                    except struct.error:
                        break

                    with self._lock:
                        if self._fingerprints[data.lap].update(data):
                            pass#if self._callback: self._callback(self._fingerprints[data.lap])

    @property
    def result(self):
        with self._lock:

            now = int(time())

            self._fingerprints = defaultdict(BtbrFingerprint, { key: value
                                    for key, value in self._fingerprints.items()
                                    if value.last_seen >= self._last_reported
            })

            self._last_reported = now

            return [ value
                    for value in self._fingerprints.values()
                    if value.last_seen-value.first_seen > self.seen_for]

    def __str__(self):
        with self._lock:
            return '=== BTBR ===\n' + \
                '\n'.join(f'{k:06x}: {v}' for k, v in self._fingerprints.items()) + \
                f'\n{len(self._fingerprints)} results.'

class Sniffer:

    def __init__(self, *, processor: Processor):
        self._processor = processor
        self._running  = False
        self._sniff_thread = None
        self._watcher_thread = None

    def start(self):
        log.debug('Starting sniffer %s.', self._processor.name)
        self._running = True
        self._watcher_thread = threading.Thread(target=Sniffer._watch_subprocess,
                                               args=[self],
                                               name=f'{self._processor.name}.watcher')
        self._watcher_thread.start()

        self._processor.start()

    def stop(self):
        log.debug('Stopping sniffer %s.', self._processor.name)

        self._running = False

        self._processor.stop()
        self._watcher_thread.join()

    def _watch_subprocess(self):
        process = subprocess.Popen(args=self._processor.cmd)

        while True:
            # Process exited
            if (exit_code := process.poll()) is not None:
                # Should be running
                if self._running:
                    log.warning('Process exited unexpectedly with code %i. Restarting...',
                                exit_code)
                    process = subprocess.Popen(args=self._processor.cmd)
                # Should not be running
                else:
                    log.debug('Process exited with code %i', exit_code)
                    break

            else:
                # Should terminate
                if not self._running:
                    try:
                        process.terminate()
                        process.communicate(timeout=5)
                        log.debug('Process exited with code %i', process.returncode)
                    except subprocess.TimeoutExpired:
                        log.warning('Process did not stop normally, killing...')
                        process.kill()
                        log.debug('Process exited with code %i', process.poll())

                    break

            sleep(1)

    result = property(lambda self: self._processor.result)

    def __str__(self):
        return str(self._processor)


if __name__ == '__main__':
    sniffer1 = Sniffer(processor=BtbrProcessor())
    sniffer2 = Sniffer(processor=BtleProcessor())
    sniffer3 = Sniffer(processor=BtleAdvProcessor())

    sniffer1.start()
    sniffer2.start()
    sniffer3.start()

    print('Sniffers started.')
    input()
    sniffer1.stop()
    sniffer2.stop()
    sniffer3.stop()
