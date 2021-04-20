#!/usr/bin/env python3.9

import threading
import subprocess
from enum import Enum, auto
from time import sleep, time
import logging as log
import os
from contextlib import suppress
from collections import namedtuple, defaultdict
from collections.abc import Callable
import struct

__all__ = ['Sniffer', 'BtbrProcessor', 'BtleProcessor', 'BtleAdvProcessor', 'BtbrFingerprint']

__author__ = "Severin Marti <severin.marti@ost.ch"
__status__  = "development"
#__version__ = "0.1"
#__date__    = ""



class BtbrFingerprint:

    def __init__(self):
        self.first_seen = int(time())
        self.uap = None
        self.lap = None
        self.nap = None
        self.last_seen = self.first_seen

    def update(self, packet):
        if packet.flags & 0b1:
            self.uap = packet.uap

        if new := self.lap == None:
            self.lap = packet.lap

        self.last_seen = packet.timestamp

        return new

    def __str__(self):
        return f'{(self.uap if self.uap else 0):02x}{self.lap:06x} first_seen: {self.first_seen} last_seen: {self.last_seen}'

class BtleFingerprint:
    def __init__(self):
        self.first_seen = int(time())
        self.last_seen = self.first_seen
        self.aa = None
        self.times_seen = 0

    def update(self, packet):
        if self.aa == None:
            self.aa = packet.aa

        self.times_seen += 1

        self.last_seen = packet.timestamp

        return self.times_seen

    def __str__(self):
        return f'{self.aa:06x} seen {self.times_seen} times, last_seen {self.last_seen}'

class Processor:

    default_pipe = 'pipes/pipe'
    name = 'base'

    def __init__(self, *, pipe_path = ""):
        self._pipe = self._create_pipe(pipe_path)
        self._lock = threading.Lock()
        self._processing_thread = None
        self._running = False

    def _create_pipe(self, path: str) -> str:

        path = self.default_pipe if not path else path

        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)

        with suppress(OSError):
            os.remove(path)
    
        os.mkfifo(path)

        return path

    def start(self, callback=None):
        raise NotImplementedError('Method not implemented in base class.')

    def process(self, callback=None):
        raise NotImplementedError('Method not implemented in base class.')

    def stop(self):
        self._running = False
        self._processing_thread.join()

    def __del__(self):
        self.stop()

class BtleAdvProcessor(Processor):
    default_pipe = 'pipes/btle-adv'
    name = 'btle-adv'
    _packet_length = 12

    def __init__(self, *, pipe_path=''):
        self.cmd = 'sleep 10'.split(' ')
        Processor.__init__(self, pipe_path=pipe_path)

class BtleProcessor(Processor):
    default_pipe = 'pipes/btle'
    name = 'btle'
    _packet_length = 8
    _fmt = 'II'
    _Packet = namedtuple('Packet', ['aa', 'timestamp'])

    def __init__(self, *, pipe_path='', callback: Callable=None, seen_threshold=5):
        self.cmd = 'sleep 7'.split(' ')
        Processor.__init__(self, pipe_path=pipe_path)
        self.cmd = f'ubertooth-btle -m {self._pipe}'.split(' ')
        self._fingerprints = defaultdict(BtleFingerprint)
        self._callback = callback
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
                packet = pipe.read(self._packet_length)
                data = self._Packet._make(struct.unpack(self._fmt, packet))

                with self._lock:
                    if self._fingerprints[data.aa].update(data) >= self.seen_threshold:
                        if self._callback: self._callback(self._fingerprints[data.aa])


class BtbrProcessor(Processor):
    default_pipe = 'pipes/btbr'
    name = 'btbr'
    _packet_length = 12
    _fmt = 'HBII'
    _Packet = namedtuple('Packet', ['flags', 'uap', 'lap', 'timestamp'])

    def __init__(self, *, pipe_path='', callback: Callable=None):
        Processor.__init__(self, pipe_path=pipe_path)
        self.cmd = f'ubertooth-rx -m {self._pipe}'.split(' ')
        self._fingerprints = defaultdict(BtbrFingerprint)
        self._callback = callback
        
    def start(self):
        self._running = True
        self._processing_thread = threading.Thread(target=BtbrProcessor.process,
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
                    else:
                        raise

                with self._lock:
                    if self._fingerprints[data.lap].update(data):
                        if self._callback: self._callback(self._fingerprints[data.lap])

    def __str__(self):
        with self._lock:
            return '\n'.join(f'{k:06x}: {v}' for k, v in self._fingerprints.items())

    @property
    def result(self):
        with self._lock:
            return self._fingerprints.values()




class Sniffer:

    def __init__(self, *, processor: Processor):
        self._processor = processor
        self._running  = False
        self._sniff_thread = None

    def start(self):
        log.debug(f'Starting sniffer {self._processor.name}.')
        self._running = True
        self._watcher_thread = threading.Thread(target=Sniffer._watch_subprocess,
                                               args=[self],
                                               name=f'{self._processor.name}.watcher')
        self._watcher_thread.start()

        self._processor.start()

    def stop(self):
        log.debug(f'Stopping sniffer {self._processor.name}.')

        self._running = False

        self._processor.stop()
        self._watcher_thread.join()

    def _watch_subprocess(self):
        # TODO: Remove stdX pipes when interprocess pipes are working
        process = subprocess.Popen(args=self._processor.cmd, 
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

        while True:
            # Process exited
            if (exit_code := process.poll()) is not None:
                # Should be running
                if self._running:
                    #TODO: Remove stdX pipes when interprocess pipes are working 
                    log.warning(f'Process exited unexpectedly with code {exit_code}. Restarting...')
                    process = subprocess.Popen(args=self._processor.cmd,
                                            stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
                # Should not be running
                else:
                    log.debug(f'Process exited with code {exit_code}')
                    break

            else:
                # Should terminate
                if not self._running:
                    try:
                        process.terminate()
                        process.communicate(timeout=5)
                        log.debug(f'Process exited with code {process.returncode}')
                    except subprocess.TimeoutExpired:
                        log.warning('Process did not stop normally, killing...')
                        process.kill()
                        log.debug(f'Process exited with code {process.poll()}')

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