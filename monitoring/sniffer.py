#!/usr/bin/env python3.9

import threading
import subprocess
from enum import Enum, auto
from time import sleep
import logging as log

__all__ = ['Sniffer', 'Type']

__author__ = "Severin Marti <severin.marti@ost.ch"
__status__  = "development"
#__version__ = "0.1"
#__date__    = ""

# Sniffer modes
class Type(Enum):
    BTBR = auto()
    BTLE_ADV = auto()
    BTLE_DATA = auto()

class Sniffer:

    def __init__(self, sniffer_type: Type):
        self.__type = sniffer_type
        self.__running  = False
        self.__sniff_thread = None

    def start(self):
        log.debug(f'Starting sniffer {self.__type.name}.')
        self.__running = True
        self.__sniff_thread = threading.Thread(target=Sniffer._sniff,
                                               args=[self, self.__get_process_args()],
                                               name=self.__type.name)
        self.__sniff_thread.start()

    def stop(self):
        log.debug(f'Stopping sniffer {self.__type.name}.')
        self.__running = False
        self.__sniff_thread.join()

    def _sniff(self, cmd):
        # TODO: Remove stdX pipes when interprocess pipes are working
        process = subprocess.Popen(args=cmd, 
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

        while True:
            # Process exited
            if (exit_code := process.poll()) is not None:
                # Should be running
                if self.__running:
                    #TODO: Remove stdX pipes when interprocess pipes are working 
                    log.warning(f'Process exited unexpectedly with code {exit_code}. Restarting...')
                    process = subprocess.Popen(args=cmd,
                                            stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
                # Should not be running
                else:
                    log.debug(f'Process exited with code {exit_code}')
                    break

            else:
                # Should terminate
                if not self.__running:
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

    def __get_process_args(self) -> list[str]:
        if self.__type == Type.BTBR:
            return 'sleep 5'.split(' ')
        elif self.__type == Type.BTLE_ADV:
            return 'sleep 7'.split(' ')
        elif self.__type == Type.BTLE_DATA:
            return 'sleep 10'.split(' ')