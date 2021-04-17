#!/usr/bin/env python3.9

import os
import subprocess
from time import sleep
import argparse
import threading
import logging as log
import sys
import atexit
import sniffer
import datetime
from networking import RequestHandler, Method



def create_pipe(filename: str) -> None:
    if os.path.isfile(filename):
        os.remove(filename)
    elif os.path.isdir(filename):
        os.rmdir(filename)
    
    os.mkfifo(filename, mode)

class LevelFilter(log.Filter):
    def __init__(self, low: int, high: int = None):
        self.__low = low
        self.__high = high if high else log.CRITICAL

    def filter(self, record: log.LogRecord) -> bool:
        return self.__low <= record.levelno <= self.__high

def init_log(log_path: str, log_name: str) -> log.Logger:

    # Create log directory if necessary
    os.makedirs(log_path, mode=0o700, exist_ok=True)


    stdout_handler = log.StreamHandler(sys.stdout)
    stdout_handler.addFilter(LevelFilter(log.NOTSET, log.WARNING))
    stderr_handler = log.StreamHandler(sys.stderr)
    stderr_handler.addFilter(LevelFilter(log.ERROR))
    
    log.basicConfig(
        level=log.DEBUG,
        format='%(asctime)s [%(threadName)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            log.FileHandler(f'{log_path}{"/" if not log_path.endswith("/") else ""}{log_name}'),       
            stdout_handler,
            stderr_handler
        ]
    )


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Bluetooth Device Tracker.')

    log_path = './logs/'
    log_name = 'log01.log'
    init_log(log_path, log_name)

    # Networking
    dict_keys = ['id', 'uap', 'lap', 'nap', 'timestamp', 'antenna']
    import random
    dict_vals = [random.randint(5, 1000), 'string', 'string', 'string', datetime.datetime.now().isoformat(), 1]

    data = dict(zip(dict_keys, dict_vals))

    request_handler = RequestHandler()
    request_handler.make_btbr_request(Method.POST, data)

    input()

    request_handler.make_btbr_request(Method.GET)

    input()

    # Threading subprocess
    sniffer1 = sniffer.Sniffer(sniffer.Type.BTBR)
    sniffer2 = sniffer.Sniffer(sniffer.Type.BTLE_ADV)
    sniffer3 = sniffer.Sniffer(sniffer.Type.BTLE_DATA)

    sniffer1.start()
    sniffer2.start()
    sniffer3.start()

    print('Sniffers started.')
    input()
    sniffer1.stop()
    sniffer2.stop()
    sniffer3.stop()
