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
from networking import RequestHandler, Method, Endpoint
from contextlib import suppress



def create_pipe(filename: str) -> None:
    with suppress(OSError):
        os.remove(filename)
    
    os.mkfifo(filename, 0o600)

class LevelFilter(log.Filter):
    def __init__(self, low: int, high: int = None):
        self.__low = low
        self.__high = high if high else log.CRITICAL

    def filter(self, record: log.LogRecord) -> bool:
        return self.__low <= record.levelno <= self.__high

def init_log(log_path: str) -> None:

    # Create log directory if necessary
    os.makedirs(os.path.dirname(log_path), mode=0o700, exist_ok=True)

    stdout_handler = log.StreamHandler(sys.stdout)
    stdout_handler.addFilter(LevelFilter(log.NOTSET, log.WARNING))
    stderr_handler = log.StreamHandler(sys.stderr)
    stderr_handler.addFilter(LevelFilter(log.ERROR))
    
    log.basicConfig(
        level=log.DEBUG,
        format='%(asctime)s [%(threadName)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            log.FileHandler(log_path),       
            stdout_handler,
            stderr_handler
        ]
    )

def test_sniffers():
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

def test_api_btbr_post():
    # Networking
    dict_keys = ['uap', 'lap', 'nap', 'timestamp', 'antenna']
    dict_vals = ['string', 'string', 'string', datetime.datetime.now().isoformat(), 1]

    data = dict(zip(dict_keys, dict_vals))

    request_handler = RequestHandler.get_instance()
    request_handler.make_post_request(Endpoint.BTBR, data)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Bluetooth Device Tracker.')

    log_path = f'./logs/{datetime.date.today()}.log'
    init_log(log_path)

    RequestHandler()

    test_api_btbr_post()

    input()

    test_sniffers()
    
