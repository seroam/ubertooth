#!/usr/bin/env python3.9

import os
import subprocess
from time import sleep
import argparse
import threading
import logging as log
import sys
import atexit
from sniffer import Sniffer, BtbrProcessor, BtleProcessor, BtleAdvProcessor, BtbrFingerprint, BtleFingerprint
from datetime import datetime, date
from networking import RequestHandler, Method, Endpoint
from contextlib import suppress


antenna = 1

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
    sniffer1 = Sniffer(processor=BtbrProcessor())
    #sniffer2 = Sniffer(BtleProcessor())
    #sniffer3 = Sniffer(BtleAdvProcessor())

    sniffer1.start()
    #sniffer2.start()
    #sniffer3.start()

    print('Sniffers started.')
    input()
    sniffer1.stop()
    #sniffer2.stop()
    #sniffer3.stop()

def test_api_btbr_post():
    # Networking
    dict_keys = ['uap', 'lap', 'nap', 'timestamp', 'antenna']
    dict_vals = ['string', 'string', 'string', datetime.datetime.now().isoformat(), antenna]

    data = dict(zip(dict_keys, dict_vals))

    RequestHandler.make_post_request(Endpoint.BTBR, data)


def report_btbr_result(fingerprint: BtbrFingerprint):
    log.debug(f'Received fingerprint {fingerprint}')
    keys = ['uap', 'lap', 'nap', 'timestamp', 'antenna']
    vals = [f'{fingerprint.uap:02x}' if fingerprint.uap != None else '00',
            f'{fingerprint.lap:06x}',
            f'{fingerprint.nap:04x}' if fingerprint.nap != None else '0000',
            datetime.fromtimestamp(fingerprint.last_seen).isoformat(),
            antenna]
        
    data = dict(zip(keys, vals))
    RequestHandler.make_post_request(Endpoint.BTBR, data)

def report_btle_result(fingerprint: BtleFingerprint):
    log.debug(f'Received fingerprint {fingerprint}')
    '''keys = ['accessAddress', 'rssi', 'std', 'timestamp', 'antenna']
    vals = [f'{fingerprint.aa:06x}',
            0, #rssi
            0, #std
            datetime.fromtimestamp(fingerprint.last_seen).isoformat(),
            antenna]

    data = dict(zip(keys, vals))
    RequestHandler.make_post_request(Endpoint.BTLE, data)'''

def test_btbr_sniffer():
    btbr_sniffer = Sniffer(processor=BtbrProcessor(callback=report_btbr_result))
    btbr_sniffer.start()

    input("enter to stop")

    btbr_sniffer.stop()

    print(str(btbr_sniffer))

def test_btle_sniffer():
    btle_sniffer = Sniffer(processor=BtleProcessor(callback=report_btle_result))
    btle_sniffer.start()

    input("enter to stop")

    btle_sniffer.stop()

    print(str(btle_sniffer))

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Bluetooth Device Tracker.')

    log_path = f'./logs/{date.today()}.log'
    init_log(log_path)

    RequestHandler()

    #test_btbr_sniffer()

    test_btle_sniffer()

    

    
