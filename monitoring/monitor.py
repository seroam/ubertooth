#!/usr/bin/env python3.8

import os
import subprocess
from time import sleep
import argparse
import threading
import logging as log
import sys
import atexit
from sniffer import Sniffer, BtbrProcessor, BtleProcessor, BtleAdvProcessor, BtbrFingerprint, BtleFingerprint, BtleAdvFingerprint
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
    pass#log.debug(f'Received fingerprint {fingerprint}')
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

def report_btle_adv_result(fingerprint: BtleAdvFingerprint):
    pass#log.debug(f'Received fingerprint {fingerprint}')

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

def test_btle_adv_sniffer():
    btle_adv_sniffer = Sniffer(processor=BtleAdvProcessor(callback=report_btle_adv_result))
    btle_adv_sniffer.start()

    input('enter to stop')

    btle_adv_sniffer.stop()

    print(str(btle_adv_sniffer))

def num_uberteeth():
    process = subprocess.Popen(args='ubertooth-util -N'.split(' '),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    out, err = process.communicate()
    if err:
        log.critical('Unable to determine number of uberteeth. Exiting.')
        sys.exit(-1)

    uberteeth = int(out.decode('utf-8').replace('\n', ''))

    return uberteeth

def test_two_sniffers():

    if num_uberteeth() < 2:
        raise ResourceWarning('Too few Uberteeth connected.')

    btbr_sniffer = Sniffer(processor=BtbrProcessor(callback=report_btbr_result, ut_id=0))
    btle_adv_sniffer = Sniffer(processor=BtleAdvProcessor(callback=report_btle_adv_result, ut_id=1))
    btbr_sniffer.start()
    btle_adv_sniffer.start()

    input("Enter to stop")

    btbr_sniffer.stop()
    btle_adv_sniffer.stop()

    print(btbr_sniffer)
    print(btle_adv_sniffer)

def create_sniffers(modes: list):

    sniffers = []

    for i, mode in enumerate(modes):
        if mode == 'btbr':
            sniffers.append(Sniffer(processor=BtbrProcessor(callback=report_btbr_result, ut_id=i)))
        elif mode == 'btle':
            sniffers.append(Sniffer(processor=BtleProcessor(callback=report_btle_result, ut_id=i)))
        elif mode == 'btle-adv':
            sniffers.append(Sniffer(processor=BtleAdvProcessor(callback=report_btle_adv_result, ut_id=i)))
        else:
            log.error(f'Unrecognized operating mode: {mode}.')
            exit(0)

    return sniffers

if __name__ == '__main__':

    log_path = f'./logs/{date.today()}.log'
    init_log(log_path)

    parser = argparse.ArgumentParser(description='Bluetooth Device Tracker.')

    parser.add_argument('modes', metavar='modes', type=str, nargs='+',
                        help='Operating modes. One or more of btbr, btle, btle-adv. On Ubertooth is required per mode.')

    args = parser.parse_args()

    if (required := len(args.modes)) > (present := num_uberteeth()):
        log.critical(f'Too few Uberteeth connected. {required} required, {present} present.')
        sys.exit(-1)
    
    RequestHandler()

    sniffers = create_sniffers(args.modes)

    for sniffer in sniffers:
        sniffer.start()

    input("Enter to stop")

    for sniffer in sniffers:
        sniffer.stop()

    for sniffer in sniffers:
        print(sniffer)

    #num_devices = num_uberteeth()

    #test_btbr_sniffer()

    #test_btle_sniffer()

    #test_btle_adv_sniffer()

    #test_two_sniffers()


    

    
