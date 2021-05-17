#!/usr/bin/env python3.8

import os
import subprocess
from time import sleep, time
import argparse
import threading
import logging as log
import sys
from datetime import date
import json
import getmac
from sniffer import Sniffer, BtbrProcessor, BtleProcessor, BtleAdvProcessor, \
    BtbrFingerprint, BtleFingerprint, BtleAdvFingerprint, mac_bytes_to_str
from networking import RequestHandler, Endpoint

ANTENNA = 0
cv = threading.Condition()

class LevelFilter(log.Filter):
    def __init__(self, low: int, high: int = None):
        super().__init__()
        self.__low = low
        self.__high = high if high else log.CRITICAL

    def filter(self, record: log.LogRecord) -> bool:
        return self.__low <= record.levelno <= self.__high

def init_log(path: str) -> None:

    # Create log directory if necessary
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)

    stdout_handler = log.StreamHandler(sys.stdout)
    stdout_handler.addFilter(LevelFilter(log.NOTSET, log.WARNING))
    stderr_handler = log.StreamHandler(sys.stderr)
    stderr_handler.addFilter(LevelFilter(log.ERROR))

    log.basicConfig(
        level=log.DEBUG,
        format='%(asctime)s [%(threadName)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            log.FileHandler(path),
            stdout_handler,
            stderr_handler
        ]
    )

def report_btbr_result(fingerprint: BtbrFingerprint):
    keys = ['uap', 'lap', 'nap', 'firstSeen', 'lastSeen', 'antennaId']
    vals = [f'{fingerprint.uap:02x}' if fingerprint.uap is not None else '00',
            f'{fingerprint.lap:06x}',
            f'{fingerprint.nap:04x}' if fingerprint.nap is not None else '0000',
            fingerprint.first_seen,
            fingerprint.last_seen,
            ANTENNA]

    data = dict(zip(keys, vals))
    RequestHandler.make_post_request(Endpoint.BTBR, data)

def report_btle_result(fingerprint: BtleFingerprint):
    keys = ['accessAddress', 'rssi', 'std', 'mean', 'firstSeen', 'lastSeen', 'antennaId']
    vals = [f'{fingerprint.aa:06X}', fingerprint.rssi, fingerprint.std, fingerprint.mean,
            fingerprint.first_seen, fingerprint.last_seen, ANTENNA]

    data = dict(zip(keys, vals))
    RequestHandler.make_post_request(Endpoint.BTLE, data)
    log.debug('Received fingerprint %s', fingerprint)

def report_btle_adv_result(fingerprint: BtleAdvFingerprint):
    keys = ['macAddress', 'rssi', 'std', 'mean', 'firstSeen', 'lastSeen', 'antennaId']
    vals = [mac_bytes_to_str(fingerprint.mac), fingerprint.rssi, fingerprint.std, fingerprint.mean,
            fingerprint.first_seen, fingerprint.last_seen, ANTENNA]

    data = dict(zip(keys, vals))
    RequestHandler.make_post_request(Endpoint.MAC, data)
    log.debug('Received fingerprint %s', fingerprint)

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

def create_sniffers(modes: list):

    sniffers = []

    for i, mode in enumerate(modes):
        if mode == 'btbr':
            sniffers.append(Sniffer(processor=BtbrProcessor(callback=report_btbr_result, ut_id=i)))
        elif mode == 'btle':
            sniffers.append(Sniffer(processor=BtleProcessor(callback=report_btle_result, ut_id=i)))
        elif mode == 'btle-adv':
            sniffers.append(Sniffer(processor=BtleAdvProcessor(callback=report_btle_adv_result,
                                                               ut_id=i)))
        else:
            log.error('Unrecognized operating mode: %s.', mode)
            sys.exit(-1)

    return sniffers

def report_results(sniffers: list):
    while True:

        sleep(5)

        log.debug("Reporting results.")
        for sniffer in sniffers:

            results = sniffer.result
            if not len(results) > 0:
                continue

            for result in results:
                if isinstance(result, BtbrFingerprint):
                    report_btbr_result(result)
                elif isinstance(result, BtleFingerprint):
                    report_btle_result(result)
                elif isinstance(result, BtleAdvFingerprint):
                    report_btle_adv_result(result)
                else:
                    raise ValueError("Invalid fingerprint.")

def report_location(interval: int):
    keys = ['longitude', 'latitude', 'timestamp', 'antennaId']

    for coordinates in get_location():
        coordinates.append(int(time()))
        coordinates.append(ANTENNA)

        data = dict(zip(keys, coordinates))

        RequestHandler.make_post_request(Endpoint.ANTENNA, data)
        sleep(interval)

def get_location():
    long = 85500000
    lat = 473666700

    while True:
        yield [long/10000000, lat/10000000]
        long, lat = long+20000, lat+20000


def get_antenna_id():
    data = {'address': getmac.get_mac_address()}
    RequestHandler.make_post_request(Endpoint.ID, data, cb_success=set_antenna_id)

def set_antenna_id(response: bytes):
    data = json.loads(response.decode())
    global ANTENNA
    ANTENNA = data['antennaId']

    log.debug('Received antenna id %i', ANTENNA)

    with cv:
        cv.notify_all()

if __name__ == '__main__':

    log_path = f'./logs/{date.today()}.log'
    init_log(log_path)

    parser = argparse.ArgumentParser(description='Bluetooth Device Tracker.')

    parser.add_argument('modes', metavar='modes', type=str, nargs='+',
                        help='Operating modes. One or more of btbr, btle, btle-adv. \
                              One Ubertooth is required per mode.')

    args = parser.parse_args()

    if (required := len(args.modes)) > (present := num_uberteeth()):
        log.critical('Too few Uberteeth connected. %i required, %i present.', required, present)
        print(f'Too few Uberteeth connected. {required} required, {present} present.')
        sys.exit(-1)

    RequestHandler()

    get_antenna_id()
    with cv:
        cv.wait()

    sniffers = create_sniffers(args.modes)

    for sniffer in sniffers:
        sniffer.start()

    location_reporter = threading.Thread(target=report_location,
                                        args=[1],
                                        name='loc_reporter',
                                        daemon=True)
    location_reporter.start()

    reporting_thread = threading.Thread(target=report_results,
                                        args=[sniffers],
                                        name='fp_reporter',
                                        daemon=True)
    reporting_thread.start()

    input("Enter to stop")

    for sniffer in sniffers:
        sniffer.stop()

    for sniffer in sniffers:
        print(sniffer)
