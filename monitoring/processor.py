#!/usr/bin/env python3

import os
import subprocess
from time import sleep
import argparse
import threading
import logging as log
import sys

running = True

def sniff_btle_adv(cmd):
    process = subprocess.Popen(args=cmd.split(' '), 
                          stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)

    while True:
        # Process exited
        if (exit_code := process.poll()) is not None:
            # Should be running
            if running:
                log.warning(f'Process exited unexpectedly with code {exit_code}. Restarting...')
                process = subprocess.Popen(args=cmd.split(' '),
                                           stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
            # Should not be running
            else:
                log.info(f'Process exited with code {exit_code}')
                break

        else:
            # Should terminate
            if not running:
                log.info("Terminating")

        sleep(1)


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

def test():
    pass


if __name__ == '__main__':
    test()
    parser = argparse.ArgumentParser(description='Bluetooth Device Tracker.')

    log_path = './logs/'
    log_name = 'log01.log'
    logger: log.Logger = init_log(log_path, log_name)

    


    cmd = f'sleep 5'

    sniff_btle_adv(cmd)