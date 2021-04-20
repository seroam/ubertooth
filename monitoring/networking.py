#!/usr/bin/env python3

# sudo dpkg-reconfigure ca-certificates
# mozilla/VeriSign_Universal_Root_Certification_Authority.crt

import requests
import json
import datetime
import logging as log
from queue import Queue
from enum import Enum, IntEnum, auto
from threading import Thread
from collections import namedtuple
from dataclasses import dataclass

__all__ = ['Endpoint', 'Method', 'RequestHandler']

__author__ = "Severin Marti <severin.marti@ost.ch"
__status__  = "development"


# TODO: Remove this once we have valid certificates
from urllib3 import disable_warnings
disable_warnings()

class Endpoint(Enum):
    BTBR = 'Btbr'
    BTLE = 'Btle'
    MAC = 'MacAddr'

class Method(IntEnum):
    GET = 0
    POST = 1
    PUT = 2
    DELETE = 3

class Request:
    def __init__(self, method: Method, endpoint: Endpoint, data: dict=None):
        self.method = method
        self.endpoint = endpoint
        self.data = data

class RequestHandler:

    __instance = None

    # Enable/disable SSL certificate verification
    _verify = False

    _hostname = None
    _port = None
    __queue = None
    __sender_thread = None

    @staticmethod
    def get_instance():
        ''' Static access method. '''
        if RequestHandler.__instance == None:
            RequestHandler()
        return RequestHandler.__instance

    def __init__(self):
        ''' Virtually private constructor. '''

        RequestHandler._hostname, RequestHandler._port = RequestHandler.__load_settings()

        RequestHandler.__queue = Queue(-1)
        RequestHandler.__sender_thread = Thread(target=RequestHandler.__send, name="NETWORK", daemon=True)
        RequestHandler.__sender_thread.start()

        if RequestHandler.__instance != None:
            raise Exception("Attempting to instance a singleton class.")
        else:
            RequestHandler.__instance = self

        
    @staticmethod
    def make_post_request(endpoint: Endpoint, data: dict):

        request = Request(method=Method.POST, endpoint=endpoint.value, data=json.dumps(data))
        RequestHandler.__queue.put_nowait(request)

    @staticmethod
    def __send():
        while True:
            if not RequestHandler.__queue.empty():
                log.debug('Grabbing request...')
                request = RequestHandler.__queue.get()

                if request.method == Method.GET:
                    headers = {'Accept': 'text/plain'}
                    response = requests.get( url=f'https://{RequestHandler._hostname}:{RequestHandler._port}/api/{request.endpoint}',
                                            headers=headers,
                                            verify=RequestHandler._verify )

                elif request.method == Method.POST:
                    headers = {'Accept': 'text/plain', 'Content-Type': 'application/json'}
                    response = requests.post( url=f'https://{RequestHandler._hostname}:{RequestHandler._port}/api/{request.endpoint}',
                                            headers=headers,
                                            data=request.data,
                                            verify=RequestHandler._verify )

                elif request.method == Method.PUT:
                    raise NotImplementedError(f'Method {request.method} not implemented.')
                elif request.method == Method.DELETE:
                    raise NotImplementedError(f'Method {request.method} not implemented.')
                else:
                    raise NotImplementedError(f'Unknown method: {request.method}.')

                
                if response.ok:
                    log.debug(f'Response ({response.status_code})\n{response.content}')
                else:
                    log.debug(f'Response ({response.status_code})')
                    RequestHandler.__queue.put_nowait(request)
    
    @staticmethod
    def __load_settings():
        with open('network.conf', 'r') as f:
            settings = json.load(f)

        try:
            hostname = settings['hostname']
            port = settings['port']
        except:
            log.critical("Unable to load network settings from file.")
            raise RuntimeError("Unable to load network settings from file.")

        log.debug(f'Remote hostname: {hostname}, remote port: {port}.')

        return hostname, port

if __name__ == '__main__':
    from sys import stdout
    log.basicConfig(
        level=log.DEBUG,
        format='%(asctime)s [%(threadName)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            log.StreamHandler(stdout)
        ]
    )

    dict_keys = ['uap', 'lap', 'nap', 'timestamp', 'antenna']
    dict_vals = ['string', 'string', 'string', datetime.datetime.now().isoformat(), 1]

    #data = json.dumps(dict(zip(dict_keys, dict_vals)))
    data = dict(zip(dict_keys, dict_vals))

    request_handler = RequestHandler()
    request_handler.make_post_request(Endpoint.BTBR, data)


    input()


