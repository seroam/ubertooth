#!/usr/bin/env python3.8

# sudo dpkg-reconfigure ca-certificates
# mozilla/VeriSign_Universal_Root_Certification_Authority.crt

import json
import datetime
import logging as log
from queue import Queue
from enum import Enum, IntEnum
import threading
import requests

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
    ID = 'Antenna'
    ANTENNA = 'AntennaMetadata'

class Method(IntEnum):
    GET = 0
    POST = 1
    PUT = 2
    DELETE = 3

class Request:
    def __init__(self, method: Method, endpoint: Endpoint,
                 data: dict=None, cb_success=None, cb_error=None):
        self.method = method
        self.endpoint = endpoint
        self.data = data
        self.cb_success = cb_success
        self.cb_error = cb_error

class RequestHandler:

    __instance = None

    # Enable/disable SSL certificate verification
    _verify = False

    _hostname = None
    _port = None
    __queue = None
    __sender_thread = None

    __successtive_fails = 0

    __delaying = False

    _cv = threading.Condition()

    @staticmethod
    def get_instance():
        ''' Static access method. '''
        if RequestHandler.__instance is None:
            RequestHandler()
        return RequestHandler.__instance

    def __init__(self):
        ''' Virtually private constructor. '''

        RequestHandler._hostname, RequestHandler._port = RequestHandler.__load_settings()

        RequestHandler.__queue = Queue(-1)
        RequestHandler.__sender_thread = threading.Thread(target=RequestHandler.__send,
                                                          name="NETWORK", daemon=True)
        RequestHandler.__sender_thread.start()

        if RequestHandler.__instance is None:
            RequestHandler.__instance = self
        else:
            raise Exception("Attempting to instance a singleton class.")

    @staticmethod
    def make_post_request(endpoint: Endpoint, data: dict, cb_success=None, cb_error=None):

        request = Request(method=Method.POST, endpoint=endpoint.value, data=json.dumps(data),
                          cb_success=cb_success, cb_error=cb_error)
        RequestHandler.__queue.put_nowait(request)

    @staticmethod
    def __retry_send():
        RequestHandler.__delaying = False

        with RequestHandler._cv:
            log.debug("Retrying send")
            RequestHandler._cv.notify_all()

    @staticmethod
    def __send():
        while True:

            log.debug('Grabbing request...')
            if RequestHandler.__delaying:
                with RequestHandler._cv:
                    RequestHandler._cv.wait()

            request = RequestHandler.__queue.get()

            if request.method == Method.POST:
                headers = {'Accept': 'text/plain', 'Content-Type': 'application/json'}
                response = requests.post( url=f'https://{RequestHandler._hostname}:\
{RequestHandler._port}/api/{request.endpoint}',
                                        headers=headers,
                                        data=request.data,
                                        verify=RequestHandler._verify )
            else:
                raise NotImplementedError(f'Unknown method: {request.method}.')


            if response.ok:
                log.debug('Response (%i)\n%s', response.status_code, response.content)
                RequestHandler.__successtive_fails = 0
                if request.cb_success:
                    request.cb_success(response.content)
            else:
                log.debug('Response (%i)', response.status_code)
                RequestHandler.__queue.put_nowait(request)

                if request.cb_error:
                    request.cb_error(response.content)

                RequestHandler.__successtive_fails += 1

                # If we've failed to send a message five times in a row, sleep for 10 seconds.
                if RequestHandler.__successtive_fails >= 5:
                    log.warning("Failed to send a request %i times in a row. \
Waiting for 10 seconds before retry.",
                                RequestHandler.__successtive_fails)
                    RequestHandler.__delaying = True

                    retry_delay = threading.Timer(10, RequestHandler.__retry_send)
                    retry_delay.start()

    @staticmethod
    def __load_settings():
        with open('network.conf', 'r') as file:
            settings = json.load(file)

        try:
            hostname = settings['hostname']
            port = settings['port']
        except:
            log.critical("Unable to load network settings from file.")
            raise RuntimeError("Unable to load network settings from file.") from None

        log.debug('Remote hostname: %s, remote port: %i.', hostname, port)

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
    #request_handler.make_post_request(Endpoint.BTBR, data)


    input()
