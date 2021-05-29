#!/usr/bin/env python3

from genericpath import isfile
import sqlite3
from sqlite3.dbapi2 import Timestamp
import sys
from os.path import isfile
import bisect
from collections import namedtuple
from math import asin, sqrt, sin, cos, radians
Coords = namedtuple("Coords", "lat lng")


class BtleAdvFingerprint:

    def __init__(self, mac, rssi, std, mean, first_seen, last_seen, antenna):
        self.mac = mac
        self.rssi = rssi
        self.std = std
        self.mean = mean
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.antenna = antenna
        self.successors = list()
        self.is_successor = False
        self.is_static = False
        self.type = 0

    def get_chain(self, *, indent: int=0) -> str:
        return f'{" "*indent}{self.mac}\n'+ \
            '\n'.join(successor.get_chain(indent=indent+2) for successor in self.successors)

    def add_candidates(self, candidates: list, max_candidates: int=2) -> None:
        '''Filters, sorts and adds a list of candidates to the successors list\n
        If candidates contains only one candidate, adds the list directly.\n
        If candidates contains at most max_candidates candidates, sorts them by rssi difference and adds them to the list.\n
        If candidates contains more than max_candidates candidates, appends the max_candidates candidates with the smallest rssi difference.\n
        is_successor is only set on a Fingerprint if it is the only candidate.
        '''
        if (num_candidates := len(candidates)) == 0:
            pass
        elif num_candidates == 1:
            self.successors = candidates
            candidates[0].is_successor = True
        else:
            candidates.sort(key=lambda x: max(abs(self.rssi-x.mean)-x.std, 0))
            self.successors = candidates[:max_candidates]

    def is_possible_successor(self, candidate) -> bool:
        #TODO: Compare type
        #TODO: Compare location
        return True

    def __str__(self) -> str:
        return ', '.join(f'{k}={v}' for k, v in self.__dict__.items())

    def __lt__(self, other) -> bool:
        return self.first_seen < other.last_seen

    def __gt__(self, other) -> bool:
        return self.first_seen > other.last_seen

    def __eq__(self, other) -> bool:
        return not (self < other or self > other)



        
class DbReader:

    __instance = None
    _db_file = None

    @staticmethod
    def get_instance():
        if DbReader.__instance is None:
            raise SyntaxError('No database file set. Please call the constructor or set_db_file with a database file')

        return DbReader.__instance
        
    def __init__(self, db_file: str = None):
        if DbReader.__instance is None:
            DbReader.__instance = self
            DbReader._db_file = db_file
        else:
            raise Exception("Attempting to instance a singleton class.")

    @staticmethod
    def set_db_file(db_file: str):
        DbReader.__db_file = db_file

    @staticmethod
    def get_antenna_path(*, start: int=0, end: int=sys.maxsize):
        statement = f"SELECT Longitude, Latitude, Timestamp FROM Metadata WHERE Timestamp BETWEEN {start} and {end}"

        print(statement)

    @staticmethod
    def get_mac_rows(*, start: int = 0, end: int = sys.maxsize):
        with sqlite3.connect(DbReader._db_file) as conn:
            cur = conn.cursor()
            rows = cur.execute("SELECT * FROM MacAddresses ORDER BY FirstSeen")

            return [BtleAdvFingerprint(*row[1:]) for row in rows]



def process_btle_adv(*, delta_max: int=5, max_candidates: int=2):
    fingerprints = DbReader.get_mac_rows()

    length = len(fingerprints)

    for index, fingerprint in enumerate(fingerprints):
        if fingerprint.is_static:
            continue

        first_candidate_index = bisect.bisect_left(fingerprints, fingerprint, index)

        candidates = list()

        if first_candidate_index < length:
            for candidate in fingerprints[first_candidate_index:]:
                if candidate.first_seen - fingerprint.last_seen < delta_max and \
                   fingerprint.is_possible_successor(candidate):
                        candidates.append(candidate)
                else:
                    break

        fingerprint.add_candidates(candidates)
            
    for fingerprint in fingerprints:
        if not fingerprint.is_successor:
            print(fingerprint.get_chain())

def haversine(a: tuple, b: tuple):
    '''Haversine equations to calculate distance on sphere'''
    earth_radius = 6371.0088

    lat1, lng1 = a
    lat2, lng2 = b

    lat1, lng1, lat2, lng2 = radians(lat1), radians(lng1), radians(lat2), radians(lng2)

    d = sin((lat2 - lat1) * 0.5) ** 2 + cos(lat1) * cos(lat2) * sin((lng2 - lng1) * 0.5) ** 2

    return 2 * earth_radius * asin(sqrt(d))

def usage():
    print(f"Usage: {sys.argv[0]} path_to_db_file")
    sys.exit(0)

if __name__ == '__main__':

    dbfile: str

    if len(sys.argv) != 2:
        if isfile('bluetooth.db'):
            db_file = 'bluetooth.db'
        else:
            usage()

    if not db_file:
        db_file = sys.argv[1]
    
    if not isfile(db_file):
        print(f"Invalid database file: {db_file}")

    DbReader(db_file)

    process_btle_adv()
    

