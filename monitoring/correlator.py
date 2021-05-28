#!/usr/bin/env python3

from genericpath import isfile
import sqlite3
from sqlite3.dbapi2 import Timestamp
import sys
from os.path import isfile
import bisect

class Fingerprint:
    def __init__(self, row: tuple):
        self.mac = row[1]
        self.rssi = row[2]
        self.rssi_mean = row[4]
        self.first_seen = row[5]
        self.last_seen = row[6]
        self.antenna = row[7]

        self.correlated = 0
        self.successors = list()

    def is_same(self, other):
        if self.mac == other.mac:
            return True

    def get_path(self):
        pass


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

    def get_chain(self, *, indent: int=0):
        return f'{" "*indent}{self.mac}\n'+ \
            '\n'.join(successor.get_chain(indent=indent+2) for successor in self.successors)

    def __str__(self):
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

def find_successor(last_seen_old, rows, successors = None, indent=2):
    
    candidates = filter(lambda x: last_seen_old+5 >= x[5] >= last_seen_old, rows)
    for candidate in candidates:

        print(f'{" "*indent}{candidate[1]}: {candidate[5]}-{candidate[6]} ({candidate[6]-candidate[5]}s) on {candidate[7]}')
        if successors is not None:
            successors.append(candidate[1])

        find_successor(candidate[6], rows, successors, indent+2)

def usage():
    print(f"Usage: {sys.argv[0]} path_to_db_file")
    sys.exit(0)

def process_btle_adv(*, delta_max: int=5, max_candidates: int=2):
    fingerprints = DbReader.get_mac_rows()

    length = len(fingerprints)

    for index, fingerprint in enumerate(fingerprints):
        first_candidate_index = bisect.bisect_left(fingerprints, fingerprint, index)

        candidates = list()

        if first_candidate_index < length:
            for candidate in fingerprints[first_candidate_index:]:
                if candidate.first_seen - fingerprint.last_seen < 5:
                    candidates.append(candidate)
                else:
                    break

        if (num_candidates := len(candidates)) == 0 or num_candidates > max_candidates:
            pass
        elif (num_candidates := len(candidates)) == 1:
            fingerprint.successors = candidates
            candidates[0].is_successor = True
        else:
            fingerprint.successors = candidates
            
    for fingerprint in fingerprints:
        if not fingerprint.is_successor:
            print(fingerprint.get_chain())
            


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

    DbReader.get_instance().get_antenna_path()
    DbReader.get_instance().get_antenna_path(start=1)
    DbReader.get_instance().get_antenna_path(start=1, end=2)

    process_btle_adv()

    

