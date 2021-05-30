#!/usr/bin/env python3

from genericpath import isfile
import sqlite3
from sqlite3.dbapi2 import Timestamp
import sys
from os.path import isfile
import bisect
from collections import namedtuple, defaultdict
from math import asin, sqrt, sin, cos, radians
from typing import Generator
import networkx as nx
import itertools
import matplotlib.pyplot as plt
import random


def haversine(a: tuple, b: tuple):
    '''Haversine equations to calculate distance on sphere'''
    earth_radius = 6371.0088

    lat1, lng1 = a
    lat2, lng2 = b

    lat1, lng1, lat2, lng2 = radians(lat1), radians(lng1), radians(lat2), radians(lng2)

    d = sin((lat2 - lat1) * 0.5) ** 2 + cos(lat1) * cos(lat2) * sin((lng2 - lng1) * 0.5) ** 2

    return 2 * earth_radius * asin(sqrt(d))

def antenna_distance(id1: int, t1: int, id2: int, t2: int=None):
    if t2 is None:
        t2 = t1

    return haversine(DbReader.get_antenna_location(antenna=id1, timestamp=t1),
                     DbReader.get_antenna_location(antenna=id2, timestamp=t2))

class BtleAdvFingerprint:

    def __init__(self, mac, rssi, std, mean, first_seen, last_seen, service_uuid, company_id, is_random, antenna):
        self.mac = mac
        self.rssi = rssi
        self.std = std
        self.mean = mean
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.service_uuid = service_uuid
        self.company_id = company_id
        self.is_random = is_random
        self.antenna = antenna

        self.is_successor = False
        self.successors = list()
        self.is_hopped = False
        self.antenna_hop = list()

    def get_chain(self, *, indent: int=0) -> str:
        return f'{" "*indent}{self.mac}\n'+ \
            '\n'.join(successor.get_chain(indent=indent+2) for successor in self.successors)

    def add_candidates(self, candidates: list, *, max_candidates: int=2, candidates_limit: int=5) -> None:
        '''Filters, sorts and adds a list of candidates to the successors list\n

        Positional arguments:
        candidates -- a list of BtleAdvFingerprints of successor candidates

        Keyword arguments:
        max_candidates -- the maximum number of candidates that will be added to the successors list
        candidates_limit -- the maximum number of candidates for which picking successors is still assumed reasonable.

        If candidates contains only one candidate, adds the list directly.\n
        If candidates contains at most max_candidates candidates, sorts them by rssi difference and adds them to the list.\n
        If candidates contains more than max_candidates candidates, but less than candidates_limit, appends the max_candidates candidates with the smallest rssi difference.\n
        is_successor is only set on a Fingerprint if it is the only candidate.
        is candidates contains more than candidates_limit candidates, does nothing

        Reasoning:
        If there is more than one candidate, we cannot be sure we picked the new successor, therefore we do not mark the candidate as a successor.
        If there is more than candidates_limit candidates, picking one would be extremely unrealiable and picking one would yield little
        
        '''
        if (num_candidates := len(candidates)) == 0:
            pass
        elif num_candidates == 1:
            self.successors = candidates
            candidates[0].is_successor = True
        elif num_candidates <= candidates_limit:
            candidates.sort(key=lambda x: max(abs(self.rssi-x.mean)-x.std, 0))
            self.successors = candidates[:max_candidates]

    def is_possible_successor(self, candidate, *, max_distance_diff: int=10) -> bool:
        '''Performs basic test if a candidate could be a successor by comparing company_id and service_uuid, as well as the location
        
        Positional arguments:\n
        candiate -- the candidate BtleAdvFingerprint\n
        
        Keyword arguments:\n
        max_distance_diff -- the maximum allowed distance in km between the antennas at points self.last_seen and candidate.first_seen'''

        return self.company_id == candidate.company_id and \
               self.service_uuid == candidate.service_uuid and \
               antenna_distance(self.antenna, self.last_seen, candidate.antenna, candidate.first_seen) <= max_distance_diff

    def add_hopped(self, other) -> None:
        raise NotImplementedError("add_hopped not yet implemented.")

    def __str__(self) -> str:
        return ', '.join(f'{k}={v}' for k, v in self.__dict__.items())

    def __repr__(self) -> str:
        return f'{self.mac[:2]}..{self.mac[-2:]} {self.first_seen}-{self.last_seen} on {self.antenna}'

    def __hash__(self) -> int:
        return ''.join(f'{v}' for v in self.__dict__.values()).__hash__()

    def __lt__(self, other) -> bool:
        '''Performs a comparison of first_seen with last_seen.

        Implementation is necessary for use in bisect algorithm, as it does not take a key parameter'''

        return self.first_seen < other.last_seen

    def __gt__(self, other) -> bool:
        '''Performs a comparison of first_seen with last_seen.

        Implementation is necessary for use in bisect algorithm, as it does not take a key parameter'''
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
    def get_antenna_path(*, antenna: int, start: int=0, end: int=sys.maxsize) -> list:
        statement = f"SELECT Longitude, Latitude, Timestamp FROM Metadata WHERE AntennaId == {antenna} AND Timestamp BETWEEN {start} AND {end}"
        return DbReader._execute(statement)

    @staticmethod
    def get_antenna_location(*, antenna: int, timestamp: int) -> tuple:
        statement = f'SELECT Latitude, Longitude FROM Metadata WHERE AntennaId == {antenna} AND Timestamp <= {timestamp} ORDER BY Timestamp DESC LIMIT 1'
        location = DbReader._execute(statement)

        if not location:
            raise LookupError(f'No location for antenna {antenna} found before {timestamp}')
        return location[0]

    @staticmethod
    def get_mac_rows(*, start: int = 0, end: int = sys.maxsize):
        statement = 'SELECT * FROM MacAddresses ORDER BY FirstSeen'
        rows = DbReader._execute_lazy(statement)

        return [BtleAdvFingerprint(*row[1:]) for row in rows]

    @staticmethod
    def get_all_macs():
        data = dict()
        
        for antenna in DbReader._execute_lazy('SELECT DISTINCT AntennaId FROM MacAddresses'):
            macs = defaultdict(list)
            for mac in DbReader._execute_lazy(f'SELECT DISTINCT MacAddress, Id FROM MacAddresses WHERE AntennaId == {antenna[0]}'):
                macs[mac[0]].append(mac[1])
            
            data[antenna[0]] = dict(macs)

        return data

    @staticmethod
    def _execute(statement: str) -> list:
        with sqlite3.connect(DbReader._db_file) as conn:
            cur = conn.cursor()
            rows = cur.execute(statement)

            return [row for row in rows]

    @staticmethod
    def _execute_lazy(statement: str) -> Generator:
        with sqlite3.connect(DbReader._db_file) as conn:
            cur = conn.cursor()
            for row in cur.execute(statement):
                yield row

def is_same(old: BtleAdvFingerprint, new: BtleAdvFingerprint, *, max_distance: int=15):
    ''' Checks for two BtleAdvFingerprints old, new if new could be the same as old by\n
     - checking if new appeared in the time span (old.first_seen, old.lastseen+15m)\n
     - checking if service_uuid and company_id match\n
     - the distance between the antennas at the time of new.first_seen is at most max_distance km if there was a gap between the observations\n
     - the distance between the antennas at the times old.last_seen and new.first_seen was at most 100m if there was no gap between the observations
    '''

    if old.first_seen <= new.first_seen <= (old.last_seen + 15*60) and \
       old.service_uuid == new.service_uuid and \
       old.company_id == new.company_id:

        if old.last_seen > new.first_seen: # If there's no gap in the observation, allow max 100m difference
            return antenna_distance(old.antenna, new.first_seen, new.antenna) <= 0.1
        else: # If there's a gap in the observation, allow max_mistance difference
            return antenna_distance(old.antenna, old.last_seen, new.antenna, new.first_seen) <= max_distance

    else:
        return False

def get_components(fingerprints: list) -> tuple:
    #if fingerprints[0].mac == '51:83:68:fd:f5:ef' or True:
    #    print(f'gc_fp=\n'+'\n'.join(str(fp) for fp in fingerprints)+'\n')

    combinations = itertools.combinations(fingerprints, 2)

    graph = nx.Graph()

    graph.add_nodes_from(fingerprints)

    for combination in combinations:
        if is_same(*combination):
            graph.add_edge(*combination)

    components = [list(comp) for comp in nx.connected_components(graph)]
    
    return graph, components

def find_end(fingerprints: list, *, end: str) -> BtleAdvFingerprint:
    if end == 'head':
        extreme = min
        attr = 'first_seen'
    elif end == 'tail':
        extreme = max
        attr = 'last_seen'
    else:
        raise ValueError("Unknown end: {end}.")

    times = [getattr(fp, attr) for fp in fingerprints]
    extreme_value = extreme(times)

    # If only one was seen until the end, return it
    if times.count(extreme_value) == 1:
        return fingerprints[times.index(extreme_value)]
    else: # Else return the one that was longest seen or first in the list if multiple were seen for the same duration
        duration_seen = [fp.last_seen - fp.first_seen if getattr(fp, attr) == extreme_value else 0 for fp in fingerprints]
        return fingerprints[duration_seen.index(max(duration_seen))]

def get_paths(fingerprints: list) -> tuple:
    graph, components = get_components(fingerprints)

    paths = list()
    unused = list()

    for component in components:
        if len(component) == 1:
            continue
        last_node = find_end(component, end='tail')
        first_node = find_end(component, end='head')
        path = nx.shortest_path(graph, first_node, last_node)
        rest = set(component).difference(set(path))

        paths.append(path)
        unused.append(rest)

    return paths, unused

def resolve_hops(fingerprints: list):
    paths, unused = get_paths(fingerprints)

    

def process_btle_adv(*, delta_max: int=5, max_candidates: int=2):

    record = defaultdict(list)

    fingerprints = DbReader.get_mac_rows()

    length = len(fingerprints)

    for index, fingerprint in enumerate(fingerprints):

        record[fingerprint.mac].append(fingerprint)

        if not fingerprint.is_random:
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

    # Determine hops
    for occurrences in record.values():
        if len(occurrences) > 1:
            resolve_hops(occurrences)
            
    for fingerprint in fingerprints:
        if not fingerprint.is_successor:
            pass#print(fingerprint.get_chain())

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
    

