import pytest
import sqlite3
import correlator
import os
from matplotlib import pyplot as plt

db_file = 'test.db'

@pytest.fixture(autouse=True)
def create_db():
    if os.path.isfile(db_file):
        os.remove(db_file)

    with sqlite3.connect(db_file) as conn:
        cur = conn.cursor()
        cur.execute('''CREATE TABLE "MacAddresses" (
	                 "Id"	INTEGER NOT NULL,
	                 "MacAddress"	TEXT,
	                 "Rssi"	INTEGER NOT NULL,
	                 "Std"	REAL NOT NULL,
	                 "Mean"	REAL NOT NULL,
	                 "FirstSeen"	INTEGER NOT NULL,
	                 "LastSeen"	INTEGER NOT NULL,
	                 "ServiceUUID"	INTEGER,
	                 "CompanyId"	INTEGER,
                  	 "Random"	INTEGER,
	                 "AntennaId"	INTEGER NOT NULL,
	                 CONSTRAINT "FK_MacAddresses_Antennas_AntennaId" FOREIGN KEY("AntennaId") REFERENCES "Antennas"("AntennaId") ON DELETE CASCADE,
	                 CONSTRAINT "PK_MacAddresses" PRIMARY KEY("Id" AUTOINCREMENT))''')

        cur.execute('''CREATE TABLE "Metadata" (
                     "AntennaMetadataId" INTEGER NOT NULL CONSTRAINT "PK_Metadata" PRIMARY KEY AUTOINCREMENT,
                     "Longitude" REAL NOT NULL,
                     "Latitude" REAL NOT NULL,
                     "Timestamp" INTEGER NOT NULL,
                     "AntennaId" INTEGER NOT NULL,
                     CONSTRAINT "FK_Metadata_Antennas_AntennaId" FOREIGN KEY ("AntennaId") REFERENCES "Antennas" ("AntennaId") ON DELETE CASCADE)''')

def add_mac_rows(db_file: str, values: list):
    with sqlite3.connect(db_file) as conn:
        cur = conn.cursor()
        cur.executemany('''INSERT INTO "main"."MacAddresses" ("MacAddress", "Rssi", "Std", "Mean", "FirstSeen", "LastSeen", "ServiceUUID", "CompanyId", "Random", "AntennaId")
                         VALUES (?, ?, ?, ?, ? , ? , ?, ?, ?, ?)''', values)

def add_antenna_rows(db_file: str,  values: list):
    with sqlite3.connect(db_file) as conn:
        cur = conn.cursor()
        cur.executemany('''INSERT INTO "main"."Metadata" ("Longitude", "Latitude", "Timestamp", "AntennaId")
                        VALUES (?, ?, ?, ?)''', values) 


@pytest.fixture(scope="session", autouse=True)
def instantiate_db_reader():
    correlator.DbReader(db_file)


class TestIsSame:
    def test_identical_is_same(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[0][9]}'),
                    ('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert(len(fingerprints) == 2)

        assert(correlator.is_same(fingerprints[0], fingerprints[1]))

    def test_different_uuid_is_not_same(self):
        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '42', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '69', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[0][9]}'),
                    ('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert(len(fingerprints) == 2)

        assert(not correlator.is_same(fingerprints[0], fingerprints[1]))

    def test_different_service_id_is_not_same(self):
        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '0', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[0][9]}'),
                    ('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert(len(fingerprints) == 2)

        assert(not correlator.is_same(fingerprints[0], fingerprints[1]))

    def test_gap_15m_is_same(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621776286', '1621777386', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.7100004196167', '50.4266708374024', f'{signals[0][5]}', f'{signals[0][9]}'),
                    ('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert(len(fingerprints) == 2)

        assert(correlator.is_same(fingerprints[0], fingerprints[1]))

    def test_gap_15m1s_is_not_same(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621776287', '1621777386', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.7100004196167', '50.4266708374024', f'{signals[0][5]}', f'{signals[0][9]}'),
                    ('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert(len(fingerprints) == 2)

        assert(not correlator.is_same(fingerprints[0], fingerprints[1]))

    def test_no_gap_100m_distance_is_same(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11', '50', f'{signals[1][4]}', f'{signals[0][9]}'),
                    ('11.001399', '50', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert(len(fingerprints) == 2)

        assert(correlator.haversine((float(antennas[0][1]), float(antennas[0][0])), (float(antennas[1][1]), float(antennas[1][0]))) < 0.1)

        assert(correlator.is_same(fingerprints[0], fingerprints[1]))

    def test_no_gap_over_100m_distance_is_not_same(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11', '50', f'{signals[1][4]}', f'{signals[0][9]}'),
                    ('11.0013991', '50', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert(len(fingerprints) == 2)

        assert(correlator.haversine((float(antennas[0][1]), float(antennas[0][0])), (float(antennas[1][1]), float(antennas[1][0]))) > 0.1)

        assert(not correlator.is_same(fingerprints[0], fingerprints[1]))

    def test_gap_15km_distance_is_same(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775387', '1621775500', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11', '50', f'{signals[0][5]}', f'{signals[0][9]}'),
                    ('11.20986', '50', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert(len(fingerprints) == 2)

        max_distance = 15
        assert(correlator.haversine((float(antennas[0][1]), float(antennas[0][0])), (float(antennas[1][1]), float(antennas[1][0]))) < max_distance)

        assert(correlator.is_same(fingerprints[0], fingerprints[1], max_distance=max_distance))

    def test_gap_over_15km_distance_is_not_same(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775387', '1621775500', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11', '50', f'{signals[0][5]}', f'{signals[0][9]}'),
                    ('11.2099', '50', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert(len(fingerprints) == 2)

        max_distance = 15
        assert(correlator.haversine((float(antennas[0][1]), float(antennas[0][0])), (float(antennas[1][1]), float(antennas[1][0]))) > max_distance)

        assert(not correlator.is_same(fingerprints[0], fingerprints[1], max_distance=max_distance))

class TestHopping:
    

    def test_with_time_gap_are_connected(self, tmpdir):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775402', '1621775559', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.7100004196167', '50.4266708374024', f'{signals[0][5]}', f'{signals[0][9]}'),
                    ('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        
        connected = correlator.resolve_hops(fingerprints)

        assert(set(fingerprints) == connected[0])
        assert(len(connected[0]) == 2)

    def test_without_time_gap_are_connected(self, tmpdir):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775386', '1621775559', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.7100004196167', '50.4266708374024', f'{signals[0][5]}', f'{signals[0][9]}'),
                    ('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        
        connected = correlator.resolve_hops(fingerprints)

        assert(set(fingerprints) == connected[0])
        assert(len(connected[0]) == 2)

    def test_overlapping_time_are_connected(self, tmpdir):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775376', '1621775559', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.3100004196167', '50.1266708374024', f'{signals[0][4]}', f'{signals[0][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        
        connected = correlator.resolve_hops(fingerprints)

        assert(set(fingerprints) == connected[0])
        assert(len(connected[0]) == 2)

    def test_contained_time_are_connected(self, tmpdir):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775276', '1621775300', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.3100004196167', '50.1266708374024', f'{signals[0][4]}', f'{signals[0][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        
        connected = correlator.resolve_hops(fingerprints)

        assert(set(fingerprints) == connected[0])
        assert(len(connected[0]) == 2)

