import pytest
import sqlite3
import correlator
import os

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
def instantiate_db_reader(tmpdir_factory):
    global db_file
    db_file = tmpdir_factory.mktemp('db').join('test.db')
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
        assert len(fingerprints) == 2, 'Wrong number of fingerprints read from database'

        assert correlator.is_same(fingerprints[0], fingerprints[1]), 'Should be the same device'

    def test_different_uuid_is_not_same(self):
        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '42', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '69', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[0][9]}'),
                    ('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert len(fingerprints) == 2, 'Wrong number of fingerprints read from database'

        assert not correlator.is_same(fingerprints[0], fingerprints[1]), 'UUID mismatch. Should not be the same device'

    def test_different_service_id_is_not_same(self):
        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '0', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[0][9]}'),
                    ('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert len(fingerprints) == 2, 'Wrong number of fingerprints read from database'

        assert not correlator.is_same(fingerprints[0], fingerprints[1]), 'Service Id mismatch. Should be the same device'

    def test_gap_15m_is_same(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621776286', '1621777386', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.7100004196167', '50.4266708374024', f'{signals[0][5]}', f'{signals[0][9]}'),
                    ('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert len(fingerprints) == 2, 'Wrong number of fingerprints read from database'

        assert correlator.is_same(fingerprints[0], fingerprints[1]), 'Should be the same device'

    def test_gap_15m1s_is_not_same(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621776287', '1621777386', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.7100004196167', '50.4266708374024', f'{signals[0][5]}', f'{signals[0][9]}'),
                    ('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert len(fingerprints) == 2, 'Wrong number of fingerprints read from database'

        assert not correlator.is_same(fingerprints[0], fingerprints[1]), 'Time difference too great. Should not be the same device'

    def test_no_gap_100m_distance_is_same(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11', '50', f'{signals[1][4]}', f'{signals[0][9]}'),
                    ('11.001399', '50', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert len(fingerprints) == 2, 'Wrong number of fingerprints read from database'

        assert correlator.haversine((float(antennas[0][1]), float(antennas[0][0])), (float(antennas[1][1]), float(antennas[1][0]))) < 0.1, 'Test assumption. Must be true for test result to be relevant.'

        assert correlator.is_same(fingerprints[0], fingerprints[1]), 'Should be the same device. 100m difference allowed when no time gap.'

    def test_no_gap_over_100m_distance_is_not_same(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11', '50', f'{signals[1][4]}', f'{signals[0][9]}'),
                    ('11.0013991', '50', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert len(fingerprints) == 2, 'Wrong number of fingerprints read from database'

        assert correlator.haversine((float(antennas[0][1]), float(antennas[0][0])), (float(antennas[1][1]), float(antennas[1][0]))) > 0.1, 'Test assumption. Must be true for test result to be relevant.'

        assert not correlator.is_same(fingerprints[0], fingerprints[1]), 'Should not be the same device. Max 100m difference allowed when no time gap.'

    def test_gap_15km_distance_is_same(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775387', '1621775500', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11', '50', f'{signals[0][5]}', f'{signals[0][9]}'),
                    ('11.20986', '50', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert len(fingerprints) == 2, 'Wrong number of fingerprints read from database'

        max_distance = 15
        assert correlator.haversine((float(antennas[0][1]), float(antennas[0][0])), (float(antennas[1][1]), float(antennas[1][0]))) < max_distance, 'Test assumption. Must be true for test result to be relevant.'

        assert correlator.is_same(fingerprints[0], fingerprints[1], max_distance=max_distance), 'Should be the same device. 15km difference allowed with time gap.'

    def test_gap_over_15km_distance_is_not_same(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775387', '1621775500', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11', '50', f'{signals[0][5]}', f'{signals[0][9]}'),
                    ('11.2099', '50', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        assert len(fingerprints) == 2, 'Wrong number of fingerprints read from database'

        max_distance = 15
        assert correlator.haversine((float(antennas[0][1]), float(antennas[0][0])), (float(antennas[1][1]), float(antennas[1][0]))) > max_distance, 'Test assumption. Must be true for test result to be relevant.'

        assert not correlator.is_same(fingerprints[0], fingerprints[1], max_distance=max_distance), 'Should not be the same device. Max 15km difference allowed with time gap.'

class TestHopping:
   
    def test_with_time_gap_are_connected(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775402', '1621775559', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.7100004196167', '50.4266708374024', f'{signals[0][5]}', f'{signals[0][9]}'),
                    ('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        
        _, components = correlator.get_components(fingerprints)

        assert(set(fingerprints) == set(components[0]))
        assert(len(components[0]) == 2)

    def test_without_time_gap_are_connected(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775386', '1621775559', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.7100004196167', '50.4266708374024', f'{signals[0][5]}', f'{signals[0][9]}'),
                    ('11.7100004196167', '50.4266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        
        _, components = correlator.get_components(fingerprints)

        assert set(fingerprints) == set(components[0]), 'Incorrect nodes in component'
        assert len(components[0]) == 2, 'Incorrect number of nodes in component'

    def test_overlapping_time_are_connected(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775376', '1621775559', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.3100004196167', '50.1266708374024', f'{signals[0][4]}', f'{signals[0][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        
        _, components = correlator.get_components(fingerprints)

        assert set(fingerprints) == set(components[0]), 'Incorrect nodes in component'
        assert len(components[0]) == 2, 'Incorrect number of nodes in component'

    def test_contained_time_are_connected(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775276', '1621775300', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.3100004196167', '50.1266708374024', f'{signals[0][4]}', f'{signals[0][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[1][4]}', f'{signals[1][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        
        _, components = correlator.get_components(fingerprints)

        assert set(fingerprints) == set(components[0]), 'Incorrect nodes in component'
        assert len(components[0]) == 2, 'Incorrect number of nodes in component'

    def test_two_components_two_nodes_each(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775276', '1621775300', '64879', '65535', '1', '2'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621777133', '1621777386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621777276', '1621777500', '64879', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.3100004196167', '50.1266708374024', f'{signals[0][4]}', f'{signals[0][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[1][4]}', f'{signals[1][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[2][4]}', f'{signals[2][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[3][4]}', f'{signals[3][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        
        _, components = correlator.get_components(fingerprints)
        assert len(components) == 2, 'Incorrect number of components returned'

        assert set(fingerprints[:2]) == set(components[0]), 'Incorrect nodes in component'

        assert set(fingerprints[2:]) == set(components[1]), 'Incorrect nodes in component'
        assert len(components[1]) == 2, 'Incorrect number of nodes in component'

    def test_two_components(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775276', '1621775300', '64879', '65535', '1', '2'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621777133', '1621777386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621777276', '1621777500', '64879', '65535', '1', '2'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621777550', '1621777600', '64879', '65535', '1', '3')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.3100004196167', '50.1266708374024', f'{signals[0][4]}', f'{signals[0][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[1][4]}', f'{signals[1][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[2][4]}', f'{signals[2][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[3][4]}', f'{signals[3][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[4][4]}', f'{signals[3][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[4][4]}', f'{signals[4][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        
        _, components = correlator.get_components(fingerprints)
        assert len(components) == 2, 'Incorrect number of components returned'

        assert set(fingerprints[:2]) == set(components[0]), 'Incorrect nodes in component'

        assert set(fingerprints[2:]) == set(components[1]), 'Incorrect nodes in component'
        assert len(components[1]) == 3, 'Incorrect number of nodes in component'

    def test_three_components(self):

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775276', '1621775300', '64879', '65535', '1', '2'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621777133', '1621777386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621777276', '1621777500', '64879', '65535', '1', '2'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621777550', '1621777600', '64879', '65535', '1', '3'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775276', '1621775300', '0', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.3100004196167', '50.1266708374024', f'{signals[0][4]}', f'{signals[0][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[1][4]}', f'{signals[1][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[2][4]}', f'{signals[2][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[3][4]}', f'{signals[3][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[4][4]}', f'{signals[3][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[4][4]}', f'{signals[4][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        
        _, components = correlator.get_components(fingerprints)
        assert len(components) == 3, 'Incorrect number of components returned'

        assert set(fingerprints[:2]) == set(components[0]), 'Incorrect nodes in component'

        assert fingerprints[2] is components[1][0], 'Incorrect nodes in component'
        assert len(components[1]) == 1, 'Incorrect number of nodes in component'

        assert set(fingerprints[3:]) == set(components[2]), 'Incorrect nodes in component'
        assert len(components[2]) == 3, 'Incorrect number of nodes in component'

    class DummyFP:
            def __init__(self, first_seen, last_seen):
                self.first_seen = first_seen
                self.last_seen = last_seen

            def __repr__(self) -> str:
                return f'{self.first_seen}:{self.last_seen}'

    def test_last_node_one_candidate(self):

        first = TestHopping.DummyFP(0, 5)
        expected = TestHopping.DummyFP(5, 10)

        actual = correlator.find_end([first, expected], end='tail')

        assert actual is expected, 'Last node recognized incorrectly'

    def test_last_node_duration_tiebreaker(self):

        first = TestHopping.DummyFP(6, 10)
        expected = TestHopping.DummyFP(5, 10)

        actual = correlator.find_end([first, expected], end='tail')

        assert actual is expected, 'Last node recognized incorrectly'

    def test_first_node_one_candidate(self):

        expected = TestHopping.DummyFP(0, 5)
        last = TestHopping.DummyFP(5, 10)

        actual = correlator.find_end([last, expected], end='head')

        assert actual is expected, 'First node recognized incorrectly'

    def test_first_node_duration_tiebreaker(self):

        expected = TestHopping.DummyFP(0, 5)
        last = TestHopping.DummyFP(0, 4)

        actual = correlator.find_end([last, expected], end='head')

        assert actual is expected, 'First node recognized incorrectly'

    def test_first_and_last_nodes(self):

        first = TestHopping.DummyFP(0, 251)
        last = TestHopping.DummyFP(790, 1000)
        fingerprints = [TestHopping.DummyFP(0, 200), first, TestHopping.DummyFP(0, 250), TestHopping.DummyFP(100, 500), TestHopping.DummyFP(75, 100), TestHopping.DummyFP(230, 400),
                        TestHopping.DummyFP(0, 200), TestHopping.DummyFP(210, 801), TestHopping.DummyFP(658, 668), TestHopping.DummyFP(48, 658), TestHopping.DummyFP(200, 400),
                        TestHopping.DummyFP(1,999), TestHopping.DummyFP(320, 500), TestHopping.DummyFP(234,456), last, TestHopping.DummyFP(162, 545), TestHopping.DummyFP(950, 1000),
                        TestHopping.DummyFP(800, 1000), TestHopping.DummyFP(540, 600), TestHopping.DummyFP(20, 90), TestHopping.DummyFP(700, 800), TestHopping.DummyFP(600, 999)]
        
        actual_first = correlator.find_end(fingerprints, end='head')
        actual_last = correlator.find_end(fingerprints, end='tail')

        assert actual_first is first, 'First node recognized incorrectly'
        assert actual_last is last, 'Last node recognized incorrectly'

    def test_multiple_paths_returned_correctly(self):
        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621775133', '1621775386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775276', '1621775400', '64879', '65535', '1', '2'),
                   ('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621777133', '1621777386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621777276', '1621778500', '64879', '65535', '1', '2'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621778550', '1621778600', '64879', '65535', '1', '3'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621775276', '1621775300', '0', '65535', '1', '2')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.3100004196167', '50.1266708374024', f'{signals[0][4]}', f'{signals[0][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[1][4]}', f'{signals[1][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[2][4]}', f'{signals[2][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[3][4]}', f'{signals[3][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[4][4]}', f'{signals[3][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[4][4]}', f'{signals[4][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()

        paths, unused = correlator.get_paths(fingerprints)
        
        assert len(paths) == 2, 'Two paths should be returned'
        assert len(unused) == 2, 'Two unused sets should be returned'

        assert len(unused[0]) == 0, 'Unused set is not empty'
        assert len(unused[1]) == 0, 'Unused set is not empty'

        expected = [fingerprints[0], fingerprints[1]]
        actual =paths[0]
        assert(actual == expected), 'Path recognized incorrectly'

        expected = [fingerprints[3], fingerprints[4], fingerprints[5]]
        actual = paths[1]
        assert(actual == expected), 'Path recognized incorrectly'

    def test_irrelevant_nodes_skipped(self):

        print(db_file)

        signals = [('51:83:68:fd:f5:ef', '-78', '2.31810188293457', '-75.4092025756836', '1621777133', '1621777386', '64879', '65535', '1', '1'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621777276', '1621777500', '64879', '65535', '1', '2'),
                   ('51:83:68:fd:f5:ef', '-86', '2.62029695510864', '-75.0869598388672', '1621777550', '1621777600', '64879', '65535', '1', '3')]
        
        add_mac_rows(db_file, signals)

        antennas = [('11.3100004196167', '50.1266708374024', f'{signals[1][4]}', f'{signals[0][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[1][4]}', f'{signals[1][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[2][4]}', f'{signals[0][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[2][4]}', f'{signals[1][9]}'),
                    ('11.3100004196167', '50.1266708374024', f'{signals[2][4]}', f'{signals[2][9]}')]
        add_antenna_rows(db_file, antennas)

        fingerprints = correlator.DbReader.get_mac_rows()
        
        paths, unused = correlator.get_paths(fingerprints)
        assert len(paths) == 1, 'One path should have been returned'
        assert len(unused) == 1, 'One unused set should have been returned'
        assert len(unused[0]) == 1, 'One fingerprint should have been unused'

        assert fingerprints[1] in unused[0], 'Incorrect node was unused'

        expected = [fingerprints[0], fingerprints[2]]
        actual = paths[0]

        assert actual == expected, 'Incorrect path recognized'