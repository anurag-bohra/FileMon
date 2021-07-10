import json
import requests
import yaml
import os
import sqlite3
import hashlib
from elasticsearch import Elasticsearch


def create_clients_table(conn):
    create_table_query = """
            CREATE TABLE FILES
            (PATH TEXT NOT NULL,
            HASH TEXT NOT NULL,
            VT_SCORE TEXT DEFAULT "UNKNOWN"
            );
        """
    conn.execute(create_table_query)
    conn.commit()


def database_init(dbfile):
    conn = sqlite3.connect(dbfile)
    DBCursor = conn.cursor()
    DBCursor.execute(''' SELECT name FROM sqlite_master WHERE type='table' AND name='FILES' ''')
    if DBCursor.fetchall() == []:
        create_clients_table(conn)
    return conn, DBCursor


def check_file_exists_db(file_hash, file_path, cursor):
    flag = False
    check_query = """
        SELECT HASH FROM FILES WHERE HASH='{hash}' AND PATH='{path}'
    """.format(hash=file_hash, path=file_path)
    cursor.execute(check_query)
    data = cursor.fetchall()
    if not len(data) == 0:
        flag = True
    return False


def get_score_from_db(file_hash, dbfile):
    conn, cursor = database_init(dbfile)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    query = """SELECT * FROM FILES WHERE HASH='{hash}'""".format(hash=file_hash)
    cursor.execute(query)
    rows_data = cursor.fetchall()
    result = [dict(row) for row in rows_data]
    conn.close()
    for row in result:
        return row['VT_SCORE']
    return "0"


def parse_vt_data(data):
    if "error" in data.keys():
        return "UNKNOWN"
    elif "data" in data.keys():
        parse1 = data['data']['attributes']
        if 'last_analysis_stats' in parse1.keys():
            last_analysis_stats = parse1['last_analysis_stats']
            score_string = str(last_analysis_stats['malicious']) + '/' + str(last_analysis_stats['malicious'] + last_analysis_stats['undetected'])
            return score_string
    else:
        return "UNKNOWN"


def get_score_from_vt(file_hash, api_key):
    score = 0
    file_url = 'https://www.virustotal.com/api/v3/files/' + str(file_hash)
    headers = {'x-apikey': 'a6569e92c604a9d2746abd74f245f85ae0d6a99421c5fa7fb5058e64e1c7daef'}
    resp = requests.get(file_url, headers=headers)
    data = json.loads(resp.text)
    score = parse_vt_data(data)
    return score


def db_insert_file(payload, dbfile):
    conn, cursor = database_init(dbfile)
    insert_query = """
        INSERT INTO FILES VALUES('{path}','{hash}','{score}');
    """.format(path=payload['srcPath'], hash=payload['sha256'], score=payload['VTScore'])
    conn.execute(insert_query)
    conn.commit()
    conn.close()


def send_payload_elastic(payload, settings):
    host = settings['elasticIP']
    port = int(settings['elasticPort'])
    es = Elasticsearch(host, port=port)
    es.index(index='fileevents', body=payload)


def check_and_insert_database(payload, settings):
    api_key = settings['virustotalAPI']
    dbfile = settings['databaseFile']
    conn, cursor = database_init(dbfile)
    file_hash = payload['sha256']
    file_path = payload['srcPath']
    flag = check_file_exists_db(file_hash, file_path, cursor)
    payload['VTScore'] = "UNKNOWN"
    conn.close()
    if flag:
        score = get_score_from_db(file_hash, dbfile)
        payload['VTScore'] = score
    else:
        score = get_score_from_vt(file_hash, api_key)
        payload['VTScore'] = score
        db_insert_file(payload, dbfile)

    send_payload_elastic(payload, settings)


def read_yaml():
    with open('settings.yaml', 'r') as rFile:
        yaml_file = yaml.load(rFile, Loader=yaml.FullLoader)
    return yaml_file


def check_path(settings):
    if os.path.exists(settings['pathsFile']):
        return True
    else:
        return False


def get_paths():
    with open(read_yaml()['pathsFile'], 'r') as rFile:
        paths = yaml.load(rFile, Loader=yaml.FullLoader)
    paths = paths['fileEvents']
    paths['createEvents'] = [os.path.expanduser(path) for path in paths['createEvents']]
    paths['modifyEvents'] = [os.path.expanduser(path) for path in paths['modifyEvents']]
    paths['deleteEvents'] = [os.path.expanduser(path) for path in paths['deleteEvents']]
    return paths


def get_event_file(event_type):
    paths = get_paths()
    event_paths = paths[event_type]
    return event_paths


def event_handler(event):
    payload = dict()
    payload['eventType'] = event.event_type
    payload['srcPath'] = event.src_path
    payload['isDirectory'] = event.is_directory
    payload['sha256'] = "None"
    payload['VTScore'] = "None"
    settings = read_yaml()
    if not payload['isDirectory']:
        sha256_hash = hashlib.sha256()
        if os.path.exists(event.src_path):
            with open(event.src_path, 'rb') as rFile:
                for byte_block in iter(lambda: rFile.read(4096), b""):
                    sha256_hash.update(byte_block)
            payload['sha256'] = sha256_hash.hexdigest()
        check_and_insert_database(payload, settings)
    else:
        send_payload_elastic(payload, settings)
