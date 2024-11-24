import psycopg2
from psycopg2 import sql
from datetime import datetime,timezone
import re
import requests
import time
import json
def load_config():
    with open('/opt/asp-24/asp.json', 'r') as file:
        config = json.load(file)
    return config

def cve_getter(product_version_query, conn):
    with conn.cursor() as cur:
        query = f"SELECT cve_id FROM cve_table WHERE description ILIKE %s AND description ILIKE %s;"
        keyword1 = product_version_query.split(' ')[0]
        keyword2 = product_version_query.split(' ')[1]
        cur.execute(query, (f'%{keyword1}%', f'%{keyword2}%'))
        records = cur.fetchall()

        return records


def main_anlt_module(scan_result_dict, scan_id):
    config = load_config()
    try:
        conn = psycopg2.connect(
            host=config['database']['ip'],
            database='hack_db',
            user='postgres',
            password='sovietchungus',
            port=5432
        )

    except Exception as e:
        print(f"Ошибка подключения к базе данных: {e}")

    if conn:
        create_table_analytics(conn)

    full_data = []
    ip_addr_counter = 0
    scan_time = datetime.now(timezone.utc)
    for ip_addr in scan_result_dict:
        ip_addr_counter += 1
        for port in scan_result_dict[ip_addr]['ports']:
            state = scan_result_dict[ip_addr]['ports'].get(port).get('state')
            service = scan_result_dict[ip_addr]['ports'].get(port).get('service')
            protocol = scan_result_dict[ip_addr]['ports'].get(port).get('protocol')
            product = scan_result_dict[ip_addr]['ports'].get(port).get('software')
            version = scan_result_dict[ip_addr]['ports'].get(port).get('version')
            ptr = scan_result_dict[ip_addr]['ports'].get(port).get('domain')
            if version is not None:
                match = re.search(r'^[\d\.]+', version) # подумать
                if match is not None:
                    version = match.group(0)
            
            if product is None:
                full_tuple = (ip_addr, port, state, service, protocol, product, version, None, scan_id, scan_time, ptr)
                full_data.append(full_tuple)
                continue
            product_version_query = str(product) + ' ' + str(version)
            cve_info = cve_getter(product_version_query, conn)
            if len(cve_info) > 0:
                for cve in cve_info:
                    full_tuple = (ip_addr, port, state, service, protocol, product, version, cve, scan_id, scan_time, ptr)
                    full_data.append(full_tuple)
            else:
                full_tuple = (ip_addr, port, state, service, protocol, product, version, None, scan_id, scan_time, ptr)
                full_data.append(full_tuple)
            
    insert_data(conn, full_data)
    send_to_tg(ip_addr_counter, conn)


def create_table_analytics(conn):
    with conn.cursor() as cursor:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS analytics (
            id SERIAL PRIMARY KEY,
            datetime TIMESTAMP,
            ip_addr VARCHAR,
            port INT,
            state VARCHAR,
            service VARCHAR,
            protocol VARCHAR,
            product VARCHAR,
            version VARCHAR,
            cve_info VARCHAR,
            scan_id VARCHAR,
            ptr VARCHAR
        )
        """)
        conn.commit()


def insert_data(conn, data):
    with conn.cursor() as cur:
        tup = ','.join(cur.mogrify("(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",x).decode('utf-8') for x in data)
        cur.execute("INSERT INTO analytics (ip_addr, port, state, service, protocol, product, version, cve_info, scan_id, datetime, ptr) VALUES "+tup)
        conn.commit()


def send_to_tg(ip_addr_counter, conn):
    config = load_config()
    with conn.cursor() as cur:
        query = f"SELECT id, cve_id, cvss FROM cve_table WHERE cve_table.cve_id IN (SELECT analytics.cve_info FROM analytics) ORDER BY cvss DESC LIMIT 3"
        cur.execute(query)
        records = cur.fetchall()
    tg_message = f'Сканирование завершено\nПросканировано {ip_addr_counter} ip-адресов\nТоп найденных язвимостей: \n{records}'
    try:
        TOKEN = config['telegram']['token']
        CHAT_ID = config['telegram']['chat_id']
        url_req = "https://api.telegram.org/bot" + TOKEN + "/sendMessage" + "?chat_id=" + CHAT_ID + "&text=" + tg_message
        requests.get(url_req)
        print("Сообщение в Telegram отправлено.")
    except:
        quit("Сообщенеие в Telegram не было отправлено.")