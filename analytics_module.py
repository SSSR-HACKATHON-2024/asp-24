import psycopg2
from psycopg2 import sql


def cve_getter(product_version_query, conn):
    with conn.cursor() as cur:
        query = f"SELECT id FROM cve_table WHERE description ILIKE %s AND description ILIKE %s;"
        keyword1 = product_version_query.split(' ')[0]
        keyword2 = product_version_query.split(' ')[1]
        cur.execute(query, (f'%{keyword1}%', f'%{keyword2}%'))
        records = cur.fetchall()

        return records


def main_anlt_module(scan_result_dict, scan_id):
    try:
        conn = psycopg2.connect(
            host='10.11.114.158',
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
    
    for ip_addr in scan_result_dict:
        for port in scan_result_dict[ip_addr]['ports']:
            state = scan_result_dict[ip_addr]['ports'].get(port).get('state')
            service = scan_result_dict[ip_addr]['ports'].get(port).get('service')
            protocol = scan_result_dict[ip_addr]['ports'].get(port).get('protocol')
            product = scan_result_dict[ip_addr]['ports'].get(port).get('software')
            version = scan_result_dict[ip_addr]['ports'].get(port).get('version')

            if product is None:
                full_tuple = (ip_addr, port, state, service, protocol, product, version, None, scan_id)
                full_data.append(full_tuple)
                continue
            product_version_query = str(product) + ' ' + str(version)
            cve_info = cve_getter(product_version_query, conn)
            if len(cve_info) > 0:
                for cve in cve_info:
                    full_tuple = (ip_addr, port, state, service, protocol, product, version, cve, scan_id)
                    full_data.append(full_tuple)
            else:
                full_tuple = (ip_addr, port, state, service, protocol, product, version, None, scan_id)
                full_data.append(full_tuple)
            # count_software_records(product_version_query, connection) # после выполнения будет количество текущего продукта в инфраструктуре
            
    insert_data(conn, full_data)


def create_table_analytics(conn):
    with conn.cursor() as cursor:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS analytics (
            id SERIAL PRIMARY KEY,
            ip_addr VARCHAR,
            port INT,
            state VARCHAR,
            service VARCHAR,
            protocol VARCHAR,
            product VARCHAR,
            version VARCHAR,
            cve_info VARCHAR,
            scan_id VARCHAR
        )
        """)
        conn.commit()


def insert_data(conn, data):
    with conn.cursor() as cur:
        tup = ','.join(cur.mogrify("(%s, %s, %s, %s, %s, %s, %s, %s, %s)",x).decode('utf-8') for x in data)
        cur.execute("INSERT INTO analytics (ip_addr, port, state, service, protocol, product, version, cve_info, scan_id) VALUES "+tup)
        conn.commit()


scan_result_dict, scan_id = ({'10.0.2.3': {'ports': {'631': {'state': 'open', 'service': 'ipp', 'software': 'CUPS', 'version': '2.3', 'cpe': 'cpe:/a:apple:cups:2.3', 'protocol': 'tcp'}, '30523': {'state': 'open', 'service': 'unknown', 'software': None, 'version': None, 'cpe': None, 'protocol': 'tcp'}, '36759': {'state': 'open', 'service': 'unknown', 'software': None, 'version': None, 'cpe': None, 'protocol': 'tcp'}, '45235': {'state': 'open', 'service': 'unknown', 'software': None, 'version': None, 'cpe': None, 'protocol': 'tcp'}}}, '10.0.2.2': {'ports': {'631': {'state': 'open', 'service': 'ipp', 'software': 'CUPS', 'version': '2.3', 'cpe': 'cpe:/a:apple:cups:2.3', 'protocol': 'tcp'}, '9879': {'state': 'open', 'service': 'tcpwrapped', 'software': None, 'version': None, 'cpe': None, 'protocol': 'tcp'}, '30523': {'state': 'open', 'service': 'unknown', 'software': None, 'version': None, 'cpe': None, 'protocol': 'tcp'}, '36759': {'state': 'open', 'service': 'unknown', 'software': None, 'version': None, 'cpe': None, 'protocol': 'tcp'}, '37966': {'state': 'open', 'service': 'tcpwrapped', 'software': None, 'version': None, 'cpe': None, 'protocol': 'tcp'}, '45235': {'state': 'open', 'service': 'unknown', 'software': 'postgres', 'version': '14', 'cpe': None, 'protocol': 'tcp'}, '58276': {'state': 'open', 'service': 'tcpwrapped', 'software': None, 'version': None, 'cpe': None, 'protocol': 'tcp'}}}, '10.0.2.4': {'ports': {'631': {'state': 'open', 'service': 'ipp', 'software': 'CUPS', 'version': '2.3', 'cpe': 'cpe:/a:apple:cups:2.3', 'protocol': 'tcp'}, '9789': {'state': 'open', 'service': 'tcpwrapped', 'software': None, 'version': None, 'cpe': None, 'protocol': 'tcp'}, '30523': {'state': 'open', 'service': 'unknown', 'software': None, 'version': None, 'cpe': None, 'protocol': 'tcp'}, '33206': {'state': 'open', 'service': 'tcpwrapped', 'software': None, 'version': None, 'cpe': None, 'protocol': 'tcp'}, '36759': {'state': 'open', 'service': 'unknown', 'software': None, 'version': None, 'cpe': None, 'protocol': 'tcp'}, '45235': {'state': 'open', 'service': 'unknown', 'software': None, 'version': None, 'cpe': None, 'protocol': 'tcp'}}}}, '23456789-sdfghjkl-345678')

main_anlt_module(scan_result_dict, scan_id)