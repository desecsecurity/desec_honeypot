#!/usr/bin/env python3
#__*__ coding: utf-8 __*__

'''
Title: Desec Honeypot Server and Sqlite3 Logs Database
Version: 1.0 
Date: 10/11/2019 
Homepage: https://www.desecsecurity.com/
Tested on: Linux
'''

import sqlite3
import datetime
import socket
import argparse
import pathlib
import select
import sys

# Constants colors
green = '\033[42m'
blue = '\033[44m'
purple = '\033[45m'
cyan = '\033[46m'
red = '\033[41m'
font_green = '\033[32m'
font_red = '\033[31m'
end = '\033[00m'


def valid_ipaddr(ip_addr):
    try:
        socket.inet_aton(ip_addr)
        return True
    except socket.error:
        print('%s>>> Invalid IP address.%s' % (font_red, end))

def get_connection():
    conn = None
    try:
        conn = sqlite3.connect('logs.db')
        conn.row_factory = sqlite3.Row
    except conn.DatabaseError as e:
        print(e)
    return conn

def create_database():
    # Create a database
    table_logs = """
                CREATE TABLE IF NOT EXISTS logs (
                    log_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    ip_orig VARCHAR(40),
                    port_orig VARCHAR(5),
                    ip_dst VARCHAR(40),
                    port_dst VARCHAR(5),
                    created DATETIME,
                    banned BOOLEAN DEFAULT 0
                );
                """

    table_info = """
                CREATE TABLE IF NOT EXISTS info (
                    info_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    msg TEXT,
                    log_fk INTEGER,
                    FOREIGN KEY (log_fk) REFERENCES logs (log_id) ON DELETE CASCADE
                );
                """

    table_ports = """
                CREATE TABLE IF NOT EXISTS ports (
                    port_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    port INTEGER UNIQUE,
                    blocked BOOLEAN
                );
                """
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute(table_logs)
        c.execute(table_info)
        c.execute(table_ports)
        conn.close()
        print('%s>>> Database created!%s' % (green, end))
    except ConnectionError as e:
        print(e)

def insert_log(conn, data_log, ip_orig):
    # Insert register in log table
    log_sql = """INSERT INTO logs (ip_orig, port_orig, ip_dst, port_dst, created) VALUES (?, ?, ?, ?, ?);"""
    try:
        c = conn.cursor()
        c.execute(log_sql, data_log)
        conn.commit()
        return c.lastrowid
    except ConnectionError as e:
        print(e)

def insert_info(conn, data_info):
    # Insert info in info table
    info_sql = """INSERT INTO info (msg, log_fk) VALUES (?, ?);"""
    try:
        c = conn.cursor()
        c.execute(info_sql, data_info)
        conn.commit()
    except ConnectionError as e:
        print(e)

def is_banned(conn, ip_orig):
    try:
        c = conn.cursor()
        c.execute("""SELECT ip_orig FROM logs WHERE banned AND ip_orig=?""", (ip_orig, ))
        client = c.fetchone()
        if client:
            return True
    except ConnectionError as e:
        print(e)

def is_blocked(conn, port):
    try:
        c = conn.cursor()
        c.execute("""SELECT port FROM ports WHERE blocked and port=?;""", (port, ))
        blocked = c.fetchone()
        if blocked:
            return True
    except ConnectionError as e:
        print(e)  

def create_server(ports, ip_addr):
    # Create a honeypot server
    servers = []
    conn = get_connection()
    localhost = ip_addr
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # the SO_REUSEADDR flag above tells the kernel to reuse a local socket 
            # in TIME_WAIT state, without waiting for its natural timeout to expire.
            # This prevent the error: socket.error: [Errno 98] Address already in use
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_address = (localhost, port)
            sock.bind(server_address)
            print('\n%s[Starting]%s Address: %s Port: %s' % (green, end, localhost, port))
            # Listen for incoming connections
            sock.listen(5)
            servers.append(sock)
        except PermissionError:
            print('\n>>> %s[Port %d restricted]%s You have to be root (have superuser privileges) in order to listen to TCP or UDP ports below 1024' % (red, port, end))
        except OSError:
            print('>>> %s[Port %d already in use]%s' % (red, port, end))    

    if servers:
        while True:
            # Wait for a connection
            print('\n%s>>>%s Waiting for a connection...' % (green, end) )
            readable , _, _ = select.select(servers, [], [])
            ready_server = readable[0]
            connection, client_address = ready_server.accept()
            ip_server, port_server = ready_server.getsockname()
            now = datetime.datetime.now()
            banned = False
            blocked = False
            
            try:
                print('\n%s<<<Connection established!>>>%s' % (green, end))
                print('Origin: %s Port: %d' % (client_address[0], client_address[1]))
                print('Destination: %s Port: %d' % (ip_server, port_server))
                data_log = (client_address[0],
                            client_address[1], 
                            ip_server, port_server,
                            now.strftime('%Y-%m-%d %H:%M:%S'))

                # Verify if client is banned and set banned to True
                if is_banned(conn, client_address[0]):
                    banned = True
                else:
                    # Insert log connection in database, and get client id
                    client_id = insert_log(conn, data_log, client_address[0])

                # Verify if port is blocked and set blocked to True
                if is_blocked(conn, port_server):
                    print('%s[Blocked Port]%s IP origin: %s Destination port: %d' % (red, end, client_address[0], port_server))
                    blocked = True                

                while True:
                    # Wait message from client
                    if banned:
                        # If client is banned the connection is terminated
                        msg = '\n%s[IP Banned]%s Refused connection from IP origin: %s in Port %d!' % (red, end, client_address[0], port_server)
                        connection.sendall('\n[Connection Refused]'.encode())
                        print(msg)
                        break
                    if blocked:
                        # if port is blocked the connection is terminated
                        break
                    # Receive information from client
                    info = connection.recv(1024)
                    print('%s<<<Received>>>%s %s' % (cyan, end, info.decode('utf-8')))
                    if info:
                        data_info = (info.decode('utf-8'), client_id)
                        insert_info(conn, data_info)
                        # Uncomment this lines for send a return message
                        #print('Sending info back to the client')
                        #connection.sendall(info)
                    else:
                        print('\n%s<<<Finished>>>%s No more info from IP origin: %s Port: %d' % (purple, end, client_address[0], client_address[1]))
                        break
            except ConnectionError as e:
                print(e)  
            finally:
                # Clean up the connections
                connection.close()

def create_header(columns):
    log_id, ip_orig, port_orig, ip_dst, port_dst, created, banned, info_id, msg, log_fk, port_id, port, blocked, count = ('',)*14
    for c in columns:
        if c == 'log_id':
            log_id = '{}{:^5s}{}'.format(green, 'Id', end)
        if c == 'ip_orig':
            ip_orig = '{}{:^20s}{}'.format(blue, 'Origin', end)
        if c == 'port_orig':
            port_orig = '{}{:^12s}{}'.format(purple, 'Port(orig)', end)
        if c == 'ip_dst':
            ip_dst = '{}{:^20s}{}'.format(blue, 'Destination', end)
        if c == 'port_dst':
            port_dst = '{}{:^12s}{}'.format(purple, 'Port(dst)', end)
        if c == 'created':
            created = '{}{:^21s}{}'.format(cyan, 'Created', end)
        if c == 'banned':
            banned = '{}{:^8s}{}'.format(red, 'Banned', end)
        if c == 'info_id':
            info_id = '{}{:^5s}{}'.format(green, 'Id', end)
        if c == 'msg':
            msg = '{}{:^40s}{}'.format(cyan, 'Message', end)
        if c == 'log_fk':
            log_fk = '{}{:^10s}{}'.format(blue, 'Log FK', end)
        if c == 'port_id':
            port_id = '{}{:^5s}{}'.format(blue, 'Id', end)
        if c == 'port':
            port = '{}{:^12s}{}'.format(purple, 'Port', end)
        if c == 'blocked':
            blocked = '{}{:^10s}{}'.format(red, 'Blocked', end)
        if c.startswith('count'):
            count = '{}{:^10s}{}'.format(purple, 'Count', end)
    print('\n'+log_id+ip_orig+port_orig+ip_dst+port_dst+created+banned+info_id+log_fk+msg+port_id+port+blocked+count+'\n')

def create_rows(records):
    log_id, ip_orig, port_orig, ip_dst, port_dst, created, banned, info_id, msg, log_fk, port_id, port, blocked, count = ('',)*14
    for r in records:
        if 'log_id' in r.keys():
            log_id = '{:^5d}'.format(r['log_id'] or 0)
        if 'ip_orig' in r.keys():
            ip_orig = '{:^20s}'.format(r['ip_orig'] or '')
        if 'port_orig' in r.keys():
            port_orig = '{:^12s}'.format(r['port_orig'] or '')
        if 'ip_dst' in r.keys():
            ip_dst = '{:^20s}'.format(r['ip_dst'] or '')
        if 'port_dst' in r.keys():
            port_dst = '{:^12s}'.format(r['port_dst'] or '')
        if 'created' in r.keys():
            created = '{:^21s}'.format(r['created'] or '')
        if 'banned' in r.keys():
            banned = '{:^8d}'.format(r['banned'] or 0)
        if 'info_id' in r.keys():
            info_id = '{:^5d}'.format(r['info_id'] or 0)
        if 'msg' in r.keys():
            msg = '{:^40s}'.format(r['msg'] or '')
        if 'log_fk' in r.keys():
            log_fk = '{:^10d}'.format(r['log_fk'] or 0)
        if 'port_id' in r.keys():
            port_id = '{:^5d}'.format(r['port_id'] or 0)
        if 'port' in r.keys():
            port = '{:^12d}'.format(r['port'] or 0) 
        if 'blocked' in r.keys():
            blocked = '{:^10d}'.format(r['blocked'] or 0)
        if 'count(ip_orig)' in r.keys():
            count = '{:^10d}'.format(r['count(ip_orig)'])
        if 'count(port_orig)' in r.keys():
            count = '{:^10d}'.format(r['count(port_orig)'])
        if 'count(ip_dst)' in r.keys():
            count = '{:^10d}'.format(r['count(ip_dst)'])
        if 'count(port_dst)' in r.keys():
            count = '{:^10d}'.format(r['count(port_dst)'])
        if 'count(created)' in r.keys():
            count = '{:^10d}'.format(r['count(created)'])
        if 'count(msg)' in r.keys():
            count = '{:^10d}'.format(r['count(msg)'])
        if 'count(banned)' in r.keys():
            count = '{:^10d}'.format(r['count(banned)'])
        if 'count(port_id)' in r.keys():
            count = '{:^10d}'.format(r['count(port_id)'])
        if 'count(port)' in r.keys():
            count = '{:^10d}'.format(r['count(port)'])
        if 'count(blocked)' in r.keys():
            count = '{:^10d}'.format(r['count(blocked)'])
        print(log_id+ip_orig+port_orig+ip_dst+port_dst+created+banned+info_id+log_fk+msg+port_id+port+blocked+count)

def run_select(cursor):
    records = cursor.fetchall()
    if cursor.description:
        columns = [description[0] for description in cursor.description]
    if records:
        create_header(columns)
        create_rows(records)
        print('\nTotal registers:', len(records))
    else:
        print('\n%s>>> No records found!%s' % (font_red, end))

def run_delete(conn, cursor):
    conn.commit()
    count = cursor.rowcount
    if count > 0:
        print('\n%s>>> Register(s) deleted: %d %s' % (font_green, count, end))
    else:
        print('\n%s>>> No rows have been deleted!%s' % (font_red, end))

def run_update(conn, cursor):
    conn.commit()
    count = cursor.rowcount
    if count > 0:
        print('\n%s>>> Register(s) updated: %d %s' % (font_green, count, end))
    else:
        print('\n%s>>> No rows have been updated!%s' % (font_red, end))

def run_insert(conn, cursor):
    conn.commit()
    count = cursor.rowcount
    if count > 0:
        print('\n%s>>> Register(s) inserted: %d %s' % (font_green, count, end))
    else:
        print('\n%s>>> No rows have been inserted!%s' % (font_red, end))

def run_query(query):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""PRAGMA foreign_keys = ON""")
        cursor.execute(query)
        if query.lower().startswith('select'):
            run_select(cursor)
        if query.lower().startswith('delete'):
            run_delete(conn, cursor)
        if query.lower().startswith('update'):
            run_update(conn, cursor)
        if query.lower().startswith('insert'):
            run_insert(conn, cursor)
        conn.close()
    except sqlite3.Error as e:
        print('\n%s>>> SQL Error.%s %s' % (font_red, end, e))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ipaddr', nargs=1, help='IP address server', type=str)
    parser.add_argument('-p', '--ports', nargs='+', type=int, help='List of ports to open.')
    parser.add_argument('-q', '--query', nargs=1, help='SQL query for search in logs', type=str)
    parser.add_argument('-e', '--examples', action='store_true', help='Examples of SQL query.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

    if args.examples:
        print('\nDatabase name: logs.db') 
        print('\nTables name: logs, info') 
        print('\nColumns in logs table:\n')
        print('{:>24s}{:>27s}'.format('log_id (integer)', 'Log ID'))
        print('{:>24s}{:>27s}'.format('ip_orig (string)', 'Origin IP'))
        print('{:>24s}{:>27s}'.format('port_orig (string)', 'Origin Port'))
        print('{:>24s}{:>27s}'.format('ip_dst (string)', 'Destination IP'))
        print('{:>24s}{:>27s}'.format('port_dst (string)', 'Destination Port'))
        print('{:>24s}{:>27s}'.format('created (datetime)', 'format: %Y-%m-%d %H:%M:%S'))
        print('{:>24s}{:>27s}'.format('banned (boolean)', 'false = 0 | true = 1'))
        print('\nColumns in info table:\n')
        print('{:>24s}{:>27s}'.format('info_id (integer)', 'Info ID'))
        print('{:>24s}{:>27s}'.format('msg (string)', 'Message from client'))
        print('{:>24s}{:>27s}'.format('log_fk (integer)', 'Logs foreign key'))
        print('\n[SQL] Example queries:\n')
        print('-q "SELECT * FROM logs;"')
        print('-q "SELECT * FROM logs WHERE ip_orig="192.168.1.132" ORDER BY created DESC LIMIT 5;"')
        print('-q "SELECT ip_orig, port_dst FROM logs WHERE port_orig BETWEEN 2222 AND 2500;"')
        print('-q "SELECT ip_orig, port_dst FROM logs WHERE created BETWEEN "2019-10-01 12:00:00" AND "2019-10-05 12:00:00;""')
        print('-q "SELECT ip_orig, msg FROM logs INNER JOIN info WHERE log_id=1 AND log_id=log_fk;"')
        print('\n[SQL] Blocking a ip origin address:\n')
        print('-q "UPDATE logs SET banned=1 WHERE ip_orig="192.168.120.132";"')
        print('\n[SQL] Blocking a specific server port:\n')
        print('-q "INSERT INTO ports (port, blocked) VALUES (2222, 1);"')
        print('\n[SQL] Unblocking a specific server port:\n')
        print('-q "UPDATE ports SET blocked=0 WHERE port=2222;"')
        print('\n[SQL] Blocking a list of server ports:\n')
        print('-q "INSERT INTO ports (port, blocked) VALUES (2222, 1), (3333, 1), (4444, 1), (5555, 1);"')
        print('\n[SQL] Unblocking a list of server ports:\n')
        print('-q "UPDATE ports SET blocked=0 WHERE port IN (2222, 3333, 4444, 5555);"')

    # Create database if not exists
    if not pathlib.Path('logs.db').exists():
        create_database()
    
    # Print usage if idaddr and ports are empty
    if args.ports and not args.ipaddr or args.ipaddr and not args.ports:
        parser.print_usage()

    # Starting the server from args
    if args.ports and args.ipaddr:
        if valid_ipaddr(args.ipaddr[0]):
            try:
                create_server(args.ports, args.ipaddr[0])    
            except KeyboardInterrupt:
                print('\n%s[Stopped]%s Honeypot server interrupted by user.' % (red, end))
        else:
            print('%s>>> Honeypot server need ports to open and a valid IP address.%s\n' % (font_red, end))

    # Create a sql query from args
    if args.query:
        run_query(args.query[0])

if __name__ == '__main__':
    main()