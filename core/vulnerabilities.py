import sqlite3
from typing import List, Dict
import json


class VulnerabilityDatabase:
    def __init__(self):
        self.conn = sqlite3.connect('vulnerabilities.db', check_same_thread=False)
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                cve_id TEXT UNIQUE,
                name TEXT,
                description TEXT,
                cvss_score REAL,
                risk_level TEXT,
                service TEXT,
                port INTEGER,
                exploitation_script TEXT
            )
        ''')

        # Добавляем демо-данные
        demo_vulnerabilities = [
            ('CVE-2021-44228', 'Log4Shell', 'Удаленное выполнение кода через Apache Log4j', 10.0, 'CRITICAL', 'web', 80,
             'log4shell_exploit.py'),
            ('CVE-2021-4034', 'PwnKit', 'Эскалация привилегий в Polkit', 9.8, 'HIGH', 'system', 0, 'pwnkit_exploit.c'),
            ('CVE-2017-0144', 'EternalBlue', 'Удаленное выполнение кода через SMB', 9.3, 'CRITICAL', 'smb', 445,
             'eternalblue_exploit.py'),
            ('CVE-2019-0708', 'BlueKeep', 'Удаленное выполнение кода через RDP', 9.8, 'CRITICAL', 'rdp', 3389,
             'bluekeep_exploit.py'),
            ('CVE-2021-34527', 'PrintNightmare', 'Удаленное выполнение кода через Print Spooler', 8.8, 'HIGH', 'print',
             445, 'printnightmare_exploit.py')
        ]

        cursor.executemany('''
            INSERT OR IGNORE INTO vulnerabilities 
            (cve_id, name, description, cvss_score, risk_level, service, port, exploitation_script)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', demo_vulnerabilities)

        self.conn.commit()

    def get_vulnerability(self, cve_id: str) -> Dict:
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM vulnerabilities WHERE cve_id = ?', (cve_id,))
        row = cursor.fetchone()

        if row:
            return {
                'id': row[1],
                'name': row[2],
                'description': row[3],
                'cvss': row[4],
                'risk': row[5],
                'service': row[6],
                'port': row[7],
                'exploitation_script': row[8]
            }
        return {}

    def search_vulnerabilities(self, service: str = None, port: int = None) -> List[Dict]:
        cursor = self.conn.cursor()

        if service and port:
            cursor.execute('SELECT * FROM vulnerabilities WHERE service = ? AND port = ?', (service, port))
        elif service:
            cursor.execute('SELECT * FROM vulnerabilities WHERE service = ?', (service,))
        elif port:
            cursor.execute('SELECT * FROM vulnerabilities WHERE port = ?', (port,))
        else:
            cursor.execute('SELECT * FROM vulnerabilities')

        vulnerabilities = []
        for row in cursor.fetchall():
            vulnerabilities.append({
                'id': row[1],
                'name': row[2],
                'description': row[3],
                'cvss': row[4],
                'risk': row[5],
                'service': row[6],
                'port': row[7]
            })

        return vulnerabilities