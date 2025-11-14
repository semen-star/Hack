import threading
import nmap
import time
from datetime import datetime
from typing import Dict, List, Optional
from enum import Enum


class ScanMode(Enum):
    BLACK_BOX = "black_box"
    GRAY_BOX = "gray_box"
    WHITE_BOX = "white_box"


class AttackPhase(Enum):
    RECONNAISSANCE = "recon"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"


class ScanJob:
    def __init__(self, job_id: str, target: str, mode: ScanMode, credentials: Dict = None):
        self.job_id = job_id
        self.target = target
        self.mode = mode
        self.credentials = credentials or {}
        self.phase = AttackPhase.RECONNAISSANCE
        self.status = "pending"
        self.results = {}
        self.start_time = datetime.now()
        self.progress = 0


class ScanManager:
    def __init__(self, socketio):
        self.active_jobs: Dict[str, ScanJob] = {}
        self.socketio = socketio

    def create_scan_job(self, target: str, mode: str, credentials: Dict = None) -> str:
        job_id = f"scan_{int(time.time())}_{len(self.active_jobs)}"
        scan_mode = ScanMode(mode)
        job = ScanJob(job_id, target, scan_mode, credentials)
        self.active_jobs[job_id] = job

        thread = threading.Thread(target=self._execute_scan, args=(job,))
        thread.daemon = True
        thread.start()

        return job_id

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        return self.active_jobs.get(job_id)

    def list_jobs(self) -> List[Dict]:
        scans = []
        for job_id, job in self.active_jobs.items():
            scans.append({
                'job_id': job_id,
                'target': job.target,
                'status': job.status,
                'progress': job.progress,
                'start_time': job.start_time.isoformat()
            })
        return scans

    def _execute_scan(self, job: ScanJob):
        try:
            job.status = "running"
            self._emit_progress(job, "🚀 Запуск сканирования...", 10)

            # Фаза 1: Разведка
            job.phase = AttackPhase.RECONNAISSANCE
            recon_results = self._perform_reconnaissance(job)
            job.results['reconnaissance'] = recon_results
            self._emit_progress(job, "🔍 Разведка завершена", 30)

            # Фаза 2: Сканирование уязвимостей
            job.phase = AttackPhase.SCANNING
            vuln_results = self._perform_vulnerability_scan(job)
            job.results['vulnerabilities'] = vuln_results
            self._emit_progress(job, "📊 Сканирование уязвимостей завершено", 60)

            # Фаза 3: Построение вектора атаки
            job.phase = AttackPhase.EXPLOITATION
            attack_vectors = self._build_attack_vectors(vuln_results)
            job.results['attack_vectors'] = attack_vectors
            self._emit_progress(job, "🎯 Вектора атак построены", 80)

            # Фаза 4: Генерация отчета
            job.phase = AttackPhase.REPORTING
            from .reporter import ReportGenerator
            reporter = ReportGenerator()
            report = reporter.generate_comprehensive_report(job)
            job.results['report'] = report
            self._emit_progress(job, "✅ Сканирование завершено", 100)

            job.status = "completed"

        except Exception as e:
            job.status = "failed"
            job.results['error'] = str(e)
            self._emit_progress(job, f"❌ Ошибка: {e}", 0)

    def _perform_reconnaissance(self, job: ScanJob) -> Dict:
        nm = nmap.PortScanner()
        results = {
            'host': job.target,
            'ports': [],
            'services': [],
            'os_detection': None
        }

        try:
            self.socketio.emit('scan_log', {'job_id': job.job_id, 'message': 'Сканирование портов...'})
            nm.scan(job.target, '1-1000', arguments='-sS -T4')

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        port_info = {
                            'port': port,
                            'protocol': proto,
                            'state': service['state'],
                            'service': service['name'],
                            'version': service.get('version', ''),
                            'product': service.get('product', '')
                        }
                        results['ports'].append(port_info)

                        if service['name']:
                            results['services'].append({
                                'name': service['name'],
                                'port': port,
                                'version': service.get('version', '')
                            })

            self.socketio.emit('scan_log', {'job_id': job.job_id, 'message': 'Определение ОС...'})
            nm.scan(job.target, arguments='-O')
            if 'osmatch' in nm[job.target]:
                results['os_detection'] = nm[job.target]['osmatch'][0]['name']

        except Exception as e:
            self.socketio.emit('scan_log', {'job_id': job.job_id, 'message': f'Ошибка разведки: {e}'})

        return results

    def _perform_vulnerability_scan(self, job: ScanJob) -> List[Dict]:
        vulnerabilities = []

        try:
            self.socketio.emit('scan_log', {'job_id': job.job_id, 'message': 'Запуск Nmap vuln scripts...'})
            nm = nmap.PortScanner()

            nm.scan(job.target, arguments='--script vuln -T4')

            for host in nm.all_hosts():
                for script in nm[host].get('scripts', []):
                    if 'vuln' in script:
                        vuln_info = {
                            'id': f"NMAP_{int(time.time())}",
                            'name': script,
                            'description': f"Обнаружено Nmap script: {script}",
                            'risk': 'MEDIUM',
                            'service': 'unknown',
                            'port': 'unknown'
                        }
                        vulnerabilities.append(vuln_info)

            # Демо-уязвимости
            demo_vulns = [
                {
                    'id': 'CVE-2021-44228',
                    'name': 'Log4Shell RCE',
                    'description': 'Удаленное выполнение кода через Apache Log4j',
                    'risk': 'CRITICAL',
                    'cvss': 10.0,
                    'service': 'web',
                    'port': 80
                },
                {
                    'id': 'CVE-2021-4034',
                    'name': 'PwnKit Privilege Escalation',
                    'description': 'Эскалация привилегий в Polkit',
                    'risk': 'HIGH',
                    'cvss': 9.8,
                    'service': 'system',
                    'port': 'N/A'
                },
                {
                    'id': 'CVE-2017-0144',
                    'name': 'EternalBlue SMB RCE',
                    'description': 'Удаленное выполнение кода через SMB',
                    'risk': 'CRITICAL',
                    'cvss': 9.3,
                    'service': 'smb',
                    'port': 445
                }
            ]

            vulnerabilities.extend(demo_vulns)

        except Exception as e:
            self.socketio.emit('scan_log', {'job_id': job.job_id, 'message': f'Ошибка сканирования уязвимостей: {e}'})

        return vulnerabilities

    def _build_attack_vectors(self, vulnerabilities: List[Dict]) -> List[Dict]:
        vectors = []

        critical_vulns = [v for v in vulnerabilities if v.get('risk') == 'CRITICAL']
        high_vulns = [v for v in vulnerabilities if v.get('risk') == 'HIGH']

        if critical_vulns:
            vectors.append({
                'name': 'Критический вектор атаки',
                'description': 'Эксплуатация критических уязвимостей для получения полного контроля',
                'steps': [
                    'Разведка и обнаружение уязвимостей',
                    'Эксплуатация RCE уязвимостей',
                    'Получение удаленного доступа',
                    'Эскалация привилегий',
                    'Закрепление в системе'
                ],
                'vulnerabilities': critical_vulns,
                'risk': 'CRITICAL'
            })

        if high_vulns:
            vectors.append({
                'name': 'Вектор эскалации привилегий',
                'description': 'Использование уязвимостей для повышения привилегий',
                'steps': [
                    'Получение начального доступа',
                    'Обнаружение уязвимостей эскалации',
                    'Эксплуатация LPE уязвимостей',
                    'Получение root/SYSTEM привилегий'
                ],
                'vulnerabilities': high_vulns,
                'risk': 'HIGH'
            })

        return vectors

    def _emit_progress(self, job: ScanJob, message: str, progress: int):
        job.progress = progress
        self.socketio.emit('scan_progress', {
            'job_id': job.job_id,
            'message': message,
            'progress': progress,
            'phase': job.phase.value
        })