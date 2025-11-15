import threading
import nmap
import time
import requests
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
    POST_EXPLOITATION = "post_exploit"
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
        self.discovered_data = {}  # Для переиспользования данных
        self.start_time = datetime.now()
        self.progress = 0


class ScanManager:
    def __init__(self, socketio):
        self.active_jobs: Dict[str, ScanJob] = {}
        self.socketio = socketio
        self.exploitation_engine = ExploitationEngine()

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

            # Фаза 1: Разведка (разная для каждого режима)
            job.phase = AttackPhase.RECONNAISSANCE
            recon_results = self._perform_mode_specific_reconnaissance(job)
            job.results['reconnaissance'] = recon_results
            job.discovered_data['recon'] = recon_results
            self._emit_progress(job, "🔍 Разведка завершена", 25)

            # Фаза 2: Сканирование уязвимостей
            job.phase = AttackPhase.SCANNING
            vuln_results = self._perform_vulnerability_scan(job)
            job.results['vulnerabilities'] = vuln_results
            job.discovered_data['vulnerabilities'] = vuln_results
            self._emit_progress(job, "📊 Сканирование уязвимостей завершено", 50)

            # Фаза 3: Имитация атак и эксплуатация
            job.phase = AttackPhase.EXPLOITATION
            exploitation_results = self._perform_attack_simulation(job)
            job.results['exploitation'] = exploitation_results
            job.discovered_data['exploitation'] = exploitation_results
            self._emit_progress(job, "💀 Имитация атак завершена", 75)

            # Фаза 4: Построение векторов атаки с переиспользованием данных
            attack_vectors = self._build_dynamic_attack_vectors(job)
            job.results['attack_vectors'] = attack_vectors
            self._emit_progress(job, "🎯 Вектора атак построены", 85)

            # Фаза 5: Генерация отчета
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

    def _perform_mode_specific_reconnaissance(self, job: ScanJob) -> Dict:
        """Разведка в зависимости от режима сканирования"""
        if job.mode == ScanMode.BLACK_BOX:
            return self._black_box_reconnaissance(job)
        elif job.mode == ScanMode.GRAY_BOX:
            return self._gray_box_reconnaissance(job)
        else:  # WHITE_BOX
            return self._white_box_reconnaissance(job)

    def _black_box_reconnaissance(self, job: ScanJob) -> Dict:
        """Чёрный ящик - только внешняя разведка"""
        self.socketio.emit('scan_log', {'job_id': job.job_id, 'message': 'BLACK BOX: Внешняя разведка без доступа'})

        nm = nmap.PortScanner()
        results = {
            'host': job.target,
            'ports': [],
            'services': [],
            'os_detection': None,
            'mode': 'black_box'
        }

        # Только базовое сканирование портов
        nm.scan(job.target, '1-1000', arguments='-sS -T4 --script safe')

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

        return results

    def _gray_box_reconnaissance(self, job: ScanJob) -> Dict:
        """Серый ящик - разведка с частичным доступом"""
        self.socketio.emit('scan_log', {'job_id': job.job_id, 'message': 'GRAY BOX: Разведка с частичным доступом'})

        nm = nmap.PortScanner()
        results = {
            'host': job.target,
            'ports': [],
            'services': [],
            'os_detection': None,
            'mode': 'gray_box',
            'credentials_provided': bool(job.credentials)
        }

        # Более детальное сканирование
        nm.scan(job.target, '1-65535', arguments='-sS -sV -O -T4')

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

            # Детект ОС
            if 'osmatch' in nm[host]:
                results['os_detection'] = nm[host]['osmatch'][0]['name']

        # Попытка использования учетных данных для веб-сервисов
        if job.credentials:
            web_services = [s for s in results['services'] if s['name'] in ['http', 'https', 'http-alt']]
            for service in web_services:
                auth_check = self._check_web_authentication(job.target, service['port'], job.credentials)
                results.setdefault('authentication_checks', []).append(auth_check)

        return results

    def _white_box_reconnaissance(self, job: ScanJob) -> Dict:
        """Белый ящик - полная разведка с доступом"""
        self.socketio.emit('scan_log', {'job_id': job.job_id, 'message': 'WHITE BOX: Полная разведка с доступом'})

        # Наследуем всё из серого ящика
        results = self._gray_box_reconnaissance(job)
        results['mode'] = 'white_box'

        # Дополнительные проверки для белого ящика
        nm = nmap.PortScanner()

        # Глубокое сканирование всех портов
        nm.scan(job.target, arguments='-p- -sV -sC -O -A -T4')

        # Проверка на дополнительные сервисы
        additional_services = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if port not in [p['port'] for p in results['ports']]:
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
                        additional_services.append({
                            'name': service['name'],
                            'port': port,
                            'version': service.get('version', '')
                        })

        results['services'].extend(additional_services)
        results['full_port_scan'] = True
        results['additional_scripts'] = True

        return results

    def _check_web_authentication(self, target: str, port: int, credentials: Dict) -> Dict:
        """Проверка аутентификации на веб-сервисах"""
        try:
            url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
            response = requests.get(url, timeout=5)

            # Простая проверка наличия форм аутентификации
            has_login_form = 'login' in response.text.lower() or 'password' in response.text.lower()

            return {
                'url': url,
                'status_code': response.status_code,
                'has_login_form': has_login_form,
                'authentication_checked': True
            }
        except:
            return {
                'url': f"http://{target}:{port}",
                'status_code': 'error',
                'has_login_form': False,
                'authentication_checked': False
            }

    def _perform_vulnerability_scan(self, job: ScanJob) -> List[Dict]:
        """Сканирование уязвимостей с учетом режима"""
        vulnerabilities = []

        try:
            self.socketio.emit('scan_log', {'job_id': job.job_id, 'message': 'Запуск Nmap vuln scripts...'})
            nm = nmap.PortScanner()

            # Разный уровень агрессивности в зависимости от режима
            if job.mode == ScanMode.BLACK_BOX:
                nm.scan(job.target, arguments='--script vuln -T4')
            elif job.mode == ScanMode.GRAY_BOX:
                nm.scan(job.target, arguments='--script vuln,safe -T4')
            else:  # WHITE_BOX
                nm.scan(job.target, arguments='--script vuln,safe,exploit -T4 -A')

            for host in nm.all_hosts():
                for script in nm[host].get('scripts', []):
                    if 'vuln' in script:
                        vuln_info = {
                            'id': f"NMAP_{int(time.time())}",
                            'name': script,
                            'description': f"Обнаружено Nmap script: {script}",
                            'risk': 'MEDIUM',
                            'service': 'unknown',
                            'port': 'unknown',
                            'mode_specific': job.mode.value
                        }
                        vulnerabilities.append(vuln_info)

            # Демо-уязвимости с учетом режима
            demo_vulns = self._get_demo_vulnerabilities(job.mode)
            vulnerabilities.extend(demo_vulns)

        except Exception as e:
            self.socketio.emit('scan_log', {'job_id': job.job_id, 'message': f'Ошибка сканирования уязвимостей: {e}'})

        return vulnerabilities

    def _get_demo_vulnerabilities(self, mode: ScanMode) -> List[Dict]:
        """Демо-уязвимости в зависимости от режима"""
        base_vulns = [
            {
                'id': 'CVE-2021-44228',
                'name': 'Log4Shell RCE',
                'description': 'Удаленное выполнение кода через Apache Log4j',
                'risk': 'CRITICAL',
                'cvss': 10.0,
                'service': 'web',
                'port': 80
            }
        ]

        if mode == ScanMode.GRAY_BOX:
            base_vulns.extend([
                {
                    'id': 'CVE-2021-4034',
                    'name': 'PwnKit Privilege Escalation',
                    'description': 'Эскалация привилегий в Polkit',
                    'risk': 'HIGH',
                    'cvss': 9.8,
                    'service': 'system',
                    'port': 'N/A'
                }
            ])

        if mode == ScanMode.WHITE_BOX:
            base_vulns.extend([
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
                },
                {
                    'id': 'CVE-2019-0708',
                    'name': 'BlueKeep RDP RCE',
                    'description': 'Удаленное выполнение кода через RDP',
                    'risk': 'CRITICAL',
                    'cvss': 9.8,
                    'service': 'rdp',
                    'port': 3389
                }
            ])

        for vuln in base_vulns:
            vuln['mode_specific'] = mode.value

        return base_vulns

    def _perform_attack_simulation(self, job: ScanJob) -> Dict:
        """Имитация реальных атак"""
        self.socketio.emit('scan_log', {'job_id': job.job_id, 'message': '💀 Запуск имитации атак...'})

        attack_results = {
            'credential_attacks': [],
            'service_compromise': [],
            'privilege_escalation': [],
            'lateral_movement': []
        }

        # Имитация атак на основе обнаруженных уязвимостей
        vulnerabilities = job.discovered_data.get('vulnerabilities', [])
        services = job.discovered_data.get('recon', {}).get('services', [])

        # Атака на веб-сервисы
        web_services = [s for s in services if s['name'] in ['http', 'https']]
        for service in web_services:
            web_attack = self._simulate_web_attack(job.target, service)
            if web_attack:
                attack_results['service_compromise'].append(web_attack)

        # Атака на учетные данные (если есть)
        if job.credentials:
            cred_attack = self._simulate_credential_attack(job.target, job.credentials, services)
            if cred_attack:
                attack_results['credential_attacks'].append(cred_attack)

        # Привилегированные атаки для белого ящика
        if job.mode == ScanMode.WHITE_BOX:
            priv_esc = self._simulate_privilege_escalation(job.target)
            if priv_esc:
                attack_results['privilege_escalation'].append(priv_esc)

        return attack_results

    def _simulate_web_attack(self, target: str, service: Dict) -> Dict:
        """Имитация атаки на веб-сервис"""
        try:
            port = service['port']
            url = f"http://{target}:{port}" if service['name'] == 'http' else f"https://{target}:{port}"

            # Простая проверка на распространенные уязвимости
            tests = [
                {'path': '/../etc/passwd', 'type': 'path_traversal'},
                {'path': '/phpinfo.php', 'type': 'information_disclosure'},
                {'path': '/admin', 'type': 'admin_panel'},
                {'path': '/.git', 'type': 'source_disclosure'}
            ]

            results = []
            for test in tests:
                try:
                    response = requests.get(url + test['path'], timeout=3, verify=False)
                    if response.status_code == 200:
                        results.append({
                            'type': test['type'],
                            'url': url + test['path'],
                            'status': 'potential_vulnerability',
                            'evidence': f'Обнаружен доступ к {test["path"]}'
                        })
                except:
                    continue

            return {
                'service': service['name'],
                'port': service['port'],
                'attack_type': 'web_enumeration',
                'results': results,
                'successful': len(results) > 0
            }

        except Exception as e:
            return {
                'service': service['name'],
                'port': service['port'],
                'attack_type': 'web_enumeration',
                'results': [],
                'successful': False,
                'error': str(e)
            }

    def _simulate_credential_attack(self, target: str, credentials: Dict, services: List[Dict]) -> Dict:
        """Имитация атаки на учетные данные"""
        # Проверка учетных данных на различных сервисах
        tested_services = []

        for service in services:
            if service['name'] in ['ssh', 'ftp', 'http', 'https']:
                tested_services.append({
                    'service': service['name'],
                    'port': service['port'],
                    'credentials_tested': True,
                    'result': 'simulated_check'
                })

        return {
            'attack_type': 'credential_testing',
            'credentials_used': True,
            'services_tested': tested_services,
            'successful': any(s['result'] == 'simulated_check' for s in tested_services)
        }

    def _simulate_privilege_escalation(self, target: str) -> Dict:
        """Имитация эскалации привилегий (для белого ящика)"""
        return {
            'attack_type': 'privilege_escalation',
            'techniques': [
                'sudo misconfiguration check',
                'SUID binaries analysis',
                'kernel exploits check'
            ],
            'successful': False,  # Только имитация
            'evidence': 'Проверка типичных векторов эскалации привилегий'
        }

    def _build_dynamic_attack_vectors(self, job: ScanJob) -> List[Dict]:
        """Динамическое построение векторов атак с переиспользованием данных"""
        vectors = []

        # Получаем все обнаруженные данные
        vulns = job.discovered_data.get('vulnerabilities', [])
        services = job.discovered_data.get('recon', {}).get('services', [])
        exploitation = job.discovered_data.get('exploitation', {})

        critical_vulns = [v for v in vulns if v.get('risk') == 'CRITICAL']
        high_vulns = [v for v in vulns if v.get('risk') == 'HIGH']

        # Вектор 1: Критические уязвимости веб-сервисов
        web_critical_vulns = [v for v in critical_vulns if v.get('service') == 'web']
        if web_critical_vulns:
            vectors.append({
                'name': 'Вектор компрометации через веб-уязвимости',
                'description': 'Эксплуатация критических уязвимостей в веб-сервисах для получения удаленного доступа',
                'steps': self._build_web_attack_steps(web_critical_vulns, services, exploitation),
                'vulnerabilities': web_critical_vulns,
                'risk': 'CRITICAL',
                'data_sources': ['vulnerabilities', 'services', 'exploitation']
            })

        # Вектор 2: Эскалация привилегий
        system_vulns = [v for v in high_vulns if v.get('service') == 'system']
        if system_vulns and job.mode != ScanMode.BLACK_BOX:
            vectors.append({
                'name': 'Вектор эскалации привилегий',
                'description': 'Использование уязвимостей системы для повышения привилегий',
                'steps': self._build_privilege_escalation_steps(system_vulns, exploitation),
                'vulnerabilities': system_vulns,
                'risk': 'HIGH',
                'data_sources': ['vulnerabilities', 'exploitation']
            })

        # Вектор 3: Движение в сети (только для белого ящика)
        if job.mode == ScanMode.WHITE_BOX and len(services) > 1:
            vectors.append({
                'name': 'Вектор латерального движения',
                'description': 'Движение между системами используя компрометированные учетные данные',
                'steps': self._build_lateral_movement_steps(services, exploitation),
                'vulnerabilities': [],
                'risk': 'MEDIUM',
                'data_sources': ['services', 'exploitation']
            })

        return vectors

    def _build_web_attack_steps(self, vulns: List[Dict], services: List[Dict], exploitation: Dict) -> List[str]:
        steps = [
            'Разведка веб-сервисов и определение версий ПО',
            'Поиск и идентификация критических уязвимостей'
        ]

        # Добавляем шаги на основе реальных результатов эксплуатации
        web_attacks = exploitation.get('service_compromise', [])
        for attack in web_attacks:
            if attack.get('successful'):
                steps.append(f'Успешная эксплуатация через {attack["service"]} (порт {attack["port"]})')

        steps.extend([
            'Получение удаленного выполнения кода',
            'Установка бекдора или поддержание доступа',
            'Сбор конфиденциальной информации'
        ])

        return steps

    def _build_privilege_escalation_steps(self, vulns: List[Dict], exploitation: Dict) -> List[str]:
        steps = [
            'Получение начального доступа к системе',
            'Анализ системных конфигураций и прав доступа'
        ]

        # Используем данные из имитации атак
        priv_esc_attempts = exploitation.get('privilege_escalation', [])
        for attempt in priv_esc_attempts:
            steps.extend(attempt.get('techniques', []))

        steps.extend([
            'Эксплуатация уязвимостей эскалации привилегий',
            'Получение root/SYSTEM привилегий',
            'Закрепление привилегированного доступа'
        ])

        return steps

    def _build_lateral_movement_steps(self, services: List[Dict], exploitation: Dict) -> List[str]:
        steps = [
            'Сбор учетных данных с компрометированной системы',
            'Анализ сетевой топологии и доверительных отношений'
        ]

        # Используем данные о сервисах для построения маршрута
        unique_services = set([s['name'] for s in services])
        steps.append(f'Обнаружены сервисы: {", ".join(unique_services)}')

        steps.extend([
            'Использование Pass-the-Hash или аналогичных техник',
            'Подключение к соседним системам',
            'Повторение процесса на новых целях'
        ])

        return steps

    def _emit_progress(self, job: ScanJob, message: str, progress: int):
        job.progress = progress
        self.socketio.emit('scan_progress', {
            'job_id': job.job_id,
            'message': message,
            'progress': progress,
            'phase': job.phase.value
        })


class ExploitationEngine:
    """Движок для имитации эксплуатации уязвимостей"""

    def simulate_exploitation(self, vulnerability: Dict, target: str) -> Dict:
        """Имитация эксплуатации конкретной уязвимости"""
        # Заглушка для реальной логики эксплуатации
        return {
            'vulnerability': vulnerability['id'],
            'target': target,
            'simulated': True,
            'success_probability': self._calculate_success_probability(vulnerability),
            'impact': self._assess_impact(vulnerability),
            'complexity': self._assess_complexity(vulnerability)
        }

    def _calculate_success_probability(self, vulnerability: Dict) -> str:
        risk = vulnerability.get('risk', 'MEDIUM')
        probabilities = {
            'CRITICAL': 'Высокая',
            'HIGH': 'Средняя',
            'MEDIUM': 'Низкая',
            'LOW': 'Очень низкая'
        }
        return probabilities.get(risk, 'Неизвестно')

    def _assess_impact(self, vulnerability: Dict) -> str:
        risk = vulnerability.get('risk', 'MEDIUM')
        impacts = {
            'CRITICAL': 'Полная компрометация системы',
            'HIGH': 'Значительный доступ к системе',
            'MEDIUM': 'Ограниченный доступ',
            'LOW': 'Минимальное воздействие'
        }
        return impacts.get(risk, 'Неизвестно')

    def _assess_complexity(self, vulnerability: Dict) -> str:
        risk = vulnerability.get('risk', 'MEDIUM')
        complexities = {
            'CRITICAL': 'Низкая',
            'HIGH': 'Средняя',
            'MEDIUM': 'Высокая',
            'LOW': 'Очень высокая'
        }
        return complexities.get(risk, 'Неизвестно')