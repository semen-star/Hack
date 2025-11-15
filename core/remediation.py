#!/usr/bin/env python3
from typing import Dict, List
import os
from datetime import datetime

class RemediationAdvisor:
    def __init__(self):
        self.remediation_guides = self._load_remediation_guides()

    def _load_remediation_guides(self) -> Dict[str, Dict]:
        """База знаний по устранению уязвимостей"""
        return {
            'CVE-2021-44228': {
                'title': 'Log4Shell (CVE-2021-44228)',
                'risk_level': 'CRITICAL',
                'description': 'Удаленное выполнение кода через Apache Log4j',
                'remediation_steps': [
                    '1. НЕМЕДЛЕННО обновить Log4j до версии 2.17.0 или выше',
                    '2. Для версий 2.10+ установить системное свойство: -Dlog4j2.formatMsgNoLookups=true',
                    '3. Удалить класс JndiLookup из log4j-core.jar: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class',
                    '4. Проверить все приложения на использование уязвимых версий Log4j',
                    '5. Настроить WAF для блокировки запросов содержащих ${jndi:}',
                    '6. Мониторить логи на предмет подозрительной активности'
                ],
                'tools': ['log4j-scan', 'log4j-detector', 'WAF правила'],
                'deadline': '24 часа',
                'references': [
                    'https://logging.apache.org/log4j/2.x/security.html',
                    'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'
                ]
            },
            'CVE-2021-4034': {
                'title': 'PwnKit (CVE-2021-4034)',
                'risk_level': 'HIGH',
                'description': 'Эскалация привилегий в Polkit',
                'remediation_steps': [
                    '1. Обновить пакет polkit до версии 0.120 или выше',
                    '2. Для CentOS/RHEL: yum update polkit',
                    '3. Для Ubuntu/Debian: apt update && apt install policykit-1',
                    '4. Проверить обновления через: pkaction --version',
                    '5. Ограничить доступ к SUID бинарникам',
                    '6. Регулярно проверять систему на наличие подозрительных процессов'
                ],
                'tools': ['lynis', 'chkrootkit', 'rkhunter'],
                'deadline': '7 дней',
                'references': [
                    'https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt',
                    'https://ubuntu.com/security/CVE-2021-4034'
                ]
            },
            'CVE-2017-0144': {
                'title': 'EternalBlue (CVE-2017-0144)',
                'risk_level': 'CRITICAL',
                'description': 'Удаленное выполнение кода через SMBv1',
                'remediation_steps': [
                    '1. Установить патч MS17-010 от Microsoft',
                    '2. ОТКЛЮЧИТЬ протокол SMBv1 полностью',
                    '3. Настроить брандмауэр для блокировки портов 445/tcp, 139/tcp',
                    '4. Использовать SMBv3 с шифрованием',
                    '5. Регулярно обновлять антивирусные базы',
                    '6. Мониторить сетевую активность на портах SMB'
                ],
                'tools': ['Windows Update', 'Nessus', 'Metasploit'],
                'deadline': '24 часа',
                'references': [
                    'https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010',
                    'https://nvd.nist.gov/vuln/detail/CVE-2017-0144'
                ]
            },
            'CVE-2019-0708': {
                'title': 'BlueKeep (CVE-2019-0708)',
                'risk_level': 'CRITICAL',
                'description': 'Удаленное выполнение кода через RDP',
                'remediation_steps': [
                    '1. Установить майские обновления безопасности 2019 года',
                    '2. Отключить RDP если он не используется',
                    '3. Настроить Network Level Authentication (NLA)',
                    '4. Изменить стандартный порт RDP (3389)',
                    '5. Настроить VPN для доступа к RDP',
                    '6. Регулярно менять пароли учетных записей'
                ],
                'tools': ['Windows Update', 'RDPGuard', 'Fail2Ban'],
                'deadline': '24 часа',
                'references': [
                    'https://support.microsoft.com/en-us/help/4499164',
                    'https://nvd.nist.gov/vuln/detail/CVE-2019-0708'
                ]
            },
            'CVE-2021-34527': {
                'title': 'PrintNightmare (CVE-2021-34527)',
                'risk_level': 'HIGH',
                'description': 'Удаленное выполнение кода через Print Spooler',
                'remediation_steps': [
                    '1. Установить последние обновления безопасности от Microsoft',
                    '2. ОТКЛЮЧИТЬ службу Print Spooler если печать не используется',
                    '3. Настроить групповые политики для ограничения установки драйверов',
                    '4. Ограничить доступ к папке spoolers по сети',
                    '5. Мониторить события в журнале System на предмет ошибок spooler'
                ],
                'tools': ['Windows Update', 'PSExec', 'Process Monitor'],
                'deadline': '48 часов',
                'references': [
                    'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527',
                    'https://nvd.nist.gov/vuln/detail/CVE-2021-34527'
                ]
            },
            'weak_passwords': {
                'title': 'Слабые пароли',
                'risk_level': 'HIGH',
                'description': 'Использование простых или стандартных паролей',
                'remediation_steps': [
                    '1. Внедрить политику сложных паролей (мин. 12 символов)',
                    '2. Требовать регулярной смены паролей (каждые 90 дней)',
                    '3. Внедрить двухфакторную аутентификацию',
                    '4. Заблокировать учетные записи после 5 неудачных попыток',
                    '5. Проводить регулярные аудиты паролей',
                    '6. Обучить сотрудников основам кибербезопасности'
                ],
                'tools': ['John the Ripper', 'Hashcat', 'Burp Suite'],
                'deadline': '14 дней',
                'references': [
                    'https://www.nist.gov/cyberframework',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
                ]
            },
            'sql_injection': {
                'title': 'SQL Injection',
                'risk_level': 'HIGH',
                'description': 'Внедрение SQL кода через пользовательский ввод',
                'remediation_steps': [
                    '1. Использовать подготовленные выражения (Prepared Statements)',
                    '2. Внедрить валидацию и санацию входных данных',
                    '3. Принцип минимальных привилегий для БД',
                    '4. Регулярно обновлять СУБД и фреймворки',
                    '5. Внедрить WAF для блокировки SQLi атак',
                    '6. Проводить регулярное тестирование на проникновение'
                ],
                'tools': ['SQLMap', 'Burp Suite', 'Acunetix'],
                'deadline': '7 дней',
                'references': [
                    'https://owasp.org/www-community/attacks/SQL_Injection',
                    'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
                ]
            },
            'xss': {
                'title': 'Cross-Site Scripting (XSS)',
                'risk_level': 'MEDIUM',
                'description': 'Выполнение JavaScript кода в браузере жертвы',
                'remediation_steps': [
                    '1. Внедрить Content Security Policy (CSP)',
                    '2. Кодировать выходные данные (HTML encoding)',
                    '3. Валидировать и санировать все пользовательские данные',
                    '4. Использовать HTTPOnly флаг для cookies',
                    '5. Регулярно обновлять фреймворки и библиотеки',
                    '6. Проводить security code review'
                ],
                'tools': ['Burp Suite', 'OWASP ZAP', 'XSStrike'],
                'deadline': '14 дней',
                'references': [
                    'https://owasp.org/www-community/attacks/xss/',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
                ]
            }
        }
    
    def get_remediation_guide(self, vulnerability_id: str) -> Dict:
        """Получить руководство по устранению для конкретной уязвимости"""
        return self.remediation_guides.get(vulnerability_id, self._get_generic_guide())
    
    def _get_generic_guide(self) -> Dict:
        """Общее руководство для неизвестных уязвимостей"""
        return {
            'title': 'Общие рекомендации по безопасности',
            'risk_level': 'MEDIUM',
            'description': 'Общие меры для повышения безопасности системы',
            'remediation_steps': [
                '1. Регулярно обновлять операционную систему и программное обеспечение',
                '2. Внедрить систему обнаружения и предотвращения вторжений (IDS/IPS)',
                '3. Настроить и поддерживать межсетевой экран',
                '4. Регулярно проводить сканирование уязвимостей',
                '5. Внедрить централизованное логирование и мониторинг',
                '6. Проводить обучение сотрудников по кибербезопасности',
                '7. Регулярно создавать и тестировать резервные копии',
                '8. Внедрить принцип минимальных привилегий'
            ],
            'tools': ['Nessus', 'OpenVAS', 'Wireshark', 'SIEM системы'],
            'deadline': '30 дней',
            'references': [
                'https://www.cisecurity.org/cybersecurity-tools/',
                'https://www.sans.org/security-resources/'
            ]
        }
    
    def generate_remediation_report(self, vulnerabilities: List[Dict]) -> str:
        """Генерация полного отчета по устранению уязвимостей"""
        report = []
        report.append("BITKILLERS - ОТЧЕТ ПО УСТРАНЕНИЮ УЯЗВИМОСТЕЙ")
        report.append("=" * 60)
        report.append(f"Дата генерации: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
        report.append(f"Обнаружено уязвимостей: {len(vulnerabilities)}")
        report.append("")
        
        critical_count = len([v for v in vulnerabilities if v.get('risk') == 'CRITICAL'])
        high_count = len([v for v in vulnerabilities if v.get('risk') == 'HIGH'])
        
        report.append("СВОДКА ПО РИСКАМ:")
        report.append(f"- Критические уязвимости: {critical_count}")
        report.append(f"- Высокие уязвимости: {high_count}")
        report.append(f"- Общая оценка риска: {'КРИТИЧЕСКИЙ' if critical_count > 0 else 'ВЫСОКИЙ' if high_count > 0 else 'СРЕДНИЙ'}")
        report.append("")
        
        report.append("ПРИОРИТЕТНЫЕ ДЕЙСТВИЯ:")
        report.append("")
        
        # Критические уязвимости (первые 24 часа)
        critical_vulns = [v for v in vulnerabilities if v.get('risk') == 'CRITICAL']
        if critical_vulns:
            report.append("🚨 КРИТИЧЕСКИЕ УЯЗВИМОСТИ (устранить в течение 24 часов):")
            report.append("")
            for vuln in critical_vulns:
                guide = self.get_remediation_guide(vuln['id'])
                report.append(f"● {guide['title']}")
                report.append(f"  Описание: {guide['description']}")
                report.append(f"  Рекомендации:")
                for step in guide['remediation_steps'][:3]:  # Только первые 3 шага для отчета
                    report.append(f"  {step}")
                report.append("")
        
        # Высокие уязвимости (7 дней)
        high_vulns = [v for v in vulnerabilities if v.get('risk') == 'HIGH']
        if high_vulns:
            report.append("🟡 ВЫСОКИЕ УЯЗВИМОСТИ (устранить в течение 7 дней):")
            report.append("")
            for vuln in high_vulns:
                guide = self.get_remediation_guide(vuln['id'])
                report.append(f"● {guide['title']}")
                report.append(f"  Описание: {guide['description']}")
                report.append("")
        
        # Общие рекомендации
        report.append("🔧 ОБЩИЕ РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ:")
        report.append("")
        general_guide = self._get_generic_guide()
        for step in general_guide['remediation_steps']:
            report.append(f"• {step}")
        
        report.append("")
        report.append("ИСПОЛЬЗУЕМЫЕ ИНСТРУМЕНТЫ:")
        all_tools = set()
        for vuln in vulnerabilities:
            guide = self.get_remediation_guide(vuln['id'])
            all_tools.update(guide['tools'])
        report.append(", ".join(all_tools))
        
        report.append("")
        report.append("ПОЛЕЗНЫЕ ССЫЛКИ:")
        report.append("- OWASP Security Guidelines: https://owasp.org")
        report.append("- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework")
        report.append("- SANS Security Resources: https://www.sans.org/security-resources")
        
        report.append("")
        report.append("—" * 60)
        report.append("Отчет сгенерирован системой BITKILLERS")
        report.append("Профессиональная платформа для оценки безопасности")
        
        return "\n".join(report)
    
    def save_remediation_report(self, vulnerabilities: List[Dict], filename: str = None) -> str:
        """Сохранение отчета в файл"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"bitkillers_remediation_{timestamp}.txt"
        
        report_content = self.generate_remediation_report(vulnerabilities)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return filename
