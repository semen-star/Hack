from datetime import datetime
import os
import json
from typing import Dict, List, Tuple
from .scanner import ScanJob


class ReportGenerator:
    def __init__(self):
        self.report_templates = {
            'executive': self._generate_executive_summary,
            'technical': self._generate_technical_details,
            'vulnerabilities': self._generate_vulnerabilities_section,
            'attack_vectors': self._generate_attack_vectors_section,
            'remediation': self._generate_remediation_guide,
            'evidence': self._generate_evidence_section,
            'methodology': self._generate_methodology_section
        }

    def generate_comprehensive_report(self, job: ScanJob) -> dict:
        """Генерация комплексного отчета со всеми разделами"""
        return {
            'executive_summary': self._generate_executive_summary(job),
            'technical_details': self._generate_technical_details(job),
            'vulnerabilities': self._generate_vulnerabilities_section(job),
            'attack_vectors': self._generate_attack_vectors_section(job),
            'remediation_guide': self._generate_remediation_guide(job),
            'evidence': self._generate_evidence_section(job),
            'methodology': self._generate_methodology_section(job),
            'metadata': self._generate_metadata(job)
        }

    def _generate_executive_summary(self, job: ScanJob) -> str:
        vulns = job.results.get('vulnerabilities', [])
        critical_count = len([v for v in vulns if v.get('risk') == 'CRITICAL'])
        high_count = len([v for v in vulns if v.get('risk') == 'HIGH'])
        medium_count = len([v for v in vulns if v.get('risk') == 'MEDIUM'])

        risk_level = 'КРИТИЧЕСКИЙ' if critical_count > 0 else 'ВЫСОКИЙ' if high_count > 0 else 'СРЕДНИЙ' if medium_count > 0 else 'НИЗКИЙ'

        return f"""
BITKILLERS - ОТЧЕТ ОБ ОЦЕНКЕ БЕЗОПАСНОСТИ
{'=' * 60}

ИСПОЛНИТЕЛЬНОЕ РЕЗЮМЕ

1. ОБЩАЯ ИНФОРМАЦИЯ:
   • Цель оценки: {job.target}
   • Дата проведения: {datetime.now().strftime('%d.%m.%Y %H:%M')}
   • Режим сканирования: {self._get_scan_mode_name(job.mode)}
   • Общее время сканирования: {self._calculate_scan_duration(job)}

2. КЛЮЧЕВЫЕ РЕЗУЛЬТАТЫ:
   • Обнаружено уязвимостей: {len(vulns)}
   • Критические уязвимости: {critical_count}
   • Высокие уязвимости: {high_count} 
   • Средние уязвимости: {medium_count}

3. ОБЩАЯ ОЦЕНКА РИСКА: {risk_level}

4. КРАТКИЕ ВЫВОДЫ:
{self._generate_risk_analysis(vulns)}

5. РЕКОМЕНДАЦИИ:
   • Немедленно устранить критические уязвимости
   • Разработать план исправления высокоуровневых уязвимостей
   • Внедрить регулярный мониторинг безопасности
   • Провести обучение персонала

{'=' * 60}
"""

    def _generate_technical_details(self, job: ScanJob) -> str:
        recon = job.results.get('reconnaissance', {})
        services = recon.get('services', [])
        ports = recon.get('ports', [])

        open_ports = [p for p in ports if p.get('state') == 'open']

        return f"""
ТЕХНИЧЕСКИЕ ДЕТАЛИ
{'=' * 60}

1. ИНФОРМАЦИЯ О ЦЕЛИ:
   • Адрес: {recon.get('host', 'N/A')}
   • Обнаруженная ОС: {recon.get('os_detection', 'Не определена')}
   • Всего портов просканировано: {len(ports)}
   • Открытых портов: {len(open_ports)}

2. ОБНАРУЖЕННЫЕ СЕРВИСЫ:
{self._format_services_list(services)}

3. СЕТЕВАЯ КОНФИГУРАЦИЯ:
   • Используемые протоколы: {self._get_protocols_summary(ports)}
   • Версии сервисов: {self._get_versions_summary(services)}

4. МЕТОДОЛОГИЯ СКАНИРОВАНИЯ:
   • Использованные инструменты: Nmap, Bitkillers Security Scanner
   • Глубина проверки: Полное сканирование с определением версий
   • Дополнительные проверки: Скрипты эксплуатации, анализ конфигураций

{'=' * 60}
"""

    def _generate_vulnerabilities_section(self, job: ScanJob) -> str:
        vulns = job.results.get('vulnerabilities', [])

        if not vulns:
            return """
ДЕТАЛИЗИРОВАННЫЙ АНАЛИЗ УЯЗВИМОСТЕЙ
===================================

Уязвимости не обнаружены. Система прошла базовые проверки безопасности.
Рекомендуется проведение более глубокого анализа.
"""

        # Группируем уязвимости по уровню риска
        critical_vulns = [v for v in vulns if v.get('risk') == 'CRITICAL']
        high_vulns = [v for v in vulns if v.get('risk') == 'HIGH']
        medium_vulns = [v for v in vulns if v.get('risk') == 'MEDIUM']
        low_vulns = [v for v in vulns if v.get('risk') == 'LOW']

        return f"""
ДЕТАЛИЗИРОВАННЫЙ АНАЛИЗ УЯЗВИМОСТЕЙ
{'=' * 60}

ОБЩАЯ СТАТИСТИКА:
• Всего обнаружено: {len(vulns)} уязвимостей
• Критические: {len(critical_vulns)}
• Высокие: {len(high_vulns)}
• Средние: {len(medium_vulns)} 
• Низкие: {len(low_vulns)}

{self._format_vulnerabilities_by_risk('КРИТИЧЕСКИЕ УЯЗВИМОСТИ', critical_vulns)}
{self._format_vulnerabilities_by_risk('ВЫСОКИЕ УЯЗВИМОСТИ', high_vulns)}
{self._format_vulnerabilities_by_risk('СРЕДНИЕ УЯЗВИМОСТИ', medium_vulns)}
{self._format_vulnerabilities_by_risk('НИЗКИЕ УЯЗВИМОСТИ', low_vulns)}

{'=' * 60}
"""

    def _generate_attack_vectors_section(self, job: ScanJob) -> str:
        vectors = job.results.get('attack_vectors', [])

        if not vectors:
            return """
АНАЛИЗ ВЕКТОРОВ АТАКИ
=====================

На основе обнаруженных уязвимостей не удалось построить подтвержденные векторы атак.
"""

        return f"""
АНАЛИЗ ВЕКТОРОВ АТАКИ
{'=' * 60}

ОБЩАЯ ИНФОРМАЦИЯ:
• Построено векторов атак: {len(vectors)}
• Наиболее опасные сценарии: {len([v for v in vectors if v.get('risk') in ['CRITICAL', 'HIGH']])}

ДЕТАЛИ ВЕКТОРОВ АТАКИ:
{self._format_attack_vectors(vectors)}

ОЦЕНКА ВОЗДЕЙСТВИЯ:
{self._generate_impact_assessment(vectors)}

{'=' * 60}
"""

    def _generate_remediation_guide(self, job: ScanJob) -> str:
        vulns = job.results.get('vulnerabilities', [])
        critical_vulns = [v for v in vulns if v.get('risk') == 'CRITICAL']
        high_vulns = [v for v in vulns if v.get('risk') == 'HIGH']

        return f"""
РУКОВОДСТВО ПО УСТРАНЕНИЮ УЯЗВИМОСТЕЙ
{'=' * 60}

ПРИОРИТЕТЫ ИСПРАВЛЕНИЯ:

1. КРИТИЧЕСКИЕ УЯЗВИМОСТИ (срок устранения: 24-48 часов)
{self._generate_remediation_steps(critical_vulns)}

2. ВЫСОКИЕ УЯЗВИМОСТИ (срок устранения: 3-7 дней)  
{self._generate_remediation_steps(high_vulns)}

3. ОБЩИЕ РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ:

   • ОБНОВЛЕНИЕ СИСТЕМ:
     - Регулярно обновлять операционные системы и ПО
     - Внедрить систему управления исправлениями
     - Тестировать обновления перед установкой в продуктив

   • КОНФИГУРАЦИЯ БЕЗОПАСНОСТИ:
     - Настроить межсетевые экраны и ACL
     - Отключить неиспользуемые сервисы и порты
     - Внедрить принцип минимальных привилегий

   • МОНИТОРИНГ И АУДИТ:
     - Внедрить SIEM систему
     - Настроить оповещения о подозрительной активности
     - Проводить регулярные аудиты безопасности

   • ОБУЧЕНИЕ ПЕРСОНАЛА:
     - Провести тренировки по кибербезопасности
     - Внедрить политику использования паролей
     - Обучить распознаванию фишинговых атак

4. ДОЛГОСРОЧНЫЕ МЕРЫ:
   • Внедрить DevSecOps практики
   • Реализовать программу Bug Bounty
   • Проводить регулярные пентесты

{'=' * 60}
"""

    def _generate_evidence_section(self, job: ScanJob) -> str:
        vulns = job.results.get('vulnerabilities', [])
        recon = job.results.get('reconnaissance', {})

        return f"""
ДОКАЗАТЕЛЬСТВА И ДЕТАЛИ ОБНАРУЖЕНИЯ
{'=' * 60}

1. МЕТОДЫ ОБНАРУЖЕНИЯ:
   • Сканирование портов и сервисов
   • Анализ версий ПО
   • Проверка на известные уязвимости (CVE)
   • Тестирование конфигураций

2. ДОКАЗАТЕЛЬСТВА ДЛЯ КРИТИЧЕСКИХ УЯЗВИМОСТЕЙ:
{self._generate_evidence_for_vulnerabilities(vulns)}

3. РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ:
   • Открытые порты: {len(recon.get('ports', []))}
   • Обнаруженные сервисы: {len(recon.get('services', []))}
   • Собранная информация: {self._get_collected_info_summary(recon)}

4. ЛОГИ ПРОВЕРОК:
   • Время начала: {job.start_time.strftime('%H:%M:%S')}
   • Использованные скрипты: Nmap vuln scripts, Bitkillers checks
   • Уровень детализации: Высокий

{'=' * 60}
"""

    def _generate_methodology_section(self, job: ScanJob) -> str:
        return """
МЕТОДОЛОГИЯ ПРОВЕДЕНИЯ ОЦЕНКИ
==============================

1. ЭТАПЫ ПРОВЕДЕНИЯ ТЕСТИРОВАНИЯ:

   ЭТАП 1: РАЗВЕДКА (Reconnaissance)
   • Сбор информации о цели
   • Определение активных хостов и сервисов
   • Анализ сетевой топологии

   ЭТАП 2: СКАНИРОВАНИЕ (Scanning) 
   • Детальное сканирование портов
   • Определение версий ПО и ОС
   • Выявление потенциальных точек входа

   ЭТАП 3: АНАЛИЗ УЯЗВИМОСТЕЙ (Vulnerability Analysis)
   • Проверка на известные уязвимости CVE
   • Анализ конфигураций безопасности
   • Оценка рисков и воздействия

   ЭТАП 4: ПОСТРОЕНИЕ ОТЧЕТА (Reporting)
   • Документирование находок
   • Подготовка рекомендаций
   • Формирование доказательной базы

2. ИСПОЛЬЗУЕМЫЕ СТАНДАРТЫ:
   • OWASP Testing Guide
   • NIST SP 800-115
   • PTES (Penetration Testing Execution Standard)

3. ИНСТРУМЕНТЫ:
   • Nmap - сканирование сети и портов
   • Bitkillers Platform - автоматизированный анализ
   • CVE Databases - базы известных уязвимостей
"""

    def _generate_metadata(self, job: ScanJob) -> dict:
        return {
            'report_id': f"BITKILLERS-{job.job_id}",
            'generated_at': datetime.now().isoformat(),
            'scan_duration': self._calculate_scan_duration(job),
            'target': job.target,
            'scan_mode': job.mode.value,
            'total_vulnerabilities': len(job.results.get('vulnerabilities', [])),
            'risk_level': self._calculate_overall_risk(job.results.get('vulnerabilities', []))
        }

    # Вспомогательные методы
    def _format_vulnerabilities_by_risk(self, title: str, vulnerabilities: List[Dict]) -> str:
        if not vulnerabilities:
            return ""

        result = f"\n{title}:\n"
        for i, vuln in enumerate(vulnerabilities, 1):
            result += f"""
{i}. {vuln['name']} ({vuln['id']})
   • Уровень риска: {vuln['risk']} (CVSS: {vuln.get('cvss', 'N/A')})
   • Описание: {vuln['description']}
   • Сервис/Порт: {vuln['service']} / {vuln['port']}
   • Доказательства: {self._get_evidence_for_vuln(vuln)}
   • Рекомендации по устранению: {self._get_remediation_for_vuln(vuln['id'])}
   • Ссылки: {self._get_references_for_vuln(vuln['id'])}
"""
        return result

    def _generate_remediation_steps(self, vulnerabilities: List[Dict]) -> str:
        if not vulnerabilities:
            return "   Уязвимости данной категории не обнаружены.\n"

        result = ""
        for vuln in vulnerabilities:
            result += f"""
   • {vuln['name']}:
     - Мера: {self._get_remediation_for_vuln(vuln['id'])}
     - Приоритет: Высокий
     - Оценка усилий: {self._get_effort_estimate(vuln['risk'])}
     - Проверка: {self._get_verification_steps(vuln['id'])}
"""
        return result

    def _get_remediation_for_vuln(self, vuln_id: str) -> str:
        remediation_guide = {
            'CVE-2021-44228': 'Обновить Log4j до версии 2.17.0 или выше. Отключить JNDI lookups в конфигурации.',
            'CVE-2021-4034': 'Обновить polkit до версии 0.120 или выше. Проверить права доступа к исполняемым файлам.',
            'CVE-2017-0144': 'Установить патч MS17-010. Отключить SMBv1 протокол. Настроить фильтрацию трафика на порту 445.',
            'CVE-2019-0708': 'Установить майские обновления безопасности 2019 года для Windows. Отключить RDP если не используется.',
            'CVE-2021-34527': 'Отключить службу диспетчера печати или установить последние обновления. Ограничить права доступа.',
            'CVE-2022-22965': 'Обновить Spring Framework до версии 5.3.18+ или 5.2.20+. Проверить конфигурацию DataBinder.',
            'CVE-2021-41773': 'Обновить Apache HTTP Server до версии 2.4.50 или выше. Проверить настройки Directory directives.'
        }
        return remediation_guide.get(vuln_id,
                                     'Обновить программное обеспечение до последней версии и проверить конфигурацию безопасности.')

    def _get_evidence_for_vuln(self, vuln: Dict) -> str:
        evidence = {
            'CVE-2021-44228': 'Обнаружена уязвимая версия Log4j через анализ заголовков HTTP и версий ПО',
            'CVE-2021-4034': 'Выявлена уязвимая версия polkit через анализ установленных пакетов',
            'CVE-2017-0144': 'Обнаружен открытый порт 445 с поддержкой SMBv1',
            'CVE-2019-0708': 'Найден открытый RDP порт с уязвимой версией службы',
            'NMAP': 'Обнаружено Nmap script с признаками уязвимости'
        }

        if vuln['id'].startswith('CVE-'):
            return evidence.get(vuln['id'], 'Обнаружено через сканирование уязвимостей и анализ версий ПО')
        return 'Обнаружено через активное сканирование и проверку конфигураций'

    def _get_references_for_vuln(self, vuln_id: str) -> str:
        references = {
            'CVE-2021-44228': 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
            'CVE-2021-4034': 'https://nvd.nist.gov/vuln/detail/CVE-2021-4034',
            'CVE-2017-0144': 'https://nvd.nist.gov/vuln/detail/CVE-2017-0144',
            'CVE-2019-0708': 'https://nvd.nist.gov/vuln/detail/CVE-2019-0708'
        }
        return references.get(vuln_id, 'https://nvd.nist.gov/vuln/detail/' + vuln_id)

    def _get_effort_estimate(self, risk: str) -> str:
        estimates = {
            'CRITICAL': 'Низкие (автоматическое обновление)',
            'HIGH': 'Низкие-Средние',
            'MEDIUM': 'Средние',
            'LOW': 'Высокие (требует тестирования)'
        }
        return estimates.get(risk, 'Средние')

    def _get_verification_steps(self, vuln_id: str) -> str:
        return "Повторное сканирование для проверки устранения уязвимости"

    def _format_services_list(self, services: List[Dict]) -> str:
        if not services:
            return "   Сервисы не обнаружены"

        result = ""
        for service in services[:10]:  # Показываем первые 10
            result += f"   • {service['name']} (порт {service['port']}) - {service.get('version', 'версия не определена')}\n"

        if len(services) > 10:
            result += f"   • ... и еще {len(services) - 10} сервисов\n"

        return result

    def _format_attack_vectors(self, vectors: List[Dict]) -> str:
        result = ""
        for i, vector in enumerate(vectors, 1):
            result += f"""
{i}. {vector['name']} (Риск: {vector['risk']})
   • Описание: {vector['description']}
   • Цепочка атаки:
{self._format_attack_steps(vector['steps'])}
   • Используемые уязвимости: {', '.join([v['name'] for v in vector.get('vulnerabilities', [])])}
"""
        return result

    def _format_attack_steps(self, steps: List[str]) -> str:
        return "\n".join([f"     {i + 1}. {step}" for i, step in enumerate(steps)])

    def _generate_impact_assessment(self, vectors: List[Dict]) -> str:
        critical_vectors = [v for v in vectors if v.get('risk') == 'CRITICAL']

        if critical_vectors:
            return "• КРИТИЧЕСКОЕ ВОЗДЕЙСТВИЕ: Возможна полная компрометация системы\n• ВРЕМЕННЫЕ РАМКИ: Мгновенная эксплуатация возможна"
        else:
            return "• УМЕРЕННОЕ ВОЗДЕЙСТВИЕ: Ограниченный доступ к системе\n• ВРЕМЕННЫЕ РАМКИ: Требуется подготовка и дополнительные действия"

    def _generate_evidence_for_vulnerabilities(self, vulns: List[Dict]) -> str:
        critical_vulns = [v for v in vulns if v.get('risk') == 'CRITICAL']

        if not critical_vulns:
            return "   Критические уязвимости не обнаружены."

        result = ""
        for vuln in critical_vulns:
            result += f"""
   • {vuln['name']}:
     - Метод обнаружения: {self._get_detection_method(vuln['id'])}
     - Уровень достоверности: Высокий
     - Подтверждающие данные: {self._get_supporting_evidence(vuln)}
"""
        return result

    def _get_detection_method(self, vuln_id: str) -> str:
        methods = {
            'CVE-2021-44228': 'Анализ версий Log4j через HTTP заголовки',
            'CVE-2021-4034': 'Проверка версий системных пакетов',
            'CVE-2017-0144': 'Сканирование SMB служб',
            'NMAP': 'Nmap vulnerability scripts'
        }
        return methods.get(vuln_id, 'Автоматизированное сканирование уязвимостей')

    def _get_supporting_evidence(self, vuln: Dict) -> str:
        return f"Обнаружена уязвимая версия в сервисе {vuln['service']} на порту {vuln['port']}"

    def _get_scan_mode_name(self, mode) -> str:
        names = {
            'black_box': 'Чёрный ящик',
            'gray_box': 'Серый ящик',
            'white_box': 'Белый ящик'
        }
        return names.get(mode.value, mode.value)

    def _calculate_scan_duration(self, job: ScanJob) -> str:
        duration = datetime.now() - job.start_time
        minutes = int(duration.total_seconds() / 60)
        seconds = int(duration.total_seconds() % 60)
        return f"{minutes} мин {seconds} сек"

    def _calculate_overall_risk(self, vulns: List[Dict]) -> str:
        risks = [v.get('risk') for v in vulns]
        if 'CRITICAL' in risks:
            return 'CRITICAL'
        elif 'HIGH' in risks:
            return 'HIGH'
        elif 'MEDIUM' in risks:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_risk_analysis(self, vulns: List[Dict]) -> str:
        critical_count = len([v for v in vulns if v.get('risk') == 'CRITICAL'])

        if critical_count > 0:
            return "   • Обнаружены критические уязвимости, требующие немедленного вмешательства\n   • Высокий риск компрометации системы и данных\n   • Рекомендуется экстренное применение исправлений"
        else:
            return "   • Уровень риска приемлемый для текущей эксплуатации\n   • Рекомендуется плановое устранение обнаруженных уязвимостей"

    def _get_protocols_summary(self, ports: List[Dict]) -> str:
        protocols = set()
        for port in ports:
            if port.get('protocol'):
                protocols.add(port['protocol'])
        return ', '.join(protocols) if protocols else 'Не определены'

    def _get_versions_summary(self, services: List[Dict]) -> str:
        versions = [s.get('version') for s in services if s.get('version')]
        unique_versions = set(versions)
        return f"{len(unique_versions)} уникальных версий" if unique_versions else 'Версии не определены'

    def _get_collected_info_summary(self, recon: Dict) -> str:
        info_types = []
        if recon.get('ports'):
            info_types.append('порты')
        if recon.get('services'):
            info_types.append('сервисы')
        if recon.get('os_detection'):
            info_types.append('ОС')
        return ', '.join(info_types) if info_types else 'минимальная'

    def generate_file_report(self, job: ScanJob) -> Tuple[str, str]:
        """Генерация полного отчета в файл"""
        report = self.generate_comprehensive_report(job)

        # Формируем полный отчет
        full_report = f"""
BITKILLERS - ПРОФЕССИОНАЛЬНЫЙ ОТЧЕТ ПО БЕЗОПАСНОСТИ
{'=' * 80}

{report['executive_summary']}

{report['technical_details']}

{report['vulnerabilities']}

{report['attack_vectors']}

{report['remediation_guide']}

{report['evidence']}

{report['methodology']}

МЕТАДАННЫЕ ОТЧЕТА:
• ID отчета: {report['metadata']['report_id']}
• Время генерации: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
• Длительность сканирования: {report['metadata']['scan_duration']}
• Уровень риска: {report['metadata']['risk_level']}

{'=' * 80}
Отчет сгенерирован автоматизированной системой Bitkillers Pentest Platform
Контактная информация: security@bitkillers.com
        """

        filename = f"bitkillers_report_{job.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(os.getcwd(), filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(full_report)

        return filename, filepath