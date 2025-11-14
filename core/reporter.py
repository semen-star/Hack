from datetime import datetime
import os
from typing import Tuple
from .scanner import ScanJob


class ReportGenerator:
    def generate_comprehensive_report(self, job: ScanJob) -> dict:
        return {
            'executive_summary': self._generate_executive_summary(job),
            'technical_details': self._generate_technical_details(job),
            'recommendations': self._generate_recommendations(job),
            'risk_assessment': self._generate_risk_assessment(job),
            'timestamp': datetime.now().isoformat()
        }

    def _generate_executive_summary(self, job: ScanJob) -> str:
        vulns = job.results.get('vulnerabilities', [])
        critical_count = len([v for v in vulns if v.get('risk') == 'CRITICAL'])
        high_count = len([v for v in vulns if v.get('risk') == 'HIGH'])

        return f"""
BITKILLERS - ОТЧЕТ ОБ ОЦЕНКЕ БЕЗОПАСНОСТИ
=========================================

ЦЕЛЬ: {job.target}
РЕЖИМ: {job.mode.value.upper()}
ДАТА: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}

КЛЮЧЕВЫЕ НАХОДКИ:
• Обнаружено уязвимостей: {len(vulns)}
• Критические уязвимости: {critical_count}
• Высокие уязвимости: {high_count}

ОБЩАЯ ОЦЕНКА РИСКА: {'КРИТИЧЕСКИЙ' if critical_count > 0 else 'ВЫСОКИЙ' if high_count > 0 else 'СРЕДНИЙ'}

СИСТЕМА BITKILLERS РЕКОМЕНДУЕТ НЕМЕДЛЕННОЕ ВНИМАНИЕ К ОБНАРУЖЕННЫМ УГРОЗАМ.
"""

    def _generate_technical_details(self, job: ScanJob) -> str:
        recon = job.results.get('reconnaissance', {})
        vulns = job.results.get('vulnerabilities', [])

        details = "ТЕХНИЧЕСКИЕ ДЕТАЛИ\n"
        details += "=================\n\n"

        details += f"ИНФОРМАЦИЯ О ХОСТЕ:\n"
        details += f"• Адрес: {recon.get('host', 'N/A')}\n"
        details += f"• Обнаруженная ОС: {recon.get('os_detection', 'Не определена')}\n"
        details += f"• Открытых портов: {len(recon.get('ports', []))}\n\n"

        details += "ОБНАРУЖЕННЫЕ СЕРВИСЫ:\n"
        for service in recon.get('services', [])[:10]:
            details += f"• {service['name']} (порт {service['port']}) - {service.get('version', 'версия не определена')}\n"

        details += f"\nОБНАРУЖЕННЫЕ УЯЗВИМОСТИ: {len(vulns)}\n"
        for vuln in vulns[:5]:  # Показываем первые 5
            details += f"• {vuln['name']} ({vuln['id']}) - Риск: {vuln['risk']}\n"

        return details

    def _generate_recommendations(self, job: ScanJob) -> str:
        vulns = job.results.get('vulnerabilities', [])
        critical_vulns = [v for v in vulns if v.get('risk') == 'CRITICAL']
        high_vulns = [v for v in vulns if v.get('risk') == 'HIGH']

        recommendations = "РЕКОМЕНДАЦИИ ПО УСТРАНЕНИЮ\n"
        recommendations += "=========================\n\n"

        if critical_vulns:
            recommendations += "🚨 КРИТИЧЕСКИЕ УЯЗВИМОСТИ (устранить в течение 24 часов):\n"
            for vuln in critical_vulns:
                recommendations += f"• {vuln['name']} - {vuln['description']}\n"
                recommendations += f"  Действие: {self._get_remediation_steps(vuln['id'])}\n\n"

        if high_vulns:
            recommendations += "🟡 ВЫСОКИЕ УЯЗВИМОСТИ (устранить в течение 7 дней):\n"
            for vuln in high_vulns:
                recommendations += f"• {vuln['name']} - {vuln['description']}\n\n"

        recommendations += "🔧 ОБЩИЕ РЕКОМЕНДАЦИИ:\n"
        recommendations += "• Регулярно обновлять программное обеспечение и операционную систему\n"
        recommendations += "• Настроить и поддерживать межсетевой экран\n"
        recommendations += "• Внедрить систему обнаружения и предотвращения вторжений\n"
        recommendations += "• Регулярно проводить аудиты безопасности\n"
        recommendations += "• Обучить персонал основам кибербезопасности\n"

        return recommendations

    def _generate_risk_assessment(self, job: ScanJob) -> str:
        vulns = job.results.get('vulnerabilities', [])
        critical_count = len([v for v in vulns if v.get('risk') == 'CRITICAL'])
        high_count = len([v for v in vulns if v.get('risk') == 'HIGH'])

        risk_level = 'КРИТИЧЕСКИЙ' if critical_count > 0 else 'ВЫСОКИЙ' if high_count > 0 else 'СРЕДНИЙ'

        return f"""
ОЦЕНКА РИСКА
============

УРОВЕНЬ РИСКА: {risk_level}

ОБОСНОВАНИЕ:
• Критические уязвимости: {critical_count}
• Высокие уязвимости: {high_count}
• Всего обнаружено угроз: {len(vulns)}

ВЛИЯНИЕ НА БИЗНЕС:
• {'ВЫСОКИЙ риск финансовых потерь' if risk_level in ['КРИТИЧЕСКИЙ', 'ВЫСОКИЙ'] else 'УМЕРЕННЫЙ риск'}
• {'ВЕРОЯТНА компрометация данных' if risk_level in ['КРИТИЧЕСКИЙ', 'ВЫСОКИЙ'] else 'ОГРАНИЧЕННАЯ угроза данным'}
• {'ТРЕБУЕТСЯ НЕМЕДЛЕННОЕ ВМЕШАТЕЛЬСТВО' if risk_level == 'КРИТИЧЕСКИЙ' else 'РЕКОМЕНДУЕТСЯ ПЛАНОВОЕ ИСПРАВЛЕНИЕ'}
"""

    def _get_remediation_steps(self, vuln_id: str) -> str:
        steps = {
            'CVE-2021-44228': 'Обновить Log4j до версии 2.17.0 или выше',
            'CVE-2021-4034': 'Обновить polkit до версии 0.120 или выше',
            'CVE-2017-0144': 'Установить патч MS17-010, отключить SMBv1',
            'CVE-2019-0708': 'Установить майские обновления безопасности 2019 года',
            'CVE-2021-34527': 'Отключить службу печати или установить последние обновления'
        }
        return steps.get(vuln_id, 'Обновить программное обеспечение до последней версии')

    def generate_file_report(self, job: ScanJob) -> Tuple[str, str]:
        report = self.generate_comprehensive_report(job)

        report_content = f"""
{report['executive_summary']}

{report['technical_details']}

{report['risk_assessment']}

{report['recommendations']}

---
Отчет сгенерирован системой BITKILLERS
Время генерации: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
        """

        filename = f"bitkillers_report_{job.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(os.getcwd(), filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_content)

        return filename, filepath