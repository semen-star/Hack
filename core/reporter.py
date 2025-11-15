from datetime import datetime
import os
from typing import Tuple
from .scanner import ScanJob
from .remediation import RemediationAdvisor

class ReportGenerator:
    def generate_comprehensive_report(self, job: ScanJob) -> dict:
        remediation_advisor = RemediationAdvisor()
        vulnerabilities = job.results.get('vulnerabilities', [])
        
        return {
            'executive_summary': self._generate_executive_summary(job),
            'technical_details': self._generate_technical_details(job),
            'remediation_guide': remediation_advisor.generate_remediation_report(vulnerabilities),
            'recommendations': self._generate_recommendations(job),
            'risk_assessment': self._generate_risk_assessment(job),
            'timestamp': datetime.now().isoformat()
        }
    
    def _generate_executive_summary(self, job: ScanJob) -> str:
        vulns = job.results.get('vulnerabilities', [])
        critical_count = len([v for v in vulns if v.get('risk') == 'CRITICAL'])
        high_count = len([v for v in vulns if v.get('risk') == 'HIGH'])
        
        return f"""
BITKILLERS - SECURITY ASSESSMENT REPORT
========================================

TARGET: {job.target}
MODE: {job.mode.value.upper()}
DATE: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}

KEY FINDINGS:
• Vulnerabilities Found: {len(vulns)}
• Critical Vulnerabilities: {critical_count}
• High Vulnerabilities: {high_count}

OVERALL RISK ASSESSMENT: {'CRITICAL' if critical_count > 0 else 'HIGH' if high_count > 0 else 'MEDIUM'}

BITKILLERS SYSTEM RECOMMENDS IMMEDIATE ATTENTION TO THE DETECTED THREATS.
"""
    
    def _generate_technical_details(self, job: ScanJob) -> str:
        recon = job.results.get('reconnaissance', {})
        vulns = job.results.get('vulnerabilities', [])
        
        details = "TECHNICAL DETAILS\n"
        details += "=================\n\n"
        
        details += f"HOST INFORMATION:\n"
        details += f"• Address: {recon.get('host', 'N/A')}\n"
        details += f"• Detected OS: {recon.get('os_detection', 'Not detected')}\n"
        details += f"• Open Ports: {len(recon.get('ports', []))}\n\n"
        
        details += "DETECTED SERVICES:\n"
        for service in recon.get('services', [])[:10]:
            details += f"• {service['name']} (port {service['port']}) - {service.get('version', 'version not detected')}\n"
        
        details += f"\nDETECTED VULNERABILITIES: {len(vulns)}\n"
        for vuln in vulns[:5]:
            details += f"• {vuln['name']} ({vuln['id']}) - Risk: {vuln['risk']}\n"
        
        return details
    
    def _generate_recommendations(self, job: ScanJob) -> str:
        vulns = job.results.get('vulnerabilities', [])
        critical_vulns = [v for v in vulns if v.get('risk') == 'CRITICAL']
        high_vulns = [v for v in vulns if v.get('risk') == 'HIGH']
        
        recommendations = "REMEDIATION RECOMMENDATIONS\n"
        recommendations += "===========================\n\n"
        
        if critical_vulns:
            recommendations += "🚨 CRITICAL VULNERABILITIES (fix within 24 hours):\n"
            for vuln in critical_vulns:
                recommendations += f"• {vuln['name']} - {vuln['description']}\n"
                recommendations += f"  Action: {self._get_remediation_steps(vuln['id'])}\n\n"
        
        if high_vulns:
            recommendations += "🟡 HIGH VULNERABILITIES (fix within 7 days):\n"
            for vuln in high_vulns:
                recommendations += f"• {vuln['name']} - {vuln['description']}\n\n"
        
        recommendations += "🔧 GENERAL RECOMMENDATIONS:\n"
        recommendations += "• Regularly update software and operating system\n"
        recommendations += "• Configure and maintain firewall\n"
        recommendations += "• Implement intrusion detection and prevention system\n"
        recommendations += "• Conduct regular security audits\n"
        recommendations += "• Train staff on cybersecurity basics\n"
        
        return recommendations
    
    def _generate_risk_assessment(self, job: ScanJob) -> str:
        vulns = job.results.get('vulnerabilities', [])
        critical_count = len([v for v in vulns if v.get('risk') == 'CRITICAL'])
        high_count = len([v for v in vulns if v.get('risk') == 'HIGH'])
        
        risk_level = 'CRITICAL' if critical_count > 0 else 'HIGH' if high_count > 0 else 'MEDIUM'
        
        return f"""
RISK ASSESSMENT
===============

RISK LEVEL: {risk_level}

JUSTIFICATION:
• Critical Vulnerabilities: {critical_count}
• High Vulnerabilities: {high_count}
• Total Threats Detected: {len(vulns)}

BUSINESS IMPACT:
• {'HIGH risk of financial losses' if risk_level in ['CRITICAL', 'HIGH'] else 'MODERATE risk'}
• {'LIKELY data compromise' if risk_level in ['CRITICAL', 'HIGH'] else 'LIMITED data threat'}
• {'IMMEDIATE INTERVENTION REQUIRED' if risk_level == 'CRITICAL' else 'PLANNED REMEDIATION RECOMMENDED'}
"""
    
    def _get_remediation_steps(self, vuln_id: str) -> str:
        steps = {
            'CVE-2021-44228': 'Update Log4j to version 2.17.0 or higher',
            'CVE-2021-4034': 'Update polkit to version 0.120 or higher',
            'CVE-2017-0144': 'Install MS17-010 patch, disable SMBv1',
            'CVE-2019-0708': 'Install May 2019 security updates',
            'CVE-2021-34527': 'Disable print service or install latest updates'
        }
        return steps.get(vuln_id, 'Update software to latest version')
    
    def generate_file_report(self, job: ScanJob) -> Tuple[str, str]:
        report = self.generate_comprehensive_report(job)
        
        report_content = f"""
{report['executive_summary']}

{report['technical_details']}

{report['risk_assessment']}

{report['recommendations']}

---
Report generated by BITKILLERS system
Generation time: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
        """
        
        filename = f"bitkillers_report_{job.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(os.getcwd(), filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return filename, filepath
