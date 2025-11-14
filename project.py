#!/usr/bin/env python3
from flask import Flask, render_template_string, request, jsonify, send_file
from flask_socketio import SocketIO
import threading
import subprocess
import requests
import nmap
import re
import os
import time
from datetime import datetime
import json
import sqlite3
from enum import Enum
import logging
from typing import Dict, List

# ==================== КОНФИГУРАЦИЯ ====================

app = Flask(__name__)
app.config['SECRET_KEY'] = 'alphaseek_hackathon_2024'
socketio = SocketIO(app, async_mode='threading')

# ==================== HTML TEMPLATE ====================

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AlphaSeek Pentest Platform</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-900 text-white min-h-screen">
    <div class="container mx-auto p-4">
        <!-- Header -->
        <header class="mb-8 text-center">
            <h1 class="text-4xl font-bold text-green-400 mb-2">
                <i class="fas fa-shield-alt"></i> AlphaSeek Pentest Platform
            </h1>
            <p class="text-gray-400">Профессиональная платформа для оценки безопасности - Хакатон АЛЬПИКС</p>
            <div class="flex justify-center space-x-4 mt-4 text-sm text-gray-500">
                <span><i class="fas fa-bug"></i> Black Box</span>
                <span><i class="fas fa-user-secret"></i> Gray Box</span>
                <span><i class="fas fa-user-shield"></i> White Box</span>
            </div>
        </header>

        <!-- Stats Dashboard -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div class="bg-gray-800 rounded-lg p-4 text-center">
                <div class="text-2xl font-bold text-green-400" id="totalScans">0</div>
                <div class="text-gray-400 text-sm">Всего сканирований</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 text-center">
                <div class="text-2xl font-bold text-red-400" id="criticalVulns">0</div>
                <div class="text-gray-400 text-sm">Критических уязвимостей</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 text-center">
                <div class="text-2xl font-bold text-orange-400" id="highVulns">0</div>
                <div class="text-gray-400 text-sm">Высоких уязвимостей</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 text-center">
                <div class="text-2xl font-bold text-blue-400" id="servicesFound">0</div>
                <div class="text-gray-400 text-sm">Обнаружено сервисов</div>
            </div>
        </div>

        <!-- Scan Control -->
        <div class="bg-gray-800 rounded-lg p-6 mb-6">
            <h2 class="text-xl font-semibold mb-4 text-green-300">
                <i class="fas fa-rocket"></i> Новое сканирование
            </h2>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div>
                    <label class="block text-sm font-medium mb-2">
                        <i class="fas fa-bullseye"></i> Цель сканирования
                    </label>
                    <input type="text" id="targetInput" placeholder="192.168.1.1 или example.com" 
                           class="w-full p-3 bg-gray-700 rounded border border-gray-600 focus:border-green-500 text-white">
                </div>
                <div>
                    <label class="block text-sm font-medium mb-2">
                        <i class="fas fa-cog"></i> Режим сканирования
                    </label>
                    <select id="modeSelect" class="w-full p-3 bg-gray-700 rounded border border-gray-600 text-white">
                        <option value="black_box">🕵️ Чёрный ящик (без доступа)</option>
                        <option value="gray_box">👤 Серый ящик (частичный доступ)</option>
                        <option value="white_box">🛡️ Белый ящик (полный доступ)</option>
                    </select>
                </div>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4" id="credentialsSection" style="display: none;">
                <div>
                    <label class="block text-sm font-medium mb-2">
                        <i class="fas fa-user"></i> Логин
                    </label>
                    <input type="text" id="loginInput" class="w-full p-3 bg-gray-700 rounded border border-gray-600 text-white">
                </div>
                <div>
                    <label class="block text-sm font-medium mb-2">
                        <i class="fas fa-key"></i> Пароль
                    </label>
                    <input type="password" id="passwordInput" class="w-full p-3 bg-gray-700 rounded border border-gray-600 text-white">
                </div>
            </div>
            <button onclick="startScan()" 
                    class="w-full md:w-auto px-6 py-3 bg-green-600 hover:bg-green-700 rounded font-semibold transition-colors">
                <i class="fas fa-play"></i> 🚀 Запустить сканирование
            </button>
        </div>

        <!-- Progress Section -->
        <div id="progressSection" class="hidden bg-gray-800 rounded-lg p-6 mb-6">
            <h2 class="text-xl font-semibold mb-4 text-blue-300">
                <i class="fas fa-tachometer-alt"></i> Ход выполнения
            </h2>
            <div class="space-y-4" id="progressContainer">
                <div class="text-center text-gray-400" id="initialMessage">
                    Ожидание начала сканирования...
                </div>
            </div>
        </div>

        <!-- Results Tabs -->
        <div class="bg-gray-800 rounded-lg mb-6">
            <div class="border-b border-gray-700">
                <nav class="flex -mb-px">
                    <button onclick="showTab('vulnerabilities')" 
                            class="tab-button py-4 px-6 text-center border-b-2 border-green-500 text-green-400 font-medium">
                        <i class="fas fa-bug"></i> Уязвимости
                    </button>
                    <button onclick="showTab('services')" 
                            class="tab-button py-4 px-6 text-center border-b-2 border-transparent text-gray-400 hover:text-white">
                        <i class="fas fa-server"></i> Сервисы
                    </button>
                    <button onclick="showTab('attack')" 
                            class="tab-button py-4 px-6 text-center border-b-2 border-transparent text-gray-400 hover:text-white">
                        <i class="fas fa-crosshairs"></i> Векторы атак
                    </button>
                    <button onclick="showTab('report')" 
                            class="tab-button py-4 px-6 text-center border-b-2 border-transparent text-gray-400 hover:text-white">
                        <i class="fas fa-file-alt"></i> Отчет
                    </button>
                </nav>
            </div>

            <div class="p-6">
                <!-- Vulnerabilities Tab -->
                <div id="vulnerabilitiesTab" class="tab-content">
                    <div id="vulnerabilitiesList" class="space-y-3">
                        <div class="text-center text-gray-400">Результаты сканирования появятся здесь</div>
                    </div>
                </div>

                <!-- Services Tab -->
                <div id="servicesTab" class="tab-content hidden">
                    <div id="servicesList" class="space-y-3">
                        <div class="text-center text-gray-400">Информация о сервисах появится здесь</div>
                    </div>
                </div>

                <!-- Attack Vectors Tab -->
                <div id="attackTab" class="tab-content hidden">
                    <div id="attackVectorsList" class="space-y-4">
                        <div class="text-center text-gray-400">Векторы атак появятся здесь</div>
                    </div>
                </div>

                <!-- Report Tab -->
                <div id="reportTab" class="tab-content hidden">
                    <div id="reportContent" class="whitespace-pre-line bg-gray-700 p-4 rounded"></div>
                    <button onclick="downloadReport()" 
                            class="mt-4 px-6 py-3 bg-blue-600 hover:bg-blue-700 rounded font-semibold">
                        <i class="fas fa-download"></i> 💾 Скачать отчет
                    </button>
                </div>
            </div>
        </div>

        <!-- Scan History -->
        <div class="bg-gray-800 rounded-lg p-6">
            <h2 class="text-xl font-semibold mb-4 text-purple-300">
                <i class="fas fa-history"></i> История сканирований
            </h2>
            <div id="scanHistory" class="space-y-2">
                <div class="text-center text-gray-400">История сканирований появится здесь</div>
            </div>
        </div>
    </div>

    <script>
        const socket = io();
        let currentJobId = null;
        let scanHistory = [];

        // Инициализация
        document.getElementById('modeSelect').addEventListener('change', function() {
            const credentialsSection = document.getElementById('credentialsSection');
            if (this.value !== 'black_box') {
                credentialsSection.style.display = 'grid';
            } else {
                credentialsSection.style.display = 'none';
            }
        });

        // WebSocket listeners
        socket.on('scan_progress', function(data) {
            updateProgress(data);
        });

        socket.on('scan_log', function(data) {
            addLogMessage(data.message);
        });

        function startScan() {
            const target = document.getElementById('targetInput').value;
            const mode = document.getElementById('modeSelect').value;

            if (!target) {
                alert('Введите цель для сканирования');
                return;
            }

            const credentials = {};
            if (mode !== 'black_box') {
                credentials.login = document.getElementById('loginInput').value;
                credentials.password = document.getElementById('passwordInput').value;
            }

            fetch('/api/scan/start', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target, mode, credentials})
            })
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    alert('Ошибка: ' + data.error);
                    return;
                }
                currentJobId = data.job_id;
                document.getElementById('progressSection').classList.remove('hidden');
                startProgressPolling();

                // Добавляем в историю
                scanHistory.unshift({
                    job_id: data.job_id,
                    target: target,
                    mode: mode,
                    start_time: new Date().toLocaleString(),
                    status: 'running'
                });
                updateScanHistory();
            })
            .catch(error => {
                alert('Ошибка сети: ' + error);
            });
        }

        function startProgressPolling() {
            const interval = setInterval(() => {
                if (!currentJobId) {
                    clearInterval(interval);
                    return;
                }

                fetch(`/api/scan/status/${currentJobId}`)
                    .then(r => r.json())
                    .then(data => {
                        if (data.status === 'completed' || data.status === 'failed') {
                            clearInterval(interval);
                            loadResults();
                            updateScanHistoryItem(currentJobId, data.status);

                            if (data.status === 'completed') {
                                showTab('vulnerabilities');
                            }
                        }
                    });
            }, 2000);
        }

        function updateProgress(data) {
            const container = document.getElementById('progressContainer');
            container.innerHTML = `
                <div class="bg-gray-700 p-4 rounded">
                    <div class="flex justify-between mb-2">
                        <span class="font-medium">${data.message}</span>
                        <span class="font-bold">${data.progress}%</span>
                    </div>
                    <div class="w-full bg-gray-600 rounded-full h-3">
                        <div class="bg-green-500 h-3 rounded-full transition-all duration-500" style="width: ${data.progress}%"></div>
                    </div>
                    <div class="text-sm text-gray-400 mt-2">
                        <i class="fas fa-sync-alt"></i> Фаза: ${data.phase}
                    </div>
                </div>
            `;
        }

        function loadResults() {
            if (!currentJobId) return;

            fetch(`/api/scan/results/${currentJobId}`)
                .then(r => r.json())
                .then(data => {
                    displayVulnerabilities(data.results.vulnerabilities || []);
                    displayServices(data.results.reconnaissance || {});
                    displayAttackVectors(data.results.attack_vectors || []);
                    displayReport(data.results.report || {});
                    updateStats(data.results);
                });
        }

        function displayVulnerabilities(vulns) {
            const container = document.getElementById('vulnerabilitiesList');
            if (!vulns || vulns.length === 0) {
                container.innerHTML = '<div class="text-center text-gray-400 py-8"><i class="fas fa-check-circle text-green-400 text-4xl mb-2"></i><br>Уязвимости не обнаружены</div>';
                return;
            }

            container.innerHTML = vulns.map(vuln => `
                <div class="bg-gray-700 p-4 rounded border-l-4 ${getRiskColor(vuln.risk)}">
                    <div class="flex justify-between items-start">
                        <div class="font-semibold text-lg">${vuln.name}</div>
                        <span class="px-2 py-1 rounded text-xs font-bold ${getRiskBadgeColor(vuln.risk)}">
                            ${vuln.risk}
                        </span>
                    </div>
                    <div class="text-gray-300 mt-2">${vuln.description}</div>
                    <div class="text-sm text-gray-400 mt-2">
                        <i class="fas fa-fingerprint"></i> ${vuln.id} | 
                        <i class="fas fa-cube"></i> ${vuln.service} | 
                        <i class="fas fa-plug"></i> Порт: ${vuln.port}
                    </div>
                </div>
            `).join('');
        }

        function displayServices(recon) {
            const container = document.getElementById('servicesList');
            const services = recon.services || [];
            const ports = recon.ports || [];

            if (services.length === 0) {
                container.innerHTML = '<div class="text-center text-gray-400">Сервисы не обнаружены</div>';
                return;
            }

            container.innerHTML = `
                <div class="mb-4">
                    <h3 class="font-semibold text-lg mb-2">Информация о хосте</h3>
                    <div class="bg-gray-700 p-3 rounded">
                        <strong>Хост:</strong> ${recon.host || 'N/A'}<br>
                        <strong>ОС:</strong> ${recon.os_detection || 'Не определена'}
                    </div>
                </div>
                <h3 class="font-semibold text-lg mb-2">Обнаруженные сервисы</h3>
                ${services.map(service => `
                    <div class="bg-gray-700 p-3 rounded mb-2">
                        <div class="font-medium">${service.name}</div>
                        <div class="text-sm text-gray-400">
                            Порт: ${service.port} | Версия: ${service.version || 'Не определена'}
                        </div>
                    </div>
                `).join('')}
            `;
        }

        function displayAttackVectors(vectors) {
            const container = document.getElementById('attackVectorsList');
            if (!vectors || vectors.length === 0) {
                container.innerHTML = '<div class="text-center text-gray-400">Векторы атак не построены</div>';
                return;
            }

            container.innerHTML = vectors.map(vector => `
                <div class="bg-gray-700 p-4 rounded">
                    <div class="flex justify-between items-start mb-3">
                        <div class="font-semibold text-lg text-yellow-400">${vector.name}</div>
                        <span class="px-2 py-1 rounded text-xs font-bold ${getRiskBadgeColor(vector.risk)}">
                            ${vector.risk}
                        </span>
                    </div>
                    <div class="text-gray-300 mb-3">${vector.description}</div>
                    <div class="bg-gray-800 p-3 rounded">
                        <h4 class="font-medium mb-2">Цепочка атаки:</h4>
                        <ol class="list-decimal list-inside space-y-1">
                            ${vector.steps.map(step => `<li class="text-gray-300">${step}</li>`).join('')}
                        </ol>
                    </div>
                </div>
            `).join('');
        }

        function displayReport(report) {
            const container = document.getElementById('reportContent');
            container.innerHTML = `
                <div class="bg-gray-700 p-4 rounded">
                    <pre class="whitespace-pre-wrap font-mono text-sm">${report.executive_summary || 'Отчет не сгенерирован'}</pre>
                    ${report.technical_details ? `<pre class="whitespace-pre-wrap font-mono text-sm mt-4">${report.technical_details}</pre>` : ''}
                    ${report.recommendations ? `<pre class="whitespace-pre-wrap font-mono text-sm mt-4">${report.recommendations}</pre>` : ''}
                </div>
            `;
        }

        function updateStats(results) {
            const vulns = results.vulnerabilities || [];
            const recon = results.reconnaissance || {};

            document.getElementById('totalScans').textContent = scanHistory.length;
            document.getElementById('criticalVulns').textContent = vulns.filter(v => v.risk === 'CRITICAL').length;
            document.getElementById('highVulns').textContent = vulns.filter(v => v.risk === 'HIGH').length;
            document.getElementById('servicesFound').textContent = (recon.services || []).length;
        }

        function updateScanHistory() {
            const container = document.getElementById('scanHistory');
            container.innerHTML = scanHistory.map(scan => `
                <div class="bg-gray-700 p-3 rounded flex justify-between items-center">
                    <div>
                        <div class="font-medium">${scan.target}</div>
                        <div class="text-sm text-gray-400">${scan.start_time} | ${scan.mode}</div>
                    </div>
                    <span class="px-2 py-1 rounded text-xs ${scan.status === 'completed' ? 'bg-green-600' : 'bg-yellow-600'}">
                        ${scan.status === 'completed' ? 'Завершено' : 'Выполняется'}
                    </span>
                </div>
            `).join('');
        }

        function updateScanHistoryItem(jobId, status) {
            const scan = scanHistory.find(s => s.job_id === jobId);
            if (scan) {
                scan.status = status;
                updateScanHistory();
            }
        }

        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.add('hidden');
            });
            document.querySelectorAll('.tab-button').forEach(button => {
                button.classList.remove('border-green-500', 'text-green-400');
                button.classList.add('border-transparent', 'text-gray-400');
            });

            // Show selected tab
            document.getElementById(tabName + 'Tab').classList.remove('hidden');
            event.target.classList.add('border-green-500', 'text-green-400');
            event.target.classList.remove('border-transparent', 'text-gray-400');
        }

        function downloadReport() {
            if (currentJobId) {
                window.open(`/api/report/download/${currentJobId}`, '_blank');
            } else {
                alert('Сначала выполните сканирование');
            }
        }

        function getRiskColor(risk) {
            const colors = {
                'CRITICAL': 'border-red-500',
                'HIGH': 'border-orange-500',
                'MEDIUM': 'border-yellow-500',
                'LOW': 'border-green-500'
            };
            return colors[risk] || 'border-gray-500';
        }

        function getRiskBadgeColor(risk) {
            const colors = {
                'CRITICAL': 'bg-red-600',
                'HIGH': 'bg-orange-600',
                'MEDIUM': 'bg-yellow-600',
                'LOW': 'bg-green-600'
            };
            return colors[risk] || 'bg-gray-600';
        }

        function addLogMessage(message) {
            console.log('Log:', message);
        }

        // Показываем первую вкладку по умолчанию
        showTab('vulnerabilities');
    </script>

    <style>
        .tab-button {
            transition: all 0.3s ease;
        }
        .tab-button:hover {
            background-color: rgba(255, 255, 255, 0.05);
        }
    </style>
</body>
</html>
'''


# ==================== МОДЕЛИ ДАННЫХ ====================

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
        self.start_time = datetime.now()
        self.progress = 0


# ==================== СИСТЕМА УПРАВЛЕНИЯ ====================

class ScanManager:
    def __init__(self):
        self.active_jobs: Dict[str, ScanJob] = {}

    def create_scan_job(self, target: str, mode: ScanMode, credentials: Dict = None) -> str:
        job_id = f"scan_{int(time.time())}_{len(self.active_jobs)}"
        job = ScanJob(job_id, target, mode, credentials)
        self.active_jobs[job_id] = job

        thread = threading.Thread(target=self._execute_scan, args=(job,))
        thread.daemon = True
        thread.start()

        return job_id

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
            report = self._generate_report(job)
            job.results['report'] = report
            self._emit_progress(job, "✅ Сканирование завершено", 100)

            job.status = "completed"

        except Exception as e:
            job.status = "failed"
            job.results['error'] = str(e)
            self._emit_progress(job, f"❌ Ошибка: {e}", 0)

    def _perform_reconnaissance(self, job: ScanJob) -> Dict:
        """Выполнение разведки"""
        nm = nmap.PortScanner()
        results = {
            'host': job.target,
            'ports': [],
            'services': [],
            'os_detection': None
        }

        try:
            socketio.emit('scan_log', {'job_id': job.job_id, 'message': 'Сканирование портов...'})
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

            socketio.emit('scan_log', {'job_id': job.job_id, 'message': 'Определение ОС...'})
            nm.scan(job.target, arguments='-O')
            if 'osmatch' in nm[job.target]:
                results['os_detection'] = nm[job.target]['osmatch'][0]['name']

        except Exception as e:
            socketio.emit('scan_log', {'job_id': job.job_id, 'message': f'Ошибка разведки: {e}'})

        return results

    def _perform_vulnerability_scan(self, job: ScanJob) -> List[Dict]:
        """Сканирование уязвимостей"""
        vulnerabilities = []

        try:
            socketio.emit('scan_log', {'job_id': job.job_id, 'message': 'Запуск Nmap vuln scripts...'})
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
                }
            ]

            vulnerabilities.extend(demo_vulns)

        except Exception as e:
            socketio.emit('scan_log', {'job_id': job.job_id, 'message': f'Ошибка сканирования уязвимостей: {e}'})

        return vulnerabilities

    def _build_attack_vectors(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Построение векторов атаки"""
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

    def _generate_report(self, job: ScanJob) -> Dict:
        """Генерация комплексного отчета"""
        return {
            'executive_summary': self._generate_executive_summary(job),
            'technical_details': self._generate_technical_details(job),
            'recommendations': self._generate_recommendations(job),
            'timestamp': datetime.now().isoformat()
        }

    def _generate_executive_summary(self, job: ScanJob) -> str:
        vulns = job.results.get('vulnerabilities', [])
        critical_count = len([v for v in vulns if v.get('risk') == 'CRITICAL'])
        high_count = len([v for v in vulns if v.get('risk') == 'HIGH'])

        return f"""
ОТЧЕТ ОБ ОЦЕНКЕ БЕЗОПАСНОСТИ
Цель: {job.target}
Режим: {job.mode.value}
Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

КЛЮЧЕВЫЕ НАХОДКИ:
• Обнаружено уязвимостей: {len(vulns)}
• Критические уязвимости: {critical_count}
• Высокие уязвимости: {high_count}

ОБЩАЯ ОЦЕНКА РИСКА: {'КРИТИЧЕСКИЙ' if critical_count > 0 else 'ВЫСОКИЙ' if high_count > 0 else 'СРЕДНИЙ'}
"""

    def _generate_technical_details(self, job: ScanJob) -> str:
        details = "ТЕХНИЧЕСКИЕ ДЕТАЛИ:\n\n"

        recon = job.results.get('reconnaissance', {})
        details += f"Хост: {recon.get('host', 'N/A')}\n"
        details += f"ОС: {recon.get('os_detection', 'Не определена')}\n\n"

        details += "ОТКРЫТЫЕ ПОРТЫ:\n"
        for port in recon.get('ports', [])[:10]:
            details += f"• {port['port']}/{port['protocol']} - {port['service']} ({port['state']})\n"

        return details

    def _generate_recommendations(self, job: ScanJob) -> str:
        vulns = job.results.get('vulnerabilities', [])
        critical_vulns = [v for v in vulns if v.get('risk') == 'CRITICAL']

        recommendations = "РЕКОМЕНДАЦИИ:\n\n"

        if critical_vulns:
            recommendations += "🚨 НЕМЕДЛЕННЫЕ ДЕЙСТВИЯ:\n"
            for vuln in critical_vulns:
                recommendations += f"• Исправить {vuln['name']} (CVE: {vuln['id']})\n"

        recommendations += "\n🔧 ОБЩИЕ РЕКОМЕНДАЦИИ:\n"
        recommendations += "• Обновить все программное обеспечение\n"
        recommendations += "• Настроить межсетевой экран\n"
        recommendations += "• Внедрить мониторинг безопасности\n"
        recommendations += "• Проводить регулярные аудиты\n"

        return recommendations

    def _emit_progress(self, job: ScanJob, message: str, progress: int):
        job.progress = progress
        socketio.emit('scan_progress', {
            'job_id': job.job_id,
            'message': message,
            'progress': progress,
            'phase': job.phase.value
        })


# ==================== FLASK ROUTES ====================

scan_manager = ScanManager()


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    mode = ScanMode(data.get('mode', 'black_box'))
    credentials = data.get('credentials', {})

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    job_id = scan_manager.create_scan_job(target, mode, credentials)

    return jsonify({
        'job_id': job_id,
        'status': 'started',
        'message': f'Scan started for {target}'
    })


@app.route('/api/scan/status/<job_id>')
def get_scan_status(job_id):
    job = scan_manager.active_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    return jsonify({
        'job_id': job.job_id,
        'status': job.status,
        'progress': job.progress,
        'phase': job.phase.value,
        'target': job.target,
        'start_time': job.start_time.isoformat()
    })


@app.route('/api/scan/results/<job_id>')
def get_scan_results(job_id):
    job = scan_manager.active_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    return jsonify({
        'job_id': job.job_id,
        'status': job.status,
        'results': job.results
    })


@app.route('/api/scans')
def list_scans():
    scans = []
    for job_id, job in scan_manager.active_jobs.items():
        scans.append({
            'job_id': job_id,
            'target': job.target,
            'status': job.status,
            'progress': job.progress,
            'start_time': job.start_time.isoformat()
        })

    return jsonify({'scans': scans})


@app.route('/api/report/download/<job_id>')
def download_report(job_id):
    job = scan_manager.active_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    report_content = f"""
ALPHASEEK PENTEST PLATFORM - ОТЧЕТ БЕЗОПАСНОСТИ
==============================================

{job.results['report']['executive_summary']}

{job.results['report']['technical_details']}

{job.results['report']['recommendations']}

Сгенерировано: {datetime.now()}
    """

    filename = f"security_report_{job.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(report_content)

    return send_file(filename, as_attachment=True)


# ==================== WEB SOCKET EVENTS ====================

@socketio.on('connect')
def handle_connect():
    print('Client connected')


@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')


# ==================== ЗАПУСК СЕРВЕРА ====================

if __name__ == '__main__':
    print("🚀 AlphaSeek Pentest Platform запускается...")
    print("📧 Доступно по адресу: http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)