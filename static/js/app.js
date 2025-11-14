const socket = io();
let currentJobId = null;
let scanHistory = [];

// Инициализация
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('modeSelect').addEventListener('change', function() {
        const credentialsSection = document.getElementById('credentialsSection');
        if (this.value !== 'black_box') {
            credentialsSection.style.display = 'grid';
        } else {
            credentialsSection.style.display = 'none';
        }
    });

    // Загружаем историю при загрузке
    loadScanHistory();
});

// WebSocket listeners
socket.on('scan_progress', function(data) {
    updateProgress(data);
});

socket.on('scan_log', function(data) {
    addLogMessage(data.message);
});

function startScan() {
    const target = document.getElementById('targetInput').value.trim();
    const mode = document.getElementById('modeSelect').value;

    if (!target) {
        showNotification('Введите цель для сканирования', 'error');
        return;
    }

    const credentials = {};
    if (mode !== 'black_box') {
        credentials.login = document.getElementById('loginInput').value;
        credentials.password = document.getElementById('passwordInput').value;
    }

    showNotification('Запуск сканирования...', 'info');

    fetch('/api/scan/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target, mode, credentials})
    })
    .then(r => r.json())
    .then(data => {
        if (data.error) {
            showNotification('Ошибка: ' + data.error, 'error');
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
        showNotification('Ошибка сети: ' + error, 'error');
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
                        showNotification('Сканирование завершено!', 'success');
                        showTab('vulnerabilities');
                    } else {
                        showNotification('Сканирование завершено с ошибками', 'error');
                    }
                }
            });
    }, 2000);
}

function updateProgress(data) {
    const container = document.getElementById('progressContainer');
    const phaseIcons = {
        'recon': 'fa-search',
        'scanning': 'fa-radar',
        'exploitation': 'fa-bug',
        'reporting': 'fa-file-alt'
    };
    
    container.innerHTML = `
        <div class="bg-gray-700 p-6 rounded-lg border border-gray-600">
            <div class="flex justify-between items-center mb-4">
                <div class="flex items-center space-x-3">
                    <i class="fas ${phaseIcons[data.phase] || 'fa-cog'} text-2xl text-green-400"></i>
                    <div>
                        <div class="font-medium text-lg">${data.message}</div>
                        <div class="text-sm text-gray-400">Фаза: ${data.phase}</div>
                    </div>
                </div>
                <span class="text-2xl font-bold text-green-400">${data.progress}%</span>
            </div>
            <div class="w-full bg-gray-600 rounded-full h-4">
                <div class="bg-gradient-to-r from-green-500 to-green-600 h-4 rounded-full transition-all duration-500 ease-out" 
                     style="width: ${data.progress}%"></div>
            </div>
        </div>
    `;
}

function loadResults() {
    if (!currentJobId) return;

    fetch(`/api/scan/results/${currentJobId}`)
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                showNotification('Ошибка загрузки результатов: ' + data.error, 'error');
                return;
            }
            displayVulnerabilities(data.results.vulnerabilities || []);
            displayServices(data.results.reconnaissance || {});
            displayAttackVectors(data.results.attack_vectors || []);
            displayReport(data.results.report || {});
            updateStats(data.results);
        })
        .catch(error => {
            showNotification('Ошибка загрузки результатов: ' + error, 'error');
        });
}

function displayVulnerabilities(vulns) {
    const container = document.getElementById('vulnerabilitiesList');
    if (!vulns || vulns.length === 0) {
        container.innerHTML = `
            <div class="text-center text-gray-400 py-12">
                <i class="fas fa-check-circle text-green-400 text-5xl mb-4"></i>
                <div class="text-xl">Уязвимости не обнаружены</div>
                <div class="text-sm mt-2">Система безопасна или требует дополнительной проверки</div>
            </div>
        `;
        return;
    }

    container.innerHTML = vulns.map(vuln => `
        <div class="bg-gray-700 p-5 rounded-lg border-l-4 ${getRiskColor(vuln.risk)} transform transition-transform hover:scale-[1.02]">
            <div class="flex justify-between items-start mb-3">
                <div class="font-semibold text-xl">${vuln.name}</div>
                <span class="px-3 py-1 rounded-full text-xs font-bold ${getRiskBadgeColor(vuln.risk)}">
                    ${vuln.risk}
                </span>
            </div>
            <div class="text-gray-300 mb-3 leading-relaxed">${vuln.description}</div>
            <div class="flex flex-wrap gap-4 text-sm text-gray-400">
                <span><i class="fas fa-fingerprint mr-1"></i> ${vuln.id}</span>
                <span><i class="fas fa-cube mr-1"></i> ${vuln.service}</span>
                <span><i class="fas fa-plug mr-1"></i> Порт: ${vuln.port}</span>
                ${vuln.cvss ? `<span><i class="fas fa-chart-line mr-1"></i> CVSS: ${vuln.cvss}</span>` : ''}
            </div>
        </div>
    `).join('');
}

function displayServices(recon) {
    const container = document.getElementById('servicesList');
    const services = recon.services || [];
    const ports = recon.ports || [];

    if (services.length === 0) {
        container.innerHTML = '<div class="text-center text-gray-400 py-8">Сервисы не обнаружены</div>';
        return;
    }

    container.innerHTML = `
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div class="bg-gray-700 p-5 rounded-lg">
                <h3 class="font-semibold text-lg mb-3 text-blue-300"><i class="fas fa-desktop mr-2"></i>Информация о хосте</h3>
                <div class="space-y-2 text-sm">
                    <div><strong>Хост:</strong> <span class="text-green-400">${recon.host || 'N/A'}</span></div>
                    <div><strong>ОС:</strong> <span class="text-yellow-400">${recon.os_detection || 'Не определена'}</span></div>
                    <div><strong>Открытых портов:</strong> <span class="text-red-400">${ports.length}</span></div>
                </div>
            </div>
            
            <div class="bg-gray-700 p-5 rounded-lg">
                <h3 class="font-semibold text-lg mb-3 text-green-300"><i class="fas fa-network-wired mr-2"></i>Обнаруженные сервисы</h3>
                <div class="space-y-3 max-h-60 overflow-y-auto">
                    ${services.map(service => `
                        <div class="bg-gray-600 p-3 rounded flex justify-between items-center">
                            <div>
                                <div class="font-medium">${service.name}</div>
                                <div class="text-xs text-gray-400">Порт: ${service.port}</div>
                            </div>
                            <span class="text-xs bg-gray-500 px-2 py-1 rounded">${service.version || '?'}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

function displayAttackVectors(vectors) {
    const container = document.getElementById('attackVectorsList');
    if (!vectors || vectors.length === 0) {
        container.innerHTML = `
            <div class="text-center text-gray-400 py-12">
                <i class="fas fa-shield-alt text-4xl mb-4"></i>
                <div class="text-xl">Векторы атак не построены</div>
                <div class="text-sm mt-2">Недостаточно данных для построения цепочек атак</div>
            </div>
        `;
        return;
    }

    container.innerHTML = vectors.map(vector => `
        <div class="bg-gray-700 p-6 rounded-lg border ${getRiskBorderColor(vector.risk)}">
            <div class="flex justify-between items-start mb-4">
                <div class="font-semibold text-xl text-yellow-400">${vector.name}</div>
                <span class="px-3 py-1 rounded-full text-sm font-bold ${getRiskBadgeColor(vector.risk)}">
                    ${vector.risk} РИСК
                </span>
            </div>
            <div class="text-gray-300 mb-4 leading-relaxed">${vector.description}</div>
            
            <div class="bg-gray-800 p-4 rounded-lg mb-4">
                <h4 class="font-medium mb-3 text-green-300"><i class="fas fa-list-ol mr-2"></i>Цепочка атаки:</h4>
                <ol class="list-decimal list-inside space-y-2">
                    ${vector.steps.map((step, index) => `
                        <li class="text-gray-300 flex items-start">
                            <span class="bg-gray-600 text-white rounded-full w-6 h-6 flex items-center justify-center text-xs mr-2 flex-shrink-0">${index + 1}</span>
                            ${step}
                        </li>
                    `).join('')}
                </ol>
            </div>
            
            ${vector.vulnerabilities && vector.vulnerabilities.length > 0 ? `
                <div class="text-sm text-gray-400">
                    <strong>Используемые уязвимости:</strong> 
                    ${vector.vulnerabilities.map(v => v.name).join(', ')}
                </div>
            ` : ''}
        </div>
    `).join('');
}

function displayReport(report) {
    const container = document.getElementById('reportContent');
    const content = report.executive_summary || 'Отчет не сгенерирован';
    container.innerHTML = `<div class="whitespace-pre-wrap leading-relaxed">${content}</div>`;
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
    if (scanHistory.length === 0) {
        container.innerHTML = '<div class="text-center text-gray-400 py-4">Нет завершенных сканирований</div>';
        return;
    }

    container.innerHTML = scanHistory.map(scan => `
        <div class="bg-gray-700 p-4 rounded-lg flex justify-between items-center transform transition-transform hover:scale-[1.02]">
            <div class="flex-1">
                <div class="font-medium text-lg">${scan.target}</div>
                <div class="text-sm text-gray-400 flex flex-wrap gap-4 mt-1">
                    <span><i class="fas fa-clock mr-1"></i>${scan.start_time}</span>
                    <span><i class="fas fa-cog mr-1"></i>${getModeDisplayName(scan.mode)}</span>
                </div>
            </div>
            <span class="px-3 py-1 rounded-full text-sm font-bold ${
                scan.status === 'completed' ? 'bg-green-600 text-white' : 
                scan.status === 'running' ? 'bg-yellow-600 text-white' : 
                'bg-red-600 text-white'
            }">
                ${scan.status === 'completed' ? 'Завершено' : 
                  scan.status === 'running' ? 'Выполняется' : 'Ошибка'}
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

function loadScanHistory() {
    fetch('/api/scans')
        .then(r => r.json())
        .then(data => {
            if (data.scans) {
                scanHistory = data.scans.map(scan => ({
                    job_id: scan.job_id,
                    target: scan.target,
                    mode: 'black_box',
                    start_time: new Date(scan.start_time).toLocaleString(),
                    status: scan.status
                }));
                updateScanHistory();
                updateStats({});
            }
        })
        .catch(error => {
            console.error('Error loading scan history:', error);
        });
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
    event.currentTarget.classList.add('border-green-500', 'text-green-400');
    event.currentTarget.classList.remove('border-transparent', 'text-gray-400');
}

function downloadReport() {
    if (currentJobId) {
        window.open(`/api/report/download/${currentJobId}`, '_blank');
    } else {
        showNotification('Сначала выполните сканирование', 'warning');
    }
}

function showNotification(message, type = 'info') {
    const colors = {
        'success': 'bg-green-600',
        'error': 'bg-red-600', 
        'warning': 'bg-yellow-600',
        'info': 'bg-blue-600'
    };
    
    // Создаем уведомление
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 ${colors[type]} text-white px-6 py-3 rounded-lg shadow-lg z-50 transform transition-transform duration-300`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Авто-удаление через 5 секунд
    setTimeout(() => {
        notification.remove();
    }, 5000);
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

function getRiskBorderColor(risk) {
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
        'CRITICAL': 'bg-red-600 text-white',
        'HIGH': 'bg-orange-600 text-white',
        'MEDIUM': 'bg-yellow-600 text-white',
        'LOW': 'bg-green-600 text-white'
    };
    return colors[risk] || 'bg-gray-600 text-white';
}

function getModeDisplayName(mode) {
    const names = {
        'black_box': 'Чёрный ящик',
        'gray_box': 'Серый ящик',
        'white_box': 'Белый ящик'
    };
    return names[mode] || mode;
}

function addLogMessage(message) {
    console.log('Bitkillers Log:', message);
}

// Показываем первую вкладку по умолчанию
showTab('vulnerabilities');

// Enhanced notification system
function showNotification(message, type = 'info', duration = 5000) {
    const container = document.getElementById('notificationContainer');
    const notification = document.createElement('div');
    notification.className = `notification ${type} transform transition-all duration-300`;
    notification.innerHTML = `
        <div class="flex items-center space-x-3">
            <i class="fas ${getNotificationIcon(type)} text-lg"></i>
            <span>${message}</span>
        </div>
    `;

    container.appendChild(notification);

    // Animate in
    setTimeout(() => {
        notification.style.transform = 'translateX(0)';
    }, 10);

    // Auto remove
    setTimeout(() => {
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, duration);
}

function getNotificationIcon(type) {
    const icons = {
        'success': 'fa-check-circle',
        'error': 'fa-exclamation-circle',
        'warning': 'fa-exclamation-triangle',
        'info': 'fa-info-circle'
    };
    return icons[type] || 'fa-info-circle';
}

// Update badge counts
function updateBadgeCounts(vulns, services, vectors) {
    document.getElementById('vulnCount').textContent = vulns;
    document.getElementById('serviceCount').textContent = services;
    document.getElementById('vectorCount').textContent = vectors;
}

// Enhanced results display with badge updates
function displayVulnerabilities(vulns) {
    const container = document.getElementById('vulnerabilitiesList');
    if (!vulns || vulns.length === 0) {
        container.innerHTML = `
            <div class="text-center text-gray-400 py-12">
                <i class="fas fa-check-circle text-green-400 text-5xl mb-4"></i>
                <div class="text-xl">No Vulnerabilities Found</div>
                <div class="text-sm mt-2">The target appears to be secure or requires deeper analysis</div>
            </div>
        `;
        updateBadgeCounts(0,
            document.getElementById('serviceCount').textContent,
            document.getElementById('vectorCount').textContent
        );
        return;
    }

    container.innerHTML = vulns.map(vuln => `
        <div class="vulnerability-card ${vuln.risk.toLowerCase()} p-5">
            <div class="flex justify-between items-start mb-3">
                <div class="font-semibold text-xl">${vuln.name}</div>
                <span class="badge badge-${vuln.risk.toLowerCase()}">
                    ${vuln.risk}
                </span>
            </div>
            <div class="text-gray-300 mb-3 leading-relaxed">${vuln.description}</div>
            <div class="flex flex-wrap gap-4 text-sm text-gray-400">
                <span><i class="fas fa-fingerprint mr-1"></i> ${vuln.id}</span>
                <span><i class="fas fa-cube mr-1"></i> ${vuln.service}</span>
                <span><i class="fas fa-plug mr-1"></i> Port: ${vuln.port}</span>
                ${vuln.cvss ? `<span><i class="fas fa-chart-line mr-1"></i> CVSS: ${vuln.cvss}</span>` : ''}
            </div>
        </div>
    `).join('');

    updateBadgeCounts(vulns.length,
        document.getElementById('serviceCount').textContent,
        document.getElementById('vectorCount').textContent
    );
}