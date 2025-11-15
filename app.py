#!/usr/bin/env python3
from core.remediation import RemediationAdvisor
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO
from core.scanner import ScanManager
import logging
import os

# ==================== КОНФИГУРАЦИЯ ====================

app = Flask(__name__)
app.config['SECRET_KEY'] = 'bitkillers_hackathon_2024'
socketio = SocketIO(app, async_mode='threading')

# ==================== ИНИЦИАЛИЗАЦИЯ ====================

scan_manager = ScanManager(socketio)
remediation_advisor = RemediationAdvisor()

# ==================== FLASK ROUTES ====================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    mode = data.get('mode', 'black_box')
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
    job = scan_manager.get_job(job_id)
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
    job = scan_manager.get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    return jsonify({
        'job_id': job.job_id,
        'status': job.status,
        'results': job.results
    })


@app.route('/api/scans')
def list_scans():
    scans = scan_manager.list_jobs()
    return jsonify({'scans': scans})


@app.route('/api/report/download/<job_id>')
def download_report(job_id):
    from core.reporter import ReportGenerator

    job = scan_manager.get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    reporter = ReportGenerator()
    filename, filepath = reporter.generate_file_report(job)

    return send_file(filepath, as_attachment=True, download_name=filename)

@app.route('/api/remediation/generate/<job_id>')
def generate_remediation_report(job_id):
    job = scan_manager.get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    vulnerabilities = job.results.get('vulnerabilities', [])
    report = remediation_advisor.generate_remediation_report(vulnerabilities)
    
    return jsonify({
        'report': report,
        'vulnerabilities_count': len(vulnerabilities)
    })

@app.route('/api/remediation/download/<job_id>')
def download_remediation_report(job_id):
    job = scan_manager.get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    vulnerabilities = job.results.get('vulnerabilities', [])
    filename = remediation_advisor.save_remediation_report(vulnerabilities)
    
    return send_file(filename, as_attachment=True, download_name=filename)

# ==================== WEB SOCKET EVENTS ====================

@socketio.on('connect')
def handle_connect():
    app.logger.info('Client connected')


@socketio.on('disconnect')
def handle_disconnect():
    app.logger.info('Client disconnected')


# ==================== ЗАПУСК СЕРВЕРА ====================

if __name__ == '__main__':
    print("🚀 Bitkillers Pentest Platform запускается...")
    print("📍 Доступно по адресу: http://localhost:5000")
    print("⚡ Версия: 1.0 | Хакатон АЛЬПИКС")
    
    # Создаем необходимые директории
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    # Запускаем с разрешением использовать Werkzeug в production-like среде
    socketio.run(app, 
                 host='0.0.0.0', 
                 port=5000, 
                 debug=True, 
                 allow_unsafe_werkzeug=True)
