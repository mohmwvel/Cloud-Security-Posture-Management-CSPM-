from flask import Blueprint, render_template, request, send_file, current_app
from app.services.scanner_service import run_all_scanners, get_mock_findings
from app.utils.report_gen import generate_pdf_report, export_json
import os

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/scan', methods=['POST'])
def run_scan():
    is_mock = request.form.get('mock') == 'true'
    
    if is_mock:
        findings = get_mock_findings()
    else:
        try:
            findings = run_all_scanners()
        except Exception as e:
            # For a production app, we would flash an error message to the UI
            findings = []

    # Generate Reports
    generate_pdf_report(findings)
    export_json(findings)
    
    # Calculate summary metrics
    summary = {
        'total': len(findings),
        'critical': sum(1 for f in findings if f['risk'] == 'Critical'),
        'high': sum(1 for f in findings if f['risk'] == 'High'),
        'medium': sum(1 for f in findings if f['risk'] == 'Medium'),
        'low': sum(1 for f in findings if f['risk'] == 'Low')
    }
    
    return render_template('results.html', findings=findings, summary=summary)

@main_bp.route('/download-report')
def download_report():
    report_path = os.path.join(current_app.root_path, 'static', 'cspm_report.pdf')
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=True)
    return "Report not found", 404

@main_bp.route('/download-json')
def download_json():
    json_path = os.path.join(current_app.root_path, 'static', 'cspm_export.json')
    if os.path.exists(json_path):
        return send_file(json_path, as_attachment=True)
    return "JSON export not found", 404
