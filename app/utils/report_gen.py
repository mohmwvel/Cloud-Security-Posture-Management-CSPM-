import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from .logger import setup_logger

logger = setup_logger(__name__)

def generate_pdf_report(findings, output_dir="app/static", filename="cspm_report.pdf"):
    """Generates a professional PDF report with timestamps."""
    try:
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
        
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        
        # Add Title and Timestamp
        elements.append(Paragraph("Cloud Security Posture Report", styles['Heading1']))
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        elements.append(Paragraph(f"Generated on: {timestamp}", styles['Normal']))
        elements.append(Spacer(1, 12))
        
        if not findings:
            elements.append(Paragraph("No misconfigurations detected.", styles['Normal']))
            doc.build(elements)
            return output_path
            
        data = [["Resource ID", "Risk Level", "Issue", "Remediation"]]
        for finding in findings:
            data.append([
                Paragraph(finding['resource_id'], styles['Normal']),
                finding['risk'],
                Paragraph(finding['issue'], styles['Normal']),
                Paragraph(finding['remediation'], styles['Normal'])
            ])
            
        table = Table(data, colWidths=[120, 60, 180, 180])
        style_cmds = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]
        
        for i, row in enumerate(data[1:], start=1):
            if row[1] == 'Critical':
                style_cmds.append(('BACKGROUND', (1, i), (1, i), colors.HexColor("#c0392b")))
            elif row[1] == 'High':
                style_cmds.append(('BACKGROUND', (1, i), (1, i), colors.HexColor("#e74c3c")))
            elif row[1] == 'Medium':
                style_cmds.append(('BACKGROUND', (1, i), (1, i), colors.HexColor("#f1c40f")))
            elif row[1] == 'Low':
                style_cmds.append(('BACKGROUND', (1, i), (1, i), colors.HexColor("#3498db")))
                
        table.setStyle(TableStyle(style_cmds))
        elements.append(table)
        doc.build(elements)
        return output_path
        
    except Exception as e:
        logger.error(f"Failed to generate PDF: {str(e)}")
        raise

def export_json(findings, output_dir="app/static", filename="cspm_export.json"):
    """Exports findings to JSON."""
    try:
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
        
        export_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "findings_count": len(findings),
            "findings": findings
        }
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=4)
        return output_path
    except Exception as e:
        logger.error(f"Failed to export JSON: {str(e)}")
        raise
