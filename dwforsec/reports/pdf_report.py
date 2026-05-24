from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from dwforsec.reports.base_report import BaseReport
from dwforsec.core.logging import logger

class PdfReport(BaseReport):
    async def generate(self) -> Path:
        filename = self.get_filename("pdf")
        out_path = self.output_dir / "pdf" / filename
        out_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            doc = SimpleDocTemplate(str(out_path), pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Custom Styles
            title_style = ParagraphStyle(
                'TitleStyle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1e3a8a'),
                spaceAfter=15
            )
            h2_style = ParagraphStyle(
                'H2Style',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#0f172a'),
                spaceBefore=12,
                spaceAfter=6
            )
            body_style = ParagraphStyle(
                'BodyStyle',
                parent=styles['BodyText'],
                fontSize=10,
                spaceAfter=6
            )
            code_style = ParagraphStyle(
                'CodeStyle',
                parent=styles['Code'],
                fontSize=8,
                textColor=colors.HexColor('#10b981'),
                backColor=colors.HexColor('#f3f4f6'),
                borderPadding=5
            )
            
            # Cover Header
            story.append(Paragraph("DWForSec-ReconSuite Audit Report", title_style))
            story.append(Paragraph(f"<b>Target Asset:</b> {self.target}", body_style))
            story.append(Paragraph(f"<b>Scan Identity:</b> {self.scan_id}", body_style))
            story.append(Paragraph(f"<b>Generated Time:</b> {self.timestamp}", body_style))
            story.append(Paragraph("<b>Classification:</b> STRICTLY CONFIDENTIAL // SECURITY AUDIT", body_style))
            story.append(Spacer(1, 15))
            
            # Executive Summary
            story.append(Paragraph("1. Executive Summary", h2_style))
            summary = self.data.get("summary", {})
            story.append(Paragraph(f"Total Discovered Subdomains: {summary.get('total_subdomains', 0)}", body_style))
            story.append(Paragraph(f"Active Live Hosts: {summary.get('live_hosts', 0)}", body_style))
            story.append(Paragraph(f"Open Service Ports: {summary.get('open_ports', 0)}", body_style))
            story.append(Spacer(1, 10))
            
            # Severity Table
            sev_data = [
                ['Severity Level', 'Count'],
                ['Critical', str(summary.get('critical', 0))],
                ['High', str(summary.get('high', 0))],
                ['Medium', str(summary.get('medium', 0))],
                ['Low', str(summary.get('low', 0))],
                ['Info', str(summary.get('info', 0))],
            ]
            t = Table(sev_data, colWidths=[150, 100])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e3a8a')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,0), 6),
                ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8fafc')),
                ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ]))
            story.append(t)
            story.append(Spacer(1, 15))
            
            # Subdomains List
            story.append(Paragraph("2. Discovered Asset Domains", h2_style))
            for sub in self.data.get("subdomains", [])[:20]: # Cap preview list in PDF
                text = f"• <b>{sub.get('subdomain')}</b> (IP: {sub.get('ip_address') or 'N/A'}, Status: {sub.get('status_code') or 'N/A'})"
                story.append(Paragraph(text, body_style))
            story.append(Spacer(1, 15))
            
            # Findings
            story.append(Paragraph("3. Vulnerabilities & Findings", h2_style))
            findings = self.data.get("findings", [])
            if not findings:
                story.append(Paragraph("No vulnerabilities discovered.", body_style))
            else:
                for f in findings[:15]: # Limit to save PDF space
                    story.append(Paragraph(f"<b>[{f.get('severity', 'info').upper()}] {f.get('template_id') or f.get('tool')}</b>", body_style))
                    story.append(Paragraph(f"Matched: {f.get('matched_url') or f.get('host')}", body_style))
                    if f.get('description'):
                        story.append(Paragraph(f"Description: {f.get('description')}", body_style))
                    story.append(Spacer(1, 5))
            
            doc.build(story)
            logger.info(f"Successfully generated PDF report at {out_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate ReportLab PDF report: {e}")
            # If ReportLab fails, let's touch the file with dummy text so execution doesn't break
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(f"PDF creation failed: {e}. Please check standard html or markdown reports.")
                
        return out_path
