"""
Report Generator — produces executive summaries, compliance audits, and risk
assessment reports in JSON, PDF, or HTML format.

Reports are stored under data/reports/ with a unique report_id derived from
a UUID.  PDF generation relies on fpdf2 (already in requirements).
"""

import datetime
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fpdf import FPDF

logger = logging.getLogger(__name__)

REPORTS_DIR = Path(os.path.dirname(__file__)).parent / "data" / "reports"

VALID_TEMPLATES = {"executive_summary", "compliance_audit", "risk_assessment"}
VALID_FORMATS = {"json", "pdf", "html"}


# ── PDF helper ──────────────────────────────────────────────────────────────

class _ReportPDF(FPDF):
    """Lightweight PDF renderer used by the report generator."""

    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 10, self._title_text, align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    # -- convenience writers --------------------------------------------------

    def section_heading(self, text: str):
        self.set_font("Helvetica", "B", 12)
        self.set_fill_color(230, 230, 230)
        self.cell(0, 8, text, new_x="LMARGIN", new_y="NEXT", fill=True)
        self.ln(2)

    def body_text(self, text: str):
        self.set_font("Helvetica", "", 10)
        self.multi_cell(0, 5, text)
        self.ln(2)

    def key_value(self, key: str, value: str):
        self.set_font("Helvetica", "B", 10)
        self.cell(55, 6, f"{key}:")
        self.set_font("Helvetica", "", 10)
        self.cell(0, 6, str(value), new_x="LMARGIN", new_y="NEXT")

    def simple_table(self, headers: List[str], rows: List[List[str]]):
        col_width = (self.w - 20) / max(len(headers), 1)
        self.set_font("Helvetica", "B", 9)
        for h in headers:
            self.cell(col_width, 7, h, border=1)
        self.ln()
        self.set_font("Helvetica", "", 9)
        for row in rows:
            for cell in row:
                self.cell(col_width, 6, str(cell)[:40], border=1)
            self.ln()
        self.ln(3)


# ── HTML helper ─────────────────────────────────────────────────────────────

def _render_html(title: str, data: Dict[str, Any]) -> str:
    """Produce a self-contained HTML report string."""
    rows_html = ""
    for key, value in data.items():
        if isinstance(value, (list, dict)):
            value = json.dumps(value, indent=2, default=str)
        rows_html += f"<tr><td><strong>{key}</strong></td><td><pre>{value}</pre></td></tr>\n"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font-family: sans-serif; margin: 2rem; }}
  h1 {{ color: #1a1a2e; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  td, th {{ border: 1px solid #ccc; padding: 8px; vertical-align: top; text-align: left; }}
  pre {{ white-space: pre-wrap; word-break: break-word; margin: 0; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p>Generated: {datetime.datetime.utcnow().isoformat()}Z</p>
<table>
{rows_html}
</table>
</body>
</html>"""


# ── Report Generator class ──────────────────────────────────────────────────

class ReportGenerator:
    """Generates reports and persists them to data/reports/."""

    def __init__(self, reports_dir: Optional[Path] = None):
        self.reports_dir = reports_dir or REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    # -- public API -----------------------------------------------------------

    def generate_report(
        self,
        template: str,
        format: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generate a report file and return metadata.

        Parameters
        ----------
        template : str
            One of "executive_summary", "compliance_audit", "risk_assessment".
        format : str
            One of "json", "pdf", "html".
        data : dict
            Report payload — typically contains keys such as risk_summary,
            compliance_results, top_findings, rules_count, etc.

        Returns
        -------
        dict  {report_id, file_path, file_size}
        """
        if template not in VALID_TEMPLATES:
            raise ValueError(f"Unknown template '{template}'. Valid: {VALID_TEMPLATES}")
        if format not in VALID_FORMATS:
            raise ValueError(f"Unknown format '{format}'. Valid: {VALID_FORMATS}")

        report_id = str(uuid.uuid4())
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{template}_{timestamp}_{report_id[:8]}.{format}"
        file_path = self.reports_dir / filename

        if format == "json":
            self._write_json(file_path, template, data)
        elif format == "pdf":
            self._write_pdf(file_path, template, data)
        elif format == "html":
            self._write_html(file_path, template, data)

        file_size = file_path.stat().st_size
        logger.info("Report generated: %s (%d bytes)", filename, file_size)

        return {
            "report_id": report_id,
            "file_path": str(file_path),
            "file_size": file_size,
        }

    # -- format writers -------------------------------------------------------

    def _write_json(self, path: Path, template: str, data: Dict[str, Any]):
        payload = {
            "template": template,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            **data,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)

    def _write_pdf(self, path: Path, template: str, data: Dict[str, Any]):
        title = template.replace("_", " ").title()
        pdf = _ReportPDF()
        pdf._title_text = f"Fortress Lens — {title}"
        pdf.alias_nb_pages()
        pdf.add_page()

        # Metadata section
        pdf.section_heading("Report Metadata")
        pdf.key_value("Template", title)
        pdf.key_value("Generated", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
        pdf.key_value("Rules Analysed", str(data.get("rules_count", "N/A")))
        pdf.ln(4)

        # Risk summary
        risk_summary = data.get("risk_summary", {})
        if risk_summary:
            pdf.section_heading("Risk Summary")
            for level in ("critical", "high", "medium", "low"):
                count = risk_summary.get(level, 0)
                pdf.key_value(level.capitalize(), str(count))
            pdf.ln(4)

        # Compliance results
        compliance_results = data.get("compliance_results", [])
        if compliance_results:
            pdf.section_heading("Compliance Results")
            headers = ["Framework", "Score", "Status", "Passed", "Failed"]
            rows = []
            for cr in compliance_results:
                rows.append([
                    str(cr.get("framework", "")),
                    str(cr.get("overall_score", "")),
                    str(cr.get("status", "")),
                    str(cr.get("passed", "")),
                    str(cr.get("failed", "")),
                ])
            pdf.simple_table(headers, rows)

        # Top findings
        top_findings = data.get("top_findings", [])
        if top_findings:
            pdf.section_heading("Top Findings")
            for i, finding in enumerate(top_findings[:20], 1):
                if isinstance(finding, dict):
                    line = (
                        f"{i}. [{finding.get('risk_level', 'N/A').upper()}] "
                        f"{finding.get('rule_name', 'Unnamed')} — "
                        f"{finding.get('reason', 'No details')}"
                    )
                else:
                    line = f"{i}. {finding}"
                pdf.body_text(line)

        # Additional data sections
        for key, value in data.items():
            if key in ("risk_summary", "compliance_results", "top_findings", "rules_count"):
                continue
            pdf.section_heading(key.replace("_", " ").title())
            if isinstance(value, (list, dict)):
                pdf.body_text(json.dumps(value, indent=2, default=str))
            else:
                pdf.body_text(str(value))

        pdf.output(str(path))

    def _write_html(self, path: Path, template: str, data: Dict[str, Any]):
        title = f"Fortress Lens — {template.replace('_', ' ').title()}"
        html_content = _render_html(title, data)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
