"""
FucyFuzz GUI - Report Generators
Ported from fucyfuzz (2)/report_generators.py for use with the standalone PyQt5 GUI.
Supports: PDF Report, Text Report, CSV Export.
"""

import os
import csv
import time
import traceback
from datetime import datetime
from collections import defaultdict

from PyQt5.QtWidgets import QMessageBox, QFileDialog


# ── ReportLab (optional, for PDF) ─────────────────────────────────────────────
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, PageBreak,
        Table, TableStyle, Preformatted, ListFlowable, ListItem,
    )
    from reportlab.platypus.tableofcontents import TableOfContents
    REPORTLAB_AVAILABLE = True
    _rl_styles = getSampleStyleSheet()
except Exception:
    REPORTLAB_AVAILABLE = False
    colors = letter = inch = None
    SimpleDocTemplate = Paragraph = Spacer = PageBreak = None
    Table = TableStyle = Preformatted = ListFlowable = ListItem = None
    TableOfContents = None
    ParagraphStyle = None
    _rl_styles = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _qt_parent(parent=None):
    """Return a valid Qt parent for dialogs, or None."""
    return parent


def _show_info(parent, title, msg):
    QMessageBox.information(parent, title, msg)


def _show_error(parent, title, msg):
    QMessageBox.critical(parent, title, msg)


def _ask_save(parent, title, default_name, file_filter):
    path, _ = QFileDialog.getSaveFileName(parent, title, default_name, file_filter)
    return path or None


# ── Data analysis helpers ──────────────────────────────────────────────────────

def _analyze_entries(entries):
    """
    Analyse DataManager faults/sessions and return summary dicts.
    entries  – list of Fault dataclass instances (from DataManager.faults)
    Returns:
        modules        – dict{ module_name -> [fault, …] }
        status_counts  – dict{ 'failed'|'warning'|'success'|'other' -> int }
        risk_scorecard – list[ (metric, status, risk_level) ]
        key_findings   – list[str]
    """
    modules = defaultdict(list)
    status_counts = defaultdict(int)

    for f in entries:
        modules[f.module].append(f)
        sev = f.severity.lower()
        if sev == "critical":
            status_counts["failed"] += 1
        elif sev == "high":
            status_counts["warning"] += 1
        elif sev in ("medium", "low"):
            status_counts["success"] += 1
        else:
            status_counts["other"] += 1

    risk_scorecard = [
        ("Bus Availability (DoS)",
         "FAILED" if status_counts["failed"] > 0 else "PASSED",
         "Critical" if status_counts["failed"] > 0 else "Low"),
        ("Input Validation",
         "WARNING" if status_counts["warning"] > 0 else "PASSED",
         "High" if status_counts["warning"] > 0 else "Low"),
        ("Diagnostic Security",
         "FAILED" if status_counts["failed"] > 2 else "PASSED",
         "High" if status_counts["failed"] > 2 else "Low"),
        ("Protocol Compliance",
         "FAILED" if (status_counts["failed"] + status_counts["warning"]) > 5 else "PASSED",
         "Medium" if (status_counts["failed"] + status_counts["warning"]) > 5 else "Low"),
    ]

    key_findings = []
    if status_counts["failed"] > 0:
        key_findings.append(
            f"Critical: {status_counts['failed']} critical fault(s) detected — immediate attention required."
        )
    if status_counts["warning"] > 0:
        key_findings.append(
            f"High: {status_counts['warning']} high-severity fault(s) observed."
        )
    if not key_findings:
        key_findings.append(
            "No major failures detected; follow-up validation recommended for edge cases."
        )

    return modules, status_counts, risk_scorecard, key_findings


def _suggested_fixes(fault):
    """Return a list of suggested fix strings based on fault.fault text."""
    text = (fault.fault or "").lower()
    base = [
        "Review full log for context",
        "Check permissions and paths",
        "Verify target availability",
        "Re-run test in isolated environment",
    ]
    if "timeout" in text:
        return ["Increase timeout or reduce load", "Check network latency"] + base
    if "connect" in text:
        return ["Confirm target is reachable", "Check firewall / interface"] + base
    if "permission" in text or "access" in text:
        return ["Run with elevated privileges or fix file permissions"] + base
    if "invalid" in text or "format" in text:
        return ["Verify inputs and formats", "Test with known-good payloads"] + base
    return base


# ── PDF helpers ────────────────────────────────────────────────────────────────

def _make_styles():
    """Build and return the ParagraphStyle objects used in all PDF reports."""
    if not REPORTLAB_AVAILABLE:
        return {}
    return {
        "title": ParagraphStyle("ReportTitle", parent=_rl_styles["Title"],
                                fontSize=26, alignment=1, spaceAfter=12,
                                textColor=colors.HexColor("#222222"),
                                fontName="Helvetica-Bold"),
        "subtitle": ParagraphStyle("Subtitle", parent=_rl_styles["Heading2"],
                                   alignment=1, spaceAfter=16,
                                   textColor=colors.HexColor("#6c757d"),
                                   fontName="Helvetica-Oblique"),
        "h1": ParagraphStyle("H1", parent=_rl_styles["Heading1"],
                             fontSize=16, textColor=colors.HexColor("#2c3e50"),
                             spaceBefore=12, spaceAfter=6, fontName="Helvetica-Bold"),
        "h2": ParagraphStyle("H2", parent=_rl_styles["Heading2"],
                             fontSize=12, textColor=colors.HexColor("#2c3e50"),
                             spaceBefore=8, spaceAfter=4, fontName="Helvetica-Bold"),
        "normal": ParagraphStyle("NormalC", parent=_rl_styles["Normal"],
                                 fontSize=10, leading=13, spaceAfter=5),
        "code": ParagraphStyle("Code", parent=_rl_styles["Code"],
                               fontSize=8, leading=10,
                               backColor=colors.HexColor("#f8f9fa"),
                               borderColor=colors.lightgrey,
                               borderWidth=0.5, borderPadding=5,
                               fontName="Courier"),
    }


def _header_footer(canvas, doc, title_text="FucyFuzz Report"):
    canvas.saveState()
    w, h = doc.pagesize
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(colors.HexColor("#2c3e50"))
    canvas.drawString(doc.leftMargin, h - 34, title_text)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.gray)
    canvas.drawRightString(w - doc.rightMargin, h - 34,
                           datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    canvas.setStrokeColor(colors.lightgrey)
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, h - 38, w - doc.rightMargin, h - 38)
    canvas.line(doc.leftMargin, 46, w - doc.rightMargin, 46)
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(w / 2.0, 33, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


# ══════════════════════════════════════════════════════════════════════════════
# 1. PDF Report
# ══════════════════════════════════════════════════════════════════════════════

class FailureReportPDF:
    """
    Generates a Failure Analysis PDF report from DataManager.faults.
    Only failed (critical / high) faults are included, matching the sample PDF.
    """

    def __init__(self, data_manager, parent_widget=None):
        self.dm = data_manager
        self.parent = parent_widget

    def _ensure_reportlab(self):
        if not REPORTLAB_AVAILABLE:
            _show_error(self.parent, "ReportLab Missing",
                        "ReportLab is required for PDF export.\n\nInstall with:\n\n  pip install reportlab")
            return False
        return True

    def _failure_faults(self):
        return [f for f in self.dm.faults if f.severity in ("critical", "high")]

    def generate(self, filename=None):
        if not self._ensure_reportlab():
            return None

        failures = self._failure_faults()
        if not failures:
            _show_info(self.parent, "No Failures",
                       "No failed/critical test cases found in the current session.")
            return None

        if filename is None:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = _ask_save(
                self.parent,
                "Save Failure Report PDF",
                f"Failure_Report_{stamp}.pdf",
                "PDF Report (*.pdf)",
            )
            if not filename:
                return None

        styles = _make_styles()
        story = []

        # ── Cover ──────────────────────────────────────────────────────────
        story.append(Spacer(1, 1.4 * inch))
        story.append(Paragraph("FAILURE ANALYSIS REPORT", styles["title"]))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["subtitle"]
        ))
        story.append(Spacer(1, 0.2 * inch))

        summary_items = [
            f"Total Failures: {len(failures)}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ]
        story.append(ListFlowable(
            [ListItem(Paragraph(s, styles["normal"])) for s in summary_items],
            bulletType="bullet", leftIndent=18
        ))
        story.append(Spacer(1, 0.3 * inch))

        # ── Per-failure entries ────────────────────────────────────────────
        for idx, fault in enumerate(failures, start=1):
            story.append(Paragraph(
                f"Failure {idx}: {fault.module} — {fault.fault[:120]}",
                styles["h2"]
            ))

            meta_data = [
                ["Timestamp", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(fault.time))],
                ["Module", fault.module],
                ["Status", fault.severity.upper()],
                ["Command", fault.cmd[:120] if fault.cmd else "—"],
            ]
            meta_tbl = Table(meta_data, colWidths=[100, 390])
            meta_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8d7da")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(meta_tbl)
            story.append(Spacer(1, 0.06 * inch))

            # Error detail
            detail = fault.fault or ""
            if len(detail) > 1200:
                detail = detail[:1200] + "\n\n[TRUNCATED — see logs]"
            story.append(Paragraph("<b>Error Output (truncated)</b>", styles["normal"]))
            story.append(Preformatted(detail, styles["code"]))
            story.append(Spacer(1, 0.1 * inch))

            # Suggested fixes
            fixes = _suggested_fixes(fault)
            story.append(Paragraph("<b>Suggested Fixes</b>", styles["normal"]))
            story.append(ListFlowable(
                [ListItem(Paragraph(x, styles["normal"])) for x in fixes],
                bulletType="bullet", leftIndent=18
            ))
            story.append(PageBreak())

        # ── Build PDF ──────────────────────────────────────────────────────
        try:
            doc = SimpleDocTemplate(
                filename, pagesize=letter,
                leftMargin=72, rightMargin=72, topMargin=72, bottomMargin=72
            )
            doc.build(
                story,
                onFirstPage=lambda c, d: _header_footer(c, d, "Failure Report"),
                onLaterPages=lambda c, d: _header_footer(c, d, "Failure Report"),
            )
            _show_info(self.parent, "PDF Report", f"Failure report saved:\n{filename}")
            return filename
        except Exception as e:
            traceback.print_exc()
            _show_error(self.parent, "PDF Error", f"Failed to generate PDF:\n{e}")
            return None


# ══════════════════════════════════════════════════════════════════════════════
# 2. Text Report
# ══════════════════════════════════════════════════════════════════════════════

class TextReportExporter:
    """Generates a plain-text Failure / Session report."""

    def __init__(self, data_manager, parent_widget=None):
        self.dm = data_manager
        self.parent = parent_widget

    def generate(self, filename=None):
        faults = self.dm.faults
        sessions = self.dm.sessions

        if not faults and not sessions:
            _show_info(self.parent, "No Data",
                       "No faults or sessions recorded in the current session.")
            return None

        if filename is None:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = _ask_save(
                self.parent,
                "Save Text Report",
                f"FucyFuzz_Report_{stamp}.txt",
                "Text Files (*.txt)",
            )
            if not filename:
                return None

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = []
        sep = "=" * 70

        lines += [
            sep,
            "  FUCYFUZZ — SESSION REPORT",
            f"  Generated : {now_str}",
            f"  Faults    : {len(faults)}",
            f"  Sessions  : {len(sessions)}",
            sep, "",
        ]

        # ── Fault summary ──────────────────────────────────────────────────
        lines += ["FAULT SUMMARY", "-" * 40]
        sev_counts = self.dm.severity_counts()
        for sev, cnt in sev_counts.items():
            lines.append(f"  {sev.upper():<12}: {cnt}")
        lines.append("")

        # ── Fault details ──────────────────────────────────────────────────
        lines += ["FAULT DETAILS", "-" * 40]
        for idx, f in enumerate(faults, 1):
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(f.time))
            lines += [
                f"[{idx}] {f.module} | {f.severity.upper()} | {ts}",
                f"    Fault  : {f.fault}",
                f"    Command: {f.cmd}",
                f"    Status : {f.status}",
                "",
            ]

        # ── Session details ────────────────────────────────────────────────
        lines += ["SESSION DETAILS", "-" * 40]
        for idx, s in enumerate(sessions, 1):
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.start))
            lines += [
                f"[{idx}] Session {s.id} | {s.module} | Started: {ts}",
                f"    Duration: {s.duration()}",
                f"    Command : {s.cmd}",
                f"    Faults  : {len(s.faults)}",
                "",
            ]

        lines += [sep, "END OF REPORT", sep]

        try:
            with open(filename, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
            _show_info(self.parent, "Text Report", f"Report saved:\n{filename}")
            return filename
        except Exception as e:
            _show_error(self.parent, "Text Export Error", f"Failed to save text report:\n{e}")
            return None


# ══════════════════════════════════════════════════════════════════════════════
# 3. CSV Export
# ══════════════════════════════════════════════════════════════════════════════

class CSVExporter:
    """Exports faults and sessions to CSV."""

    def __init__(self, data_manager, parent_widget=None):
        self.dm = data_manager
        self.parent = parent_widget

    def generate(self, filename=None):
        faults = self.dm.faults

        if not faults:
            _show_info(self.parent, "No Data",
                       "No fault data to export in the current session.")
            return None

        if filename is None:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = _ask_save(
                self.parent,
                "Export CSV",
                f"FucyFuzz_Export_{stamp}.csv",
                "CSV Files (*.csv)",
            )
            if not filename:
                return None

        try:
            with open(filename, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow([
                    "ID", "Timestamp", "Module", "Severity",
                    "Fault", "Command", "Status",
                ])
                for f in faults:
                    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(f.time))
                    writer.writerow([
                        f.id, ts, f.module, f.severity.upper(),
                        f.fault, f.cmd, f.status,
                    ])

            _show_info(self.parent, "CSV Export",
                       f"Exported {len(faults)} fault(s) to:\n{filename}")
            return filename
        except Exception as e:
            _show_error(self.parent, "CSV Export Error", f"Failed to export CSV:\n{e}")
            return None
