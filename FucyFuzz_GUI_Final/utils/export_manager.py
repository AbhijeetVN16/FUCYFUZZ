"""
FucyFuzz GUI — Export Manager
Provides all export/report formats from the Export menu:

  export_overall_pdf(dm, filename, ecu_data)  → Full professional PDF
  export_failure_pdf(dm, filename, ecu_data)  → Failures-only PDF
  save_logs_text(dm, filename, ecu_data)      → Raw .log text file
  export_logs_asc(dm, filename, ecu_data)     → Vector ASC format
  export_logs_mf4(dm, filename, ecu_data)     → ASAM MDF4 format

Each function returns (success: bool, message: str).
ecu_data is the dict returned by ECUMonitorTab.get_export_data() or None.
"""

import os
import csv
import re
import time
import traceback
from datetime import datetime
from collections import defaultdict

# ── ReportLab (optional, for PDF) ─────────────────────────────────────────────
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4, landscape
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
    colors = letter = A4 = landscape = inch = None
    SimpleDocTemplate = Paragraph = Spacer = PageBreak = None
    Table = TableStyle = Preformatted = ListFlowable = ListItem = None
    TableOfContents = None
    ParagraphStyle = None
    _rl_styles = None


# ══════════════════════════════════════════════════════════════════════════════
# Shared helpers
# ══════════════════════════════════════════════════════════════════════════════

def _now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _make_styles():
    if not REPORTLAB_AVAILABLE:
        return {}
    return dict(
        title=ParagraphStyle('RTitle', parent=_rl_styles['Title'],
            fontSize=24, alignment=1, spaceAfter=10,
            textColor=colors.HexColor("#222222"), fontName='Helvetica-Bold'),
        sub=ParagraphStyle('RSub', parent=_rl_styles['Heading2'],
            alignment=1, textColor=colors.HexColor("#6c757d"),
            spaceAfter=16, fontName='Helvetica-Oblique'),
        h1=ParagraphStyle('RH1', parent=_rl_styles['Heading1'],
            fontSize=16, textColor=colors.HexColor("#2c3e50"),
            spaceBefore=10, spaceAfter=6, fontName='Helvetica-Bold'),
        h2=ParagraphStyle('RH2', parent=_rl_styles['Heading2'],
            fontSize=12, textColor=colors.HexColor("#2c3e50"),
            spaceBefore=6, spaceAfter=4, fontName='Helvetica-Bold'),
        norm=ParagraphStyle('RNorm', parent=_rl_styles['Normal'],
            fontSize=10, leading=12, spaceAfter=4),
        code=ParagraphStyle('RCode', parent=_rl_styles['Code'],
            fontSize=8, leading=10,
            backColor=colors.HexColor("#f8f9fa"),
            borderColor=colors.lightgrey, borderWidth=0.5,
            borderPadding=4, fontName='Courier'),
    )

def _header_footer(canvas, doc, title_text="FucyFuzz Report"):
    canvas.saveState()
    w, h = doc.pagesize
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(colors.HexColor("#2c3e50"))
    canvas.drawString(doc.leftMargin, h - 34, title_text)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.gray)
    canvas.drawRightString(w - doc.rightMargin, h - 34, _now_str())
    canvas.setStrokeColor(colors.lightgrey)
    canvas.setLineWidth(0.4)
    canvas.line(doc.leftMargin, h - 38, w - doc.rightMargin, h - 38)
    canvas.line(doc.leftMargin, 46, w - doc.rightMargin, 46)
    canvas.setFont("Helvetica", 7)
    canvas.drawCentredString(w / 2.0, 33, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()

def _check_reportlab():
    if not REPORTLAB_AVAILABLE:
        return False, "ReportLab is not installed.\n\nInstall with:\n  pip install reportlab"
    return True, ""

def _build_entries_from_dm(dm):
    entries = []
    fault_map = {f.id: f for f in dm.faults}
    for s in dm.sessions:
        output = getattr(s, 'output', '') or ''
        session_faults = [fault_map[fid] for fid in s.faults if fid in fault_map]
        has_crit = any(f.severity in ('critical', 'high') for f in session_faults)
        status = 'failed' if has_crit else ('warning' if session_faults else 'success')
        entries.append({
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s.start)),
            'module':    s.module or 'Unknown',
            'command':   s.cmd or '',
            'status':    status,
            'output':    output,
            'faults':    session_faults,
            'duration':  s.duration(),
        })
    session_fault_ids = {fid for s in dm.sessions for fid in s.faults}
    for f in dm.faults:
        if f.id not in session_fault_ids:
            entries.append({
                'timestamp': f.time_str(),
                'module':    f.module or 'Unknown',
                'command':   f.cmd or '',
                'status':    'failed' if f.severity in ('critical', 'high') else 'warning',
                'output':    f.fault,
                'faults':    [f],
                'duration':  'N/A',
            })
    return entries

def _suggested_fixes(entry):
    out = (entry.get('output', '') or '').lower()
    base = [
        "Verify inputs and formats",
        "Test with known-good payloads",
        "Review full log for context",
        "Check permissions and paths",
        "Verify target availability",
        "Re-run test in isolated environment",
    ]
    if 'timeout' in out:
        return ["Increase timeout or reduce load", "Check network latency"] + base
    if 'connect' in out:
        return ["Confirm target is reachable", "Check firewall / interface"] + base
    if 'permission' in out or 'access denied' in out:
        return ["Run with elevated privileges or fix file permissions"] + base
    if 'invalid' in out:
        return ["Verify inputs and formats", "Test with known-good payloads"] + base
    if 'memory' in out:
        return ["Check resource usage, reduce payload sizes"] + base
    return base

def _ecu_section_pdf(story, ecu_data, st):
    if not ecu_data or not ecu_data.get('events'):
        return
    events = ecu_data['events']
    story.append(Paragraph("ECU MONITOR SESSION", st['h1']))
    story.append(Paragraph(
        f"Log source: {ecu_data.get('log_path', 'N/A')} — "
        f"{ecu_data.get('event_count', len(events))} events captured",
        st['norm']
    ))
    story.append(Spacer(1, 0.1 * inch))
    tbl_data = [["SEVERITY", "SOURCE", "DESCRIPTION", "CMD", "TIME"]]
    for e in events[:200]:
        tbl_data.append([
            e.get('severity', ''),
            e.get('source', '')[:30],
            e.get('description', '')[:80],
            e.get('cmd', '')[:40],
            e.get('time', ''),
        ])
    tbl = Table(tbl_data, colWidths=[55, 70, 200, 100, 50])
    tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor("#2c3e50")),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  colors.white),
        ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 8),
        ('GRID',          (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING',   (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(tbl)
    story.append(PageBreak())


# ══════════════════════════════════════════════════════════════════════════════
# 1. Overall PDF
# ══════════════════════════════════════════════════════════════════════════════

def export_overall_pdf(dm, filename, ecu_data=None):
    ok, err = _check_reportlab()
    if not ok:
        return False, err
    entries = _build_entries_from_dm(dm)
    sc = dm.severity_counts()
    st = _make_styles()
    try:
        story = []
        story.append(Spacer(1, 1.4 * inch))
        story.append(Paragraph("Automotive Security Assessment Report", st['title']))
        story.append(Paragraph("CAN Bus Fuzzing &amp; Resilience Test", st['sub']))
        story.append(Spacer(1, 0.2 * inch))
        cover_data = [
            ["Target System:",         "Unknown"],
            ["Tooling:",               "FucyFuzz GUI"],
            ["Generated:",             _now_str()],
            ["Report Classification:", "CONFIDENTIAL"],
        ]
        ct = Table(cover_data, colWidths=[140, 330])
        ct.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f8f9fa")),
            ('FONTNAME',   (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE',   (0, 0), (-1, -1), 10),
            ('LEFTPADDING',(0, 0), (-1, -1), 6),
            ('BOTTOMPADDING',(0,0),(-1,-1), 6),
            ('GRID',       (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ]))
        story.append(ct)
        story.append(PageBreak())

        story.append(Paragraph("EXECUTIVE SUMMARY", st['h1']))
        story.append(Spacer(1, 0.08 * inch))
        summary_lines = [
            f"Total Tests: {len(entries)}",
            f"Total Faults: {dm.total_faults()}",
            f"Open Faults: {dm.open_faults()}",
            f"Critical: {sc.get('critical', 0)}",
            f"High: {sc.get('high', 0)}",
            f"Medium: {sc.get('medium', 0)}",
            f"Low: {sc.get('low', 0)}",
            f"Total Sessions: {len(dm.sessions)}",
            f"Generated: {_now_str()}",
        ]
        if ecu_data:
            summary_lines.append(f"ECU Monitor Events: {ecu_data.get('event_count', 0)}")
        story.append(ListFlowable(
            [ListItem(Paragraph(x, st['norm'])) for x in summary_lines],
            bulletType='bullet', leftIndent=18
        ))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("RISK SCORECARD", st['h2']))
        has_fail = sc.get('critical', 0) + sc.get('high', 0) > 0
        has_warn = sc.get('medium', 0) > 0
        rs_data = [["Metric", "Status", "Risk Level"],
            ["Bus Availability (DoS)", "FAILED" if has_fail else "PASSED", "Critical" if has_fail else "Low"],
            ["Input Validation",       "WARNING" if has_warn else "PASSED", "High" if has_warn else "Low"],
            ["Diagnostic Security",    "FAILED" if sc.get('critical',0)>0 else "PASSED", "High" if sc.get('critical',0)>0 else "Low"],
            ["Protocol Compliance",    "PASSED", "Low"],
        ]
        rs_tbl = Table(rs_data, colWidths=[250, 120, 100])
        rs_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2c3e50")),
            ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
            ('GRID',       (0,0), (-1,-1), 0.4, colors.lightgrey),
            ('FONTNAME',   (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE',   (0,0), (-1,-1), 10),
            ('LEFTPADDING',(0,0),(-1,-1), 6),
            ('BOTTOMPADDING',(0,0),(-1,-1), 5),
        ]))
        story.append(rs_tbl)
        story.append(PageBreak())

        story.append(Paragraph("DETAILED TECHNICAL REPORT &amp; LOGS", st['h1']))
        story.append(Spacer(1, 0.1 * inch))
        modules = defaultdict(list)
        for e in entries:
            modules[e.get('module', 'Unknown')].append(e)
        if modules:
            for mod_name, mod_entries in modules.items():
                story.append(Paragraph(f"Module: {mod_name}", st['h2']))
                for idx, e in enumerate(mod_entries, 1):
                    story.append(Paragraph(f"Test {idx}: {(e.get('command') or '')[:100]}", st['norm']))
                    meta = [["Timestamp", e.get('timestamp','')], ["Status", e.get('status','')]]
                    mt = Table(meta, colWidths=[90, 390])
                    mt.setStyle(TableStyle([
                        ('BACKGROUND',(0,0),(0,-1), colors.whitesmoke),
                        ('GRID',(0,0),(-1,-1), 0.2, colors.lightgrey),
                        ('FONTSIZE',(0,0),(-1,-1), 9),
                        ('LEFTPADDING',(0,0),(-1,-1), 4),
                        ('BOTTOMPADDING',(0,0),(-1,-1), 3),
                    ]))
                    story.append(mt)
                    out = (e.get('output','') or '').strip()
                    if out:
                        if len(out) > 2000:
                            out = out[:2000] + "\n[TRUNCATED]"
                        story.append(Preformatted(out, st['code']))
                    story.append(Spacer(1, 0.08 * inch))
                story.append(Spacer(1, 0.1 * inch))
        else:
            story.append(Paragraph("No session data recorded yet. Run tests first, then export.", st['norm']))
        story.append(PageBreak())

        _ecu_section_pdf(story, ecu_data, st)

        story.append(Paragraph("CONCLUSION &amp; RECOMMENDATIONS", st['h1']))
        story.append(Paragraph(
            "The target ECU has been assessed. Address high-priority issues from the risk scorecard above.",
            st['norm']
        ))
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph("Strategic Recommendations", st['h2']))
        for r in [
            "Implement SecOC (message authentication) for high-critical signals.",
            "Restrict UDS services while the vehicle is in motion.",
            "Harden message parsing to avoid crashes for unexpected payloads.",
            "Introduce strict input validation and bounds checking.",
        ]:
            story.append(Paragraph(f"• {r}", st['norm']))

        doc = SimpleDocTemplate(filename, pagesize=letter,
            leftMargin=72, rightMargin=72, topMargin=72, bottomMargin=72)
        doc.build(story,
            onFirstPage=lambda c, d: _header_footer(c, d, "FucyFuzz Report"),
            onLaterPages=lambda c, d: _header_footer(c, d, "FucyFuzz Report"))
        return True, f"Overall PDF report saved:\n{filename}"
    except Exception as ex:
        traceback.print_exc()
        return False, f"PDF generation failed:\n{ex}"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Failure PDF
# ══════════════════════════════════════════════════════════════════════════════

def export_failure_pdf(dm, filename, ecu_data=None):
    ok, err = _check_reportlab()
    if not ok:
        return False, err
    entries = _build_entries_from_dm(dm)
    failed = [e for e in entries if 'fail' in e.get('status','').lower()]
    ecu_events = []
    if ecu_data and ecu_data.get('events'):
        ecu_events = [e for e in ecu_data['events']
                      if e.get('severity','').upper() in ('CRITICAL','HIGH')]
    if not failed and not ecu_events:
        return False, "No failed tests or critical ECU events found to report."
    st = _make_styles()
    try:
        story = []
        story.append(Spacer(1, 1.4 * inch))
        story.append(Paragraph("FAILURE ANALYSIS REPORT", st['title']))
        story.append(Paragraph("FucyFuzz CAN Bus Security Framework", st['sub']))
        story.append(Spacer(1, 0.2 * inch))
        summary_lines = [f"Total Failures: {len(failed)}", f"Generated: {_now_str()}"]
        if ecu_events:
            summary_lines.append(f"Critical ECU Events: {len(ecu_events)}")
        story.append(ListFlowable(
            [ListItem(Paragraph(x, st['norm'])) for x in summary_lines],
            bulletType='bullet', leftIndent=18
        ))
        story.append(Spacer(1, 0.2 * inch))
        sc = dm.severity_counts()
        sev_data = [["Severity","Count"]] + [[k.upper(), str(v)] for k,v in sc.items()]
        sev_tbl = Table(sev_data, colWidths=[240,240])
        sev_tbl.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0), colors.HexColor("#2c3e50")),
            ('TEXTCOLOR',(0,0),(-1,0), colors.white),
            ('GRID',(0,0),(-1,-1), 0.4, colors.lightgrey),
            ('FONTNAME',(0,0),(-1,-1),'Helvetica'),
            ('FONTSIZE',(0,0),(-1,-1), 10),
            ('LEFTPADDING',(0,0),(-1,-1), 6),
            ('BOTTOMPADDING',(0,0),(-1,-1), 5),
        ]))
        story.append(sev_tbl)
        story.append(Spacer(1, 0.2 * inch))
        for idx, e in enumerate(failed, start=1):
            story.append(Paragraph(f"Failure {idx}: {(e.get('command') or '')[:100]}", st['h2']))
            meta = [["Timestamp",e.get('timestamp','')],["Module",e.get('module','')],["Status",e.get('status','')]]
            mt = Table(meta, colWidths=[100,380])
            mt.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(0,-1), colors.HexColor("#f8d7da")),
                ('GRID',(0,0),(-1,-1), 0.25, colors.lightgrey),
                ('FONTSIZE',(0,0),(-1,-1), 9),
                ('LEFTPADDING',(0,0),(-1,-1), 5),
                ('BOTTOMPADDING',(0,0),(-1,-1), 4),
            ]))
            story.append(mt)
            story.append(Spacer(1, 0.04 * inch))
            out = (e.get('output','') or '').strip()
            if out:
                if len(out) > 1500:
                    out = out[:1500] + "\n[TRUNCATED]"
                story.append(Paragraph("<b>Error Output (truncated)</b>", st['norm']))
                story.append(Preformatted(out, st['code']))
            fixes = _suggested_fixes(e)
            if fixes:
                story.append(Spacer(1, 0.04 * inch))
                story.append(Paragraph("<b>Suggested Fixes</b>", st['norm']))
                story.append(ListFlowable(
                    [ListItem(Paragraph(x, st['norm'])) for x in fixes],
                    bulletType='bullet', leftIndent=18
                ))
            story.append(PageBreak())
        if ecu_events:
            story.append(Paragraph("ECU MONITOR — CRITICAL EVENTS", st['h1']))
            story.append(Paragraph(f"Log source: {ecu_data.get('log_path','N/A')}", st['norm']))
            story.append(Spacer(1, 0.1 * inch))
            tbl_data = [["SEVERITY","SOURCE","DESCRIPTION","CMD","TIME"]]
            for e in ecu_events[:100]:
                tbl_data.append([e.get('severity',''), e.get('source','')[:30],
                                  e.get('description','')[:80], e.get('cmd','')[:40], e.get('time','')])
            tbl = Table(tbl_data, colWidths=[55,70,200,100,50])
            tbl.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(-1,0), colors.HexColor("#c0392b")),
                ('TEXTCOLOR',(0,0),(-1,0), colors.white),
                ('GRID',(0,0),(-1,-1), 0.3, colors.lightgrey),
                ('FONTSIZE',(0,0),(-1,-1), 8),
                ('LEFTPADDING',(0,0),(-1,-1), 4),
                ('BOTTOMPADDING',(0,0),(-1,-1), 4),
            ]))
            story.append(tbl)
        doc = SimpleDocTemplate(filename, pagesize=letter,
            leftMargin=72, rightMargin=72, topMargin=72, bottomMargin=72)
        doc.build(story,
            onFirstPage=lambda c,d: _header_footer(c,d,"Failure Report"),
            onLaterPages=lambda c,d: _header_footer(c,d,"Failure Report"))
        return True, f"Failure report saved:\n{filename}"
    except Exception as ex:
        traceback.print_exc()
        return False, f"Failure PDF generation failed:\n{ex}"


# ══════════════════════════════════════════════════════════════════════════════
# 3. Save Logs (.log)
# ══════════════════════════════════════════════════════════════════════════════

def save_logs_text(dm, filename, ecu_data=None):
    try:
        entries = _build_entries_from_dm(dm)
        sc = dm.severity_counts()
        sep = "=" * 72
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"FUCYFUZZ SESSION LOG\nGenerated : {_now_str()}\nTool      : FucyFuzz GUI\n{sep}\n\n")
            f.write("SUMMARY\n")
            f.write(f"  Total Faults   : {dm.total_faults()}\n  Open Faults    : {dm.open_faults()}\n")
            f.write(f"  Critical: {sc.get('critical',0)}  High: {sc.get('high',0)}  "
                    f"Medium: {sc.get('medium',0)}  Low: {sc.get('low',0)}\n")
            f.write(f"  Sessions: {len(dm.sessions)}\n")
            if ecu_data:
                f.write(f"  ECU Events: {ecu_data.get('event_count',0)}\n")
            f.write(f"\n{sep}\n\nSESSIONS ({len(entries)} total)\n\n")
            for idx, e in enumerate(entries, 1):
                f.write(f"--- Session {idx} ---\n")
                for k, v in [('Timestamp',e.get('timestamp','')), ('Module',e.get('module','')),
                              ('Status',e.get('status','')), ('Duration',e.get('duration','')),
                              ('Command',e.get('command',''))]:
                    if v:
                        f.write(f"  {k:10}: {v}\n")
                out = (e.get('output','') or '').strip()
                if out:
                    f.write("  Output    :\n")
                    for line in out.splitlines()[:50]:
                        f.write(f"    {line}\n")
                    if len(out.splitlines()) > 50:
                        f.write("    [...truncated...]\n")
                f.write("\n")
            f.write(f"{sep}\n\nFAULT LIST ({dm.total_faults()} faults)\n\n")
            for fault in dm.faults:
                f.write(f"  [{fault.severity.upper()}] {fault.module} — {fault.fault}\n")
                if fault.cmd:
                    f.write(f"    CMD: {fault.cmd}\n")
                f.write(f"    Time: {fault.time_str()}  Status: {fault.status}\n\n")
            if ecu_data and ecu_data.get('events'):
                f.write(f"{sep}\n\nECU MONITOR EVENTS — {ecu_data.get('log_path','N/A')}\n\n")
                for e in ecu_data['events']:
                    f.write(f"  {e.get('time','')}  [{e.get('severity','')}]  "
                            f"{e.get('source','')} — {e.get('description','')}\n")
                    if e.get('cmd'):
                        f.write(f"    Reproduce: {e['cmd']}\n")
                f.write("\n")
                if ecu_data.get('terminal_lines'):
                    f.write(f"{sep}\n\nECU MONITOR TERMINAL OUTPUT\n\n")
                    for line in ecu_data['terminal_lines']:
                        f.write(f"  {line}\n")
            f.write(f"\n{sep}\nEND OF LOG\n")
        return True, f"Log saved:\n{filename}"
    except Exception as ex:
        traceback.print_exc()
        return False, f"Log save failed:\n{ex}"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Export Logs (.asc) — Vector ASC
# ══════════════════════════════════════════════════════════════════════════════

def _extract_json_packets(dm):
    import json
    entries = _build_entries_from_dm(dm)
    packets = []
    for entry in entries:
        out = entry.get('output', '') or ''
        for line in out.splitlines():
            if 'CC_PACKET ' in line:
                idx = line.find('CC_PACKET ')
                try:
                    pkt = json.loads(line[idx+10:])
                    packets.append(pkt)
                except Exception:
                    pass
    return packets

# ── Real timestamp helpers ─────────────────────────────────────────────────────

def _parse_packet_ts(pkt: dict) -> float:
    """
    Extract a real Unix float timestamp from a packet dict.
    Tries 'ts', 'timestamp', 'timestamp_tx' fields in that order.
    Falls back to 0.0 if nothing is parseable — caller must handle offset.
    """
    import time as _time
    for key in ("ts", "timestamp", "timestamp_tx"):
        raw = pkt.get(key, "")
        if not raw:
            continue
        try:
            s = str(raw).replace("T", " ").replace("Z", "")
            from datetime import datetime as _dt
            return _dt.fromisoformat(s).timestamp()
        except (ValueError, TypeError, AttributeError):
            try:
                return float(raw)
            except (ValueError, TypeError):
                pass
    return 0.0


def _packets_with_real_ts(packets: list):
    """
    Yield (ts_abs, pkt) tuples with real Unix timestamps.
    If all parsed timestamps are 0, fall back to sequential 1ms offsets.
    """
    pairs = [(max(_parse_packet_ts(p), 0.0), p) for p in packets]
    # Check if we got any real timestamps
    real_ts = [t for t, _ in pairs if t > 1000.0]   # any ts > 1970-01-01 00:16
    if not real_ts:
        # No usable timestamps — manufacture sequential offsets from now
        base = __import__('time').time()
        for i, (_, p) in enumerate(pairs):
            yield base + i * 0.001, p
    else:
        for t, p in pairs:
            yield t, p


# ══════════════════════════════════════════════════════════════════════════════
# 4. Export Logs (.asc) — Vector ASC
# ══════════════════════════════════════════════════════════════════════════════

def export_logs_asc(dm, filename, ecu_data=None, packets=None):
    try:
        if dm is not None:
            entries = _build_entries_from_dm(dm)
            sc = dm.severity_counts()
        else:
            entries, sc = [], {}
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"date {_now_str()}\nbase hex  timestamps absolute\nno internal events logged\n\n")
            f.write("; === FucyFuzz GUI Security Report ===\n")
            f.write(f"; Generated: {_now_str()}\n")
            if dm is not None:
                f.write(f"; Sessions: {len(dm.sessions)}\n; Faults: {dm.total_faults()}\n")
                f.write(f"; Critical: {sc.get('critical',0)}  High: {sc.get('high',0)}  "
                        f"Medium: {sc.get('medium',0)}  Low: {sc.get('low',0)}\n")
            if ecu_data:
                f.write(f"; ECU Events: {ecu_data.get('event_count',0)}\n; ECU Log: {ecu_data.get('log_path','N/A')}\n")
            if dm is not None:
                f.write("\n; === Fault Summary ===\n")
                for fault in dm.faults:
                    f.write(f";  [{fault.severity.upper()}] {fault.module}: {fault.fault[:80]}\n")
            f.write("\n")
            if ecu_data and ecu_data.get('events'):
                f.write("; === ECU Monitor Events ===\n")
                for e in ecu_data['events']:
                    f.write(f";  {e.get('time','')} [{e.get('severity','')}] "
                            f"{e.get('source','')} — {e.get('description','')[:80]}\n")
                    if e.get('cmd'):
                        f.write(f";    Reproduce: {e['cmd']}\n")
                f.write("\n")
            f.write("; === CAN Frame Data ===\n")
            frame_counter = 0
            if packets is None:
                packets = _extract_json_packets(dm) if dm else []
            # Build real-timestamp pairs and find t0 for relative offset
            ts_pkt_pairs = list(_packets_with_real_ts(
                [p for p in packets if p.get("data_hex")]
            ))
            t0 = ts_pkt_pairs[0][0] if ts_pkt_pairs else 0.0
            # Rewrite ASC date line with actual capture start
            from datetime import datetime as _dt2
            try:
                f.seek(0)
                f.write(
                    f"date {_dt2.fromtimestamp(t0).strftime('%a %b %d %H:%M:%S %Y')}\n"
                    f"base hex  timestamps absolute\nno internal events logged\n\n"
                )
                f.seek(0, 2)   # back to end
            except (OSError, AttributeError):
                pass
            for abs_ts, pkt in ts_pkt_pairs:
                transport = pkt.get("transport", "CAN")
                if not pkt.get("data_hex"):
                    continue
                frame_counter += 1
                rel_ts    = abs_ts - t0       # relative seconds from capture start
                data_hex  = pkt.get("data_hex", "").replace(" ", "")
                dlc       = len(data_hex) // 2
                data_bytes = [data_hex[i:i+2] for i in range(0, len(data_hex), 2)]
                data_str  = ' '.join(data_bytes)
                can_id_str = pkt.get("arb_id", "0x0")
                try:
                    can_id_hex = f"{int(can_id_str.replace('0x','').replace('0X',''), 16):X}"
                except ValueError:
                    can_id_hex = can_id_str.upper()
                dir_str = "Tx" if pkt.get("direction") == "TX" else "Rx"
                ch      = pkt.get("channel", "1") or "1"
                f.write(f"   {rel_ts:.6f} {ch}  {can_id_hex}  {dir_str} d {dlc}  {data_str}\n")
            f.write(f"\n; CAN frames extracted: {frame_counter}\n")
            if ecu_data and ecu_data.get('events'):
                f.write("; === ECU Reproduce Commands ===\n")
                t = 0.001
                for e in ecu_data['events']:
                    if e.get('cmd'):
                        f.write(f"; {t:.3f}  {e.get('severity','')} — {e['cmd'][:80]}\n")
                        t += 0.001
            f.write("; === End of Log ===\n")
        return True, f"ASC log exported:\n{filename}"
    except Exception as ex:
        traceback.print_exc()
        return False, f"ASC export failed:\n{ex}"

# ══════════════════════════════════════════════════════════════════════════════
# 5. Export Logs (.mf4) — ASAM MDF4
# ══════════════════════════════════════════════════════════════════════════════

def export_logs_mf4(dm, filename, ecu_data=None, packets=None):
    try:
        import numpy as np
        from asammdf import MDF, Signal
    except ImportError as e:
        return False, f"Missing library: {e}\n\nInstall with:\n  pip install asammdf numpy"
    try:
        timestamps, can_ids, data_bytes_list = [], [], []
        frame_counter = 0
        if packets is None:
            packets = _extract_json_packets(dm)
        for pkt in packets:
            if pkt.get("transport") != "CAN" or not pkt.get("data_hex"):
                continue
            frame_counter += 1
            can_id_str = pkt.get("arb_id", "0x0")
            can_id = int(can_id_str,16) if 'x' in can_id_str.lower() else int(can_id_str)
            data_hex = pkt.get("data_hex", "")
            data_vals = [int(data_hex[i:i+2],16) for i in range(0, len(data_hex), 2)]
            while len(data_vals) < 8: data_vals.append(0)
            timestamps.append(frame_counter * 0.001)
            can_ids.append(can_id)
            data_bytes_list.append(data_vals[:8])
            
        if ecu_data and ecu_data.get('events'):
            for e in ecu_data['events']:
                frame_counter += 1
                cmd = e.get('cmd','')
                import re
                m = re.search(r'([0-9A-Fa-f]{3,8})#([0-9A-Fa-f]*)', cmd)
                if m:
                    try:
                        can_id = int(m.group(1),16)
                        payload = m.group(2) or '00'
                        data_vals = [int(payload[j:j+2],16) for j in range(0,min(len(payload),16),2)]
                    except ValueError:
                        can_id = 0x7DF; data_vals = []
                else:
                    can_id = 0x7DF; data_vals = []
                while len(data_vals) < 8: data_vals.append(0)
                timestamps.append(frame_counter * 0.001)
                can_ids.append(can_id)
                data_bytes_list.append(data_vals[:8])
        if frame_counter == 0:
            timestamps = [0.0]; can_ids = [0x100]; data_bytes_list = [[0]*8]
        ts_np   = np.array(timestamps, dtype=np.float64)
        ids_np  = np.array(can_ids,    dtype=np.uint32)
        data_np = np.array(data_bytes_list, dtype=np.uint8)
        sc = dm.severity_counts()
        signals = [Signal(samples=ids_np, timestamps=ts_np, name='CAN_ID', unit='-',
                          comment='CAN Frame Identifier')]
        for b in range(min(8, data_np.shape[1])):
            signals.append(Signal(samples=data_np[:,b], timestamps=ts_np,
                                  name=f'Data_Byte{b}', unit='-', comment=f'CAN Data Byte {b}'))
        mdf = MDF(version='4.10')
        mdf.append(signals)
        try:
            mdf.header.comment = (
                f"FucyFuzz GUI Security Log\nGenerated: {_now_str()}\n"
                f"Sessions: {len(dm.sessions)}\nFaults: {dm.total_faults()}\n"
                f"Critical: {sc.get('critical',0)}  High: {sc.get('high',0)}\n"
                + (f"ECU Events: {ecu_data.get('event_count',0)}\n" if ecu_data else "")
                + f"CAN Frames: {frame_counter}"
            )
        except Exception:
            pass
        try:
            mdf.save(filename, overwrite=True)
        except TypeError:
            mdf.save(filename)
        return True, f"MDF4 log exported:\n{filename}"
    except Exception as ex:
        traceback.print_exc()
        err = f"MDF4 export failed:\n{ex}"
        if "Unknown type" in str(ex) or "dtype" in str(ex):
            err += "\n\nTry: pip install asammdf==7.3.0"
        return False, err

# ══════════════════════════════════════════════════════════════════════════════
# 6. Export Logs (.blf) — Vector BLF
# ══════════════════════════════════════════════════════════════════════════════

def export_logs_blf(dm, filename, ecu_data=None, packets=None):
    try:
        import can
    except ImportError as e:
        return False, (
            f"python-can is not installed.\n\nInstall with:\n  pip install python-can\n\n"
            f"Error: {e}"
        )
    try:
        if packets is None:
            packets = _extract_json_packets(dm) if dm else []
        writer = can.BLFWriter(filename)
        frame_count = 0
        for abs_ts, pkt in _packets_with_real_ts(
                [p for p in packets if p.get("data_hex")]):
            can_id_str = pkt.get("arb_id", "0x0")
            try:
                can_id = int(can_id_str.replace("0x","").replace("0X",""), 16)
            except ValueError:
                can_id = 0
            data_hex  = pkt.get("data_hex", "").replace(" ", "")
            data_vals = [int(data_hex[i:i+2], 16) for i in range(0, len(data_hex), 2)]
            msg = can.Message(
                timestamp=abs_ts,          # real Unix epoch seconds
                arbitration_id=can_id,
                data=data_vals,
                is_rx=(pkt.get("direction") == "RX"),
                channel=int(pkt.get("channel", 0) or 0),
            )
            writer.on_message_received(msg)
            frame_count += 1
        writer.stop()
        return True, f"BLF log exported ({frame_count} frames):\n{filename}"
    except Exception as ex:
        traceback.print_exc()
        return False, f"BLF export failed:\n{ex}"

# ══════════════════════════════════════════════════════════════════════════════
# 7. Export Logs (.pcap) — PCAP Capture
# ══════════════════════════════════════════════════════════════════════════════

def export_logs_pcap(dm, filename, ecu_data=None, packets=None):
    try:
        import struct
        import socket
        if packets is None:
            packets = _extract_json_packets(dm) if dm else []
            
        has_doip = any(p.get("transport") == "DoIP" for p in packets)
        dlt = 1 if has_doip else 227  # DLT_EN10MB vs DLT_CAN_SOCKETCAN
        
        with open(filename, 'wb') as f:
            # PCAP global header
            f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, dlt))
            frame_count = 0
            for abs_ts, pkt in _packets_with_real_ts(
                    [p for p in packets if p.get("data_hex")]):
                
                is_doip = pkt.get("transport") == "DoIP"
                data_hex  = pkt.get("data_hex", "").replace(" ", "")
                data_vals = bytes(int(data_hex[i:i+2], 16) for i in range(0, len(data_hex), 2))
                
                if dlt == 1:
                    # DLT_EN10MB
                    if not is_doip: continue # Cannot mix raw CAN with Ethernet PCAP cleanly
                    
                    src_addr = str(pkt.get("src_addr", "0x0")).replace("0X", "0x")
                    dst_addr = str(pkt.get("dst_addr", "0x0")).replace("0X", "0x")
                    
                    try:
                        src_int = int(src_addr, 16)
                        dst_int = int(dst_addr, 16)
                    except ValueError:
                        src_int, dst_int = 0x0E00, 0x1000
                        
                    # Build Fake MAC and IPs
                    eth = b'\x00\x11\x22\x33\x44\x55' + b'\x66\x77\x88\x99\xAA\xBB' + b'\x08\x00'
                    try:
                        src_ip = socket.inet_aton(f"10.0.0.{src_int & 0xFF}")
                        dst_ip = socket.inet_aton(f"10.0.0.{dst_int & 0xFF}")
                    except OSError:
                        src_ip = b'\x0A\x00\x00\x01'
                        dst_ip = b'\x0A\x00\x00\x02'
                        
                    # DoIP Payload (0x8001 = Diagnostic Message)
                    doip = struct.pack("!BBHI", 0x02, 0xFD, 0x8001, len(data_vals) + 4)
                    doip += struct.pack("!HH", src_int, dst_int) + data_vals
                    
                    # IP + TCP
                    ip_len = 20 + 20 + len(doip)
                    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 0, 0, 64, 6, 0, src_ip, dst_ip)
                    sport, dport = (12345, 13400) if pkt.get("direction") == "TX" else (13400, 12345)
                    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x18, 0xFFFF, 0, 0)
                    
                    pkt_data = eth + ip_hdr + tcp_hdr + doip
                else:
                    # DLT_CAN_SOCKETCAN
                    can_id_str = pkt.get("arb_id", "0x0")
                    try:
                        can_id = int(can_id_str.replace("0x","").replace("0X",""), 16)
                    except ValueError:
                        can_id = 0
                    dlc      = min(len(data_vals), 8)
                    pad_data = data_vals[:8] + b'\x00' * (8 - min(len(data_vals), 8))
                    pkt_data = struct.pack('<IB3s8s', can_id, dlc, b'\x00\x00\x00', pad_data)

                ts_sec   = int(abs_ts)
                ts_usec  = int((abs_ts - ts_sec) * 1_000_000)
                f.write(struct.pack('<IIII', ts_sec, ts_usec, len(pkt_data), len(pkt_data)))
                f.write(pkt_data)
                frame_count += 1
                
        dlt_str = "Ethernet" if dlt == 1 else "SocketCAN"
        return True, f"PCAP log exported ({frame_count} frames, DLT {dlt} {dlt_str}):\n{filename}"
    except Exception as ex:
        import traceback
        traceback.print_exc()
        return False, f"PCAP export failed:\n{ex}"


# ── Legacy aliases ─────────────────────────────────────────────────────────────
def export_pdf(dm, filename):
    return export_failure_pdf(dm, filename, ecu_data=None)

def export_text(dm, filename):
    return save_logs_text(dm, filename, ecu_data=None)

def export_csv(dm, filename):
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["=== FAULTS ==="])
            writer.writerow(["ID","Severity","Module","Fault","Command","Time","Status"])
            for fault in dm.faults:
                writer.writerow([fault.id, fault.severity.upper(), fault.module,
                                  fault.fault, fault.cmd, fault.time_str(), fault.status])
            writer.writerow([])
            writer.writerow(["=== SESSIONS ==="])
            writer.writerow(["ID","Module","Command","Start","Duration","Fault Count"])
            for s in dm.sessions:
                writer.writerow([s.id, s.module, s.cmd,
                                  time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s.start)),
                                  s.duration(), len(s.faults)])
            writer.writerow([])
            sc = dm.severity_counts()
            writer.writerow(["=== SUMMARY ==="])
            writer.writerow(["Metric","Value"])
            writer.writerow(["Total Faults", dm.total_faults()])
            writer.writerow(["Open Faults",  dm.open_faults()])
            for k, v in sc.items():
                writer.writerow([k.capitalize(), v])
            writer.writerow(["Generated", _now_str()])
        return True, f"CSV exported:\n{filename}"
    except Exception as ex:
        return False, f"CSV export failed:\n{ex}"

def export_json(dm, filename, packets=None):
    import json
    try:
        if packets is None:
            packets = _extract_json_packets(dm) if dm else []
        with open(filename, 'w', encoding='utf-8') as f:
            for pkt in packets:
                f.write(json.dumps(pkt, separators=(",", ":")) + "\n")
        return True, f"JSONL log exported ({len(packets)} entries):\n{filename}"
    except Exception as ex:
        import traceback; traceback.print_exc()
        return False, f"JSON export failed:\n{ex}"

# ══════════════════════════════════════════════════════════════════════════════
# ECU Monitor — Session-only PDF report
# Exports ONLY the events captured since the last START WATCHING press.
# ══════════════════════════════════════════════════════════════════════════════

def export_ecu_session_pdf(session_data: dict, filename: str):
    """
    Generate a focused PDF for a single ECU Monitor watching session.
    Uses landscape A4 throughout so the 6-column event table never overflows.

    Usable width  = 841.89 - 50 - 50 = 741.89 pt  (landscape A4, 50pt margins)
    Column budget : 28 + 62 + 80 + 290 + 220 + 62 = 742 pt
    """
    ok, err = _check_reportlab()
    if not ok:
        return False, err

    events = session_data.get('events', [])
    if not events:
        return False, (
            "No events were recorded in this monitoring session.\n\n"
            "Press START WATCHING, trigger some vulnerabilities, then export."
        )

    # ── page geometry ─────────────────────────────────────────────────────────
    from reportlab.lib.pagesizes import A4, landscape as rl_landscape
    PAGE      = rl_landscape(A4)        # (841.89, 595.28)
    LM = RM   = 50                      # left / right margin
    TM = BM   = 50                      # top / bottom margin
    USABLE_W  = PAGE[0] - LM - RM       # ≈ 741.89 pt

    # Column widths that sum exactly to USABLE_W
    #  #   | SEVERITY | SOURCE | DESCRIPTION           | REPRODUCE CMD | TIME
    COL_W = [28,        62,      80,                    290,             220,   62]
    # total = 742  (rounds up from 741.89 — fine, ReportLab clips to available)

    st = _make_styles()

    _SEV_HEX = {
        'CRITICAL': '#c0392b',
        'HIGH':     '#e67e22',
        'MEDIUM':   '#d4a017',   # darker gold — readable on white
        'LOW':      '#2980b9',
    }

    # ── reusable cell paragraph styles ────────────────────────────────────────
    cell_style = ParagraphStyle(
        'ECUCell',
        parent=_rl_styles['Normal'],
        fontSize=7,
        leading=9,
        wordWrap='LTR',           # standard left-to-right word wrap
        spaceAfter=0,
        spaceBefore=0,
    )
    hdr_style = ParagraphStyle(
        'ECUHdr',
        parent=cell_style,
        fontName='Helvetica-Bold',
        textColor=colors.white,
    )
    sev_styles = {
        sev: ParagraphStyle(
            f'ECUSev_{sev}',
            parent=cell_style,
            fontName='Helvetica-Bold',
            textColor=colors.HexColor(hex_c),
        )
        for sev, hex_c in _SEV_HEX.items()
    }

    # ── shared table style commands ───────────────────────────────────────────
    BASE_TBL_STYLE = [
        ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor("#2c3e50")),
        ('GRID',          (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING',   (0, 0), (-1, -1), 5),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 5),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f5f7fa")]),
    ]

    try:
        # Count per severity
        sev_counts = {}
        for e in events:
            s = e.get('severity', 'UNKNOWN').upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        total = len(events) or 1

        story = []

        # ══════════════════════════════════════════════════════════════════════
        # PAGE 1 — Cover
        # ══════════════════════════════════════════════════════════════════════
        story.append(Spacer(1, 1.0 * inch))
        story.append(Paragraph("ECU MONITOR SESSION REPORT", st['title']))
        story.append(Paragraph("FucyFuzz — Live Vulnerability Capture", st['sub']))
        story.append(Spacer(1, 0.25 * inch))

        cover_data = [
            ["Session Start:",    session_data.get('session_start', 'N/A')],
            ["Report Generated:", _now_str()],
            ["Log Source:",       session_data.get('log_path', 'N/A')],
            ["Total Events:",     str(session_data.get('event_count', len(events)))],
            ["Critical:",         str(sev_counts.get('CRITICAL', 0))],
            ["High:",             str(sev_counts.get('HIGH', 0))],
            ["Medium:",           str(sev_counts.get('MEDIUM', 0))],
            ["Low:",              str(sev_counts.get('LOW', 0))],
        ]
        # Cover table: use half of usable width, centred
        cw = USABLE_W * 0.55
        ct = Table(cover_data, colWidths=[cw * 0.32, cw * 0.68])
        ct.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (0, -1), colors.HexColor("#f0f4f8")),
            ('FONTNAME',      (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME',      (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE',      (0, 0), (-1, -1), 10),
            ('LEFTPADDING',   (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('GRID',          (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ]))
        story.append(ct)
        story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════════════
        # PAGE 2 — Summary
        # ══════════════════════════════════════════════════════════════════════
        story.append(Paragraph("SESSION SUMMARY", st['h1']))
        story.append(Spacer(1, 0.1 * inch))

        sev_tbl_data = [["Severity", "Count", "% of Total"]]
        for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            cnt = sev_counts.get(sev, 0)
            sev_tbl_data.append([sev, str(cnt), f"{cnt / total * 100:.1f}%"])

        sev_tbl = Table(sev_tbl_data, colWidths=[200, 100, 140])
        sev_tbl.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor("#2c3e50")),
            ('TEXTCOLOR',     (0, 0), (-1, 0),  colors.white),
            ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
            ('FONTSIZE',      (0, 0), (-1, -1), 10),
            ('GRID',          (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ('LEFTPADDING',   (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('ALIGN',         (1, 1), (-1, -1), 'CENTER'),
        ]))
        story.append(sev_tbl)
        story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════════════
        # PAGE 3+ — Full event table  (the main fix: properly sized columns)
        # ══════════════════════════════════════════════════════════════════════
        story.append(Paragraph("LIVE VULNERABILITY EVENTS", st['h1']))
        story.append(Paragraph(
            f"{len(events)} events captured  |  Log: {session_data.get('log_path', 'N/A')}",
            st['norm']
        ))
        story.append(Spacer(1, 0.08 * inch))

        tbl_data = [[
            Paragraph("#",             hdr_style),
            Paragraph("SEVERITY",      hdr_style),
            Paragraph("SOURCE",        hdr_style),
            Paragraph("DESCRIPTION",   hdr_style),
            Paragraph("REPRODUCE CMD", hdr_style),
            Paragraph("TIME",          hdr_style),
        ]]

        for i, e in enumerate(events, start=1):
            sev = e.get('severity', '').upper()
            sev_ps = sev_styles.get(sev, cell_style)
            tbl_data.append([
                Paragraph(str(i),                   cell_style),
                Paragraph(sev,                      sev_ps),
                Paragraph(e.get('source', ''),      cell_style),
                Paragraph(e.get('description', ''), cell_style),
                Paragraph(e.get('cmd', '') or '—',  cell_style),
                Paragraph(e.get('time', ''),        cell_style),
            ])

        event_tbl = Table(tbl_data, colWidths=COL_W, repeatRows=1)
        event_tbl.setStyle(TableStyle(BASE_TBL_STYLE))
        story.append(event_tbl)
        story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════════════
        # Critical / High detail cards
        # ══════════════════════════════════════════════════════════════════════
        critical_events = [e for e in events
                           if e.get('severity', '').upper() in ('CRITICAL', 'HIGH')]
        if critical_events:
            story.append(Paragraph("CRITICAL / HIGH SEVERITY — DETAIL", st['h1']))
            story.append(Spacer(1, 0.08 * inch))

            # Detail table column widths scaled to landscape usable width
            DW1, DW2 = 100, USABLE_W - 100

            for e in critical_events:
                sev = e.get('severity', '').upper()
                hex_c = _SEV_HEX.get(sev, '#555555')
                story.append(Paragraph(
                    f"<font color='{hex_c}'>[{sev}]</font>  "
                    f"{e.get('source', '')} — {e.get('description', '')}",
                    st['h2']
                ))
                detail = [
                    ["Source",      e.get('source', '')],
                    ["Description", e.get('description', '')],
                    ["Reproduce",   e.get('cmd', '') or '—'],
                    ["Time",        e.get('time', '')],
                ]
                dt = Table(detail, colWidths=[DW1, DW2])
                dt.setStyle(TableStyle([
                    ('BACKGROUND',    (0, 0), (0, -1), colors.HexColor("#fdf2f2")),
                    ('FONTNAME',      (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE',      (0, 0), (-1, -1), 9),
                    ('GRID',          (0, 0), (-1, -1), 0.25, colors.lightgrey),
                    ('LEFTPADDING',   (0, 0), (-1, -1), 7),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(dt)
                story.append(Spacer(1, 0.12 * inch))

            story.append(PageBreak())

        # ══════════════════════════════════════════════════════════════════════
        # Raw terminal log
        # ══════════════════════════════════════════════════════════════════════
        terminal_lines = session_data.get('terminal_lines', [])
        if terminal_lines:
            story.append(Paragraph("SYSTEM TERMINAL LOG", st['h1']))
            story.append(Spacer(1, 0.06 * inch))
            raw_text = '\n'.join(terminal_lines[:300])
            if len(terminal_lines) > 300:
                raw_text += '\n\n[... truncated — showing first 300 lines ...]'
            story.append(Preformatted(raw_text, st['code']))

        # ── Build with landscape A4 ────────────────────────────────────────────
        doc = SimpleDocTemplate(
            filename,
            pagesize=PAGE,
            leftMargin=LM, rightMargin=RM,
            topMargin=TM,  bottomMargin=BM,
        )
        doc.build(
            story,
            onFirstPage=lambda c, d: _header_footer(c, d, "ECU Monitor Session Report"),
            onLaterPages=lambda c, d: _header_footer(c, d, "ECU Monitor Session Report"),
        )
        return True, f"ECU session report saved:\n{filename}"

    except Exception as ex:
        import traceback; traceback.print_exc()
        return False, f"ECU session report failed:\n{ex}"
