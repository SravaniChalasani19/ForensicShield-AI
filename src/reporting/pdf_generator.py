import os
import uuid
import hashlib
import json
from xml.sax.saxutils import escape
from src.ml.evaluator import ForensicEvaluator
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable,
    Image,
    PageBreak,
)

from config import BASE_DIR, REPORTS_DIR, LEGAL_DISCLAIMER, APP_NAME, MODEL_VERSION
from src.storage.db import get_db_connection
from src.audit.audit_trail import AuditTrail
from src.explainability.shap_explainer import ForensicShapExplainer, SHAP_CAVEAT
from src.investigation.timeline import TimelineInvestigator

class ForensicPdfReportGenerator:
    """
    Generates structured, investigator-ready forensic PDF reports
    documenting case metadata, evidence hashes, ML/rule findings, SHAP attributions,
    timeline context, and cryptographic audit records.
    """

    @classmethod
    def generate_case_report(
        cls,
        case_id: str,
        examiner_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        conn = get_db_connection()
        cur = conn.cursor()

        # 1. Fetch Case
        cur.execute("SELECT * FROM cases WHERE case_id = ?;", (case_id,))
        case_row = cur.fetchone()
        if not case_row:
            conn.close()
            raise ValueError(f"Case with ID '{case_id}' does not exist.")
        case_data = dict(case_row)

        cur.execute("SELECT COUNT(*) as count FROM reports WHERE case_id = ?;", (case_id,))
        rep_count = cur.fetchone()["count"]
        from config import MAX_REPORTS_PER_CASE
        if rep_count >= MAX_REPORTS_PER_CASE:
            conn.close()
            raise ValueError(f"Report limit reached: A case may contain at most {MAX_REPORTS_PER_CASE} reports.")

        # 2. Fetch Evidence
        cur.execute("SELECT * FROM evidence WHERE case_id = ? ORDER BY ingested_at ASC;", (case_id,))
        evidence_rows = [dict(r) for r in cur.fetchall()]

        # 3. Fetch Flagged / Analyzed Events
        cur.execute("""
            SELECT * FROM events 
            WHERE case_id = ? AND (predicted_label = 'suspicious' OR rule_flags IS NOT NULL)
            ORDER BY timestamp_utc ASC, event_id ASC;
        """, (case_id,))

        def has_rule_flags(value):
            if not value:
                return False

            if isinstance(value, str):
                try:
                    return bool(json.loads(value))
                except ValueError:
                    return bool(value.strip())

            return bool(value)

        flagged_events = [
            dict(r) for r in cur.fetchall()
        ]

        flagged_events = [
            event for event in flagged_events
            if event.get("predicted_label") == "suspicious"
            or has_rule_flags(event.get("rule_flags"))
        ]

        # 4. Fetch All Events count
        cur.execute("SELECT COUNT(*) as total FROM events WHERE case_id = ?;", (case_id,))
        total_events_count = cur.fetchone()["total"]

        # 5. Fetch Audit Log
        cur.execute("SELECT * FROM audit_log WHERE case_id = ? ORDER BY audit_id ASC;", (case_id,))
        audit_rows = [dict(r) for r in cur.fetchall()]

        conn.close()

        # Fetch timeline and gaps
        timeline_data = TimelineInvestigator.get_case_timeline(case_id)
        log_gaps = timeline_data.get("log_gaps", [])

        # Prepare report document
        report_id = f"REP-{uuid.uuid4().hex[:8].upper()}"
        filename = f"{case_id}_{report_id}.pdf"
        output_path = REPORTS_DIR / filename

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
        )

        styles = getSampleStyleSheet()

        # Custom typography
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            alignment=1, # Center
        )
        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#475569"),
            alignment=1,
        )
        h1_style = ParagraphStyle(
            "ReportH1",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=10,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#1e293b"),
        )
        disclaimer_style = ParagraphStyle(
            "ReportDisclaimer",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#991b1b"),
        )
        table_cell_style = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor("#1e293b"),
        )
        table_cell_code = ParagraphStyle(
            "TableCellCode",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=6.5,
            leading=8,
            textColor=colors.HexColor("#0f172a"),
        )

        story = []

        # Header Block
        story.append(Paragraph(f"{APP_NAME} — FORENSIC INVESTIGATION REPORT", title_style))
        story.append(Paragraph("Anti-Forensic Technique Detection via Natural Language Processing for Ransomware Incident Response", subtitle_style))
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

        # Legal & Scientific Integrity Notice
        disclaimer_box = [
            [Paragraph(f"<b>CRITICAL LEGAL DISCLAIMER:</b> {LEGAL_DISCLAIMER}", disclaimer_style)]
        ]
        t_disc = Table(disclaimer_box, colWidths=[7.5 * inch])
        t_disc.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#fef2f2")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#f87171")),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t_disc)
        story.append(Spacer(1, 10))

        # Section 1: Case & Examiner Details
        story.append(Paragraph("1. Case Identification & Examiner Metadata", h1_style))
        examiner = examiner_override or case_data.get("examiner") or "Forensic Examiner"
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        case_meta_table = [
            [
                Paragraph(f"<b>Case ID:</b> {case_data['case_id']}", body_style),
                Paragraph(f"<b>Report ID:</b> {report_id}", body_style)
            ],
            [
                Paragraph(f"<b>Case Title:</b> {case_data['case_title']}", body_style),
                Paragraph(f"<b>Report Generated:</b> {now_utc}", body_style)
            ],
            [
                Paragraph(f"<b>Lead Examiner:</b> {examiner}", body_style),
                Paragraph(f"<b>Total Log Events Processed:</b> {total_events_count}", body_style)
            ],
            [
                Paragraph(f"<b>Case Description:</b> {case_data.get('description') or 'N/A'}", body_style),
                Paragraph(f"<b>Flagged Candidate Findings:</b> {len(flagged_events)}", body_style)
            ],
        ]
        t_case = Table(case_meta_table, colWidths=[3.75 * inch, 3.75 * inch])
        t_case.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_case)
        story.append(Spacer(1, 10))

        # Section 2: Chain of Custody & Evidence Hash Integrity
        story.append(Paragraph("2. Evidence Chain of Custody & Cryptographic Integrity (SHA-256)", h1_style))
        if evidence_rows:
            ev_headers = ["Evidence ID", "Original Filename", "Ingest Timestamp (UTC)", "Size (Bytes)", "Original SHA-256 Digest"]
            ev_data = [[Paragraph(f"<b>{h}</b>", table_cell_style) for h in ev_headers]]
            for ev in evidence_rows:
                ev_data.append([
                    Paragraph(ev["evidence_id"], table_cell_style),
                    Paragraph(ev["original_filename"], table_cell_style),
                    Paragraph(ev["ingested_at"][:19], table_cell_style),
                    Paragraph(str(ev["file_size_bytes"]), table_cell_style),
                    Paragraph(ev["sha256_hash"], table_cell_code),
                ])
            t_ev = Table(ev_data, repeatRows=1, colWidths=[1.1 * inch, 1.4 * inch, 1.3 * inch, 0.9 * inch, 2.8 * inch])
            t_ev.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#94a3b8")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(t_ev)
        else:
            story.append(Paragraph("No physical or digital evidence artifacts recorded for this case.", body_style))
        story.append(Spacer(1, 10))

        # Section 3: Detection Methodology & Model Provenance
        story.append(Paragraph("3. Detection Methodology & Machine Learning Provenance", h1_style))
        method_text = (
            "<b>Integrated Pipeline Architecture:</b> Evidence intake preserves original raw bytes with SHA-256 "
            "digests. Log records are normalized into canonical schema while retaining unmodified raw messages. "
            "NLP feature extraction employs sublinear TF-IDF n-grams (1-2) fitted strictly on the training distribution. "
            "A balanced Random Forest ensemble classifies each event as Normal vs Suspicious (investigative triage). "
            "Independent heuristic rules aligned with Anti-Forensics SoK (2026) highlight explicit command signatures "
            "separately from statistical model probabilities."
        )
        story.append(Paragraph(method_text, body_style))
        evaluation = ForensicEvaluator.get_evaluation_status()

        story.append(Spacer(1, 6))
        story.append(Paragraph(
            "<b>Model Evaluation and Scientific Limitations</b>",
            body_style
        ))

        if (
            evaluation.get("evaluated")
            and evaluation.get("dataset_name")
            == "Cleaned Synthetic Held-Out Test Dataset"
        ):
            metrics = evaluation.get("metrics") or {}
            counts = evaluation.get("sample_counts") or {}

            evaluation_text = (
                "<b>Evaluation Type:</b> Preliminary synthetic evaluation.<br/>"
                f"<b>Test Records:</b> {counts.get('total', 0)}<br/>"
                f"<b>Accuracy:</b> {metrics.get('accuracy', 0)*100:.2f}%<br/>"
                f"<b>Precision:</b> {metrics.get('precision', 0)*100:.2f}%<br/>"
                f"<b>Recall:</b> {metrics.get('recall', 0)*100:.2f}%<br/>"
                f"<b>F1-Score (Suspicious):</b> "
                f"{metrics.get('f1_score', 0)*100:.2f}%<br/>"
                f"<b>False Positive Rate:</b> "
                f"{metrics.get('false_positive_rate', 0)*100:.2f}%"
            )

            story.append(Paragraph(evaluation_text, body_style))
        else:
            story.append(Paragraph(
                "Cleaned synthetic evaluation results unavailable.",
                body_style
            ))

        story.append(Spacer(1, 5))

        story.append(Paragraph(
            "<b>Independent External Validation:</b> NOT EVALUATED.<br/>"
            "External datasets have been acquired and analyzed. "
            "Independent anti-forensic labels remain unavailable. "
            "Similar-template leakage risk remains. "
            "Synthetic evaluation results do not establish real-world "
            "performance. Findings require independent investigator review.",
            disclaimer_style
        ))

        story.append(Paragraph(
            "The evaluation metrics describe the stored benchmark results, "
            "not the accuracy of findings in this individual case.",
            body_style
        ))
        story.append(Spacer(1, 10))

        # Section 4: Candidate Anti-Forensic Findings
        story.append(Paragraph(f"4. Candidate Anti-Forensic Findings ({len(flagged_events)} Events)", h1_style))
        if flagged_events:
            flag_headers = ["Event ID", "Timestamp (UTC)", "Host", "User", "Source", "Score", "Raw Command / Message"]
            flag_data = [[Paragraph(f"<b>{h}</b>", table_cell_style) for h in flag_headers]]
            for fe in flagged_events:
                src = "RULE+ML" if (fe.get("predicted_label") == "suspicious" and has_rule_flags(fe.get("rule_flags"))) else ("RULE" if has_rule_flags(fe.get("rule_flags")) else "ML")
                score_str = f"{fe['score']:.2f}" if fe.get("score") is not None else "N/A"
                raw_snippet = str(fe.get("raw_message") or "")
                if len(raw_snippet) > 85:
                    raw_snippet = raw_snippet[:82] + "..."
                flag_data.append([
                    Paragraph(fe["event_id"], table_cell_style),
                    Paragraph((fe.get("timestamp_utc") or "N/A")[:19], table_cell_style),
                    Paragraph(fe.get("host") or "N/A", table_cell_style),
                    Paragraph(fe.get("user") or "N/A", table_cell_style),
                    Paragraph(src, table_cell_style),
                    Paragraph(score_str, table_cell_style),
                    Paragraph(escape(raw_snippet), table_cell_code),
                ])
            t_flag = Table(flag_data, repeatRows=1, colWidths=[1.1 * inch, 1.2 * inch, 0.9 * inch, 0.8 * inch, 0.7 * inch, 0.5 * inch, 2.3 * inch])
            t_flag.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#fecdd3")),
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#f43f5e")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#fda4af")),
                ('PADDING', (0,0), (-1,-1), 3),
            ]))
            story.append(t_flag)
        else:
            story.append(Paragraph("No events were flagged as suspicious or matched anti-forensic heuristic rules.", body_style))
        story.append(Spacer(1, 10))

        
        # Section 5: Complete Event-wise Explanations

        story.append(Paragraph(
            "5. Event-wise Detection Explanations",
            h1_style
        ))

        story.append(Paragraph(
            escape(SHAP_CAVEAT),
            disclaimer_style
        ))

        story.append(Paragraph(
            "Every flagged event is listed with its detection "
            "source, available model explanation and rule rationale. "
            "Candidate findings require investigator review.",
            body_style
        ))

        explained_count = 0

        for fe in flagged_events:

            event_id = str(fe.get("event_id") or "N/A")
            ml_flag = fe.get("predicted_label") == "suspicious"
            rule_flag = has_rule_flags(fe.get("rule_flags"))

            source = (
                "RULE + ML" if ml_flag and rule_flag
                else "RULE" if rule_flag
                else "ML"
            )

            story.append(Paragraph(
                "<b>Event ID:</b> " + escape(event_id),
                body_style
            ))

            story.append(Paragraph(
                "<b>Detection source:</b> " + source,
                body_style
            ))

            if rule_flag:
                raw_flags = fe.get("rule_flags")

                try:
                    rules = (
                        json.loads(raw_flags)
                        if isinstance(raw_flags, str)
                        else raw_flags
                    )
                except (ValueError, TypeError):
                    rules = []

                if isinstance(rules, list) and rules:
                    for rule in rules:
                        if isinstance(rule, dict):
                            reason = (
                                str(rule.get("rule_id", "")) + " - "
                                + str(rule.get("description")
                                      or rule.get("name")
                                      or rule.get("technique")
                                      or "Rule indicator matched")
                            )
                        else:
                            reason = str(rule)

                        story.append(Paragraph(
                            "<b>Rule rationale:</b> " + escape(reason),
                            body_style
                        ))
                else:
                    story.append(Paragraph(
                        "Rule indicator recorded; detailed rationale unavailable.",
                        body_style
                    ))

            if ml_flag:
                norm_text = (
                    fe.get("normalized_text")
                    or fe.get("raw_message")
                    or ""
                )

                try:
                    explanation = (
                        ForensicShapExplainer.explain_log_event(norm_text)
                    )

                    status = explanation.get("status", "UNKNOWN")
                    tokens = explanation.get("tokens") or []

                    story.append(Paragraph(
                        "<b>SHAP status:</b> " + escape(str(status)),
                        body_style
                    ))

                    if status == "SUCCESS" and tokens:
                        for token in tokens:
                            feature = str(token.get("feature", "N/A"))
                            contribution = str(
                                token.get("contribution", "N/A")
                            )

                            story.append(Paragraph(
                                "Feature: " + escape(feature)
                                + " | Contribution: "
                                + escape(contribution),
                                table_cell_style
                            ))

                        story.append(Paragraph(
                            "<b>Model rationale:</b> "
                            + escape(str(explanation.get("rationale", "N/A"))),
                            body_style
                        ))
                    else:
                        story.append(Paragraph(
                            "Valid token attribution unavailable. "
                            "Independent review is required.",
                            body_style
                        ))

                except Exception:
                    story.append(Paragraph(
                        "SHAP explanation could not be generated. "
                        "Independent review is required.",
                        body_style
                    ))

            else:
                story.append(Paragraph(
                    "Rule-only finding. The ML classifier did not "
                    "classify this event as suspicious.",
                    body_style
                ))

            explained_count += 1
            story.append(Spacer(1, 8))

        if not flagged_events:
            story.append(Paragraph(
                "No flagged events available for explanation.",
                body_style
            ))

        story.append(Paragraph(
            f"Event-wise entries: {explained_count}/{len(flagged_events)}",
            body_style
        ))

        story.append(Spacer(1, 8))


        # Section 6: Log Gaps & Contextual Timeline
        story.append(Paragraph("6. Log Continuity & Silent Logging Gaps", h1_style))
        if log_gaps:
            gap_headers = ["Host", "Gap Start (UTC)", "Gap End (UTC)", "Duration (Mins)", "Preceding Event", "Subsequent Event"]
            gap_data = [[Paragraph(f"<b>{h}</b>", table_cell_style) for h in gap_headers]]
            for g in log_gaps[:10]:
                gap_data.append([
                    Paragraph(g["host"], table_cell_style),
                    Paragraph(g["start_time"][:19], table_cell_style),
                    Paragraph(g["end_time"][:19], table_cell_style),
                    Paragraph(str(g["gap_duration_minutes"]), table_cell_style),
                    Paragraph(g["preceding_event_id"], table_cell_style),
                    Paragraph(g["subsequent_event_id"], table_cell_style),
                ])
            t_gap = Table(gap_data, repeatRows=1, colWidths=[1.1 * inch, 1.4 * inch, 1.4 * inch, 1.0 * inch, 1.3 * inch, 1.3 * inch])
            t_gap.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#fef3c7")),
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#f59e0b")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#fde68a")),
                ('PADDING', (0,0), (-1,-1), 3),
            ]))
            story.append(t_gap)
        else:
            story.append(Paragraph("No silent log gaps exceeding the configured threshold were identified.", body_style))
        story.append(Spacer(1, 10))

        # Section 7: Audit Trail Verification
        story.append(Paragraph("7. Case Investigation Audit Trail & Cryptographic Chaining", h1_style))
        chain_status = AuditTrail.verify_chain(case_id)
        status_color = "#15803d" if chain_status["is_valid"] else "#b91c1c"
        story.append(Paragraph(
            f"<b>Cryptographic Hash Chain Status:</b> <font color='{status_color}'><b>{'VALID (Integrity Verified)' if chain_status['is_valid'] else 'INVALID - REVIEW REQUIRED'}</b></font> (Verified {chain_status['total_entries']} case audit blocks)",
            body_style
        ))
        story.append(Spacer(1, 6))

        # Section 8: Examiner Sign-off
        story.append(Spacer(1, 10))
        story.append(Paragraph("8. Examiner Attestation & Sign-off", h1_style))
        sig_data = [
            [
                Paragraph("<b>Primary Forensic Examiner</b><br/><br/>________________________________________<br/>Signature<br/>Date: ________________________", body_style),
                Paragraph("<b>Peer Reviewer / Case Supervisor</b><br/><br/>________________________________________<br/>Signature<br/>Date: ________________________", body_style)
            ]
        ]
        t_sig = Table(sig_data, colWidths=[3.75 * inch, 3.75 * inch])
        t_sig.setStyle(TableStyle([
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(t_sig)


        story.append(PageBreak())

        story.append(Paragraph(
            "9. Research Evaluation Appendix",
            title_style
        ))

        story.append(Spacer(1, 10))

        story.append(Paragraph(
            "This appendix presents stored research benchmark "
            "results. These are not case-specific accuracy "
            "measurements or independently confirmed attacks.",
            body_style
        ))

        research_dir = BASE_DIR / "reports" / "evaluation"

        def read_research(relative_path):

            path = research_dir / relative_path

            try:
                data = json.loads(
                    path.read_text(encoding="utf-8")
                )

                return data if isinstance(data, dict) else None

            except (OSError, ValueError):
                return None

        def fmt_percent(value):

            if value is None:
                return "N/A"

            return f"{float(value)*100:.2f}%"

        def research_table(headers, rows, widths):

            data = [[
                Paragraph(
                    "<b>" + escape(str(v)) + "</b>",
                    table_cell_style
                )
                for v in headers
            ]]

            for row in rows:

                data.append([
                    Paragraph(
                        escape(str(v)),
                        table_cell_style
                    )
                    for v in row
                ])

            table = Table(
                data,
                colWidths=widths,
                repeatRows=1
            )

            table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0),
                 colors.HexColor("#e2e8f0")),

                ("GRID", (0,0), (-1,-1),
                 0.5, colors.HexColor("#cbd5e1")),

                ("VALIGN", (0,0), (-1,-1), "TOP"),

                ("PADDING", (0,0), (-1,-1), 5),
            ]))

            story.append(table)
            story.append(Spacer(1, 8))

        # SILRAD supporting model

        story.append(Paragraph(
            "9.1 SILRAD Supporting Ransomware Evaluation",
            h1_style
        ))

        silrad = read_research(
            "silrad/silrad_evaluation_summary.json"
        )

        if silrad:

            research_table(
                ["Parameter", "Measured Result"],
                [
                    ["Model version",
                     silrad.get("model_version", "N/A")],

                    ["Training records",
                     silrad.get("training_records", "N/A")],

                    ["Testing records",
                     silrad.get("testing_records", "N/A")],

                    ["Accuracy",
                     fmt_percent(silrad.get("accuracy"))],

                    ["Precision",
                     fmt_percent(silrad.get("precision"))],

                    ["Recall",
                     fmt_percent(silrad.get("recall"))],

                    ["F1-score",
                     fmt_percent(silrad.get("f1_score"))],

                    ["False positive rate",
                     fmt_percent(
                         silrad.get("false_positive_rate")
                     )],

                    ["Evaluation status",
                     silrad.get("evaluation_status", "N/A")]
                ],
                [3.0 * inch, 4.3 * inch]
            )

        else:

            story.append(Paragraph(
                "SILRAD evaluation results unavailable.",
                body_style
            ))

        story.append(Paragraph(
            "SILRAD evaluates ransomware versus goodware "
            "classification using numeric features. It does "
            "not measure anti-forensic detection accuracy. "
            "Exact feature overlap was removed, but ransomware "
            "family and session independence remain unverified.",
            disclaimer_style
        ))

        # Feature ablation

        story.append(Paragraph(
            "9.2 Feature Ablation and Reliability",
            h1_style
        ))

        ablation = read_research(
            "silrad/silrad_ablation_summary.json"
        )

        if ablation:

            research_table(
                ["Parameter", "Measured Result"],
                [
                    ["Removed features",
                     ", ".join(
                         ablation.get("removed_features", [])
                     )],

                    ["Remaining features",
                     ablation.get("remaining_features", "N/A")],

                    ["Testing records",
                     ablation.get("testing_records", "N/A")],

                    ["Accuracy",
                     fmt_percent(ablation.get("accuracy"))],

                    ["Precision",
                     fmt_percent(ablation.get("precision"))],

                    ["Recall",
                     fmt_percent(ablation.get("recall"))],

                    ["F1-score",
                     fmt_percent(ablation.get("f1_score"))],

                    ["Remaining exact overlap",
                     ablation.get("remaining_overlap", "N/A")],

                    ["Conflicting groups removed",
                     ablation.get(
                         "conflicting_groups_removed", "N/A"
                     )]
                ],
                [3.0 * inch, 4.3 * inch]
            )

        else:

            story.append(Paragraph(
                "Ablation results unavailable.",
                body_style
            ))

        story.append(Paragraph(
            "The reduced-feature experiment uses a different "
            "cleaned test population. The results provide "
            "exploratory reliability evidence rather than "
            "a controlled comparison on identical records.",
            body_style
        ))

        # External forensic analysis

        story.append(Paragraph(
            "9.3 External Hybrid Forensic Analysis",
            h1_style
        ))

        external = read_research(
            "external/external_combined_summary.json"
        )

        if external:

            rows = []

            for dataset in external.get("datasets", []):

                counts = dataset.get("combined_counts", {})
                shap_counts = dataset.get(
                    "shap_status_counts", {}
                )

                rows.append([
                    dataset.get("dataset", "N/A"),
                    dataset.get("parsed_records", "N/A"),
                    counts.get("ML_ONLY_CANDIDATE", 0),
                    counts.get("ML_AND_RULE_CANDIDATE", 0),
                    counts.get("RULE_ONLY_CANDIDATE", 0),
                    counts.get("NO_INDICATOR_UNVERIFIED", 0),
                    counts.get("INSUFFICIENT_VOCABULARY", 0),
                    shap_counts.get("SUCCESS", 0)
                ])

            research_table(
                [
                    "Dataset",
                    "Records",
                    "NLP only",
                    "NLP + Rule",
                    "Rule only",
                    "No indicator",
                    "Insufficient vocabulary",
                    "SHAP success"
                ],
                rows,
                [
                    1.05*inch,
                    0.7*inch,
                    0.75*inch,
                    0.85*inch,
                    0.7*inch,
                    0.95*inch,
                    1.45*inch,
                    0.85*inch
                ]
            )

            for dataset in external.get("datasets", []):

                for ref in dataset.get("reference_records", []):

                    story.append(Paragraph(
                        "Official HTB Reference Verification",
                        h1_style
                    ))

                    research_table(
                        ["Parameter", "Recorded Result"],
                        [
                            ["Original CSV row",
                             ref.get("original_row", "N/A")],

                            ["Event ID",
                             ref.get("event_code", "N/A")],

                            ["Prediction",
                             ref.get("model_prediction", "N/A")],

                            ["Suspicious score",
                             fmt_percent(
                                 ref.get("suspicious_score")
                             )],

                            ["Rule",
                             ref.get("rule_ids", "N/A")],

                            ["SHAP status",
                             ref.get("shap_status", "N/A")],

                            ["Source SHA-256",
                             ref.get("source_sha256", "N/A")]
                        ],
                        [2.0*inch, 5.3*inch]
                    )

        else:

            story.append(Paragraph(
                "External combined results unavailable.",
                body_style
            ))

        story.append(Paragraph(
            "Independent anti-forensic validation: NOT EVALUATED. "
            "The HTB reference demonstrates functional detection; "
            "the rule was updated after reference inspection. "
            "DFRWS contains investigator annotations. Candidate "
            "predictions are not confirmed malicious events.",
            disclaimer_style
        ))

        # Research visualizations

        story.append(PageBreak())

        story.append(Paragraph(
            "9.4 SILRAD Evaluation and SHAP Visualizations",
            h1_style
        ))

        graph_files = [
            (
                "silrad_confusion_matrix.png",
                "SILRAD Confusion Matrix"
            ),
            (
                "silrad_performance.png",
                "SILRAD Performance Metrics"
            ),
            (
                "silrad_shap_importance.png",
                "SHAP Feature Importance"
            ),
            (
                "silrad_shap_summary.png",
                "SHAP Summary"
            )
        ]

        for graph_filename, heading in graph_files:

            graph_path = research_dir / "silrad" / graph_filename

            heading_flow = Paragraph(heading, h1_style)

            if graph_path.is_file():

                image = Image(str(graph_path))

                scale = min(
                    6.7 * inch / image.imageWidth,
                    3.6 * inch / image.imageHeight
                )

                image.drawWidth = image.imageWidth * scale
                image.drawHeight = image.imageHeight * scale

                story.append(KeepTogether([
                    heading_flow,
                    image,
                    Spacer(1, 8)
                ]))

            else:

                story.append(heading_flow)

                story.append(Paragraph(
                    "Graph unavailable.",
                    body_style
                ))

        story.append(Paragraph(
            "SHAP visualizations use a reproducible sample "
            "of 200 test records. Feature contributions "
            "explain model behavior, not attacker intent. "
            "Strong identifier dependence remains a "
            "model reliability limitation.",
            body_style
        ))

        story.append(Paragraph(
            "9.5 Final Scientific and Legal Limitations",
            h1_style
        ))

        for limitation in [
            "Primary NLP metrics are preliminary synthetic results.",
            "Independent anti-forensic accuracy is not established.",
            "SILRAD numeric features require a separate model.",
            "External reference cases do not establish ransomware-specific generalization.",
            "Evidence hashes support byte integrity verification.",
            "Legal admissibility requires appropriate procedures and judicial review."
        ]:

            story.append(Paragraph(
                "- " + escape(limitation),
                body_style
            ))

            story.append(Spacer(1, 4))


        # Build document
        doc.build(story)

        # Validate generated PDF
        if not output_path.is_file():
            raise RuntimeError("PDF report was not created.")

        with open(output_path, "rb") as pdf_file:
            if pdf_file.read(5) != b"%PDF-":
                raise RuntimeError("Generated file is not a valid PDF.")

        # Preserve actual report filename
        filename = output_path.name

        # Compute SHA-256 of generated PDF and read bytes for serverless persistence
        pdf_bytes = output_path.read_bytes()
        report_sha256 = hashlib.sha256(pdf_bytes).hexdigest().lower()

        # Insert into database
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO reports (report_id, case_id, filename, file_path, sha256_hash, created_at, examiner, report_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            report_id,
            case_id,
            filename,
            str(output_path.resolve()),
            report_sha256,
            datetime.now(timezone.utc).isoformat(),
            examiner,
            pdf_bytes,
        ))
        conn.commit()
        conn.close()

        # Log audit action
        AuditTrail.record_event(
            case_id=case_id,
            actor=examiner,
            action="REPORT_GENERATED",
            output_hash=report_sha256,
        )

        return {
            "report_id": report_id,
            "case_id": case_id,
            "filename": filename,
            "file_path": str(output_path.resolve()),
            "sha256_hash": report_sha256,
            "created_at_utc": now_utc,
            "examiner": examiner,
            "download_url": f"/api/reports/{report_id}/download",
        }
