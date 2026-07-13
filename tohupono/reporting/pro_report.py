from __future__ import annotations

from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from tohupono.core.proof import load_manifest
from tohupono.concepts.execution import evaluate_declared_concepts
from tohupono.trust.keys import export_public_key, sign_bytes
from tohupono.verdicts.classifier import manifest_signature_status
from tohupono.core.proof import verify_evidence_chain

COMMUNITY_TEXT = (
    "Community Edition: full proof functionality for Maori sovereignty, iwi, hapu, marae, and community use."
)
DISCLAIMER = (
    "This report is an evidence-based verification summary for a legal-support evidence bundle. "
    "It summarises technical evidence and limitations."
)
FORBIDDEN_LANGUAGE = [
    "court-ready",
    "real",
    "not AI",
    "guaranteed authentic",
    "impossible to fake",
]


def _safe(value: Any) -> str:
    return "" if value is None else str(value)


def render_pdf_report(proof: Path, output: Path, community: bool = False) -> None:
    manifest = load_manifest(proof)
    file_info = manifest.get("file", {})
    if not isinstance(file_info, dict):
        file_info = {}
    signature_status = manifest_signature_status(proof)
    chain_path = proof.parent / "evidence_chain.jsonl"
    if chain_path.exists():
        chain_ok, _ = verify_evidence_chain(chain_path)
        evidence_chain_status = "valid" if chain_ok else "invalid"
    else:
        evidence_chain_status = "missing"

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        title="TohuPono Verification Report",
        pageCompression=0,
    )
    story: list[Any] = []
    story.append(Paragraph("TohuPono Evidence Report", styles["Title"]))
    story.append(Paragraph("Evidence-based verification", styles["Heading2"]))
    if community:
        story.append(Paragraph(COMMUNITY_TEXT, styles["Normal"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(DISCLAIMER, styles["Normal"]))
    story.append(Spacer(1, 12))

    rows = [
        ["Proof ID", _safe(manifest.get("proof_id"))],
        ["Sealed at UTC", _safe(manifest.get("sealed_at_utc"))],
        ["File name", _safe(file_info.get("name"))],
        ["Observed path", _safe(file_info.get("path_observed"))],
        ["Size bytes", _safe(file_info.get("size_bytes"))],
        ["MIME observed", _safe(file_info.get("mime_observed"))],
        ["SHA-256", _safe(file_info.get("sha256"))],
        ["SHA-512", _safe(file_info.get("sha512"))],
        ["BLAKE3", _safe(file_info.get("blake3") or "unavailable")],
        ["Manifest signature status", signature_status],
        ["Evidence chain status", evidence_chain_status],
    ]
    table = Table(rows, colWidths=[120, 360])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8EEF2")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 12))
    concept_diagnostics = evaluate_declared_concepts(proof, manifest)
    story.append(Paragraph("Proof Concepts", styles["Heading2"]))
    story.append(
        Paragraph(
            "A result for one Proof Concept does not establish another Proof Concept.",
            styles["Normal"],
        )
    )
    concept_results = concept_diagnostics.get("results") or []
    if isinstance(concept_results, list) and concept_results:
        concept_rows = [["Concept", "Status", "Evidence", "Limitations"]]
        for result in concept_results:
            if not isinstance(result, dict):
                continue
            concept_rows.append(
                [
                    _safe(result.get("display_name")),
                    _safe(result.get("status")),
                    _safe(result.get("evidence_summary")),
                    "; ".join(str(item) for item in result.get("limitations", []) if item),
                ]
            )
        concept_table = Table(concept_rows, colWidths=[110, 60, 150, 160])
        concept_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEF2")),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(concept_table)
        for result in concept_results:
            if not isinstance(result, dict) or result.get("concept_id") != "records":
                continue
            records = result.get("records") if isinstance(result.get("records"), list) else []
            rows = [["Record ID", "Type", "Namespace", "Reference", "Attributes"]]
            for record in records:
                if not isinstance(record, dict):
                    continue
                rows.append(
                    [
                        _safe(record.get("record_id")),
                        _safe(record.get("record_type")),
                        _safe(record.get("namespace")),
                        _safe(record.get("reference") if record.get("reference") is not None else "none"),
                        _safe(record.get("attribute_count")),
                    ]
                )
            if len(rows) > 1:
                story.append(Spacer(1, 8))
                story.append(Paragraph("Proof of Records Details", styles["Heading3"]))
                record_table = Table(rows, colWidths=[150, 70, 80, 120, 60])
                record_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEF2")),
                            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ]
                    )
                )
                story.append(record_table)
        for result in concept_results:
            if not isinstance(result, dict) or result.get("concept_id") != "custody":
                continue
            events = result.get("events") if isinstance(result.get("events"), list) else []
            rows = [["Seq", "Event ID", "Type", "Declared Actor", "Declared Time"]]
            for event in events:
                if not isinstance(event, dict):
                    continue
                actor = event.get("actor") if isinstance(event.get("actor"), dict) else {}
                actor_text = (
                    f"{actor.get('namespace')}/{actor.get('identifier')}" if isinstance(actor, dict) else "unknown"
                )
                rows.append(
                    [
                        _safe(event.get("sequence")),
                        _safe(event.get("event_id")),
                        _safe(event.get("event_type")),
                        _safe(actor_text),
                        _safe(event.get("occurred_at") or "none"),
                    ]
                )
            if len(rows) > 1:
                story.append(Spacer(1, 8))
                story.append(Paragraph("Proof of Custody Details", styles["Heading3"]))
                story.append(Paragraph(f"Chain head: {_safe(result.get('chain_head'))}", styles["Normal"]))
                custody_table = Table(rows, colWidths=[35, 145, 70, 120, 110])
                custody_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEF2")),
                            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ]
                    )
                )
                story.append(custody_table)
        for result in concept_results:
            if not isinstance(result, dict) or result.get("concept_id") != "provenance":
                continue
            edges = result.get("edges") if isinstance(result.get("edges"), list) else []
            rows = [["Edge ID", "Relation", "Parent Digest", "Operation"]]
            for edge in edges:
                if not isinstance(edge, dict):
                    continue
                parent = edge.get("parent") if isinstance(edge.get("parent"), dict) else {}
                operation = edge.get("operation") if isinstance(edge.get("operation"), dict) else None
                rows.append(
                    [
                        _safe(edge.get("edge_id")),
                        _safe(edge.get("relation_type")),
                        _safe(parent.get("digest") if isinstance(parent, dict) else "unknown"),
                        _safe(operation.get("name") if isinstance(operation, dict) else "none"),
                    ]
                )
            if len(rows) > 1:
                story.append(Spacer(1, 8))
                story.append(Paragraph("Proof of Provenance Details", styles["Heading3"]))
                provenance_table = Table(rows, colWidths=[145, 90, 180, 65])
                provenance_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEF2")),
                            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ]
                    )
                )
                story.append(provenance_table)
        for result in concept_results:
            if not isinstance(result, dict) or result.get("concept_id") != "transaction":
                continue
            transactions = result.get("transactions") if isinstance(result.get("transactions"), list) else []
            rows = [["Transaction ID", "Type", "Participants", "Declared Time"]]
            for item in transactions:
                if not isinstance(item, dict):
                    continue
                rows.append(
                    [
                        _safe(item.get("transaction_id")),
                        _safe(item.get("transaction_type")),
                        _safe(item.get("participant_count")),
                        _safe(item.get("occurred_at") or "none"),
                    ]
                )
            if len(rows) > 1:
                story.append(Spacer(1, 8))
                story.append(Paragraph("Proof of Transaction Details", styles["Heading3"]))
                transaction_table = Table(rows, colWidths=[145, 85, 80, 170])
                transaction_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEF2")),
                            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ]
                    )
                )
                story.append(transaction_table)
    else:
        story.append(Paragraph("No explicit Proof Concepts declaration is stored in this packet.", styles["Normal"]))
    story.append(
        Paragraph(
            "Integrity matches do not prove authenticity, ownership, authorship, or truth. "
            "Existence evidence may be local-only, externally verified, missing, or invalid.",
            styles["Normal"],
        )
    )
    story.append(
        Paragraph(
            "Proof of Records verifies the packet's canonical record envelope and its link to the recorded subject. "
            "It does not independently establish that declared record metadata is true, authoritative, complete, or legally valid.",
            styles["Normal"],
        )
    )
    story.append(
        Paragraph(
            "Proof of Custody verifies the retained packet's canonical custody-event sequence and internal hash links. "
            "It does not independently prove physical possession, actor identity, legal custody, complete history, or that the declared events occurred.",
            styles["Normal"],
        )
    )
    story.append(
        Paragraph(
            "Proof of Provenance verifies canonical declared lineage relationships retained in the packet. "
            "It does not independently prove that parent files exist, that declared transformations occurred, or that lineage is complete, authentic, or authoritative.",
            styles["Normal"],
        )
    )
    story.append(
        Paragraph(
            "Proof of Transaction verifies canonical declared transaction envelopes retained in the packet. "
            "It does not independently prove that a transaction, payment, delivery, consent, ownership transfer, or legal agreement occurred.",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 12))
    story.append(Paragraph("Missing evidence is classified as UNPROVEN.", styles["Normal"]))
    story.append(Paragraph("Report signature: detached signature over final PDF bytes.", styles["Normal"]))
    if community:
        story.append(Spacer(1, 12))
        story.append(Paragraph(COMMUNITY_TEXT, styles["Normal"]))

    doc.build(story)


def generate_report(
    proof: Path,
    output: Path,
    report_key: Path,
    community: bool = False,
    fmt: str = "pdf",
) -> Path:
    if fmt != "pdf":
        raise ValueError("MVP report format support is limited to pdf.")
    output.parent.mkdir(parents=True, exist_ok=True)
    render_pdf_report(proof, output, community=community)
    signature = sign_bytes(report_key, output.read_bytes())
    sig_path = output.with_name(output.name + ".sig")
    sig_path.write_bytes(signature)
    export_public_key(report_key, output.with_name(output.name + ".pub"))
    return sig_path
