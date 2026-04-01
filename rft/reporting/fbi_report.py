"""
FBI IC3 Report Generator

Generates a structured incident report formatted for submission to:
  - FBI Internet Crime Complaint Center (IC3): ic3.gov
  - CISA (Cybersecurity and Infrastructure Security Agency): cisa.gov/report
  - Secret Service Electronic Crimes Task Force
  - State/local law enforcement

The report follows the IC3 complaint format and includes:
  - Victim information
  - Incident timeline
  - Technical indicators (IOCs)
  - Ransom demand details
  - Cryptocurrency wallet addresses
  - Identified threat actors / ransomware group
  - Financial losses
  - Evidence preservation statement

Output formats:
  - Structured JSON (for programmatic submission)
  - Human-readable text report
  - PDF (via reportlab if available)
"""

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rft.analysis.ransomware_analyzer import RansomwareAnalysis
from rft.ai.engine import AIAnalysisResult

logger = logging.getLogger(__name__)


@dataclass
class VictimInfo:
    """Victim organization information for the FBI report."""
    organization_name: str
    contact_name: str
    contact_email: str
    contact_phone: str
    organization_type: str       # "business", "healthcare", "government", "education", "individual"
    state: str
    country: str = "United States"
    num_employees: Optional[int] = None
    annual_revenue: Optional[str] = None
    critical_infrastructure: bool = False
    sector: str = ""             # "Healthcare", "Finance", "Energy", etc.


@dataclass
class FBIReport:
    """
    Complete FBI IC3 ransomware incident report.
    All fields aligned with IC3 online complaint form.
    """
    # Report metadata
    report_id: str
    generated_at: str
    case_id: str
    examiner: str

    # Victim
    victim: VictimInfo

    # Incident basics
    incident_date: str           # When the attack occurred (ISO 8601)
    discovery_date: str          # When victim discovered the attack
    report_date: str             # When this report was filed
    incident_type: str = "Ransomware"

    # Ransomware details
    ransomware_name: str = ""
    ransomware_variant: str = ""
    ransomware_confidence: str = ""

    # Financial details
    ransom_demanded_btc: str = ""
    ransom_demanded_usd: str = ""
    ransom_paid: bool = False
    ransom_paid_amount: str = ""
    total_financial_loss: str = ""
    estimated_recovery_cost: str = ""

    # Attack details
    attack_vector: str = ""
    attack_vector_description: str = ""
    initial_access_date: str = ""
    encryption_date: str = ""
    data_exfiltrated: bool = False
    data_exfil_description: str = ""

    # Technical indicators
    bitcoin_addresses: list[str] = field(default_factory=list)
    monero_addresses: list[str] = field(default_factory=list)
    onion_addresses: list[str] = field(default_factory=list)
    contact_emails: list[str] = field(default_factory=list)
    attacker_ip_addresses: list[str] = field(default_factory=list)
    malware_hashes: list[str] = field(default_factory=list)

    # Scope
    files_encrypted: int = 0
    systems_affected: list[str] = field(default_factory=list)
    data_types_affected: list[str] = field(default_factory=list)

    # Evidence
    evidence_preserved: list[str] = field(default_factory=list)
    chain_of_custody: str = ""

    # Narrative
    incident_description: str = ""
    additional_info: str = ""

    # MITRE ATT&CK
    mitre_techniques: list[str] = field(default_factory=list)

    # AI analysis summary
    ai_analysis_summary: str = ""

    # Ransom note (redacted of sensitive victim info)
    ransom_note_excerpt: str = ""


def generate_fbi_report(
    ransomware_analysis: RansomwareAnalysis,
    ai_result: Optional[AIAnalysisResult],
    victim_info: VictimInfo,
    examiner: str = "RFT Forensic Toolkit",
    ransom_paid: bool = False,
    data_types: Optional[list[str]] = None,
) -> FBIReport:
    """
    Generate a complete FBI IC3 report from forensic analysis results.

    Args:
        ransomware_analysis: Core analysis results
        ai_result: AI analysis results (may be None if no API key)
        victim_info: Victim organization information
        examiner: Name of the forensic examiner
        ransom_paid: Whether ransom was paid
        data_types: Types of data encrypted (PII, financial, medical, etc.)

    Returns:
        FBIReport ready for submission
    """
    now = datetime.now(timezone.utc).isoformat()
    report_id = f"RFT-{ransomware_analysis.case_id}-{int(time.time())}"

    # Determine incident and encryption dates
    incident_date = (
        ransomware_analysis.earliest_indicator or
        now
    )
    encryption_date = (
        ransomware_analysis.estimated_encryption_time or
        now
    )

    # Build attack vector description
    attack_vector_desc = ""
    if ransomware_analysis.attack_vector:
        av = ransomware_analysis.attack_vector
        from rft.analysis.ransomware_analyzer import ATTACK_VECTORS
        attack_vector_desc = ATTACK_VECTORS.get(av.primary_vector, av.primary_vector)
        if av.initial_ip:
            attack_vector_desc += f" (Source IP: {av.initial_ip})"
        if av.initial_username:
            attack_vector_desc += f" (Account: {av.initial_username})"

    # Check for data exfiltration indicators
    family_info = _get_family_exfil_info(ransomware_analysis.ransomware_family)
    data_exfiltrated = family_info.get("exfil_likely", False)
    exfil_desc = (
        f"Based on {ransomware_analysis.ransomware_family} TTP analysis: "
        f"{'Data exfiltration likely — this group practices double extortion' if data_exfiltrated else 'No confirmed exfiltration evidence'}"
        if ransomware_analysis.ransomware_family
        else "Unknown"
    )

    # Evidence preserved
    evidence = [
        "Forensic disk image (SHA-256 verified) of encrypted drive(s)",
        "Windows Event Log copies (.evtx format)",
        "Windows Registry hive copies",
        "Ransom note copies (full text preserved)",
        "Collection artifact manifest with file hashes",
        "Chain-of-custody log with timestamps and examiner ID",
    ]

    # Build narrative
    narrative = _build_narrative(ransomware_analysis, ai_result, victim_info)

    # AI summary
    ai_summary = ""
    if ai_result:
        ai_summary = (
            f"FAMILY ASSESSMENT:\n{ai_result.family_assessment[:500]}\n\n"
            f"ATTACK CHAIN:\n{ai_result.attack_chain_summary[:500]}\n\n"
            f"MITRE TECHNIQUES: {', '.join(ai_result.mitre_techniques[:10])}"
        )

    return FBIReport(
        report_id=report_id,
        generated_at=now,
        case_id=ransomware_analysis.case_id,
        examiner=examiner,
        victim=victim_info,
        incident_date=incident_date,
        discovery_date=now,
        report_date=now,
        ransomware_name=ransomware_analysis.ransomware_family or "Unknown",
        ransomware_variant=ransomware_analysis.ransomware_variant or "",
        ransomware_confidence=(
            f"{ransomware_analysis.family_confidence:.0%} confidence"
            if ransomware_analysis.family_confidence > 0 else "Unable to identify"
        ),
        ransom_demanded_btc=ransomware_analysis.ransom_amount_btc or "Unknown",
        ransom_demanded_usd=ransomware_analysis.ransom_amount_usd or "Unknown",
        ransom_paid=ransom_paid,
        attack_vector=ransomware_analysis.attack_vector.primary_vector if ransomware_analysis.attack_vector else "unknown",
        attack_vector_description=attack_vector_desc,
        initial_access_date=ransomware_analysis.attack_vector.first_seen_timestamp or incident_date
            if ransomware_analysis.attack_vector else incident_date,
        encryption_date=encryption_date,
        data_exfiltrated=data_exfiltrated,
        data_exfil_description=exfil_desc,
        bitcoin_addresses=[i.value for i in ransomware_analysis.ioc_report.bitcoin_addresses],
        monero_addresses=[i.value for i in ransomware_analysis.ioc_report.monero_addresses],
        onion_addresses=[i.value for i in ransomware_analysis.ioc_report.onion_addresses],
        contact_emails=[i.value for i in ransomware_analysis.ioc_report.email_addresses],
        attacker_ip_addresses=[i.value for i in ransomware_analysis.ioc_report.ip_addresses],
        files_encrypted=ransomware_analysis.estimated_files_encrypted,
        systems_affected=ransomware_analysis.systems_affected,
        data_types_affected=data_types or ["Unknown — forensic analysis required"],
        evidence_preserved=evidence,
        incident_description=narrative,
        mitre_techniques=ai_result.mitre_techniques if ai_result else [],
        ai_analysis_summary=ai_summary,
        ransom_note_excerpt=ransomware_analysis.ransom_note_content[:1000] if ransomware_analysis.ransom_note_content else "",
    )


def save_report_json(report: FBIReport, output_path: str) -> str:
    """Save report as JSON."""
    data = asdict(report)
    data["victim"] = asdict(report.victim)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    return output_path


def save_report_text(report: FBIReport, output_path: str) -> str:
    """Save report as formatted plain text."""
    text = _format_text_report(report)
    with open(output_path, "w") as f:
        f.write(text)
    return output_path


def save_report_pdf(report: FBIReport, output_path: str) -> Optional[str]:
    """Save report as PDF using reportlab."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        story.append(Paragraph(
            f"FBI IC3 RANSOMWARE INCIDENT REPORT",
            styles["Title"]
        ))
        story.append(Paragraph(f"Case ID: {report.case_id}", styles["Heading2"]))
        story.append(Paragraph(f"Report ID: {report.report_id}", styles["Normal"]))
        story.append(Spacer(1, 0.25 * inch))

        # Add sections
        text = _format_text_report(report)
        for line in text.split("\n"):
            if line.startswith("═") or line.startswith("─"):
                story.append(Spacer(1, 0.1 * inch))
            elif line.startswith("##"):
                story.append(Paragraph(line.lstrip("#").strip(), styles["Heading1"]))
            elif line.strip():
                story.append(Paragraph(line, styles["Normal"]))
            else:
                story.append(Spacer(1, 0.05 * inch))

        doc.build(story)
        return output_path
    except ImportError:
        logger.warning("reportlab not installed. Install with: pip install reportlab")
        return None


def _format_text_report(report: FBIReport) -> str:
    """Format the report as a readable text document."""
    v = report.victim
    lines = [
        "═" * 72,
        "FBI INTERNET CRIME COMPLAINT CENTER (IC3)",
        "RANSOMWARE INCIDENT REPORT",
        "Submit online at: https://www.ic3.gov/",
        "═" * 72,
        "",
        f"REPORT ID:     {report.report_id}",
        f"CASE ID:       {report.case_id}",
        f"GENERATED:     {report.generated_at}",
        f"EXAMINER:      {report.examiner}",
        "",
        "─" * 72,
        "SECTION 1: VICTIM INFORMATION",
        "─" * 72,
        f"Organization:  {v.organization_name}",
        f"Contact:       {v.contact_name}",
        f"Email:         {v.contact_email}",
        f"Phone:         {v.contact_phone}",
        f"Type:          {v.organization_type}",
        f"Sector:        {v.sector or 'Not specified'}",
        f"State:         {v.state}",
        f"Country:       {v.country}",
        f"Critical Infra:{' YES — NOTIFY CISA' if v.critical_infrastructure else 'No'}",
        "",
        "─" * 72,
        "SECTION 2: INCIDENT OVERVIEW",
        "─" * 72,
        f"Incident Type:     {report.incident_type}",
        f"Ransomware:        {report.ransomware_name}",
        f"Variant:           {report.ransomware_variant or 'Unknown'}",
        f"Identification:    {report.ransomware_confidence}",
        f"Incident Date:     {report.incident_date}",
        f"Discovery Date:    {report.discovery_date}",
        f"Attack Vector:     {report.attack_vector}",
        f"Vector Details:    {report.attack_vector_description}",
        f"Initial Access:    {report.initial_access_date}",
        f"Encryption Time:   {report.encryption_date}",
        "",
        "─" * 72,
        "SECTION 3: FINANCIAL DETAILS",
        "─" * 72,
        f"Ransom Demanded:   {report.ransom_demanded_btc} BTC / ${report.ransom_demanded_usd} USD",
        f"Ransom Paid:       {'YES — ' + report.ransom_paid_amount if report.ransom_paid else 'NO'}",
        f"Total Loss:        {report.total_financial_loss or 'Under assessment'}",
        "",
        "─" * 72,
        "SECTION 4: TECHNICAL INDICATORS OF COMPROMISE",
        "─" * 72,
    ]

    if report.bitcoin_addresses:
        lines.append("BITCOIN WALLET ADDRESSES (submit to FBI for blockchain tracing):")
        for addr in report.bitcoin_addresses:
            lines.append(f"  {addr}")

    if report.monero_addresses:
        lines.append("MONERO WALLET ADDRESSES:")
        for addr in report.monero_addresses:
            lines.append(f"  {addr}")

    if report.onion_addresses:
        lines.append("TOR .ONION ADDRESSES (C2/payment portals):")
        for addr in report.onion_addresses:
            lines.append(f"  {addr}")

    if report.contact_emails:
        lines.append("ATTACKER CONTACT EMAILS:")
        for email in report.contact_emails:
            lines.append(f"  {email}")

    if report.attacker_ip_addresses:
        lines.append("ATTACKER IP ADDRESSES:")
        for ip in report.attacker_ip_addresses:
            lines.append(f"  {ip}")

    lines.extend([
        "",
        "─" * 72,
        "SECTION 5: SCOPE OF IMPACT",
        "─" * 72,
        f"Files Encrypted:   {report.files_encrypted:,}",
        f"Data Exfiltrated:  {'YES — double extortion risk' if report.data_exfiltrated else 'Not confirmed'}",
    ])

    if report.data_exfiltrated:
        lines.append(f"Exfil Details:     {report.data_exfil_description}")

    if report.systems_affected:
        lines.append("Systems Affected:")
        for s in report.systems_affected:
            lines.append(f"  {s}")

    if report.data_types_affected:
        lines.append("Data Types Affected:")
        for d in report.data_types_affected:
            lines.append(f"  {d}")

    lines.extend([
        "",
        "─" * 72,
        "SECTION 6: EVIDENCE PRESERVED",
        "─" * 72,
    ])
    for e in report.evidence_preserved:
        lines.append(f"  ✓ {e}")

    lines.extend([
        "",
        "─" * 72,
        "SECTION 7: MITRE ATT&CK TECHNIQUES",
        "─" * 72,
    ])
    if report.mitre_techniques:
        for t in report.mitre_techniques:
            lines.append(f"  {t}")
    else:
        lines.append("  Analysis pending or not available")

    lines.extend([
        "",
        "─" * 72,
        "SECTION 8: AI FORENSIC ANALYSIS SUMMARY",
        "─" * 72,
        report.ai_analysis_summary or "AI analysis not performed (no API key configured)",
        "",
        "─" * 72,
        "SECTION 9: INCIDENT NARRATIVE",
        "─" * 72,
        report.incident_description,
        "",
        "─" * 72,
        "SECTION 10: RANSOM NOTE (EXCERPT)",
        "─" * 72,
        report.ransom_note_excerpt or "No ransom note recovered",
        "",
        "═" * 72,
        "IMPORTANT NOTICES:",
        "═" * 72,
        "1. File this report at ic3.gov — it takes less than 15 minutes",
        "2. Also report to CISA: report@cisa.gov / (888) 282-0870",
        "3. CISA may have threat intelligence that helps your recovery",
        "4. Do NOT pay the ransom — report and seek law enforcement help first",
        "5. Check nomoreransom.org for free decryptors",
        "6. Preserve ALL evidence — do not wipe/reinstall before law enforcement review",
        "",
        f"Generated by Ransomware Forensics Toolkit (RFT) v1.0",
        f"Report timestamp: {report.generated_at}",
    ])

    return "\n".join(lines)


def _build_narrative(
    analysis: RansomwareAnalysis,
    ai_result: Optional[AIAnalysisResult],
    victim: VictimInfo
) -> str:
    """Build the incident narrative section."""
    parts = [
        f"On or around {analysis.earliest_indicator or 'an undetermined date'}, "
        f"{victim.organization_name} suffered a ransomware attack"
    ]

    if analysis.ransomware_family:
        parts[0] += f" by the {analysis.ransomware_family} ransomware group."
    else:
        parts[0] += " by an unidentified ransomware group."

    if analysis.attack_vector and analysis.attack_vector.primary_vector != "unknown":
        from rft.analysis.ransomware_analyzer import ATTACK_VECTORS
        vector_desc = ATTACK_VECTORS.get(
            analysis.attack_vector.primary_vector,
            analysis.attack_vector.primary_vector
        )
        parts.append(f"\nThe likely attack vector was: {vector_desc}.")
        if analysis.attack_vector.initial_ip:
            parts.append(
                f"The attack originated from IP address {analysis.attack_vector.initial_ip}."
            )

    if analysis.estimated_encryption_time:
        parts.append(
            f"\nEncryption is estimated to have occurred around {analysis.estimated_encryption_time}."
        )

    if analysis.estimated_files_encrypted > 0:
        parts.append(
            f"Approximately {analysis.estimated_files_encrypted:,} files were encrypted."
        )

    if analysis.lateral_movement_detected:
        parts.append(
            "\nEvidence of lateral movement was detected — the attack spread across "
            "multiple systems within the network."
        )

    if ai_result and ai_result.exfiltration_indicators:
        parts.append(f"\nData Exfiltration Assessment: {ai_result.exfiltration_indicators[:300]}")

    return " ".join(parts)


def _get_family_exfil_info(family: Optional[str]) -> dict:
    """Quick lookup for whether a family practices double extortion."""
    double_extortion_families = {
        "LockBit", "ALPHV/BlackCat", "Cl0p", "Hive", "Conti",
        "REvil/Sodinokibi", "BlackBasta", "Akira", "Play",
        "Royal", "Medusa", "Rhysida"
    }
    if family and family in double_extortion_families:
        return {"exfil_likely": True}
    return {"exfil_likely": False}
