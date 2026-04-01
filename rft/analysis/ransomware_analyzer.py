"""
Core Ransomware Analyzer

Synthesizes all collected artifacts into a structured analysis:
  - Identifies ransomware family and variant
  - Determines likely encryption algorithm
  - Reconstructs attack vector (RDP brute force, phishing, VPN exploit, etc.)
  - Maps the kill chain (initial access → execution → encryption → exfiltration)
  - Scores confidence for each finding
  - Prepares structured data for AI analysis and FBI reporting
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from rft.analysis.ioc_extractor import IOCReport, identify_ransomware_family
from rft.analysis.log_analyzer import LogAnalysisResult
from rft.forensics.artifact_collector import CollectionResult

logger = logging.getLogger(__name__)


# ─── Attack Vector Classifications ────────────────────────────────────────────

ATTACK_VECTORS = {
    "rdp_brute_force": "RDP Brute Force — attacker repeatedly tried passwords on exposed RDP port",
    "rdp_credential_stuffing": "RDP Credential Stuffing — attacker used stolen username/password pairs",
    "phishing_email": "Phishing Email — malicious attachment or link delivered the ransomware dropper",
    "vpn_exploit": "VPN Vulnerability Exploit — attacker exploited an unpatched VPN appliance",
    "public_exploit": "Public-Facing Application Exploit — exploit against web app or service",
    "supply_chain": "Supply Chain Compromise — malicious update or third-party software",
    "insider": "Insider Threat — attack originated from a trusted internal account",
    "lateral_from_initial": "Lateral Movement — ransomware spread from an initial foothold",
    "unknown": "Attack vector could not be determined from available evidence",
}

# ─── Encryption Algorithm Indicators ──────────────────────────────────────────

ENCRYPTION_SIGNATURES = {
    "AES-256": {
        "note_patterns": [r"(?i)AES.?256", r"(?i)advanced encryption standard"],
        "file_patterns": ["uniform high entropy", "no file header"],
    },
    "RSA-2048": {
        "note_patterns": [r"(?i)RSA.?2048", r"(?i)asymmetric", r"(?i)public key"],
        "file_patterns": ["short encrypted key block at start"],
    },
    "RSA-4096": {
        "note_patterns": [r"(?i)RSA.?4096"],
        "file_patterns": [],
    },
    "ChaCha20": {
        "note_patterns": [r"(?i)chacha20", r"(?i)chacha"],
        "file_patterns": [],
    },
    "Salsa20": {
        "note_patterns": [r"(?i)salsa20"],
        "file_patterns": [],
    },
    "AES+RSA (hybrid)": {
        "note_patterns": [
            r"(?i)AES.{0,10}RSA",
            r"(?i)RSA.{0,10}AES",
            r"(?i)hybrid encryption",
        ],
        "file_patterns": [],
    },
}


@dataclass
class EncryptionAnalysis:
    """Results of encryption algorithm analysis."""
    detected_algorithms: list[str]
    confidence: float
    hybrid_scheme: bool         # Most modern ransomware uses AES+RSA hybrid
    key_length_bits: Optional[int]
    decryption_likelihood: str  # "possible", "unlikely", "impossible"
    notes: str


@dataclass
class AttackVectorAnalysis:
    """Reconstructed attack entry point."""
    primary_vector: str
    confidence: float
    supporting_evidence: list[str]
    first_seen_timestamp: Optional[str]
    initial_ip: Optional[str]
    initial_username: Optional[str]


@dataclass
class RansomwareAnalysis:
    """
    Complete ransomware incident analysis.
    This is the primary output that feeds the AI engine and FBI report.
    """
    # Case metadata
    case_id: str
    analysis_timestamp: float

    # Ransomware identity
    ransomware_family: Optional[str]
    ransomware_variant: Optional[str]
    family_confidence: float

    # IOCs
    ioc_report: IOCReport

    # Attack chain
    attack_vector: AttackVectorAnalysis
    encryption_analysis: EncryptionAnalysis

    # Timeline
    earliest_indicator: Optional[str]
    estimated_encryption_time: Optional[str]
    lateral_movement_detected: bool

    # Ransom demand
    ransom_note_content: str
    ransom_amount_btc: Optional[str]
    ransom_amount_usd: Optional[str]
    payment_deadline: Optional[str]

    # Affected scope
    estimated_files_encrypted: int
    systems_affected: list[str]

    # Recommendations
    recovery_recommendations: list[str]
    fbi_reporting_recommended: bool

    # Raw data
    raw_notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_summary_dict(self) -> dict:
        """Serialize to a dict suitable for AI analysis or reporting."""
        return {
            "case_id": self.case_id,
            "ransomware_family": self.ransomware_family,
            "ransomware_variant": self.ransomware_variant,
            "family_confidence": self.family_confidence,
            "attack_vector": self.attack_vector.primary_vector,
            "attack_vector_confidence": self.attack_vector.confidence,
            "attack_supporting_evidence": self.attack_vector.supporting_evidence,
            "encryption_algorithms": self.encryption_analysis.detected_algorithms,
            "encryption_confidence": self.encryption_analysis.confidence,
            "decryption_likelihood": self.encryption_analysis.decryption_likelihood,
            "iocs": {
                "bitcoin_addresses": [i.value for i in self.ioc_report.bitcoin_addresses],
                "monero_addresses": [i.value for i in self.ioc_report.monero_addresses],
                "onion_addresses": [i.value for i in self.ioc_report.onion_addresses],
                "email_addresses": [i.value for i in self.ioc_report.email_addresses],
                "ip_addresses": [i.value for i in self.ioc_report.ip_addresses],
            },
            "ransom_note_preview": self.ransom_note_content[:1000],
            "ransom_amount_btc": self.ransom_amount_btc,
            "estimated_files_encrypted": self.estimated_files_encrypted,
            "earliest_indicator": self.earliest_indicator,
            "estimated_encryption_time": self.estimated_encryption_time,
            "lateral_movement": self.lateral_movement_detected,
            "fbi_report_recommended": self.fbi_reporting_recommended,
        }


def analyze_ransomware_incident(
    collection: CollectionResult,
    log_analysis: LogAnalysisResult,
    ioc_report: IOCReport,
    case_id: str,
) -> RansomwareAnalysis:
    """
    Synthesize all evidence into a structured ransomware analysis.

    Args:
        collection: Artifact collection results from the infected drive
        log_analysis: Parsed Windows event log analysis
        ioc_report: Extracted IOCs
        case_id: Case identifier

    Returns:
        RansomwareAnalysis with all findings
    """
    logger.info(f"Synthesizing ransomware analysis for case {case_id}")

    # Combine all ransom note text
    all_note_text = "\n\n".join(
        a.content_preview for a in collection.ransom_notes
        if a.content_preview
    )

    # Identify ransomware family
    family_result = identify_ransomware_family(all_note_text)
    if family_result:
        family, confidence = family_result
    else:
        # Try from IOC report
        if ioc_report.ransom_family_clues:
            family = ioc_report.ransom_family_clues[0].value
            confidence = ioc_report.ransom_family_clues[0].confidence
        else:
            family = None
            confidence = 0.0

    # Analyze encryption
    enc_analysis = _analyze_encryption(all_note_text, collection)

    # Determine attack vector
    attack_vector = _determine_attack_vector(log_analysis, ioc_report, all_note_text)

    # Extract ransom demand details
    ransom_btc, ransom_usd, deadline = _extract_ransom_details(all_note_text)

    # Timeline
    earliest = _get_earliest_indicator(log_analysis)
    enc_time = _estimate_encryption_time(collection, log_analysis)

    # Affected systems
    affected_systems = _identify_affected_systems(log_analysis)

    # Recovery recommendations
    recommendations = _generate_recommendations(
        family, enc_analysis, log_analysis, bool(collection.ransom_notes)
    )

    analysis = RansomwareAnalysis(
        case_id=case_id,
        analysis_timestamp=time.time(),
        ransomware_family=family,
        ransomware_variant=_detect_variant(all_note_text, family),
        family_confidence=confidence,
        ioc_report=ioc_report,
        attack_vector=attack_vector,
        encryption_analysis=enc_analysis,
        earliest_indicator=earliest,
        estimated_encryption_time=enc_time,
        lateral_movement_detected=_detect_lateral_movement(log_analysis),
        ransom_note_content=all_note_text,
        ransom_amount_btc=ransom_btc,
        ransom_amount_usd=ransom_usd,
        payment_deadline=deadline,
        estimated_files_encrypted=len(collection.encrypted_files),
        systems_affected=affected_systems,
        recovery_recommendations=recommendations,
        fbi_reporting_recommended=True,  # Always recommend FBI reporting
        raw_notes=[a.content_preview for a in collection.ransom_notes],
    )

    logger.info(
        f"Analysis complete:\n"
        f"  Family: {family} (confidence: {confidence:.0%})\n"
        f"  Vector: {attack_vector.primary_vector}\n"
        f"  Encryption: {enc_analysis.detected_algorithms}\n"
        f"  IOCs: {ioc_report.summary()}"
    )

    return analysis


def _analyze_encryption(note_text: str, collection: CollectionResult) -> EncryptionAnalysis:
    detected = []
    hybrid = False

    for algo, sig in ENCRYPTION_SIGNATURES.items():
        for pattern in sig["note_patterns"]:
            if re.search(pattern, note_text):
                detected.append(algo)
                break

    if not detected:
        # Default assumption based on common modern ransomware
        detected = ["AES-256 (assumed)", "RSA-2048 (assumed)"]
        confidence = 0.4
    else:
        confidence = 0.85

    hybrid = any("+" in a for a in detected) or (
        any("AES" in a for a in detected) and any("RSA" in a for a in detected)
    )

    # Key length
    key_length = None
    for algo in detected:
        m = re.search(r"(\d+)", algo)
        if m:
            key_length = int(m.group(1))
            break

    # Decryption likelihood
    if hybrid or (key_length and key_length >= 2048):
        decryption = "unlikely (without paying or law enforcement decryptor)"
    elif not detected:
        decryption = "unknown"
    else:
        decryption = "unlikely"

    return EncryptionAnalysis(
        detected_algorithms=detected,
        confidence=confidence,
        hybrid_scheme=hybrid,
        key_length_bits=key_length,
        decryption_likelihood=decryption,
        notes=(
            "Modern ransomware typically uses AES-256 to encrypt file contents "
            "and RSA-2048 or higher to encrypt the AES key. Without the attacker's "
            "private RSA key, decryption is computationally infeasible."
        )
    )


def _determine_attack_vector(
    logs: LogAnalysisResult,
    iocs: IOCReport,
    note_text: str
) -> AttackVectorAnalysis:
    evidence = []
    primary = "unknown"
    confidence = 0.3
    first_time = None
    initial_ip = None
    initial_user = None

    # RDP brute force: many failed logons from one IP
    bf_ips = {ip: c for ip, c in logs.brute_force_ips.items() if c >= 10}
    if bf_ips:
        top_ip = max(bf_ips, key=bf_ips.get)
        top_count = bf_ips[top_ip]
        evidence.append(f"Brute force: {top_count} failed logons from {top_ip}")
        primary = "rdp_brute_force"
        confidence = 0.8
        initial_ip = top_ip

        # Find first successful RDP logon from this IP
        for e in logs.logon_events:
            if e.source_ip == top_ip and e.logon_type == 10:
                first_time = e.timestamp.isoformat()
                initial_user = e.username
                break

    elif logs.rdp_sessions:
        evidence.append(f"RDP sessions detected: {len(logs.rdp_sessions)}")
        primary = "rdp_credential_stuffing"
        confidence = 0.6
        if logs.rdp_sessions:
            s = logs.rdp_sessions[0]
            initial_ip = s.get("source_ip")
            initial_user = s.get("username")
            first_time = s.get("timestamp")

    elif logs.powershell_executions:
        suspicious = [p for p in logs.powershell_executions if p.get("suspicious")]
        if suspicious:
            evidence.append(f"Suspicious PowerShell execution detected")
            primary = "phishing_email"
            confidence = 0.5

    # Check for VPN/exchange exploit indicators in note
    if any(kw in note_text.lower() for kw in ["exchange", "fortinet", "citrix", "pulse", "anydesk"]):
        evidence.append("Reference to common exploit targets in ransom note")
        if primary == "unknown":
            primary = "vpn_exploit"
            confidence = 0.5

    return AttackVectorAnalysis(
        primary_vector=primary,
        confidence=confidence,
        supporting_evidence=evidence,
        first_seen_timestamp=first_time,
        initial_ip=initial_ip,
        initial_username=initial_user,
    )


def _detect_lateral_movement(logs: LogAnalysisResult) -> bool:
    """Look for indicators of lateral movement across systems."""
    # Multiple unique source IPs in logon events
    source_ips = {e.source_ip for e in logs.logon_events if e.source_ip}
    if len(source_ips) > 3:
        return True
    # Network share access combined with new service installations
    if logs.network_shares and logs.new_services:
        return True
    # Logon with explicit credentials (lateral movement technique)
    lateral_logons = [e for e in logs.logon_events if e.logon_type == 3]
    return len(lateral_logons) > 2


def _extract_ransom_details(note_text: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract ransom amount (BTC/USD) and deadline from note text."""
    btc = None
    usd = None
    deadline = None

    # Bitcoin amount
    btc_m = re.search(r"(\d+\.?\d*)\s*(?:BTC|Bitcoin|bitcoin)", note_text)
    if btc_m:
        btc = btc_m.group(1)

    # USD amount
    usd_m = re.search(r"\$\s*([\d,]+(?:\.\d{2})?)", note_text)
    if usd_m:
        usd = usd_m.group(1)

    # Deadline (days)
    dead_m = re.search(r"(\d+)\s*day", note_text, re.IGNORECASE)
    if dead_m:
        deadline = f"{dead_m.group(1)} days"

    return btc, usd, deadline


def _get_earliest_indicator(logs: LogAnalysisResult) -> Optional[str]:
    if logs.timeline_entries:
        return logs.timeline_entries[0].timestamp.isoformat()
    return None


def _estimate_encryption_time(
    collection: CollectionResult,
    logs: LogAnalysisResult
) -> Optional[str]:
    """Estimate when encryption started based on file modification times."""
    if not collection.encrypted_files:
        return None

    # Encrypted files should cluster around the encryption event time
    times = [f.modified_time for f in collection.encrypted_files if f.modified_time > 0]
    if not times:
        return None

    import statistics
    if len(times) > 1:
        # Use median to filter outliers
        median_time = statistics.median(times)
        from datetime import datetime, timezone
        return datetime.fromtimestamp(median_time, tz=timezone.utc).isoformat()
    return None


def _identify_affected_systems(logs: LogAnalysisResult) -> list[str]:
    """Identify hostnames/IPs that show signs of compromise."""
    systems = set()
    for event in logs.logon_events:
        if event.workstation:
            systems.add(event.workstation)
    for session in logs.rdp_sessions:
        if session.get("source_ip"):
            systems.add(session["source_ip"])
    return list(systems)


def _detect_variant(note_text: str, family: Optional[str]) -> Optional[str]:
    """Try to identify the specific variant within a ransomware family."""
    if not family:
        return None
    variant_patterns = {
        "LockBit": {
            "LockBit 2.0": r"(?i)lockbit\s*2",
            "LockBit 3.0": r"(?i)lockbit\s*3|lockbit\s*black",
        },
        "ALPHV/BlackCat": {
            "ALPHV v2": r"(?i)noescapevm",
            "BlackCat": r"(?i)blackcat",
        },
    }
    family_variants = variant_patterns.get(family, {})
    for variant, pattern in family_variants.items():
        if re.search(pattern, note_text):
            return variant
    return None


def _generate_recommendations(
    family: Optional[str],
    enc: EncryptionAnalysis,
    logs: LogAnalysisResult,
    has_ransom_notes: bool
) -> list[str]:
    recs = [
        "1. FILE FBI IC3 REPORT at ic3.gov immediately — ransomware is a federal crime",
        "2. Preserve all forensic evidence (disk images, logs) per this tool's chain-of-custody records",
        "3. Do NOT pay the ransom — payment does not guarantee recovery and funds criminal operations",
        "4. Check nomoreransom.org for a free decryptor before considering any payment",
        "5. Isolate all affected systems from the network immediately if not already done",
        "6. Change ALL credentials — assume all passwords on affected systems are compromised",
        "7. Contact your cyber insurance carrier if applicable",
        "8. Engage a professional incident response firm for remediation",
    ]

    # Vector-specific
    if logs.brute_force_ips:
        recs.append("9. Block all external RDP — RDP should never be internet-exposed")
        recs.append("10. Enable MFA on all remote access methods immediately")

    if logs.new_accounts:
        recs.append("11. Audit all user accounts — attacker created backdoor accounts")

    if logs.log_cleared_events:
        recs.append("12. Restore event logs from backup — attacker cleared security logs")

    return recs
