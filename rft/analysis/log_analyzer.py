"""
Windows Event Log Analyzer

Parses .evtx files from infected systems to reconstruct the attack timeline.

Key event IDs analyzed:
  Authentication / Credential Access:
    4624 — Successful logon (look for Type 3 network, Type 10 remote interactive)
    4625 — Failed logon (brute force indicators)
    4648 — Logon using explicit credentials (lateral movement)
    4672 — Special privileges assigned (privilege escalation)
    4720 — User account created (persistence)
    4732 — Member added to security-enabled local group (admin added)
    4776 — NTLM authentication (pass-the-hash indicators)

  Remote Access:
    1149 — RDP: User auth succeeded
    21    — RDP: Session logon succeeded
    22    — RDP: Shell start
    25    — RDP: Session reconnect
    4778  — Session reconnect

  Execution:
    4103 — PowerShell pipeline execution (often used by ransomware dropper)
    4104 — PowerShell script block logging (full script content)
    7045 — New service installed (common for ransomware persistence)
    7036 — Service state change

  Defense Evasion:
    1102 — Audit log cleared (CRITICAL — attacker covering tracks)
    104   — System log cleared

  Lateral Movement:
    5140 — Network share accessed
    5145 — Network share object access check

Requires python-evtx (pip install python-evtx)
"""

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# Event IDs that are most forensically significant for ransomware
HIGH_VALUE_EVENT_IDS = {
    1102: ("Security", "CRITICAL: Audit log cleared"),
    104:  ("System", "CRITICAL: System log cleared"),
    4624: ("Security", "Successful logon"),
    4625: ("Security", "Failed logon (brute force indicator)"),
    4648: ("Security", "Logon with explicit credentials (lateral movement)"),
    4672: ("Security", "Special privileges assigned to new logon"),
    4720: ("Security", "User account created"),
    4732: ("Security", "Member added to administrators group"),
    4776: ("Security", "NTLM authentication (pass-the-hash indicator)"),
    4103: ("PowerShell", "PowerShell pipeline execution"),
    4104: ("PowerShell", "PowerShell script block logging"),
    7045: ("System", "New service installed"),
    7036: ("System", "Service state changed"),
    5140: ("Security", "Network share accessed"),
    5145: ("Security", "Network share access check"),
    1149: ("RDP", "RDP user authentication succeeded"),
    21:   ("RDP", "RDP session logon succeeded"),
    22:   ("RDP", "RDP shell start"),
    25:   ("RDP", "RDP session reconnect"),
    4778: ("Security", "RDP session reconnect"),
}

# Logon types of interest
LOGON_TYPES = {
    2: "Interactive (keyboard)",
    3: "Network (SMB/file share)",
    4: "Batch (scheduled task)",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials (runas)",
    10: "RemoteInteractive (RDP/TS)",
    11: "CachedInteractive",
}


@dataclass
class LogonEvent:
    """Parsed logon event."""
    event_id: int
    timestamp: datetime
    username: str
    domain: str
    logon_type: int
    logon_type_name: str
    source_ip: str
    workstation: str
    success: bool
    raw_xml: str = ""


@dataclass
class AttackTimelineEntry:
    """Single entry in the reconstructed attack timeline."""
    timestamp: datetime
    event_id: int
    category: str           # "initial_access", "credential_attack", "lateral_movement", etc.
    description: str
    severity: str           # "critical", "high", "medium", "low"
    username: str = ""
    source_ip: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class LogAnalysisResult:
    """Results of event log analysis."""
    logon_events: list[LogonEvent] = field(default_factory=list)
    failed_logons: list[LogonEvent] = field(default_factory=list)
    timeline_entries: list[AttackTimelineEntry] = field(default_factory=list)
    log_cleared_events: list[dict] = field(default_factory=list)
    new_services: list[dict] = field(default_factory=list)
    powershell_executions: list[dict] = field(default_factory=list)
    new_accounts: list[dict] = field(default_factory=list)
    rdp_sessions: list[dict] = field(default_factory=list)
    network_shares: list[dict] = field(default_factory=list)
    brute_force_ips: dict = field(default_factory=dict)  # IP → count
    suspicious_usernames: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def get_attack_window(self) -> Optional[tuple[datetime, datetime]]:
        """Return (first_event, last_event) for the attack window."""
        if not self.timeline_entries:
            return None
        times = [e.timestamp for e in self.timeline_entries]
        return min(times), max(times)


def analyze_event_logs(evtx_paths: list[str]) -> LogAnalysisResult:
    """
    Analyze a collection of Windows Event Log (.evtx) files.

    Args:
        evtx_paths: List of paths to .evtx files

    Returns:
        LogAnalysisResult with reconstructed attack timeline
    """
    result = LogAnalysisResult()

    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views
    except ImportError:
        logger.warning(
            "python-evtx not installed. Install with: pip install python-evtx\n"
            "Falling back to basic text parsing."
        )
        for path in evtx_paths:
            _parse_basic(path, result)
        return result

    for evtx_path in evtx_paths:
        if not Path(evtx_path).exists():
            continue
        logger.info(f"Analyzing event log: {evtx_path}")
        try:
            with evtx.Evtx(evtx_path) as log:
                for record in log.records():
                    try:
                        _process_record(record, result)
                    except Exception as e:
                        pass  # Skip malformed records
        except Exception as e:
            result.errors.append(f"Failed to parse {evtx_path}: {e}")
            logger.error(f"Failed to parse {evtx_path}: {e}")

    _post_process(result)
    return result


def _process_record(record, result: LogAnalysisResult) -> None:
    """Process a single EVTX record."""
    try:
        xml = record.xml()
        event_id = _extract_xml_value(xml, "EventID")
        if not event_id:
            return
        eid = int(event_id)
    except Exception:
        return

    # Skip uninteresting events
    if eid not in HIGH_VALUE_EVENT_IDS:
        return

    timestamp_str = _extract_xml_value(xml, "TimeCreated", attr="SystemTime")
    timestamp = _parse_timestamp(timestamp_str)

    category, description = HIGH_VALUE_EVENT_IDS.get(eid, ("Unknown", ""))

    # ── Logon events ──────────────────────────────────────────────────────────
    if eid in (4624, 4625, 4648):
        username = _extract_xml_value(xml, "TargetUserName") or ""
        domain = _extract_xml_value(xml, "TargetDomainName") or ""
        logon_type_str = _extract_xml_value(xml, "LogonType") or "0"
        logon_type = int(logon_type_str)
        source_ip = (
            _extract_xml_value(xml, "IpAddress") or
            _extract_xml_value(xml, "SourceAddress") or ""
        )
        workstation = _extract_xml_value(xml, "WorkstationName") or ""

        # Filter system accounts
        if username and not _is_system_account(username):
            event = LogonEvent(
                event_id=eid,
                timestamp=timestamp,
                username=username,
                domain=domain,
                logon_type=logon_type,
                logon_type_name=LOGON_TYPES.get(logon_type, f"Type {logon_type}"),
                source_ip=source_ip.strip("-"),
                workstation=workstation,
                success=(eid == 4624),
            )
            if eid == 4624:
                result.logon_events.append(event)
            elif eid == 4625:
                result.failed_logons.append(event)
                # Track brute force by source IP
                if source_ip and source_ip not in ("-", "::1", "127.0.0.1"):
                    result.brute_force_ips[source_ip] = (
                        result.brute_force_ips.get(source_ip, 0) + 1
                    )

        # Add to timeline for remote/network logons (potential lateral movement)
        if logon_type in (3, 10) and eid == 4624:
            severity = "high" if logon_type == 10 else "medium"
            result.timeline_entries.append(AttackTimelineEntry(
                timestamp=timestamp,
                event_id=eid,
                category="credential_access",
                description=f"Remote logon ({LOGON_TYPES.get(logon_type)}) as {username}@{domain}",
                severity=severity,
                username=username,
                source_ip=source_ip,
                details={"logon_type": logon_type, "domain": domain},
            ))

    # ── Log cleared (attacker covering tracks) ────────────────────────────────
    elif eid in (1102, 104):
        subject = _extract_xml_value(xml, "SubjectUserName") or "unknown"
        result.log_cleared_events.append({
            "timestamp": timestamp.isoformat(),
            "event_id": eid,
            "cleared_by": subject,
        })
        result.timeline_entries.append(AttackTimelineEntry(
            timestamp=timestamp,
            event_id=eid,
            category="defense_evasion",
            description=f"Event log CLEARED by {subject} — attacker covering tracks",
            severity="critical",
            username=subject,
        ))

    # ── New service installed ─────────────────────────────────────────────────
    elif eid == 7045:
        service_name = _extract_xml_value(xml, "ServiceName") or "unknown"
        service_file = _extract_xml_value(xml, "ImagePath") or ""
        result.new_services.append({
            "timestamp": timestamp.isoformat(),
            "name": service_name,
            "path": service_file,
        })
        result.timeline_entries.append(AttackTimelineEntry(
            timestamp=timestamp,
            event_id=eid,
            category="persistence",
            description=f"New service installed: {service_name} → {service_file}",
            severity="high",
            details={"service_name": service_name, "image_path": service_file},
        ))

    # ── PowerShell execution ──────────────────────────────────────────────────
    elif eid in (4103, 4104):
        script_block = _extract_xml_value(xml, "ScriptBlockText") or ""
        # Flag obfuscated / suspicious PS
        is_suspicious = any(kw in script_block.lower() for kw in [
            "invoke-expression", "iex ", "-enc ", "downloadstring",
            "webclient", "bypass", "hidden", "noprofile",
            "frombase64string", "vssadmin", "wbadmin", "bcdedit",
            "disable shadow", "delete shadow", "wmic shadowcopy"
        ])
        result.powershell_executions.append({
            "timestamp": timestamp.isoformat(),
            "script_preview": script_block[:200],
            "suspicious": is_suspicious,
        })
        if is_suspicious:
            result.timeline_entries.append(AttackTimelineEntry(
                timestamp=timestamp,
                event_id=eid,
                category="execution",
                description=f"Suspicious PowerShell: {script_block[:100]}...",
                severity="critical",
                details={"script_block": script_block[:500]},
            ))

    # ── New user account created ──────────────────────────────────────────────
    elif eid == 4720:
        new_user = _extract_xml_value(xml, "TargetUserName") or "unknown"
        created_by = _extract_xml_value(xml, "SubjectUserName") or "unknown"
        result.new_accounts.append({
            "timestamp": timestamp.isoformat(),
            "username": new_user,
            "created_by": created_by,
        })
        result.timeline_entries.append(AttackTimelineEntry(
            timestamp=timestamp,
            event_id=eid,
            category="persistence",
            description=f"New user account created: {new_user} (by {created_by})",
            severity="high",
            username=new_user,
        ))

    # ── RDP sessions ──────────────────────────────────────────────────────────
    elif eid in (1149, 21, 22, 25):
        username = _extract_xml_value(xml, "Param1") or _extract_xml_value(xml, "User") or ""
        source_ip = _extract_xml_value(xml, "Param3") or _extract_xml_value(xml, "Address") or ""
        result.rdp_sessions.append({
            "timestamp": timestamp.isoformat(),
            "event_id": eid,
            "username": username,
            "source_ip": source_ip,
        })
        result.timeline_entries.append(AttackTimelineEntry(
            timestamp=timestamp,
            event_id=eid,
            category="initial_access",
            description=f"RDP session: {username} from {source_ip}",
            severity="high",
            username=username,
            source_ip=source_ip,
        ))

    # ── Network share access ──────────────────────────────────────────────────
    elif eid == 5140:
        share = _extract_xml_value(xml, "ShareName") or ""
        username = _extract_xml_value(xml, "SubjectUserName") or ""
        source_ip = _extract_xml_value(xml, "IpAddress") or ""
        result.network_shares.append({
            "timestamp": timestamp.isoformat(),
            "share": share,
            "username": username,
            "source_ip": source_ip,
        })


def _post_process(result: LogAnalysisResult) -> None:
    """Sort timeline and compute statistics."""
    result.timeline_entries.sort(key=lambda e: e.timestamp)

    # Identify brute-force IPs (>10 failed logons)
    bf_threshold = 10
    for ip, count in result.brute_force_ips.items():
        if count >= bf_threshold:
            # Find timestamp of first failed attempt from this IP
            first_attempt = next(
                (e.timestamp for e in result.failed_logons
                 if e.source_ip == ip), None
            )
            result.timeline_entries.append(AttackTimelineEntry(
                timestamp=first_attempt or datetime.now(timezone.utc),
                event_id=4625,
                category="credential_attack",
                description=f"Brute force detected: {count} failed logons from {ip}",
                severity="critical",
                source_ip=ip,
                details={"failed_count": count},
            ))

    result.stats = {
        "total_logon_events": len(result.logon_events),
        "total_failed_logons": len(result.failed_logons),
        "logs_cleared": len(result.log_cleared_events),
        "new_services": len(result.new_services),
        "powershell_executions": len(result.powershell_executions),
        "new_accounts": len(result.new_accounts),
        "rdp_sessions": len(result.rdp_sessions),
        "brute_force_ips": {ip: c for ip, c in result.brute_force_ips.items() if c >= 10},
        "timeline_entries": len(result.timeline_entries),
    }


def _parse_basic(path: str, result: LogAnalysisResult) -> None:
    """Fallback: basic text-based pattern matching on exported logs."""
    # Handles plain-text exported .evtx or .txt log exports
    try:
        content = Path(path).read_text(errors="replace")
        # Look for key event IDs in text
        for eid, (cat, desc) in HIGH_VALUE_EVENT_IDS.items():
            if str(eid) in content:
                result.errors.append(
                    f"[TEXT PARSE] Found Event ID {eid} in {path} — install python-evtx for full parsing"
                )
    except Exception as e:
        result.errors.append(f"Cannot parse {path}: {e}")


def _extract_xml_value(xml: str, tag: str, attr: str = None) -> Optional[str]:
    """Simple XML value extractor without dependencies."""
    import re
    if attr:
        pattern = rf'<{tag}[^>]*{attr}="([^"]*)"'
        m = re.search(pattern, xml)
        if m:
            return m.group(1)
    # Inner text
    pattern = rf"<{tag}[^>]*>([^<]*)</{tag}>"
    m = re.search(pattern, xml)
    return m.group(1).strip() if m else None


def _parse_timestamp(ts_str: Optional[str]) -> datetime:
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        # Handle various timestamp formats
        ts_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except Exception:
        return datetime.now(timezone.utc)


def _is_system_account(username: str) -> bool:
    system_accounts = {
        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
        "ANONYMOUS LOGON", "DWM-1", "DWM-2", "DWM-3",
        "UMFD-0", "UMFD-1", "UMFD-2",
    }
    return username.upper() in system_accounts or username.endswith("$")
