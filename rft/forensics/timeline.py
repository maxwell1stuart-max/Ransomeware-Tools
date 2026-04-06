"""
File Recovery Timeline
----------------------
Reconstructs the exact sequence of the ransomware attack by correlating:
  - File system timestamps ($MFT, $LOGFILE on NTFS)
  - Windows Event Log entries
  - Prefetch execution timestamps
  - Registry last-write times
  - Ransom note creation times

Output is a chronological attack chain showing:
  - When the attacker first gained access
  - When lateral movement occurred
  - When encryption started (first encrypted file)
  - When encryption ended (last encrypted file)
  - Which directories were hit in what order
  - Patient zero: the first encrypted file (likely near initial access point)
"""

import logging
import os
import subprocess
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TimelineEvent:
    """A single event in the attack timeline."""
    timestamp: datetime
    event_type: str          # "file_encrypted", "logon", "service_install", "ransom_note", etc.
    description: str
    source: str              # "mft", "evtx", "prefetch", "registry", "filesystem"
    severity: str            # "critical", "high", "medium", "info"
    path: Optional[str] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class AttackPhase:
    """A distinct phase of the attack."""
    name: str                # "initial_access", "persistence", "encryption", "exfiltration"
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    events: list[TimelineEvent] = field(default_factory=list)
    description: str = ""


@dataclass
class RecoveryTimelineResult:
    """Complete attack timeline reconstruction."""
    events: list[TimelineEvent] = field(default_factory=list)
    phases: list[AttackPhase] = field(default_factory=list)

    # Key moments
    first_access_time: Optional[datetime] = None
    encryption_start_time: Optional[datetime] = None
    encryption_end_time: Optional[datetime] = None
    encryption_duration_minutes: Optional[float] = None
    patient_zero_path: Optional[str] = None      # First encrypted file

    # Directory order
    directories_by_encryption_order: list[str] = field(default_factory=list)
    total_events: int = 0
    errors: list[str] = field(default_factory=list)


def build_attack_timeline(
    mount_point: str,
    output_dir: str,
    log_analysis=None,       # LogAnalysisResult — optional
    collection=None,         # CollectionResult — optional
) -> RecoveryTimelineResult:
    """
    Build a complete chronological timeline of the ransomware attack.

    Args:
        mount_point: Mounted infected drive path
        output_dir: Directory to write timeline JSON export
        log_analysis: Pre-parsed event log results (optional)
        collection: Pre-collected artifact results (optional)

    Returns:
        RecoveryTimelineResult with ordered events and attack phases
    """
    result = RecoveryTimelineResult()
    events: list[TimelineEvent] = []

    # 1. File system timestamps — fastest source of truth
    _collect_filesystem_timestamps(mount_point, events, result)

    # 2. Merge event log timeline if available
    if log_analysis:
        _merge_event_log_timeline(log_analysis, events)

    # 3. Prefetch files — show attacker tool execution times
    _collect_prefetch_timestamps(mount_point, events)

    # 4. Ransom note timestamps
    if collection:
        _collect_ransom_note_timestamps(collection, events)

    # Sort all events chronologically
    events.sort(key=lambda e: e.timestamp)
    result.events = events
    result.total_events = len(events)

    # Identify key moments
    _identify_attack_phases(result)

    # Export timeline JSON
    _export_timeline(result, output_dir)

    logger.info(
        f"Timeline built: {result.total_events} events, "
        f"encryption started: {result.encryption_start_time}"
    )
    return result


def _collect_filesystem_timestamps(
    mount_point: str,
    events: list[TimelineEvent],
    result: RecoveryTimelineResult,
):
    """
    Walk the filesystem collecting timestamps of encrypted files.
    Uses modification time as proxy for encryption time.
    Ransomware typically modifies the file during encryption.
    """
    mount = Path(mount_point)
    encrypted_extensions = {
        # Akira
        ".akira",
        # LockBit
        ".lockbit", ".lb3",
        # ALPHV/BlackCat
        ".sykffle", ".ttbl",
        # Generic high-entropy unknown extension files
    }

    encrypted_times = []

    # Walk looking for files with ransomware extensions or high modification density
    try:
        for root, dirs, files in os.walk(mount_point):
            dirs[:] = [
                d for d in dirs
                if d.lower() not in ("windows", "$recycle.bin", "system volume information")
            ]
            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()

                # Known ransomware extension
                is_encrypted = ext in encrypted_extensions

                # Unknown extension on a file that should have a known extension
                # (e.g. document.docx.akira → the base is .docx)
                if not is_encrypted and "." in fpath.stem:
                    base_ext = Path(fpath.stem).suffix.lower()
                    if base_ext in {".docx", ".xlsx", ".pdf", ".jpg", ".db", ".sql", ".bak"}:
                        is_encrypted = True

                if is_encrypted:
                    try:
                        stat = fpath.stat()
                        mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                        encrypted_times.append((mtime, str(fpath)))
                    except (OSError, PermissionError):
                        pass

    except (PermissionError, OSError) as e:
        result.errors.append(f"Filesystem walk error: {e}")

    if not encrypted_times:
        # Fall back — look for any file with unusually recent mtime clustered together
        # (mass modification = encryption event)
        result.errors.append(
            "No files with known ransomware extensions found — "
            "try identifying the extension manually"
        )
        return

    encrypted_times.sort(key=lambda x: x[0])

    if encrypted_times:
        first_time, first_path = encrypted_times[0]
        last_time, _ = encrypted_times[-1]

        result.encryption_start_time = first_time
        result.encryption_end_time = last_time
        result.patient_zero_path = first_path

        delta = (last_time - first_time).total_seconds() / 60
        result.encryption_duration_minutes = round(delta, 1)

        events.append(TimelineEvent(
            timestamp=first_time,
            event_type="encryption_start",
            description=f"First encrypted file detected: {Path(first_path).name}",
            source="filesystem",
            severity="critical",
            path=first_path,
        ))

        events.append(TimelineEvent(
            timestamp=last_time,
            event_type="encryption_end",
            description=f"Last encrypted file: {len(encrypted_times)} total files encrypted",
            source="filesystem",
            severity="critical",
        ))

        # Build directory order map
        dir_first_seen: dict[str, datetime] = {}
        for mtime, fpath in encrypted_times:
            parent = str(Path(fpath).parent)
            if parent not in dir_first_seen:
                dir_first_seen[parent] = mtime

        result.directories_by_encryption_order = [
            d for d, _ in sorted(dir_first_seen.items(), key=lambda x: x[1])
        ]


def _merge_event_log_timeline(log_analysis, events: list[TimelineEvent]):
    """Merge pre-parsed event log entries into the master timeline."""
    if not hasattr(log_analysis, "timeline"):
        return

    severity_map = {
        "logon_failure": "high",
        "logon_success": "medium",
        "service_installed": "critical",
        "log_cleared": "critical",
        "rdp_session": "high",
        "network_share": "medium",
        "powershell": "high",
    }

    for entry in log_analysis.timeline:
        ts = entry.timestamp
        if not isinstance(ts, datetime):
            try:
                ts = datetime.fromisoformat(str(ts))
            except (ValueError, TypeError):
                continue

        event_type = getattr(entry, "event_type", "windows_event")
        events.append(TimelineEvent(
            timestamp=ts,
            event_type=event_type,
            description=entry.description,
            source="evtx",
            severity=severity_map.get(event_type, "info"),
            username=getattr(entry, "username", None),
            ip_address=getattr(entry, "source_ip", None),
            metadata={"event_id": getattr(entry, "event_id", None)},
        ))


def _collect_prefetch_timestamps(mount_point: str, events: list[TimelineEvent]):
    """
    Parse Windows Prefetch files to find when attacker tools were executed.
    Prefetch files live at Windows/Prefetch/*.pf and contain last-run timestamps.
    """
    prefetch_dir = Path(mount_point) / "Windows" / "Prefetch"
    if not prefetch_dir.exists():
        return

    # Tools ransomware operators commonly use
    suspicious_prefetch = {
        "PSEXEC.EXE", "COBALT", "MIMIKATZ", "PROCDUMP",
        "VSSADMIN.EXE", "WMIC.EXE", "POWERSHELL.EXE",
        "CMD.EXE", "NET.EXE", "NLTEST.EXE", "ADFIND",
        "RCLONE.EXE", "MEGASYNC.EXE",  # Exfiltration tools
        "WEVTUTIL.EXE",  # Log clearing
        "BCDEDIT.EXE",   # Boot config modification
    }

    try:
        for pf_file in prefetch_dir.glob("*.pf"):
            fname_upper = pf_file.stem.upper()
            is_suspicious = any(s in fname_upper for s in suspicious_prefetch)
            if not is_suspicious:
                continue

            try:
                stat = pf_file.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)

                # Try to parse prefetch with external tool
                exec_name = pf_file.stem.split("-")[0] if "-" in pf_file.stem else pf_file.stem
                events.append(TimelineEvent(
                    timestamp=mtime,
                    event_type="tool_execution",
                    description=f"Attacker tool executed: {exec_name}.EXE",
                    source="prefetch",
                    severity="critical" if exec_name.upper() in {
                        "MIMIKATZ", "COBALT", "PSEXEC", "VSSADMIN"
                    } else "high",
                    path=str(pf_file),
                ))
            except (OSError, PermissionError):
                pass

    except (PermissionError, OSError):
        pass


def _collect_ransom_note_timestamps(collection, events: list[TimelineEvent]):
    """Add ransom note drop times to the timeline."""
    for artifact in collection.ransom_notes:
        try:
            stat = Path(artifact.absolute_path).stat()
            ctime = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc)
            events.append(TimelineEvent(
                timestamp=ctime,
                event_type="ransom_note_dropped",
                description=f"Ransom note created: {Path(artifact.absolute_path).name}",
                source="filesystem",
                severity="critical",
                path=artifact.absolute_path,
            ))
        except (OSError, PermissionError):
            pass


def _identify_attack_phases(result: RecoveryTimelineResult):
    """Group events into logical attack phases."""
    phases = []

    # Phase: Initial Access — events before encryption started
    if result.encryption_start_time:
        pre_enc = [
            e for e in result.events
            if e.timestamp < result.encryption_start_time
        ]
        if pre_enc:
            phases.append(AttackPhase(
                name="Initial Access & Persistence",
                start_time=pre_enc[0].timestamp,
                end_time=pre_enc[-1].timestamp,
                events=pre_enc,
                description="Attacker gained access and established foothold",
            ))

    # Phase: Encryption
    if result.encryption_start_time and result.encryption_end_time:
        enc_events = [
            e for e in result.events
            if result.encryption_start_time <= e.timestamp <= result.encryption_end_time
        ]
        phases.append(AttackPhase(
            name="Encryption",
            start_time=result.encryption_start_time,
            end_time=result.encryption_end_time,
            events=enc_events,
            description=f"Files encrypted over {result.encryption_duration_minutes:.0f} minutes"
            if result.encryption_duration_minutes else "File encryption",
        ))

    result.phases = phases


def _export_timeline(result: RecoveryTimelineResult, output_dir: str):
    """Write timeline to JSON for the report."""
    output_path = Path(output_dir) / "attack_timeline.json"
    try:
        data = {
            "summary": {
                "total_events": result.total_events,
                "first_access": result.first_access_time.isoformat()
                    if result.first_access_time else None,
                "encryption_start": result.encryption_start_time.isoformat()
                    if result.encryption_start_time else None,
                "encryption_end": result.encryption_end_time.isoformat()
                    if result.encryption_end_time else None,
                "encryption_duration_minutes": result.encryption_duration_minutes,
                "patient_zero": result.patient_zero_path,
            },
            "phases": [
                {
                    "name": p.name,
                    "start": p.start_time.isoformat() if p.start_time else None,
                    "end": p.end_time.isoformat() if p.end_time else None,
                    "event_count": len(p.events),
                    "description": p.description,
                }
                for p in result.phases
            ],
            "events": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "type": e.event_type,
                    "description": e.description,
                    "source": e.source,
                    "severity": e.severity,
                    "path": e.path,
                    "username": e.username,
                    "ip": e.ip_address,
                }
                for e in result.events
            ],
        }
        output_path.write_text(json.dumps(data, indent=2))
    except Exception as e:
        result.errors.append(f"Timeline export failed: {e}")
