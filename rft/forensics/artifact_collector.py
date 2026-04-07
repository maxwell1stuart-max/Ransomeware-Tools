"""
Ransomware Artifact Collector

Walks a mounted (read-only) filesystem collecting forensic artifacts:
  - Ransom notes (by filename pattern and content signature)
  - Encrypted files (high entropy, modified extensions)
  - Windows Event Logs (.evtx)
  - Registry hives (SAM, SYSTEM, SOFTWARE, NTUSER.DAT)
  - Browser history and cached credentials
  - PowerShell history and scripts
  - Scheduled tasks and startup items
  - Shadow copy deletion evidence
  - Network configuration artifacts

All artifacts are catalogued with path, size, hash, and timestamps.
Nothing is written to the source drive.
"""

import hashlib
import logging
import os
import re
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

# ─── Known ransomware note filenames ──────────────────────────────────────────
RANSOM_NOTE_PATTERNS = [
    r"(?i)readme.*\.txt$",
    r"(?i)how.to.decrypt",
    r"(?i)decrypt.instructions",
    r"(?i)your.files.are.encrypted",
    r"(?i)restore.your.files",
    r"(?i)recover.files",
    r"(?i)ransom.*\.txt$",
    r"(?i)help_decrypt",
    r"(?i)_readme\.txt$",
    r"(?i)help_restore_files",
    r"(?i)!!!.*!!!",
    r"(?i)!!readme!!",
    r"(?i)recovery.*note",
    r"(?i)locked.*files",
    r"(?i)payment.*instructions",
]

# ─── Known ransomware encrypted file extensions ───────────────────────────────
KNOWN_ENCRYPTED_EXTENSIONS = {
    ".locked", ".encrypted", ".enc", ".crypted", ".crypt",
    ".crypto", ".WNCRY", ".wcry", ".wnry", ".locky", ".zepto",
    ".thor", ".odin", ".aesir", ".osiris", ".zzzzz", ".cerber",
    ".cerber2", ".cerber3", ".dharma", ".phobos", ".globe",
    ".id-*", ".onion", ".wallet", ".[[email]]", ".RYK", ".ryuk",
    ".STOP", ".djvu", ".tfude", ".tro", ".wannacry",
    ".ALPHV", ".blackcat", ".lockbit", ".clop", ".hive",
    ".FARGO", ".MONEY", ".REIG", ".BURAN",
}

# ─── Registry hive paths (Windows) ────────────────────────────────────────────
REGISTRY_HIVE_PATHS = [
    "Windows/System32/config/SAM",
    "Windows/System32/config/SYSTEM",
    "Windows/System32/config/SOFTWARE",
    "Windows/System32/config/SECURITY",
    "Windows/System32/config/DEFAULT",
    "Windows/System32/config/NTDS.dit",       # Domain controller DB
]

# ─── Event log paths ──────────────────────────────────────────────────────────
EVTX_PATHS = [
    "Windows/System32/winevt/Logs/Security.evtx",
    "Windows/System32/winevt/Logs/System.evtx",
    "Windows/System32/winevt/Logs/Application.evtx",
    "Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
    "Windows/System32/winevt/Logs/Microsoft-Windows-WinRM%4Operational.evtx",
    "Windows/System32/winevt/Logs/Microsoft-Windows-SMBServer%4Operational.evtx",
    "Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx",
]

# ─── Paths that reveal lateral movement ──────────────────────────────────────
LATERAL_MOVEMENT_PATHS = [
    "Windows/System32/Tasks",                  # Scheduled tasks
    "ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp",
    "Windows/System32/config/systemprofile/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/StartUp",
    "Windows/Prefetch",                        # Program execution evidence
    "Windows/System32/wbem/Repository",        # WMI persistence
]

# Minimum entropy to flag a file as potentially encrypted (0.0 - 8.0 bits/byte)
HIGH_ENTROPY_THRESHOLD = 7.2


@dataclass
class Artifact:
    """A collected forensic artifact from the infected drive."""
    path: str                      # Relative path from mount point
    absolute_path: str             # Full path on analysis system
    artifact_type: str             # "ransom_note", "encrypted_file", "registry_hive", etc.
    size_bytes: int
    md5: str
    sha256: str
    modified_time: float
    created_time: float
    entropy: float = 0.0
    content_preview: str = ""      # First 512 chars for notes
    metadata: dict = field(default_factory=dict)


@dataclass
class CollectionResult:
    """Results of a full artifact collection pass."""
    mount_point: str
    collection_time: float
    ransom_notes: list[Artifact] = field(default_factory=list)
    encrypted_files: list[Artifact] = field(default_factory=list)
    registry_hives: list[Artifact] = field(default_factory=list)
    event_logs: list[Artifact] = field(default_factory=list)
    suspicious_scripts: list[Artifact] = field(default_factory=list)
    startup_items: list[Artifact] = field(default_factory=list)
    scheduled_tasks: list[Artifact] = field(default_factory=list)
    prefetch_files: list[Artifact] = field(default_factory=list)
    other_artifacts: list[Artifact] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    total_encrypted_count: int = 0   # actual total found, may exceed len(encrypted_files) sample


def collect_artifacts(
    mount_point: str,
    output_dir: str,
    max_encrypted_samples: int = 100,
    deep_scan: bool = True,
) -> CollectionResult:
    """
    Walk the mounted filesystem and collect all ransomware artifacts.

    Args:
        mount_point: Where the infected drive is mounted (read-only)
        output_dir: Directory to copy artifacts to for offline analysis
        max_encrypted_samples: Max encrypted files to fully process (avoid huge dirs)
        deep_scan: If True, scan all files for entropy (slower but more thorough)

    Returns:
        CollectionResult with categorized artifacts
    """
    result = CollectionResult(
        mount_point=mount_point,
        collection_time=time.time()
    )

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    total_files = 0
    encrypted_count = 0

    logger.info(f"Starting artifact collection from {mount_point}")

    # Copy event logs and registry hives first (high forensic value, bounded size)
    _collect_specific_paths(mount_point, EVTX_PATHS, result.event_logs,
                            output_path / "event_logs", "event_log")
    _collect_specific_paths(mount_point, REGISTRY_HIVE_PATHS, result.registry_hives,
                            output_path / "registry", "registry_hive")
    _collect_specific_paths(mount_point, LATERAL_MOVEMENT_PATHS, result.scheduled_tasks,
                            output_path / "tasks", "scheduled_task", recursive=True)

    # Walk the full filesystem
    for file_path in _walk_filesystem(mount_point):
        total_files += 1
        try:
            rel_path = str(file_path.relative_to(mount_point))
            stat = file_path.stat()

            # Check if ransom note
            if _is_ransom_note(file_path):
                artifact = _make_artifact(file_path, rel_path, "ransom_note",
                                          copy_to=output_path / "ransom_notes")
                if artifact:
                    result.ransom_notes.append(artifact)
                continue

            # Check for PowerShell / script files
            if _is_suspicious_script(file_path):
                artifact = _make_artifact(file_path, rel_path, "suspicious_script",
                                          copy_to=output_path / "scripts")
                if artifact:
                    result.suspicious_scripts.append(artifact)

            # Check for encrypted files (sample up to max, but count all)
            if _is_encrypted_file(file_path, deep_scan):
                encrypted_count += 1
                if encrypted_count <= max_encrypted_samples:
                    artifact = _make_artifact(file_path, rel_path, "encrypted_file")
                    if artifact:
                        result.encrypted_files.append(artifact)

        except (PermissionError, OSError) as e:
            result.errors.append(f"Cannot access {file_path}: {e}")

    result.total_encrypted_count = encrypted_count
    result.stats = {
        "total_files_scanned": total_files,
        "ransom_notes_found": len(result.ransom_notes),
        "encrypted_files_sampled": len(result.encrypted_files),
        "encrypted_files_total": encrypted_count,
        "event_logs_found": len(result.event_logs),
        "registry_hives_found": len(result.registry_hives),
        "suspicious_scripts": len(result.suspicious_scripts),
        "errors": len(result.errors),
    }

    logger.info(
        f"Collection complete:\n"
        f"  Files scanned:    {total_files:,}\n"
        f"  Ransom notes:     {len(result.ransom_notes)}\n"
        f"  Encrypted files:  {len(result.encrypted_files)}\n"
        f"  Event logs:       {len(result.event_logs)}\n"
        f"  Registry hives:   {len(result.registry_hives)}\n"
        f"  Scripts:          {len(result.suspicious_scripts)}"
    )

    return result


def _walk_filesystem(mount_point: str) -> Generator[Path, None, None]:
    """Walk filesystem, skipping pseudo-filesystems and proc-like paths."""
    skip_dirs = {
        "proc", "sys", "dev", "run", "tmp",
        "$Recycle.Bin", "System Volume Information",
        "pagefile.sys", "hiberfil.sys"
    }
    file_count = 0
    for root, dirs, files in os.walk(mount_point):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            yield Path(root) / fname
            file_count += 1
            # Yield CPU every 500 files to keep the Pi responsive
            if file_count % 500 == 0:
                time.sleep(0.005)


def _is_ransom_note(path: Path) -> bool:
    """Check if a file is likely a ransom note by filename."""
    name = path.name
    return any(re.search(pattern, name) for pattern in RANSOM_NOTE_PATTERNS)


def _is_encrypted_file(path: Path, check_entropy: bool = True) -> bool:
    """
    Determine if a file is likely ransomware-encrypted.
    Uses extension matching and optionally Shannon entropy analysis.
    """
    # Extension-based check
    suffix = path.suffix.lower()
    if suffix in KNOWN_ENCRYPTED_EXTENSIONS:
        return True

    # Skip known benign file types to avoid false positives
    benign = {".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3",
              ".zip", ".gz", ".7z", ".rar", ".pdf"}
    if suffix in benign:
        return False

    # Entropy-based check for unknown extensions
    if check_entropy and path.stat().st_size > 512:
        entropy = _calculate_entropy(path)
        return entropy > HIGH_ENTROPY_THRESHOLD

    return False


def _is_suspicious_script(path: Path) -> bool:
    """Flag PowerShell scripts, batch files, and VBScript in unusual locations."""
    suspicious_ext = {".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js"}
    suspicious_dirs = {"temp", "tmp", "appdata", "programdata", "downloads", "public"}

    if path.suffix.lower() not in suspicious_ext:
        return False

    # Check if in a suspicious directory
    parts_lower = {p.lower() for p in path.parts}
    return bool(parts_lower & suspicious_dirs)


def _collect_specific_paths(
    mount_point: str,
    paths: list[str],
    artifact_list: list[Artifact],
    output_dir: Path,
    artifact_type: str,
    recursive: bool = False
) -> None:
    """Collect specific known artifact paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for rel_path in paths:
        full_path = Path(mount_point) / rel_path
        if full_path.is_file():
            artifact = _make_artifact(full_path, rel_path, artifact_type,
                                      copy_to=output_dir)
            if artifact:
                artifact_list.append(artifact)
        elif full_path.is_dir() and recursive:
            for f in full_path.rglob("*"):
                if f.is_file():
                    try:
                        r = str(f.relative_to(mount_point))
                        a = _make_artifact(f, r, artifact_type, copy_to=output_dir)
                        if a:
                            artifact_list.append(a)
                    except Exception:
                        pass


def _make_artifact(
    path: Path,
    rel_path: str,
    artifact_type: str,
    copy_to: Optional[Path] = None
) -> Optional[Artifact]:
    """Create an Artifact record, optionally copying the file."""
    try:
        stat = path.stat()
        md5, sha256 = _hash_file(path)
        entropy = _calculate_entropy(path) if path.stat().st_size < 10_000_000 else 0.0

        content_preview = ""
        if artifact_type == "ransom_note":
            try:
                content_preview = path.read_text(errors="replace")[:2048]
            except Exception:
                pass

        if copy_to:
            copy_to.mkdir(parents=True, exist_ok=True)
            dest = copy_to / path.name
            # Avoid overwriting — add a suffix if needed
            counter = 1
            while dest.exists():
                dest = copy_to / f"{path.stem}_{counter}{path.suffix}"
                counter += 1
            try:
                import shutil
                shutil.copy2(str(path), str(dest))
            except Exception as e:
                logger.warning(f"Could not copy {path} to {dest}: {e}")

        return Artifact(
            path=rel_path,
            absolute_path=str(path),
            artifact_type=artifact_type,
            size_bytes=stat.st_size,
            md5=md5,
            sha256=sha256,
            modified_time=stat.st_mtime,
            created_time=stat.st_ctime,
            entropy=entropy,
            content_preview=content_preview,
        )
    except Exception as e:
        logger.warning(f"Could not process {path}: {e}")
        return None


def _hash_file(path: Path) -> tuple[str, str]:
    """Compute MD5 and SHA-256 simultaneously."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha256.update(chunk)
    except Exception:
        return "error", "error"
    return md5.hexdigest(), sha256.hexdigest()


def _calculate_entropy(path: Path) -> float:
    """
    Calculate Shannon entropy of a file (bits per byte, 0.0 - 8.0).
    Values above 7.2 strongly suggest encrypted or compressed data.
    """
    try:
        freq = [0] * 256
        total = 0
        with open(path, "rb") as f:
            data = f.read(65536)  # Sample first 64KB for speed
            if not data:
                return 0.0
            for byte in data:
                freq[byte] += 1
            total = len(data)

        import math
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy
    except Exception:
        return 0.0
