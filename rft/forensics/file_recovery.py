"""
Deleted File Recovery
---------------------
Attempts to recover files the attacker deleted after encryption.
Ransomware typically:
  1. Encrypts each file → writes encrypted copy
  2. Deletes the original (sometimes securely, often not)

On NTFS, deleted files often remain in unallocated clusters until
overwritten. Recovery tools can find them by scanning MFT entries
and unallocated space.

Tools used (in order of preference):
  1. photorec / testdisk — best for unallocated space carving
  2. ntfsundelete — NTFS-specific MFT recovery
  3. foremost — signature-based file carving
  4. Manual $MFT scanning — no external tools required
"""

import logging
import os
import shutil
import subprocess
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class RecoveredFile:
    """A file recovered from unallocated space or MFT."""
    original_name: str
    recovered_path: str
    file_type: str
    size_bytes: int
    confidence: str          # "high", "medium", "low"
    recovery_method: str
    original_path: Optional[str] = None  # If MFT still has the path


@dataclass
class FileRecoveryResult:
    """Results of deleted file recovery attempt."""
    recovered_files: list[RecoveredFile] = field(default_factory=list)
    mft_deleted_entries: list[dict] = field(default_factory=list)
    total_recovered: int = 0
    total_size_bytes: int = 0
    tool_used: str = ""
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# File signatures (magic bytes) for carving from unallocated space
FILE_SIGNATURES = {
    "pdf":  (b"%PDF", b"%%EOF", ".pdf"),
    "docx": (b"PK\x03\x04", None, ".docx"),   # ZIP-based Office
    "xlsx": (b"PK\x03\x04", None, ".xlsx"),
    "jpg":  (b"\xff\xd8\xff", b"\xff\xd9", ".jpg"),
    "png":  (b"\x89PNG\r\n", b"IEND\xaeB`\x82", ".png"),
    "sqlite": (b"SQLite format 3", None, ".db"),
    "zip":  (b"PK\x03\x04", b"PK\x05\x06", ".zip"),
    "mdb":  (b"\x00\x01\x00\x00Standard Jet DB", None, ".mdb"),
    "pst":  (b"!BDN", None, ".pst"),
}


def attempt_file_recovery(
    device: str,
    output_dir: str,
    max_files: int = 500,
) -> FileRecoveryResult:
    """
    Attempt to recover deleted files from an infected drive.

    NOTE: This reads from the raw device, not the mount point.
    The device must be write-protected before calling this.

    Args:
        device: Raw block device path (e.g. /dev/sda3)
        output_dir: Directory to save recovered files
        max_files: Cap on recovered files to avoid filling disk

    Returns:
        FileRecoveryResult with all recovered files
    """
    result = FileRecoveryResult()
    output_path = Path(output_dir) / "recovered_files"
    output_path.mkdir(parents=True, exist_ok=True)

    # Try tools in order of quality
    if shutil.which("photorec"):
        result.tool_used = "photorec"
        _recover_with_photorec(device, str(output_path), result, max_files)
    elif shutil.which("ntfsundelete"):
        result.tool_used = "ntfsundelete"
        _recover_with_ntfsundelete(device, str(output_path), result, max_files)
    elif shutil.which("foremost"):
        result.tool_used = "foremost"
        _recover_with_foremost(device, str(output_path), result, max_files)
    else:
        result.tool_used = "mft_scan"
        result.notes.append(
            "No recovery tools installed. Install for better results: "
            "sudo apt-get install testdisk ntfs-3g foremost"
        )
        _scan_mft_for_deleted(device, str(output_path), result, max_files)

    result.total_recovered = len(result.recovered_files)
    result.total_size_bytes = sum(f.size_bytes for f in result.recovered_files)

    _export_recovery_report(result, str(output_path))

    logger.info(
        f"File recovery complete: {result.total_recovered} files recovered "
        f"({result.total_size_bytes // 1024}KB total) using {result.tool_used}"
    )
    return result


def _recover_with_photorec(
    device: str,
    output_dir: str,
    result: FileRecoveryResult,
    max_files: int,
):
    """
    Run photorec in batch mode for unallocated space carving.
    photorec is part of the testdisk package.
    """
    # photorec requires an interactive or scripted run
    # Use the scripted mode with a config file
    config_path = Path(output_dir) / "photorec.cmd"
    config_path.write_text(
        f"search\n"
        f"quit\n"
    )

    try:
        proc = subprocess.run(
            [
                "photorec",
                "/log",
                "/d", output_dir,
                "/cmd", device,
                "fileopt,enable,everything",
                f"photorec,search",
            ],
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour max
        )

        # Count recovered files
        count = 0
        for root, _, files in os.walk(output_dir):
            for fname in files:
                if fname == "photorec.log":
                    continue
                fpath = Path(root) / fname
                count += 1
                result.recovered_files.append(RecoveredFile(
                    original_name=fname,
                    recovered_path=str(fpath),
                    file_type=fpath.suffix.lower().lstrip(".") or "unknown",
                    size_bytes=fpath.stat().st_size,
                    confidence="medium",
                    recovery_method="photorec_carving",
                ))
                if count >= max_files:
                    break
            if count >= max_files:
                break

    except subprocess.TimeoutExpired:
        result.errors.append("photorec timed out after 1 hour")
    except Exception as e:
        result.errors.append(f"photorec error: {e}")
        # Fall back to ntfsundelete
        _recover_with_ntfsundelete(device, output_dir, result, max_files)


def _recover_with_ntfsundelete(
    device: str,
    output_dir: str,
    result: FileRecoveryResult,
    max_files: int,
):
    """
    Use ntfsundelete to recover files from NTFS MFT entries.
    Better than photorec for recovering files with their original names.
    """
    # First: scan to see what's recoverable
    scan_result = subprocess.run(
        ["ntfsundelete", device, "--scan"],
        capture_output=True, text=True, timeout=120
    )

    if scan_result.returncode != 0:
        result.errors.append(f"ntfsundelete scan failed: {scan_result.stderr.strip()}")
        return

    # Parse scan output to get inode numbers and filenames
    recoverable = _parse_ntfsundelete_scan(scan_result.stdout)

    if not recoverable:
        result.notes.append("ntfsundelete found no recoverable files in MFT")
        return

    logger.info(f"ntfsundelete found {len(recoverable)} potentially recoverable files")

    # Recover each file
    count = 0
    for inode, fname, pct in recoverable[:max_files]:
        try:
            recover_result = subprocess.run(
                ["ntfsundelete", device,
                 "--undelete", "--inodes", str(inode),
                 "--output", output_dir],
                capture_output=True, text=True, timeout=30
            )
            if recover_result.returncode == 0:
                recovered_path = Path(output_dir) / fname
                if recovered_path.exists():
                    result.recovered_files.append(RecoveredFile(
                        original_name=fname,
                        recovered_path=str(recovered_path),
                        file_type=Path(fname).suffix.lower().lstrip(".") or "unknown",
                        size_bytes=recovered_path.stat().st_size,
                        confidence="high" if pct >= 90 else "medium" if pct >= 50 else "low",
                        recovery_method="ntfsundelete_mft",
                    ))
                    count += 1
        except Exception as e:
            result.errors.append(f"Failed to recover inode {inode}: {e}")

    result.notes.append(
        f"ntfsundelete: {len(recoverable)} files found in MFT, {count} recovered"
    )


def _recover_with_foremost(
    device: str,
    output_dir: str,
    result: FileRecoveryResult,
    max_files: int,
):
    """Use foremost for signature-based file carving."""
    try:
        proc = subprocess.run(
            ["foremost", "-t", "all", "-i", device, "-o", output_dir],
            capture_output=True, text=True, timeout=3600
        )

        count = 0
        for root, _, files in os.walk(output_dir):
            for fname in files:
                if fname in ("audit.txt",):
                    continue
                fpath = Path(root) / fname
                count += 1
                result.recovered_files.append(RecoveredFile(
                    original_name=fname,
                    recovered_path=str(fpath),
                    file_type=fpath.suffix.lower().lstrip(".") or "unknown",
                    size_bytes=fpath.stat().st_size,
                    confidence="medium",
                    recovery_method="foremost_carving",
                ))
                if count >= max_files:
                    break
            if count >= max_files:
                break

    except subprocess.TimeoutExpired:
        result.errors.append("foremost timed out")
    except Exception as e:
        result.errors.append(f"foremost error: {e}")


def _scan_mft_for_deleted(
    device: str,
    output_dir: str,
    result: FileRecoveryResult,
    max_files: int,
):
    """
    Last resort: scan the raw $MFT for deleted file entries.
    NTFS marks deleted files with a flag but keeps their MFT record
    until the space is reused. This finds them without any external tools.
    """
    MFT_RECORD_SIZE = 1024
    FILE_SIGNATURE = b"FILE"
    DELETED_FLAG = 0x0000  # Not in-use

    found = 0
    try:
        with open(device, "rb") as f:
            # $MFT starts at cluster 0 — scan first 512MB for MFT records
            max_scan = 512 * 1024 * 1024
            offset = 0

            while offset < max_scan and found < max_files:
                f.seek(offset)
                record = f.read(MFT_RECORD_SIZE)
                if len(record) < MFT_RECORD_SIZE:
                    break

                if record[:4] == FILE_SIGNATURE:
                    flags = int.from_bytes(record[22:24], "little")
                    if flags == DELETED_FLAG:
                        # Try to extract filename from MFT record
                        fname = _extract_mft_filename(record)
                        if fname and _is_valuable_file(fname):
                            result.mft_deleted_entries.append({
                                "filename": fname,
                                "offset": offset,
                                "flags": flags,
                            })
                            found += 1

                offset += MFT_RECORD_SIZE

    except (PermissionError, OSError) as e:
        result.errors.append(f"MFT scan error: {e}")

    if result.mft_deleted_entries:
        result.notes.append(
            f"Found {len(result.mft_deleted_entries)} deleted file entries in MFT. "
            f"Install ntfsundelete to recover them: sudo apt-get install ntfs-3g"
        )
    else:
        result.notes.append("No recoverable deleted files found in MFT scan")


def _extract_mft_filename(record: bytes) -> Optional[str]:
    """Extract filename from raw MFT record bytes."""
    # Scan for $FILE_NAME attribute (type 0x30)
    try:
        offset = 56  # Standard attribute offset
        while offset < len(record) - 4:
            attr_type = int.from_bytes(record[offset:offset+4], "little")
            attr_len = int.from_bytes(record[offset+4:offset+8], "little")
            if attr_len == 0 or attr_len > 1024:
                break
            if attr_type == 0x30:  # $FILE_NAME
                name_len = record[offset + 88]
                name_offset = offset + 90
                name_bytes = record[name_offset:name_offset + name_len * 2]
                return name_bytes.decode("utf-16-le", errors="replace")
            offset += attr_len
    except Exception:
        pass
    return None


def _is_valuable_file(filename: str) -> bool:
    """Return True if this file type is worth recovering."""
    valuable = {
        ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".ppt", ".pptx",
        ".jpg", ".jpeg", ".png", ".mp4", ".zip", ".7z",
        ".mdb", ".accdb", ".sql", ".bak", ".pst", ".ost",
        ".kdbx", ".txt", ".csv",
    }
    return Path(filename).suffix.lower() in valuable


def _parse_ntfsundelete_scan(output: str) -> list[tuple[int, str, int]]:
    """Parse ntfsundelete --scan output. Returns [(inode, filename, pct_recoverable)]."""
    results = []
    import re
    # Format: "  42    100%  24576    Tue Jan  1 00:00:00 2024  document.docx"
    pattern = re.compile(r"^\s*(\d+)\s+(\d+)%\s+\d+\s+.+?\s{2,}(\S+)\s*$")
    for line in output.splitlines():
        match = pattern.match(line)
        if match:
            inode = int(match.group(1))
            pct = int(match.group(2))
            fname = match.group(3)
            if pct > 10:  # Only bother with >10% recoverable
                results.append((inode, fname, pct))
    return results


def _export_recovery_report(result: FileRecoveryResult, output_dir: str):
    """Write recovery summary to JSON."""
    out = Path(output_dir) / "recovery_report.json"
    try:
        data = {
            "tool_used": result.tool_used,
            "total_recovered": result.total_recovered,
            "total_size_bytes": result.total_size_bytes,
            "mft_deleted_entries": len(result.mft_deleted_entries),
            "recovered_files": [
                {
                    "name": f.original_name,
                    "type": f.file_type,
                    "size": f.size_bytes,
                    "confidence": f.confidence,
                    "method": f.recovery_method,
                    "path": f.recovered_path,
                }
                for f in result.recovered_files
            ],
            "mft_entries": result.mft_deleted_entries[:100],
            "notes": result.notes,
            "errors": result.errors,
        }
        out.write_text(json.dumps(data, indent=2))
    except Exception as e:
        result.errors.append(f"Export failed: {e}")
