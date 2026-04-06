"""
Shadow Copy Recovery
--------------------
Detects and extracts files from Windows Volume Shadow Copies (VSS)
that ransomware failed to delete. Many ransomware families attempt
vssadmin delete shadows /all but fail due to permissions or timing.

Requires: vss-ntfs (Linux VSS reader) or dislocker for NTFS VSS access.
Falls back to parsing the VSS catalog directly if tools aren't available.
"""

import logging
import os
import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ShadowCopy:
    """A single VSS snapshot found on the drive."""
    snapshot_id: str
    volume: str
    creation_time: str
    size_bytes: int
    mount_point: Optional[str] = None        # Set after mounting
    recovered_files: list[str] = field(default_factory=list)
    file_count: int = 0
    total_size_bytes: int = 0


@dataclass
class ShadowCopyResult:
    """Results of VSS scanning and recovery."""
    snapshots_found: int = 0
    snapshots_mounted: int = 0
    recovered_files: list[str] = field(default_factory=list)
    shadow_copies: list[ShadowCopy] = field(default_factory=list)
    vss_deleted: bool = False          # Evidence attacker tried to delete VSS
    vss_deletion_failed: bool = False  # Deletion attempt failed (files survived)
    errors: list[str] = field(default_factory=list)
    tool_used: str = ""


def scan_shadow_copies(
    mount_point: str,
    output_dir: str,
    max_files_per_snapshot: int = 1000,
) -> ShadowCopyResult:
    """
    Scan a mounted NTFS volume for surviving VSS snapshots.

    Strategy:
    1. Check event logs for vssadmin delete commands (attacker evidence)
    2. Scan for VSS catalog and snapshot store on the volume
    3. Use vshadowmount (libvshadow) if available — most reliable
    4. Fall back to direct VSS catalog parsing
    5. Extract recoverable files from each snapshot

    Args:
        mount_point: Where the infected NTFS volume is mounted read-only
        output_dir: Where to save recovered files
        max_files_per_snapshot: Cap to avoid filling disk

    Returns:
        ShadowCopyResult with all findings
    """
    result = ShadowCopyResult()
    output_path = Path(output_dir) / "shadow_copies"
    output_path.mkdir(parents=True, exist_ok=True)

    # Step 1: Check for evidence attacker tried to delete VSS
    _check_vss_deletion_evidence(mount_point, result)

    # Step 2: Try vshadowmount (libvshadow-utils) — best tool
    if shutil.which("vshadowmount"):
        result.tool_used = "vshadowmount"
        _mount_with_vshadow(mount_point, str(output_path), result, max_files_per_snapshot)
    # Step 3: Try vss-ntfs Python library
    elif _try_import_vss():
        result.tool_used = "vss-ntfs"
        _scan_with_vss_lib(mount_point, str(output_path), result, max_files_per_snapshot)
    # Step 4: Manual VSS catalog scan — no external tools needed
    else:
        result.tool_used = "manual_catalog"
        _scan_vss_catalog_manually(mount_point, str(output_path), result)

    logger.info(
        f"VSS scan complete: {result.snapshots_found} snapshots found, "
        f"{len(result.recovered_files)} files recovered"
    )
    return result


def _check_vss_deletion_evidence(mount_point: str, result: ShadowCopyResult):
    """
    Look for evidence the attacker tried to delete shadow copies.
    Checks: PowerShell history, prefetch files, scheduled tasks, bat scripts.
    """
    vss_delete_patterns = [
        "vssadmin delete shadows",
        "vssadmin.exe delete",
        "wmic shadowcopy delete",
        "Get-WmiObject Win32_ShadowCopy",
        "gwmi win32_shadowcopy",
        "bcdedit /set {default} recoveryenabled no",
        "wbadmin delete catalog",
    ]

    search_paths = [
        "Windows/System32/winevt/Logs",
        "Users",  # PowerShell history in user profiles
        "Windows/Prefetch",
        "Windows/System32/Tasks",
        "Windows/SysWOW64/Tasks",
    ]

    mount = Path(mount_point)
    for search_dir in search_paths:
        search_path = mount / search_dir
        if not search_path.exists():
            continue
        try:
            for file_path in search_path.rglob("*"):
                if not file_path.is_file():
                    continue
                # Only scan text-ish files
                if file_path.suffix.lower() not in (
                    ".txt", ".ps1", ".bat", ".cmd", ".log", ".xml", ""
                ):
                    continue
                try:
                    text = file_path.read_text(errors="replace")
                    for pattern in vss_delete_patterns:
                        if pattern.lower() in text.lower():
                            result.vss_deleted = True
                            logger.info(
                                f"VSS deletion command found in {file_path}: '{pattern}'"
                            )
                except (PermissionError, OSError):
                    pass
        except (PermissionError, OSError):
            pass

    # Check if VSS store path exists but is empty (deletion succeeded)
    vss_store = mount / "System Volume Information"
    if vss_store.exists():
        try:
            contents = list(vss_store.iterdir())
            snapshot_files = [f for f in contents if "{" in f.name]
            if result.vss_deleted and len(snapshot_files) == 0:
                result.vss_deletion_failed = False
                logger.info("VSS deletion appears to have succeeded — no snapshots found")
            elif result.vss_deleted and len(snapshot_files) > 0:
                result.vss_deletion_failed = True
                logger.info(
                    f"VSS deletion attempted but {len(snapshot_files)} snapshot(s) survived!"
                )
        except PermissionError:
            pass


def _mount_with_vshadow(
    mount_point: str,
    output_dir: str,
    result: ShadowCopyResult,
    max_files: int,
):
    """Use vshadowmount (libvshadow) to mount and extract VSS snapshots."""
    vss_mount_base = Path(output_dir) / "vss_mounts"
    vss_mount_base.mkdir(parents=True, exist_ok=True)

    # Get list of shadow copies
    info_result = subprocess.run(
        ["vshadowinfo", mount_point],
        capture_output=True, text=True
    )

    if info_result.returncode != 0:
        result.errors.append(f"vshadowinfo failed: {info_result.stderr.strip()}")
        return

    # Parse snapshot count from output
    snapshots = _parse_vshadowinfo(info_result.stdout)
    result.snapshots_found = len(snapshots)

    for i, snap in enumerate(snapshots):
        vss_mount_point = vss_mount_base / f"vss{i}"
        vss_mount_point.mkdir(exist_ok=True)

        mount_result = subprocess.run(
            ["vshadowmount", "-o", str(i), mount_point, str(vss_mount_point)],
            capture_output=True, text=True
        )

        if mount_result.returncode != 0:
            result.errors.append(f"Failed to mount snapshot {i}: {mount_result.stderr.strip()}")
            continue

        snap.mount_point = str(vss_mount_point)
        result.snapshots_mounted += 1

        # Mount the NTFS filesystem inside the VSS snapshot
        ntfs_mount = vss_mount_base / f"ntfs{i}"
        ntfs_mount.mkdir(exist_ok=True)

        ntfs_result = subprocess.run(
            ["mount", "-t", "ntfs-3g", "-o", "ro",
             str(vss_mount_point / "vss1"), str(ntfs_mount)],
            capture_output=True, text=True
        )

        if ntfs_result.returncode == 0:
            recovered = _extract_valuable_files(
                str(ntfs_mount), output_dir, f"snapshot_{i}", max_files
            )
            snap.recovered_files = recovered
            snap.file_count = len(recovered)
            result.recovered_files.extend(recovered)
            result.shadow_copies.append(snap)

            subprocess.run(["umount", str(ntfs_mount)], capture_output=True)

        subprocess.run(["umount", str(vss_mount_point)], capture_output=True)


def _scan_with_vss_lib(
    mount_point: str,
    output_dir: str,
    result: ShadowCopyResult,
    max_files: int,
):
    """Use vss Python library to read VSS snapshots without external tools."""
    try:
        import vss
        store = vss.VSSClient(mount_point)
        snapshots = store.get_snapshots()
        result.snapshots_found = len(snapshots)

        for i, snap in enumerate(snapshots):
            copy = ShadowCopy(
                snapshot_id=str(snap.id),
                volume=snap.volume_name,
                creation_time=str(snap.creation_time),
                size_bytes=snap.allocated_size,
            )
            result.shadow_copies.append(copy)
            result.snapshots_mounted += 1

    except Exception as e:
        result.errors.append(f"VSS library error: {e}")


def _scan_vss_catalog_manually(
    mount_point: str,
    output_dir: str,
    result: ShadowCopyResult,
):
    """
    Last resort: scan for VSS catalog files directly.
    Looks in System Volume Information for snapshot metadata.
    """
    svi_path = Path(mount_point) / "System Volume Information"
    if not svi_path.exists():
        result.errors.append("System Volume Information directory not found or not accessible")
        return

    try:
        snapshot_dirs = []
        for item in svi_path.iterdir():
            # VSS snapshot dirs have GUID names like {xxxxxxxx-xxxx-...}
            if item.is_dir() and item.name.startswith("{"):
                snapshot_dirs.append(item)

        result.snapshots_found = len(snapshot_dirs)

        if snapshot_dirs:
            logger.info(
                f"Found {len(snapshot_dirs)} VSS snapshot directories "
                f"(manual scan — install libvshadow-utils for full extraction)"
            )
            for snap_dir in snapshot_dirs:
                copy = ShadowCopy(
                    snapshot_id=snap_dir.name,
                    volume=mount_point,
                    creation_time="unknown",
                    size_bytes=0,
                )
                result.shadow_copies.append(copy)
        else:
            logger.info("No VSS snapshot directories found in System Volume Information")

    except PermissionError:
        result.errors.append(
            "Cannot read System Volume Information — run as root with: "
            "sudo mount -o ro,uid=0 /dev/sdX /mnt/..."
        )


def _extract_valuable_files(
    ntfs_mount: str,
    output_dir: str,
    label: str,
    max_files: int,
) -> list[str]:
    """
    Extract the most valuable files from a mounted VSS snapshot.
    Prioritizes: documents, databases, emails, configs — not encrypted files.
    """
    valuable_extensions = {
        ".docx", ".doc", ".xlsx", ".xls", ".pdf", ".pptx",
        ".mdb", ".accdb", ".sql", ".bak",
        ".pst", ".ost", ".eml", ".msg",
        ".txt", ".csv", ".json", ".xml",
        ".jpg", ".jpeg", ".png",
        ".zip", ".7z",
        ".kdbx",  # KeePass databases
    }

    recovered = []
    dest_base = Path(output_dir) / label
    dest_base.mkdir(parents=True, exist_ok=True)

    count = 0
    for root, dirs, files in os.walk(ntfs_mount):
        # Skip Windows system dirs — focus on user data
        dirs[:] = [
            d for d in dirs
            if d.lower() not in ("windows", "program files", "program files (x86)", "$recycle.bin")
        ]

        for fname in files:
            if count >= max_files:
                break
            ext = Path(fname).suffix.lower()
            if ext not in valuable_extensions:
                continue

            src = Path(root) / fname
            # Recreate relative directory structure
            try:
                rel = src.relative_to(ntfs_mount)
                dest = dest_base / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                recovered.append(str(dest))
                count += 1
            except (PermissionError, OSError, shutil.Error):
                pass

    return recovered


def _parse_vshadowinfo(output: str) -> list[ShadowCopy]:
    """Parse vshadowinfo text output into ShadowCopy objects."""
    snapshots = []
    current = {}

    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Shadow copy:"):
            if current:
                snapshots.append(ShadowCopy(
                    snapshot_id=current.get("id", "unknown"),
                    volume=current.get("volume", ""),
                    creation_time=current.get("creation_time", ""),
                    size_bytes=int(current.get("size", 0)),
                ))
            current = {}
        elif ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower().replace(" ", "_")
            current[key] = val.strip()

    if current:
        snapshots.append(ShadowCopy(
            snapshot_id=current.get("id", "unknown"),
            volume=current.get("volume", ""),
            creation_time=current.get("creation_time", ""),
            size_bytes=int(current.get("size", 0)),
        ))

    return snapshots


def _try_import_vss() -> bool:
    try:
        import vss
        return True
    except ImportError:
        return False
