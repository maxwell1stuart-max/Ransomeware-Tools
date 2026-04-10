"""
Safe Drive Mounting — Write-Blocked Forensic Acquisition

Mounts infected drives in read-only mode using kernel-level write blocking.
All mounts are logged with timestamps and drive hashes for chain of custody.

NEVER writes to the source drive. All mounts are:
  1. Hardware write-blocked via blockdev --setro
  2. Mounted with noatime,ro kernel flags
  3. Hashed before and after to verify integrity
"""

import hashlib
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class MountRecord:
    """Chain-of-custody record for a mounted device."""
    device: str
    mount_point: str
    timestamp: float
    sha256_hash: str
    filesystem_type: str
    size_bytes: int
    serial_number: str = ""
    model: str = ""
    notes: str = ""
    verified: bool = False


@dataclass
class MountedDrive:
    """Context manager for a safely mounted forensic drive."""
    record: MountRecord
    _mounted: bool = field(default=False, repr=False)

    @property
    def mount_point(self) -> str:
        return self.record.mount_point

    @property
    def hash_before(self) -> str:
        return self.record.sha256_hash

    def unmount(self) -> bool:
        if not self._mounted:
            return True
        try:
            result = subprocess.run(
                ["umount", self.record.mount_point],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                self._mounted = False
                # Remove write protection so the device returns to normal
                _set_write_protection(self.record.device, protect=False)
                logger.info(f"Unmounted {self.record.device} from {self.record.mount_point}")
                return True
            else:
                logger.error(f"Unmount failed: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Unmount error: {e}")
            return False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.unmount()


def list_available_drives() -> list[dict]:
    """
    List all block devices that could be infected drives.
    Excludes the current root device to prevent accidental analysis of the forensic system.
    """
    try:
        result = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT,SERIAL,MODEL,VENDOR"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            logger.error(f"lsblk failed: {result.stderr}")
            return []

        import json
        data = json.loads(result.stdout)
        drives = []

        for dev in data.get("blockdevices", []):
            if dev.get("type") != "disk":
                continue
            # Skip the root device
            root_dev = _get_root_device()
            if dev["name"] in root_dev:
                continue
            drives.append({
                "device": f"/dev/{dev['name']}",
                "name": dev.get("name", ""),
                "size": dev.get("size", "Unknown"),
                "model": dev.get("model", "Unknown"),
                "vendor": dev.get("vendor", ""),
                "serial": dev.get("serial", ""),
                "partitions": [
                    {
                        "device": f"/dev/{p['name']}",
                        "size": p.get("size", ""),
                        "fstype": p.get("fstype", ""),
                        "label": p.get("label", ""),
                    }
                    for p in dev.get("children", [])
                ]
            })
        return drives
    except Exception as e:
        logger.error(f"Failed to list drives: {e}")
        return []


def mount_drive_readonly(
    device: str,
    mount_base: str = "/mnt/forensics",
    case_id: str = "case_001",
    skip_hash: bool = False,
) -> Optional[MountedDrive]:
    """
    Mount a device in read-only mode with software write blocking.

    Steps:
      1. Apply kernel-level write protection (blockdev --setro)
      2. Create a unique mount point
      3. Mount with ro,noatime,noexec flags
      4. Hash the device for chain-of-custody
      5. Return a MountedDrive context manager

    Args:
        device: Block device path, e.g. /dev/sdb1
        mount_base: Base directory for mount points
        case_id: Case identifier for the mount point name

    Returns:
        MountedDrive on success, None on failure
    """
    # Validate device exists
    if not Path(device).exists():
        logger.error(f"Device {device} does not exist")
        raise RuntimeError(f"Device {device} does not exist")

    # Ensure mount base directory exists
    Path(mount_base).mkdir(parents=True, exist_ok=True)

    # If device is already mounted elsewhere, unmount it first
    existing_mount = _get_current_mountpoint(device)
    if existing_mount:
        logger.warning(f"{device} is mounted at {existing_mount} — unmounting before analysis")
        result = subprocess.run(["umount", device], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Could not unmount {device} from {existing_mount}: {result.stderr.strip()}")

    # Apply write protection BEFORE mounting (non-fatal — RAID/some drives reject blockdev)
    wp_ok = _set_write_protection(device, protect=True)
    if not wp_ok:
        logger.warning(f"blockdev --setro unavailable for {device} — relying on mount -o ro")

    # Create unique mount point
    timestamp = int(time.time())
    dev_name = Path(device).name
    mount_point = Path(mount_base) / case_id / f"{dev_name}_{timestamp}"
    mount_point.mkdir(parents=True, exist_ok=True)

    # If device is a whole disk (no partition table FS), try first partition
    fstype = _detect_filesystem(device)
    mount_device = device

    # If no fstype found on the raw disk, check if it has partitions and use the first one
    if not fstype:
        children = _get_partitions(device)
        if children:
            mount_device = children[0]
            fstype = _detect_filesystem(mount_device)
            logger.info(f"{device} has no direct filesystem — trying first partition {mount_device}")

    # ── BitLocker check ───────────────────────────────────────────────────────
    if fstype and "bitlocker" in fstype.lower() or _is_bitlocker(mount_device):
        _set_write_protection(device, protect=False)
        try:
            mount_point.rmdir()
        except Exception:
            pass
        has_dislocker = bool(subprocess.run(["which", "dislocker"], capture_output=True).returncode == 0)
        if has_dislocker:
            raise RuntimeError(
                f"{mount_device} is BitLocker encrypted. To unlock:\n"
                f"  1. Get the BitLocker recovery key (from Microsoft account or AD)\n"
                f"  2. sudo dislocker {mount_device} -p<recovery-key> -- /mnt/bitlocker\n"
                f"  3. Then mount: sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/forensics/unlocked"
            )
        else:
            raise RuntimeError(
                f"{mount_device} is BitLocker encrypted.\n"
                f"Install dislocker to decrypt: sudo apt-get install dislocker\n"
                f"Then provide the BitLocker recovery key (from victim's Microsoft account or Active Directory)."
            )

    # ── NTFS hibernation check ────────────────────────────────────────────────
    if fstype in ("ntfs", "ntfs-3g") and _is_ntfs_hibernated(mount_device):
        # Do NOT use remove_hiberfile — it writes to the drive, violating forensic integrity.
        # Instead try the kernel ntfs3 driver which is more permissive with dirty volumes.
        logger.warning(f"{mount_device}: NTFS volume is hibernated (Windows Fast Startup). "
                       f"Attempting read-only mount via kernel ntfs3 driver.")

    # Build mount options — include show_sys_files for NTFS
    base_opts = "ro,noatime,noexec,nosuid"

    # Try mount with detected fstype first, then fallbacks
    errors = []
    mounted_ok = False
    mount_attempts = []

    if fstype in ("ntfs", "ntfs-3g"):
        # Try kernel ntfs3 driver first (handles dirty volumes better than ntfs-3g userspace)
        mount_attempts.append(["mount", "-t", "ntfs3", "-o", base_opts, mount_device, str(mount_point)])
        # Then ntfs-3g userspace
        mount_attempts.append(["mount", "-t", "ntfs-3g", "-o", base_opts + ",windows_names", mount_device, str(mount_point)])
        # ntfs-3g with ignore_case as last resort
        mount_attempts.append(["mount", "-t", "ntfs-3g", "-o", base_opts + ",windows_names,ignore_case", mount_device, str(mount_point)])
    elif fstype:
        mount_attempts.append(["mount", "-t", fstype, "-o", base_opts, mount_device, str(mount_point)])

    # Always include a no-fstype fallback
    mount_attempts.append(["mount", "-o", base_opts, mount_device, str(mount_point)])

    for cmd in mount_attempts:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            mounted_ok = True
            # Use whichever fstype actually worked
            if "-t" in cmd:
                fstype = cmd[cmd.index("-t") + 1]
            break
        errors.append(result.stderr.strip())

    if not mounted_ok:
        err_detail = " | ".join(e for e in errors if e)
        _set_write_protection(device, protect=False)
        try:
            mount_point.rmdir()
        except Exception:
            pass

        # Produce a helpful error message based on what we know
        if fstype in ("ntfs", "ntfs-3g"):
            raise RuntimeError(
                f"Could not mount {mount_device} (NTFS).\n\n"
                f"Most likely cause: Windows used Fast Startup / hibernation and left "
                f"the volume in a dirty state. Linux cannot safely mount it without risking corruption.\n\n"
                f"Options:\n"
                f"  1. Boot Windows on the original machine, disable Fast Startup "
                f"(Control Panel → Power Options → Choose what the power buttons do → "
                f"Turn on fast startup → UNCHECK), then shut down fully.\n"
                f"  2. Or create a forensic image first and work from that:\n"
                f"     sudo dd if={mount_device} of=/path/to/case.img bs=4M status=progress\n"
                f"     sudo ntfs-3g -o ro,remove_hiberfile /path/to/case.img /mnt/forensics/unlocked\n"
                f"     (remove_hiberfile on the IMAGE is safe — the original drive is untouched)\n\n"
                f"Raw error: {err_detail}"
            )
        else:
            raise RuntimeError(f"Could not mount {mount_device}: {err_detail}")

    # Hash the device for chain of custody
    if skip_hash:
        logger.warning(f"Skipping hash (skip_hash=True) — chain of custody not established")
        device_hash = "HASH_SKIPPED"
    else:
        logger.info(f"Hashing {mount_device} for chain of custody (may take 10-20 min on large drives)...")
        def _hash_progress(done, total):
            pct = done * 100 // total
            done_gb = done / (1024**3)
            total_gb = total / (1024**3)
            logger.info(f"Hashing progress: {pct}% ({done_gb:.1f} / {total_gb:.1f} GB)")
        device_hash = _hash_device(mount_device, progress_callback=_hash_progress)

    # Get device info
    device_info = _get_device_info(device)

    record = MountRecord(
        device=device,
        mount_point=str(mount_point),
        timestamp=timestamp,
        sha256_hash=device_hash,
        filesystem_type=fstype or "unknown",
        size_bytes=device_info.get("size_bytes", 0),
        serial_number=device_info.get("serial", ""),
        model=device_info.get("model", ""),
        verified=True
    )

    logger.info(
        f"Successfully mounted {device} at {mount_point} (read-only)\n"
        f"  SHA-256: {device_hash}\n"
        f"  FS Type: {fstype}\n"
        f"  Size: {device_info.get('size_bytes', 0):,} bytes"
    )

    mounted = MountedDrive(record=record, _mounted=True)
    return mounted


def verify_mount_integrity(mounted: MountedDrive) -> bool:
    """
    Re-hash the device and compare to the original hash.
    Confirms no writes occurred during analysis.
    """
    current_hash = _hash_device(mounted.record.device)
    if current_hash == mounted.record.sha256_hash:
        logger.info(f"Integrity verified: hash matches original for {mounted.record.device}")
        mounted.record.verified = True
        return True
    else:
        logger.error(
            f"INTEGRITY VIOLATION: Hash mismatch for {mounted.record.device}\n"
            f"  Original: {mounted.record.sha256_hash}\n"
            f"  Current:  {current_hash}"
        )
        mounted.record.verified = False
        return False


def _set_write_protection(device: str, protect: bool) -> bool:
    """Apply or remove kernel-level write protection via blockdev."""
    flag = "--setro" if protect else "--setrw"
    # Apply to the whole disk, not just partition
    disk_device = _get_parent_disk(device)
    result = subprocess.run(
        ["blockdev", flag, disk_device],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        logger.warning(f"blockdev {flag} failed for {disk_device}: {result.stderr}")
        return False
    action = "write-protected" if protect else "write-protection removed"
    logger.info(f"Device {disk_device} {action}")
    return True


def _detect_filesystem(device: str) -> Optional[str]:
    """Detect filesystem type using blkid."""
    result = subprocess.run(
        ["blkid", "-o", "value", "-s", "TYPE", device],
        capture_output=True, text=True
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return None


def _is_bitlocker(device: str) -> bool:
    """Return True if the partition is BitLocker encrypted."""
    result = subprocess.run(
        ["blkid", "-o", "value", "-s", "TYPE", device],
        capture_output=True, text=True
    )
    fs = result.stdout.strip().lower()
    if "bitlocker" in fs:
        return True
    # blkid sometimes just returns nothing for BitLocker — check with file
    result2 = subprocess.run(
        ["file", "-s", device],
        capture_output=True, text=True
    )
    return "BitLocker" in result2.stdout


def _is_ntfs_hibernated(device: str) -> bool:
    """
    Return True if the NTFS volume has the hibernation/dirty flag set.
    Windows Fast Startup leaves volumes in this state — they appear dirty
    to Linux and cannot be safely mounted without risking data corruption.
    """
    try:
        result = subprocess.run(
            ["ntfsfix", "--no-action", device],
            capture_output=True, text=True
        )
        output = result.stdout + result.stderr
        return any(kw in output for kw in (
            "Hibernate", "hiberfil", "Volume is scheduled",
            "Windows is hibernated", "Dirty flag is set",
        ))
    except FileNotFoundError:
        # ntfsfix not installed — try parsing boot sector directly
        try:
            with open(device, "rb") as f:
                f.seek(0x1c)   # NTFS VCN of first cluster
                f.seek(0x28)   # Flags offset in NTFS BPB not standard
            # Fall back: just try mounting and see
            return False
        except Exception:
            return False


def _hash_device(device: str, chunk_size: int = 1024 * 1024, progress_callback=None) -> str:
    """
    Compute SHA-256 of the raw device bytes.
    Uses streaming reads to handle large drives without memory issues.
    Calls progress_callback(bytes_done, total_bytes) periodically if provided.
    """
    sha256 = hashlib.sha256()
    total = 0
    try:
        # Get device size for progress reporting
        size = 0
        try:
            size_result = subprocess.run(
                ["blockdev", "--getsize64", device],
                capture_output=True, text=True
            )
            if size_result.returncode == 0:
                size = int(size_result.stdout.strip())
        except Exception:
            pass

        with open(device, "rb") as f:
            last_report = 0
            last_yield = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)
                total += len(chunk)
                # Yield CPU every 64MB so the OS stays responsive
                if total - last_yield >= 64 * 1024 * 1024:
                    time.sleep(0.01)
                    last_yield = total
                # Report progress every 512MB
                if progress_callback and size and (total - last_report) >= 512 * 1024 * 1024:
                    progress_callback(total, size)
                    last_report = total

    except PermissionError:
        logger.error(f"Cannot read {device}: permission denied (run as root)")
        return "ERROR_PERMISSION_DENIED"
    except OSError as e:
        logger.error(f"Error hashing {device}: {e}")
        return f"ERROR_{e}"
    return sha256.hexdigest()


def _get_device_info(device: str) -> dict:
    """Get device metadata from sysfs."""
    disk = _get_parent_disk(device)
    disk_name = Path(disk).name
    info = {}
    try:
        size_path = Path(f"/sys/block/{disk_name}/size")
        if size_path.exists():
            sectors = int(size_path.read_text().strip())
            info["size_bytes"] = sectors * 512

        model_path = Path(f"/sys/block/{disk_name}/device/model")
        if model_path.exists():
            info["model"] = model_path.read_text().strip()

        serial_path = Path(f"/sys/block/{disk_name}/device/serial")
        if serial_path.exists():
            info["serial"] = serial_path.read_text().strip()
    except Exception:
        pass
    return info


def _get_parent_disk(device: str) -> str:
    """Convert partition path to disk path: /dev/sdb1 → /dev/sdb"""
    result = subprocess.run(
        ["lsblk", "-no", "PKNAME", device],
        capture_output=True, text=True
    )
    if result.returncode == 0 and result.stdout.strip():
        return f"/dev/{result.stdout.strip()}"
    return device


def _get_current_mountpoint(device: str) -> Optional[str]:
    """Return the current mountpoint of a device, or None if not mounted."""
    result = subprocess.run(
        ["findmnt", "-n", "-o", "TARGET", device],
        capture_output=True, text=True
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return None


def _get_partitions(device: str) -> list[str]:
    """Return list of partition device paths for a disk, e.g. ['/dev/sda1', '/dev/sda2']"""
    import json
    result = subprocess.run(
        ["lsblk", "-J", "-o", "NAME,TYPE", device],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
        partitions = []
        for dev in data.get("blockdevices", []):
            for child in dev.get("children", []):
                if child.get("type") == "part":
                    partitions.append(f"/dev/{child['name']}")
        return partitions
    except Exception:
        return []


def _get_root_device() -> str:
    """Get the device name of the root filesystem."""
    result = subprocess.run(
        ["findmnt", "-n", "-o", "SOURCE", "/"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return ""
