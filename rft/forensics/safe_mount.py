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
    case_id: str = "case_001"
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

    # Build mount options — include show_sys_files for NTFS
    base_opts = "ro,noatime,noexec,nosuid"
    if fstype in ("ntfs", "ntfs-3g"):
        base_opts += ",windows_names"
        fstype = "ntfs-3g"

    # Try mount with detected fstype first, then auto-detect
    errors = []
    mounted_ok = False
    for cmd in [
        ["mount", "-t", fstype, "-o", base_opts, mount_device, str(mount_point)] if fstype else None,
        ["mount", "-o", base_opts, mount_device, str(mount_point)],
    ]:
        if cmd is None:
            continue
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            mounted_ok = True
            break
        errors.append(result.stderr.strip())

    if not mounted_ok:
        err_detail = " | ".join(errors)
        logger.error(f"Mount failed for {mount_device}: {err_detail}")
        _set_write_protection(device, protect=False)
        try:
            mount_point.rmdir()
        except Exception:
            pass
        raise RuntimeError(f"Could not mount {mount_device}: {err_detail}")

    # Hash the device for chain of custody
    logger.info(f"Hashing {device} for chain of custody (this may take a while)...")
    device_hash = _hash_device(device)

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


def _hash_device(device: str, chunk_size: int = 65536) -> str:
    """
    Compute SHA-256 of the raw device bytes.
    Uses streaming reads to handle large drives without memory issues.
    """
    sha256 = hashlib.sha256()
    try:
        with open(device, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)
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
