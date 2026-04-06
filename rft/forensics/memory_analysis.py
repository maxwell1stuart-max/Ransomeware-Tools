"""
Memory Artifact Analysis
------------------------
Scans memory dumps and pagefile/swapfile for:
  - Encryption keys left in RAM (poorly implemented ransomware)
  - Credentials (LSASS dumps, plaintext passwords)
  - Attacker C2 infrastructure (URLs, IPs in memory strings)
  - Ransomware process artifacts
  - Injected shellcode signatures

Works with:
  - Raw memory dumps (.raw, .mem, .dmp, .vmem)
  - Windows pagefile.sys / swapfile.sys (partial)
  - Hibernation file (hiberfil.sys) — contains full RAM snapshot
  - Crash dumps (MEMORY.DMP, minidumps in Minidump/)

Uses volatility3 if available for structured analysis,
falls back to string/pattern scanning if not installed.
"""

import logging
import os
import re
import subprocess
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class MemoryFinding:
    """A single finding extracted from memory."""
    finding_type: str     # "encryption_key", "credential", "c2_url", "process", "string"
    value: str
    confidence: float     # 0.0 - 1.0
    context: str = ""     # Surrounding bytes as hex/text for verification
    offset: int = 0       # Byte offset in memory file
    source_file: str = ""


@dataclass
class MemoryAnalysisResult:
    """Results of memory artifact analysis."""
    memory_files_found: list[str] = field(default_factory=list)
    findings: list[MemoryFinding] = field(default_factory=list)

    # Key categories
    potential_keys: list[MemoryFinding] = field(default_factory=list)
    credentials: list[MemoryFinding] = field(default_factory=list)
    c2_indicators: list[MemoryFinding] = field(default_factory=list)
    process_artifacts: list[MemoryFinding] = field(default_factory=list)

    tool_used: str = ""
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# Patterns that may indicate encryption keys in memory
# AES keys are 16, 24, or 32 bytes of high-entropy data
# We look for them near key schedule markers
KEY_CONTEXT_MARKERS = [
    b"AES",
    b"Rijndael",
    b"ChaCha",
    b"Salsa20",
    b"encrypt",
    b"Encrypt",
    b"ENCRYPT",
    b"key\x00",
    b"Key\x00",
]

# C2 and ransomware infrastructure patterns
C2_PATTERNS = [
    rb"https?://[a-zA-Z0-9\-\.]{4,50}\.onion[/\w]*",   # Tor onion
    rb"https?://[a-zA-Z0-9\-\.]+\.[a-z]{2,6}/[^\s\"'<>]{5,100}",  # C2 URLs
    rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}",    # IP:port
]

# Credential patterns
CRED_PATTERNS = [
    rb"password[=: ]+[^\s\x00]{6,64}",
    rb"passwd[=: ]+[^\s\x00]{6,64}",
    rb"pwd[=: ]+[^\s\x00]{6,64}",
    rb"NTLM[:\s][0-9a-fA-F]{32}",
    rb"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}",  # NTLM hash format
]

# Known ransomware process/mutex names in memory
RANSOMWARE_STRINGS = {
    "akira":    [b"akira", b".akira", b"akiranote"],
    "lockbit":  [b"LockBit", b"lockbit", b"{1765FE8E"],
    "alphv":    [b"ALPHV", b"BlackCat", b"alphv"],
    "hive":     [b"HiveLeaks", b"hive_sign"],
    "conti":    [b"Conti", b"conti_sign"],
    "revil":    [b"REvil", b"sodinokibi", b"BlackLivesMatter"],
}


def analyze_memory(
    mount_point: str,
    output_dir: str,
    ransomware_family: Optional[str] = None,
) -> MemoryAnalysisResult:
    """
    Find and analyze memory dumps on the mounted drive.

    Args:
        mount_point: Mounted infected drive path
        output_dir: Where to save extracted artifacts
        ransomware_family: Known family for targeted pattern matching

    Returns:
        MemoryAnalysisResult with all memory findings
    """
    result = MemoryAnalysisResult()
    output_path = Path(output_dir) / "memory_analysis"
    output_path.mkdir(parents=True, exist_ok=True)

    # Find all memory dump files on the drive
    memory_files = _find_memory_files(mount_point)
    result.memory_files_found = [str(f) for f in memory_files]

    if not memory_files:
        result.notes.append(
            "No memory dump files found on this drive. "
            "For memory analysis, acquire a live RAM dump while the system is running: "
            "winpmem_mini_x64.exe mem.raw"
        )
        return result

    logger.info(f"Found {len(memory_files)} memory file(s): {[f.name for f in memory_files]}")

    # Choose analysis method
    if shutil.which("vol") or shutil.which("vol3") or shutil.which("volatility3"):
        result.tool_used = "volatility3"
        _analyze_with_volatility(memory_files, str(output_path), result, ransomware_family)
    else:
        result.tool_used = "string_scan"
        result.notes.append(
            "volatility3 not installed — using pattern scanning. "
            "Install for deeper analysis: pip3 install volatility3"
        )
        for mem_file in memory_files:
            _scan_memory_strings(mem_file, result, ransomware_family)

    # Categorize findings
    for finding in result.findings:
        if finding.finding_type == "encryption_key":
            result.potential_keys.append(finding)
        elif finding.finding_type == "credential":
            result.credentials.append(finding)
        elif finding.finding_type in ("c2_url", "c2_ip"):
            result.c2_indicators.append(finding)
        elif finding.finding_type == "process":
            result.process_artifacts.append(finding)

    logger.info(
        f"Memory analysis complete: {len(result.potential_keys)} potential keys, "
        f"{len(result.credentials)} credentials, "
        f"{len(result.c2_indicators)} C2 indicators"
    )

    # Export findings
    _export_memory_findings(result, str(output_path))

    return result


def _find_memory_files(mount_point: str) -> list[Path]:
    """Find memory dump files on the mounted drive."""
    memory_extensions = {".raw", ".mem", ".dmp", ".vmem", ".bin"}
    memory_filenames = {
        "pagefile.sys",
        "swapfile.sys",
        "hiberfil.sys",   # Hibernation = full RAM snapshot
        "MEMORY.DMP",
        "memory.dmp",
    }

    found = []
    mount = Path(mount_point)

    # Check known locations first
    known_paths = [
        mount / "pagefile.sys",
        mount / "swapfile.sys",
        mount / "hiberfil.sys",
        mount / "Windows" / "MEMORY.DMP",
        mount / "Windows" / "Minidump",
    ]

    for p in known_paths:
        if p.is_file() and p.stat().st_size > 1024 * 1024:  # >1MB
            found.append(p)
        elif p.is_dir():
            for dmp in p.glob("*.dmp"):
                found.append(dmp)

    # Search for explicit dump files in user directories
    try:
        for user_dir in (mount / "Users").iterdir():
            if not user_dir.is_dir():
                continue
            for ext in memory_extensions:
                for f in user_dir.rglob(f"*{ext}"):
                    if f.stat().st_size > 10 * 1024 * 1024:  # >10MB likely a real dump
                        found.append(f)
    except (PermissionError, FileNotFoundError):
        pass

    return list(set(found))  # Deduplicate


def _analyze_with_volatility(
    memory_files: list[Path],
    output_dir: str,
    result: MemoryAnalysisResult,
    ransomware_family: Optional[str],
):
    """Run volatility3 plugins on memory dumps."""
    vol_cmd = "vol3" if shutil.which("vol3") else ("vol" if shutil.which("vol") else "volatility3")

    for mem_file in memory_files:
        logger.info(f"Running volatility3 on {mem_file.name}...")

        plugins = [
            ("windows.pslist.PsList", "process_list"),
            ("windows.cmdline.CmdLine", "cmdline"),
            ("windows.netscan.NetScan", "network"),
            ("windows.hashdump.Hashdump", "hashes"),
            ("windows.malfind.Malfind", "malfind"),
        ]

        for plugin, label in plugins:
            try:
                cmd = [vol_cmd, "-f", str(mem_file), plugin]
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120
                )
                if proc.returncode == 0 and proc.stdout:
                    out_file = Path(output_dir) / f"{mem_file.stem}_{label}.txt"
                    out_file.write_text(proc.stdout)
                    _parse_volatility_output(proc.stdout, plugin, result, str(mem_file))
            except subprocess.TimeoutExpired:
                result.errors.append(f"Volatility plugin {plugin} timed out on {mem_file.name}")
            except Exception as e:
                result.errors.append(f"Volatility {plugin} error: {e}")


def _parse_volatility_output(output: str, plugin: str, result: MemoryAnalysisResult, source: str):
    """Parse volatility plugin output into findings."""
    if "PsList" in plugin or "CmdLine" in plugin:
        suspicious_procs = [
            "mimikatz", "procdump", "psexec", "cobalt",
            "meterpreter", "empire", "vssadmin", "wmic",
        ]
        for line in output.splitlines():
            lower = line.lower()
            for proc in suspicious_procs:
                if proc in lower:
                    result.findings.append(MemoryFinding(
                        finding_type="process",
                        value=line.strip(),
                        confidence=0.8,
                        source_file=source,
                    ))

    elif "Hashdump" in plugin:
        # NTLM hash format: username:rid:lmhash:nthash
        hash_pattern = re.compile(r"([^:]+):\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}")
        for match in hash_pattern.finditer(output):
            result.findings.append(MemoryFinding(
                finding_type="credential",
                value=match.group(0),
                confidence=0.95,
                source_file=source,
            ))

    elif "NetScan" in plugin:
        # Extract external IPs from network connections
        ip_pattern = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d+)")
        for match in ip_pattern.finditer(output):
            ip = match.group(1)
            if not _is_private_ip(ip):
                result.findings.append(MemoryFinding(
                    finding_type="c2_ip",
                    value=f"{ip}:{match.group(2)}",
                    confidence=0.7,
                    source_file=source,
                ))


def _scan_memory_strings(
    mem_file: Path,
    result: MemoryAnalysisResult,
    ransomware_family: Optional[str],
):
    """
    Pattern-based scan of raw memory file.
    Reads in chunks to handle multi-GB files without OOM.
    """
    chunk_size = 10 * 1024 * 1024  # 10MB chunks
    overlap = 1024  # Overlap to catch patterns spanning chunk boundaries

    family_patterns = []
    if ransomware_family:
        family_lower = ransomware_family.lower()
        for fam, patterns in RANSOMWARE_STRINGS.items():
            if fam in family_lower:
                family_patterns = patterns
                break

    try:
        file_size = mem_file.stat().st_size
        logger.info(f"Scanning {mem_file.name} ({file_size // (1024**2)}MB)...")

        with open(mem_file, "rb") as f:
            offset = 0
            prev_tail = b""

            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                data = prev_tail + chunk

                # Scan for C2 patterns
                for pattern in C2_PATTERNS:
                    for match in re.finditer(pattern, data, re.IGNORECASE):
                        value = match.group(0).decode("utf-8", errors="replace")
                        result.findings.append(MemoryFinding(
                            finding_type="c2_url",
                            value=value,
                            confidence=0.75,
                            offset=offset + match.start() - len(prev_tail),
                            source_file=str(mem_file),
                        ))

                # Scan for credentials
                for pattern in CRED_PATTERNS:
                    for match in re.finditer(pattern, data, re.IGNORECASE):
                        value = match.group(0).decode("utf-8", errors="replace")
                        result.findings.append(MemoryFinding(
                            finding_type="credential",
                            value=value[:128],  # Cap length
                            confidence=0.6,
                            offset=offset + match.start() - len(prev_tail),
                            source_file=str(mem_file),
                        ))

                # Scan for ransomware-family-specific strings
                for pattern in family_patterns:
                    if pattern in data:
                        idx = data.find(pattern)
                        context = data[max(0, idx-32):idx+64]
                        result.findings.append(MemoryFinding(
                            finding_type="ransomware_artifact",
                            value=pattern.decode("utf-8", errors="replace"),
                            confidence=0.9,
                            context=context.hex(),
                            offset=offset + idx - len(prev_tail),
                            source_file=str(mem_file),
                        ))

                # Check for key-schedule-like data near key markers
                for marker in KEY_CONTEXT_MARKERS:
                    pos = 0
                    while True:
                        idx = data.find(marker, pos)
                        if idx == -1:
                            break
                        # Extract 32 bytes after the marker as potential key material
                        key_candidate = data[idx + len(marker): idx + len(marker) + 32]
                        if len(key_candidate) == 32 and _looks_like_key(key_candidate):
                            result.findings.append(MemoryFinding(
                                finding_type="encryption_key",
                                value=key_candidate.hex(),
                                confidence=0.4,  # Low confidence — needs manual verification
                                context=f"Found after marker: {marker.decode('utf-8', errors='replace')}",
                                offset=offset + idx - len(prev_tail),
                                source_file=str(mem_file),
                            ))
                        pos = idx + 1

                prev_tail = chunk[-overlap:]
                offset += len(chunk)

    except (PermissionError, OSError) as e:
        result.errors.append(f"Cannot read {mem_file.name}: {e}")


def _looks_like_key(data: bytes) -> bool:
    """
    Heuristic: does this 32-byte sequence look like an AES key?
    Real keys have high entropy and are not all-zero or repeating.
    """
    if len(data) < 16:
        return False
    if len(set(data)) < 8:  # Too few unique bytes
        return False
    if data == bytes(len(data)):  # All zeros
        return False
    # Check entropy
    from collections import Counter
    counts = Counter(data)
    total = len(data)
    entropy = -sum((c / total) * __import__("math").log2(c / total) for c in counts.values())
    return entropy > 3.5  # AES keys typically have entropy > 3.5 bits/byte


def _is_private_ip(ip: str) -> bool:
    """Return True if IP is RFC1918 private."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or a == 127 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168))
    except ValueError:
        return True


def _export_memory_findings(result: MemoryAnalysisResult, output_dir: str):
    """Write memory findings to JSON."""
    out = Path(output_dir) / "memory_findings.json"
    try:
        data = {
            "files_analyzed": result.memory_files_found,
            "tool_used": result.tool_used,
            "summary": {
                "total_findings": len(result.findings),
                "potential_keys": len(result.potential_keys),
                "credentials": len(result.credentials),
                "c2_indicators": len(result.c2_indicators),
                "process_artifacts": len(result.process_artifacts),
            },
            "findings": [
                {
                    "type": f.finding_type,
                    "value": f.value,
                    "confidence": f.confidence,
                    "context": f.context,
                    "source": f.source_file,
                }
                for f in result.findings
            ],
            "notes": result.notes,
            "errors": result.errors,
        }
        out.write_text(json.dumps(data, indent=2))
    except Exception as e:
        result.errors.append(f"Export failed: {e}")
