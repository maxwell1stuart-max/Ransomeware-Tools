"""
APT Scanner — Phase 4: Credential Testing
Tests common/default credentials against discovered services using hydra
and direct protocol connections.
"""

import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from apt.scanner.enumeration import HostEnumResult


# ── Top 60 most common credential pairs ──────────────────────────────────────

COMMON_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("administrator", "password"),
    ("administrator", "Administrator"),
    ("administrator", ""),
    ("administrator", "admin"),
    ("root", "root"),
    ("root", "toor"),
    ("root", ""),
    ("root", "password"),
    ("root", "123456"),
    ("guest", "guest"),
    ("guest", ""),
    ("user", "user"),
    ("user", "password"),
    ("pi", "raspberry"),
    ("pi", ""),
    ("test", "test"),
    ("demo", "demo"),
    ("service", "service"),
    ("support", "support"),
    ("backup", "backup"),
    ("oracle", "oracle"),
    ("sa", ""),
    ("sa", "sa"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
    ("ubnt", "ubnt"),
    ("cisco", "cisco"),
    ("enable", "enable"),
    ("netgear", "netgear"),
    ("admin", "netgear"),
    ("admin", "1111"),
    ("admin", "0000"),
]

SERVICES_TO_TEST = {"ssh", "ftp", "rdp", "smb", "telnet", "vnc", "http", "https", "winrm", "mssql", "mysql", "postgresql"}


@dataclass
class CredentialFinding:
    ip: str
    service: str
    port: int
    username: str
    password: str
    access_level: str = "unknown"    # admin / user / readonly
    notes: str = ""


@dataclass
class CredTestResult:
    findings: list = field(default_factory=list)
    hosts_tested: int = 0
    services_tested: int = 0
    errors: list = field(default_factory=list)


def _log(msg: str, level: str = "info", callback: Optional[Callable] = None):
    if callback:
        callback(msg, level)


def _write_credential_files(creds: list) -> tuple:
    """Write username and password lists to temp files for hydra."""
    users = list({c[0] for c in creds})
    passwords = list({c[1] for c in creds})

    user_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    for u in users:
        user_file.write(u + "\n")
    user_file.close()

    pass_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    for p in passwords:
        pass_file.write(p + "\n")
    pass_file.close()

    return user_file.name, pass_file.name


def _test_with_hydra(ip: str, service: str, port: int, creds: list,
                      log_callback: Optional[Callable] = None) -> list:
    """Run hydra against a service and return list of CredentialFinding."""
    findings = []
    if not shutil.which("hydra"):
        return findings

    user_file, pass_file = _write_credential_files(creds)

    try:
        # Map service name to hydra service module
        hydra_service_map = {
            "ssh": "ssh",
            "ftp": "ftp",
            "rdp": "rdp",
            "smb": "smb",
            "telnet": "telnet",
            "vnc": "vnc",
            "http": "http-get",
            "https": "https-get",
            "mssql": "mssql",
            "mysql": "mysql",
            "postgresql": "postgres",
        }
        hydra_svc = hydra_service_map.get(service)
        if not hydra_svc:
            return findings

        cmd = [
            "hydra",
            "-L", user_file,
            "-P", pass_file,
            "-t", "2",          # 2 parallel tasks (was 4) — gentler on target services
            "-w", "5",          # 5 second response wait (was 3)
            "-c", "2",          # 2 second delay between connection attempts per task
            "-f",               # stop after first valid pair found
            "-q",               # quiet
            f"{ip}",
            hydra_svc,
            "-s", str(port),
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = proc.stdout + proc.stderr

        # Parse hydra output: "[port][service] host: IP   login: USER   password: PASS"
        import re
        for line in output.splitlines():
            match = re.search(
                r"host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(.*)",
                line, re.IGNORECASE
            )
            if match:
                username = match.group(2).strip()
                password = match.group(3).strip()
                access = "admin" if username.lower() in ("admin", "administrator", "root", "sa") else "user"
                findings.append(CredentialFinding(
                    ip=ip,
                    service=service,
                    port=port,
                    username=username,
                    password=password,
                    access_level=access,
                ))
                _log(f"  CREDENTIAL FOUND: {service}://{username}:{'*' * len(password)}@{ip}:{port} [{access}]", "success", log_callback)

    except subprocess.TimeoutExpired:
        _log(f"  hydra timed out for {service}://{ip}:{port}", "warn", log_callback)
    except Exception as e:
        _log(f"  hydra error for {service}://{ip}: {e}", "warn", log_callback)
    finally:
        Path(user_file).unlink(missing_ok=True)
        Path(pass_file).unlink(missing_ok=True)

    return findings


def _test_smb_direct(ip: str, port: int, creds: list,
                      log_callback: Optional[Callable] = None) -> list:
    """Test SMB credentials directly using impacket (no hydra needed)."""
    findings = []
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        return findings

    for username, password in creds:
        try:
            smb = SMBConnection(ip, ip, timeout=5)
            smb.login(username, password)
            smb.logoff()
            access = "admin" if username.lower() in ("admin", "administrator", "root") else "user"
            findings.append(CredentialFinding(
                ip=ip, service="smb", port=port,
                username=username, password=password,
                access_level=access,
            ))
            _log(f"  SMB credential valid: {username}:{'*' * len(password)} @ {ip}", "success", log_callback)
            break  # Stop after first valid pair
        except Exception:
            continue

    return findings


def test_credentials(
    enum_results: list,
    custom_creds: Optional[list] = None,
    log_callback: Optional[Callable] = None,
) -> CredTestResult:
    """
    Test common credentials against discovered services.

    Args:
        enum_results: List of HostEnumResult from Phase 2
        custom_creds: Optional list of (username, password) tuples to add
        log_callback: Optional callable(msg, level)

    Returns:
        CredTestResult with all confirmed credential findings
    """
    result = CredTestResult()
    creds = COMMON_CREDS + (custom_creds or [])

    if not enum_results:
        _log("No hosts to test credentials against.", "warn", log_callback)
        return result

    _log(f"Starting credential testing on {len(enum_results)} hosts ({len(creds)} credential pairs)...", "info", log_callback)

    use_hydra = bool(shutil.which("hydra"))
    if not use_hydra:
        _log("hydra not found — using direct protocol testing only (SMB via impacket)", "warn", log_callback)

    for enum_result in enum_results:
        ip = enum_result.ip
        services_on_host = {s.service: s.port for s in enum_result.services if s.service in SERVICES_TO_TEST}

        if not services_on_host:
            continue

        result.hosts_tested += 1
        _log(f"Testing credentials on {ip}: {', '.join(services_on_host.keys())}", "info", log_callback)

        for service, port in services_on_host.items():
            result.services_tested += 1

            if service == "smb":
                # Try impacket first (faster, no subprocess), then hydra
                findings = _test_smb_direct(ip, port, creds, log_callback)
                if not findings and use_hydra:
                    findings = _test_with_hydra(ip, service, port, creds, log_callback)
            elif use_hydra:
                findings = _test_with_hydra(ip, service, port, creds, log_callback)
            else:
                findings = []

            result.findings.extend(findings)

        if not any(f.ip == ip for f in result.findings):
            _log(f"  No valid credentials found on {ip}", "info", log_callback)

    total = len(result.findings)
    if total:
        _log(f"Credential testing complete: {total} valid credential pair(s) found!", "success", log_callback)
    else:
        _log(f"Credential testing complete: No default/common credentials found", "info", log_callback)

    return result
