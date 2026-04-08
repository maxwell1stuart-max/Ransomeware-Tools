"""
APT Scanner — Phase 2: Service Enumeration
Runs nmap service/version scan, enum4linux, and crackmapexec on discovered hosts.
"""

import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable, Optional

from apt.scanner.discovery import DiscoveredHost


# ── Data Classes ────────────────────────────────────────────────────────────────

@dataclass
class ServiceInfo:
    port: int
    protocol: str        # tcp / udp
    service: str         # http, ssh, smb, rdp, ftp, etc.
    version: str = ""
    banner: str = ""
    cpe: str = ""        # Common Platform Enumeration string


@dataclass
class HostEnumResult:
    ip: str
    services: list = field(default_factory=list)
    smb_shares: list = field(default_factory=list)
    smb_users: list = field(default_factory=list)
    ad_domain: str = ""
    os_info: str = ""
    hostname: str = ""
    errors: list = field(default_factory=list)


# ── Helpers ──────────────────────────────────────────────────────────────────────

def _log(msg: str, level: str = "info", callback: Optional[Callable] = None):
    if callback:
        callback(msg, level)


def _parse_nmap_services(xml_output: str, ip: str) -> list:
    """Parse nmap XML to extract ServiceInfo list for a given host."""
    services = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return services

    for host_el in root.findall("host"):
        # Match by IP
        ip_found = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip_found = addr.get("addr", "")
        if ip_found != ip:
            continue

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid = int(port_el.get("portid", "0"))
            proto = port_el.get("protocol", "tcp")

            svc_el = port_el.find("service")
            svc_name = ""
            svc_version = ""
            svc_cpe = ""
            svc_banner = ""

            if svc_el is not None:
                svc_name = svc_el.get("name", "")
                product = svc_el.get("product", "")
                version = svc_el.get("version", "")
                extrainfo = svc_el.get("extrainfo", "")
                if product:
                    svc_version = product
                    if version:
                        svc_version += f" {version}"
                    if extrainfo:
                        svc_version += f" ({extrainfo})"
                # CPE
                cpe_el = svc_el.find("cpe")
                if cpe_el is not None:
                    svc_cpe = cpe_el.text or ""

            # Script output as banner
            for script_el in port_el.findall("script"):
                if script_el.get("id") in ("banner", "http-title", "ssl-cert"):
                    out = script_el.get("output", "")
                    if out:
                        svc_banner = out[:200]
                        break

            services.append(ServiceInfo(
                port=portid,
                protocol=proto,
                service=_normalize_service(svc_name, portid),
                version=svc_version,
                banner=svc_banner,
                cpe=svc_cpe,
            ))

    return services


def _normalize_service(svc_name: str, port: int) -> str:
    """Normalize nmap service names to consistent names."""
    name_map = {
        "microsoft-ds": "smb",
        "netbios-ssn": "smb",
        "ms-wbt-server": "rdp",
        "ssl/https": "https",
        "ssl/http": "https",
    }
    name = svc_name.lower()
    if name in name_map:
        return name_map[name]

    # Port-based fallbacks
    port_defaults = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 139: "smb",
        143: "imap", 443: "https", 445: "smb", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5985: "winrm",
        6379: "redis", 8080: "http", 8443: "https",
        27017: "mongodb", 1433: "mssql", 1521: "oracle",
    }
    if name:
        return name
    return port_defaults.get(port, f"unknown-{port}")


def _run_enum4linux(ip: str, log_callback: Optional[Callable] = None) -> tuple:
    """
    Run enum4linux against an SMB host.
    Returns (shares, users, domain, os_info).
    """
    shares = []
    users = []
    domain = ""
    os_info = ""

    if not shutil.which("enum4linux"):
        _log(f"  enum4linux not found — skipping SMB enumeration for {ip}", "warn", log_callback)
        return shares, users, domain, os_info

    _log(f"  Running enum4linux -a {ip}", "info", log_callback)
    try:
        proc = subprocess.run(
            ["enum4linux", "-a", ip],
            capture_output=True, text=True, timeout=120
        )
        output = proc.stdout + proc.stderr

        # Parse shares
        for line in output.splitlines():
            # Sharename patterns: [+] Got share list via RPC, then table rows
            share_match = re.match(r"\s+(\w[\w\s-]*?)\s+Disk\s", line, re.IGNORECASE)
            if share_match:
                share = share_match.group(1).strip()
                if share not in shares:
                    shares.append(share)
            # Alternate format
            share_match2 = re.match(r"\s*//[\d.]+/(\S+)", line)
            if share_match2:
                share = share_match2.group(1)
                if share not in shares:
                    shares.append(share)

        # Parse users
        for line in output.splitlines():
            user_match = re.match(r".*user:\[([^\]]+)\]", line, re.IGNORECASE)
            if user_match:
                user = user_match.group(1).strip()
                if user not in users:
                    users.append(user)
            # Alternate: "index: 0x..." lines with username
            alt_match = re.match(r".*\bUser:\s*(\S+)", line, re.IGNORECASE)
            if alt_match:
                user = alt_match.group(1).strip().rstrip(",")
                if user and user not in users:
                    users.append(user)

        # Domain/OS
        for line in output.splitlines():
            if "Domain Name:" in line or "Domain=" in line:
                dm = re.search(r"Domain[= ]+[Name:]*\s*(\S+)", line, re.IGNORECASE)
                if dm:
                    domain = dm.group(1).strip().strip("\\")
            if "OS:" in line:
                os_match = re.search(r"OS:\s*(.+)", line, re.IGNORECASE)
                if os_match:
                    os_info = os_match.group(1).strip()

    except subprocess.TimeoutExpired:
        _log(f"  enum4linux timed out for {ip}", "warn", log_callback)
    except Exception as e:
        _log(f"  enum4linux error for {ip}: {e}", "warn", log_callback)

    return shares, users, domain, os_info


def _run_crackmapexec(ip: str, log_callback: Optional[Callable] = None) -> tuple:
    """
    Run crackmapexec smb for Windows/AD host info.
    Returns (hostname, domain, os_info, shares, users).
    """
    hostname = ""
    domain = ""
    os_info = ""
    shares = []
    users = []

    # Try 'crackmapexec' or 'cme'
    cme_bin = shutil.which("crackmapexec") or shutil.which("cme") or shutil.which("netexec") or shutil.which("nxc")
    if not cme_bin:
        _log(f"  crackmapexec/netexec not found — skipping for {ip}", "warn", log_callback)
        return hostname, domain, os_info, shares, users

    _log(f"  Running crackmapexec smb {ip}", "info", log_callback)
    try:
        proc = subprocess.run(
            [cme_bin, "smb", ip],
            capture_output=True, text=True, timeout=60
        )
        output = proc.stdout + proc.stderr

        # Parse: SMB  192.168.1.10  445  HOSTNAME  [*] Windows 10 x64 (name:HOSTNAME) (domain:DOMAIN)
        for line in output.splitlines():
            if "SMB" in line and ip in line:
                # Extract hostname
                hn_match = re.search(r"\)\s+\[[\*+]\]\s+\S+\s+\S+\s+\(name:([^)]+)\)", line)
                if hn_match:
                    hostname = hn_match.group(1)
                # Simple hostname extraction
                parts = line.split()
                if len(parts) >= 4:
                    hostname = hostname or parts[3]

                # Domain
                dm_match = re.search(r"\(domain:([^)]+)\)", line, re.IGNORECASE)
                if dm_match:
                    domain = dm_match.group(1)

                # OS
                os_match = re.search(r"\[\*\]\s+(.+?)\s+\(name:", line)
                if os_match:
                    os_info = os_match.group(1).strip()

        # Enumerate shares
        proc2 = subprocess.run(
            [cme_bin, "smb", ip, "--shares"],
            capture_output=True, text=True, timeout=60
        )
        for line in (proc2.stdout + proc2.stderr).splitlines():
            # Share lines: SMB  ip  445  HOST  [*]  ShareName  ...
            share_match = re.search(r"READ|WRITE|NO ACCESS", line, re.IGNORECASE)
            if share_match:
                cols = line.split()
                if len(cols) >= 6:
                    share = cols[5]
                    if share not in shares:
                        shares.append(share)

    except subprocess.TimeoutExpired:
        _log(f"  crackmapexec timed out for {ip}", "warn", log_callback)
    except Exception as e:
        _log(f"  crackmapexec error for {ip}: {e}", "warn", log_callback)

    return hostname, domain, os_info, shares, users


# ── Main Entry Point ─────────────────────────────────────────────────────────────

def enumerate_hosts(
    hosts: list,
    top_ports: bool = True,
    log_callback: Optional[Callable] = None,
) -> list:
    """
    Run nmap service/version scan + enum4linux/crackmapexec on each host.

    Args:
        hosts: List of DiscoveredHost from Phase 1
        top_ports: If True scan top 1000 ports; if False scan all 65535 (slow)
        log_callback: Optional callable(msg, level)

    Returns:
        List of HostEnumResult
    """
    results = []

    if not hosts:
        _log("No hosts to enumerate.", "warn", log_callback)
        return results

    _log(f"Starting service enumeration on {len(hosts)} hosts...", "info", log_callback)

    for host in hosts:
        ip = host.ip
        _log(f"Enumerating {ip}{'  (' + host.hostname + ')' if host.hostname else ''}...", "info", log_callback)

        enum_result = HostEnumResult(ip=ip, hostname=host.hostname, os_info=host.os_guess)

        # Build nmap service scan command
        # -sV: version detection
        # -sC: default scripts
        # -O requires root (raw socket access); use -sT (TCP connect) when not root
        import os as _os
        is_root = _os.getuid() == 0

        cmd = ["nmap", "-sV", "-sC", "--version-intensity", "5", "-T4"]

        if is_root:
            # SYN scan (faster) + OS detection — both require root
            cmd += ["-O", "--osscan-guess"]
        else:
            # TCP connect scan — works without root, slightly slower
            cmd += ["-sT"]
            _log(f"  Not running as root — using TCP connect scan (no OS detection). For full results, run as root.", "warn", log_callback)

        if top_ports:
            cmd += ["--top-ports", "1000"]
        else:
            cmd += ["-p-"]

        cmd += ["-oX", "-", ip]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if proc.stdout:
                services = _parse_nmap_services(proc.stdout, ip)
                enum_result.services = services

                if services:
                    _log(f"  Found {len(services)} open services:", "success", log_callback)
                    for svc in services[:10]:  # Log first 10
                        ver_str = f" [{svc.version}]" if svc.version else ""
                        _log(f"    {svc.port}/{svc.protocol}  {svc.service}{ver_str}", "info", log_callback)
                    if len(services) > 10:
                        _log(f"    ... and {len(services) - 10} more", "info", log_callback)
                else:
                    _log(f"  No open ports found on {ip}", "warn", log_callback)

                # Extract OS info from nmap result
                try:
                    root = ET.fromstring(proc.stdout)
                    for host_el in root.findall("host"):
                        for addr in host_el.findall("address"):
                            if addr.get("addrtype") == "ipv4" and addr.get("addr") == ip:
                                os_el = host_el.find("os")
                                if os_el is not None:
                                    osmatch = os_el.find("osmatch")
                                    if osmatch is not None:
                                        enum_result.os_info = osmatch.get("name", enum_result.os_info)
                except Exception:
                    pass

            if proc.returncode not in (0, 1) and proc.stderr:
                _log(f"  nmap stderr: {proc.stderr.strip()[:200]}", "warn", log_callback)

        except subprocess.TimeoutExpired:
            _log(f"  nmap timed out for {ip}", "warn", log_callback)
            enum_result.errors.append("nmap scan timed out")
        except Exception as e:
            _log(f"  nmap error for {ip}: {e}", "error", log_callback)
            enum_result.errors.append(str(e))

        # Check if SMB is present (port 445 or 139)
        has_smb = any(s.port in (139, 445) for s in enum_result.services)

        if has_smb:
            _log(f"  SMB detected on {ip} — running enum4linux and crackmapexec...", "info", log_callback)

            # enum4linux
            shares_e4l, users_e4l, domain_e4l, os_e4l = _run_enum4linux(ip, log_callback)

            # crackmapexec
            cme_hostname, cme_domain, cme_os, cme_shares, cme_users = _run_crackmapexec(ip, log_callback)

            # Merge results
            enum_result.smb_shares = list(set(shares_e4l + cme_shares))
            enum_result.smb_users = list(set(users_e4l + cme_users))
            enum_result.ad_domain = domain_e4l or cme_domain
            if cme_os:
                enum_result.os_info = cme_os
            elif os_e4l:
                enum_result.os_info = os_e4l
            if cme_hostname:
                enum_result.hostname = cme_hostname

            if enum_result.smb_shares:
                _log(f"  SMB shares: {', '.join(enum_result.smb_shares)}", "success", log_callback)
            if enum_result.smb_users:
                _log(f"  SMB users: {', '.join(enum_result.smb_users[:10])}", "success", log_callback)
            if enum_result.ad_domain:
                _log(f"  AD domain: {enum_result.ad_domain}", "success", log_callback)

        results.append(enum_result)
        _log(f"  Enumeration complete for {ip}", "success", log_callback)

    _log(f"Enumeration complete: {len(results)} hosts processed.", "success", log_callback)
    return results
