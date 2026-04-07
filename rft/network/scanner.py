"""
Network Scanner
---------------
Discovers live Windows machines on the local network for remote acquisition.
Uses nmap for host discovery and OS fingerprinting.
"""

import json
import logging
import subprocess
import socket
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class NetworkHost:
    """A discovered host on the network."""
    ip: str
    hostname: str = ""
    os_guess: str = ""
    open_ports: list[int] = field(default_factory=list)
    smb_available: bool = False
    winrm_available: bool = False
    ssh_available: bool = False
    is_windows: bool = False
    is_online: bool = True
    mac_address: str = ""
    vendor: str = ""


@dataclass
class ScanResult:
    """Results of a network scan."""
    hosts: list[NetworkHost] = field(default_factory=list)
    local_ip: str = ""
    subnet: str = ""
    scan_time_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


def get_local_network() -> tuple[str, str]:
    """Return (local_ip, subnet_cidr) for the current network interface."""
    try:
        # Get default route interface IP
        result = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            capture_output=True, text=True
        )
        for token in result.stdout.split():
            if token.count(".") == 3:
                local_ip = token
                break
        else:
            local_ip = "127.0.0.1"

        # Get subnet from ip addr
        result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if local_ip in line and "/" in line:
                parts = line.strip().split()
                for p in parts:
                    if local_ip in p and "/" in p:
                        subnet = p  # e.g. 192.168.1.42/24
                        return local_ip, subnet

        return local_ip, f"{'.'.join(local_ip.split('.')[:3])}.0/24"
    except Exception as e:
        logger.error(f"Could not determine local network: {e}")
        return "unknown", "192.168.1.0/24"


def scan_network(
    subnet: Optional[str] = None,
    fast: bool = True,
) -> ScanResult:
    """
    Scan the local network for live hosts.

    Args:
        subnet: CIDR subnet to scan (e.g. "192.168.1.0/24"). Auto-detected if None.
        fast: If True use fast ping scan. If False do full port scan.

    Returns:
        ScanResult with all discovered hosts.
    """
    result = ScanResult()

    local_ip, detected_subnet = get_local_network()
    result.local_ip = local_ip
    result.subnet = subnet or detected_subnet

    import shutil
    if not shutil.which("nmap"):
        result.errors.append(
            "nmap not installed. Install with: sudo apt-get install nmap"
        )
        # Fall back to basic ping sweep
        _ping_sweep(result)
        return result

    try:
        import time
        start = time.time()

        if fast:
            # Fast: ping scan + check SMB/WinRM ports only
            cmd = [
                "nmap", "-sn",           # Ping scan (no port scan)
                "--min-rate", "500",
                "-T4",                   # Aggressive timing
                result.subnet,
                "-oX", "-"              # XML output to stdout
            ]
        else:
            # Full: OS detection + key Windows ports
            cmd = [
                "nmap",
                "-O",                    # OS detection
                "-p", "22,135,139,445,3389,5985,5986",  # SSH,RPC,SMB,RDP,WinRM
                "--min-rate", "300",
                "-T3",
                result.subnet,
                "-oX", "-"
            ]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        result.scan_time_seconds = time.time() - start

        hosts = _parse_nmap_xml(proc.stdout)
        result.hosts = [h for h in hosts if h.ip != local_ip]  # Exclude Pi itself

        logger.info(
            f"Network scan complete: {len(result.hosts)} hosts found "
            f"in {result.scan_time_seconds:.1f}s"
        )

    except subprocess.TimeoutExpired:
        result.errors.append("Network scan timed out after 2 minutes")
    except Exception as e:
        result.errors.append(f"Scan error: {e}")
        _ping_sweep(result)

    return result


def _ping_sweep(result: ScanResult):
    """Basic ping sweep fallback when nmap isn't available."""
    import ipaddress
    import concurrent.futures

    try:
        network = ipaddress.ip_network(result.subnet, strict=False)
    except ValueError:
        result.errors.append(f"Invalid subnet: {result.subnet}")
        return

    def ping_host(ip_str: str) -> Optional[NetworkHost]:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip_str],
            capture_output=True
        )
        if r.returncode == 0:
            host = NetworkHost(ip=ip_str)
            # Quick SMB check
            try:
                s = socket.socket()
                s.settimeout(0.5)
                if s.connect_ex((ip_str, 445)) == 0:
                    host.smb_available = True
                    host.is_windows = True
                s.close()
            except Exception:
                pass
            return host
        return None

    hosts_to_ping = [str(ip) for ip in network.hosts()][:254]
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(ping_host, ip): ip for ip in hosts_to_ping}
        for future in concurrent.futures.as_completed(futures):
            host = future.result()
            if host and host.ip != result.local_ip:
                result.hosts.append(host)


def _parse_nmap_xml(xml_output: str) -> list[NetworkHost]:
    """Parse nmap XML output into NetworkHost objects."""
    import xml.etree.ElementTree as ET
    hosts = []

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return hosts

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        # Get IP
        ip = ""
        mac = ""
        vendor = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")

        if not ip:
            continue

        host = NetworkHost(ip=ip, mac_address=mac, vendor=vendor)

        # Hostname
        hostnames = host_el.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                host.hostname = hn.get("name", "")

        # OS guess
        os_el = host_el.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                host.os_guess = match.get("name", "")
                if "windows" in host.os_guess.lower():
                    host.is_windows = True

        # Ports
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    portnum = int(port_el.get("portid", 0))
                    host.open_ports.append(portnum)
                    if portnum == 445:
                        host.smb_available = True
                        host.is_windows = True
                    elif portnum in (5985, 5986):
                        host.winrm_available = True
                        host.is_windows = True
                    elif portnum == 22:
                        host.ssh_available = True
                    elif portnum == 3389:
                        host.is_windows = True

        hosts.append(host)

    return hosts
