"""
APT Scanner — Phase 1: Host Discovery
Runs nmap ping sweep and OS fingerprinting to find live hosts on the subnet.
"""

import re
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable, Optional


# ── Data Classes ────────────────────────────────────────────────────────────────

@dataclass
class DiscoveredHost:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    os_confidence: int = 0
    mac_address: str = ""
    vendor: str = ""
    is_online: bool = True
    open_ports: list = field(default_factory=list)
    response_time_ms: float = 0.0


@dataclass
class DiscoveryResult:
    hosts: list = field(default_factory=list)
    subnet: str = ""
    scan_duration: float = 0.0
    local_ip: str = ""
    errors: list = field(default_factory=list)


# ── Helpers ──────────────────────────────────────────────────────────────────────

def _log(msg: str, level: str = "info", callback: Optional[Callable] = None):
    if callback:
        callback(msg, level)


def get_local_ip(interface: str = "") -> str:
    """Return the local IP of the primary interface (or specified interface)."""
    if interface:
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", interface],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass

    # Auto-detect
    for iface in ("eth0", "wlan0", "wlan1", "ens33", "ens3", "enp0s3"):
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", iface],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
        except Exception:
            continue

    try:
        # Last resort: connect to external and check source IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def ip_to_subnet(ip: str, prefix: int = 24) -> str:
    """Convert an IP to a /24 subnet CIDR (e.g., 192.168.1.50 → 192.168.1.0/24)."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/{prefix}"
    return f"{ip}/{prefix}"


def _parse_nmap_xml(xml_output: str) -> list:
    """Parse nmap XML output into a list of DiscoveredHost objects."""
    hosts = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return hosts

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = ""
        hostname = ""
        mac = ""
        vendor = ""

        for addr in host_el.findall("address"):
            atype = addr.get("addrtype", "")
            if atype == "ipv4":
                ip = addr.get("addr", "")
            elif atype == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")

        # Hostnames
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        if not ip:
            continue

        # OS detection
        os_guess = ""
        os_confidence = 0
        os_el = host_el.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                os_guess = osmatch.get("name", "")
                try:
                    os_confidence = int(osmatch.get("accuracy", "0"))
                except ValueError:
                    os_confidence = 0

        # Response time (rtt from ping probe)
        rtt = 0.0
        times_el = host_el.find("times")
        if times_el is not None:
            try:
                rtt = float(times_el.get("rttvar", "0")) / 1000.0
            except ValueError:
                pass

        # Open ports from this scan (if any)
        open_ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    try:
                        open_ports.append(int(port_el.get("portid", "0")))
                    except ValueError:
                        pass

        hosts.append(DiscoveredHost(
            ip=ip,
            hostname=hostname,
            os_guess=os_guess,
            os_confidence=os_confidence,
            mac_address=mac,
            vendor=vendor,
            is_online=True,
            open_ports=open_ports,
            response_time_ms=rtt,
        ))

    return hosts


def _ping_sweep_fallback(subnet: str, log_callback: Optional[Callable] = None) -> list:
    """Simple ping-based host discovery when nmap is unavailable."""
    import ipaddress
    import concurrent.futures

    _log("nmap not found — falling back to ICMP ping sweep", "warn", log_callback)
    hosts = []

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return hosts

    def ping_host(ip_str):
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip_str],
            capture_output=True, timeout=3
        )
        if result.returncode == 0:
            try:
                hostname = socket.gethostbyaddr(ip_str)[0]
            except Exception:
                hostname = ""
            return DiscoveredHost(ip=ip_str, hostname=hostname, is_online=True)
        return None

    host_list = [str(h) for h in network.hosts()]
    # max_workers=10 keeps ARP/ICMP load low enough to avoid overwhelming switches
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in host_list}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                hosts.append(result)

    return hosts


# ── Main Entry Point ─────────────────────────────────────────────────────────────

def discover_hosts(
    subnet: str,
    fast: bool = True,
    skip_ping: bool = False,
    log_callback: Optional[Callable] = None,
) -> DiscoveryResult:
    """
    Run nmap ping sweep and OS detection on subnet.

    Args:
        subnet: CIDR notation (e.g., '192.168.1.0/24')
        fast: Use -T4 timing (faster, slightly less accurate)
        skip_ping: Use -Pn (treat all hosts as up — for firewalled environments)
        log_callback: Optional callable(msg, level) for streaming log output

    Returns:
        DiscoveryResult with list of live DiscoveredHost objects
    """
    result = DiscoveryResult(subnet=subnet)
    start = time.time()

    _log(f"Starting host discovery on {subnet}", "info", log_callback)

    # Detect local IP
    local_ip = get_local_ip()
    result.local_ip = local_ip
    if local_ip:
        _log(f"Local IP: {local_ip}", "info", log_callback)

    if not shutil.which("nmap"):
        _log("nmap not found in PATH — using fallback ping sweep", "warn", log_callback)
        result.errors.append("nmap not found — used ICMP ping fallback")
        result.hosts = _ping_sweep_fallback(subnet, log_callback)
        result.scan_duration = time.time() - start
        _log(f"Discovery complete: {len(result.hosts)} hosts found", "success", log_callback)
        return result

    # Build nmap command
    # -sn: ping scan only (no port scan in this phase — service scan is Phase 2)
    # Note: -O (OS detection) requires a port scan, so it cannot be combined with -sn here
    cmd = ["nmap", "-sn"]

    # Use T2 (polite) timing regardless of fast flag — T4 sends ARP/SYN packets too
    # rapidly and can overwhelm the state tables of consumer/unmanaged switches,
    # causing them to reboot or drop connections during a /24 sweep.
    if fast:
        cmd += ["-T2"]
    else:
        cmd += ["-T1"]

    # Cap packet rate to avoid flooding switch ARP/CAM tables.
    # 50 pps is enough to sweep a /24 comfortably without stressing hardware.
    cmd += ["--max-rate", "50"]

    if skip_ping:
        # -Pn skips ping, treats all hosts as up — used when ICMP is blocked
        cmd += ["-Pn"]
        _log("Skip ping enabled — treating all hosts as up (slower)", "warn", log_callback)
    else:
        # -PE: ICMP echo only — dropped -PP (timestamp) to reduce probe volume
        # -PS on just 4 common ports instead of 8 to further reduce traffic
        cmd += ["-PE", "-PS22,80,443,445"]

    cmd += ["-oX", "-", subnet]

    _log(f"Running: {' '.join(cmd)}", "info", log_callback)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=300,  # 5 minute max
        )
        if proc.returncode not in (0, 1):  # nmap returns 1 if no hosts found
            err = proc.stderr.strip()
            if err:
                _log(f"nmap error: {err}", "warn", log_callback)
                result.errors.append(err)

        if proc.stdout:
            result.hosts = _parse_nmap_xml(proc.stdout)
        else:
            result.errors.append("nmap produced no output")
            _log("nmap produced no output — check permissions (run as root?)", "warn", log_callback)

    except subprocess.TimeoutExpired:
        _log("nmap discovery timed out after 5 minutes", "warn", log_callback)
        result.errors.append("nmap discovery timed out")
    except Exception as e:
        _log(f"Discovery error: {e}", "error", log_callback)
        result.errors.append(str(e))
        # Fall back to ping sweep
        result.hosts = _ping_sweep_fallback(subnet, log_callback)

    result.scan_duration = time.time() - start

    if result.hosts:
        _log(f"Discovery complete: {len(result.hosts)} live hosts found in {result.scan_duration:.1f}s", "success", log_callback)
        for h in result.hosts:
            os_str = f" [{h.os_guess}]" if h.os_guess else ""
            host_str = f" ({h.hostname})" if h.hostname else ""
            mac_str = f" {h.mac_address}" if h.mac_address else ""
            vendor_str = f" [{h.vendor}]" if h.vendor else ""
            _log(f"  {h.ip}{host_str}{mac_str}{vendor_str}{os_str}", "info", log_callback)
    else:
        _log("No live hosts found. Check subnet and ensure you are on the same network.", "warn", log_callback)

    return result
