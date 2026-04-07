"""
APT Scanner — Phase 3: Vulnerability Scanning
Runs nmap NSE vuln scripts and maps findings to CVE IDs and CVSS scores.
"""

import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable, Optional

from apt.scanner.enumeration import HostEnumResult


# ── Known CVE → CVSS mapping for common vulns nmap detects ───────────────────

CVE_DATA = {
    "CVE-2017-0144": {"score": 9.3, "title": "EternalBlue SMB RCE (MS17-010)", "remediation": "Apply MS17-010 patch. Disable SMBv1."},
    "CVE-2017-0145": {"score": 9.3, "title": "EternalRomance SMB RCE (MS17-010)", "remediation": "Apply MS17-010 patch. Disable SMBv1."},
    "CVE-2019-0708": {"score": 9.8, "title": "BlueKeep RDP RCE", "remediation": "Apply CVE-2019-0708 patch. Disable RDP or restrict with NLA."},
    "CVE-2020-0796": {"score": 10.0, "title": "SMBGhost SMBv3 RCE", "remediation": "Apply KB4551762 patch. Block port 445 externally."},
    "CVE-2021-34527": {"score": 8.8, "title": "PrintNightmare Print Spooler RCE", "remediation": "Disable Print Spooler service if not needed. Apply patch."},
    "CVE-2021-44228": {"score": 10.0, "title": "Log4Shell Log4j RCE", "remediation": "Update Log4j to 2.17.1+. Set LOG4J_FORMAT_MSG_NO_LOOKUPS=true."},
    "CVE-2014-6271": {"score": 10.0, "title": "Shellshock Bash RCE", "remediation": "Update bash to patched version."},
    "CVE-2014-0160": {"score": 7.5, "title": "Heartbleed OpenSSL Info Disclosure", "remediation": "Update OpenSSL. Revoke and reissue all certificates."},
    "CVE-2021-26855": {"score": 9.8, "title": "ProxyLogon Exchange SSRF", "remediation": "Apply Exchange security updates. Check for webshells."},
    "CVE-2022-30190": {"score": 7.8, "title": "Follina MSDT RCE", "remediation": "Apply KB5014699. Disable MSDT URL protocol."},
}

# nmap NSE script IDs → CVE mappings
NSE_TO_CVE = {
    "smb-vuln-ms17-010": "CVE-2017-0144",
    "smb-vuln-ms10-054": "CVE-2010-2550",
    "smb-vuln-ms10-061": "CVE-2010-2729",
    "rdp-vuln-ms12-020": "CVE-2012-0152",
    "ssl-heartbleed": "CVE-2014-0160",
    "http-shellshock": "CVE-2014-6271",
    "smb-vuln-cve2009-3103": "CVE-2009-3103",
    "smb-vuln-cve-2017-7494": "CVE-2017-7494",
}


@dataclass
class Vulnerability:
    cve_id: str
    cvss_score: float
    severity: str          # critical / high / medium / low / info
    title: str
    description: str
    affected_ip: str
    affected_service: str
    port: int
    proof: str = ""        # raw nmap script output
    remediation: str = ""


@dataclass
class VulnScanResult:
    host_ip: str
    vulnerabilities: list = field(default_factory=list)
    scan_duration: float = 0.0
    errors: list = field(default_factory=list)


def _log(msg: str, level: str = "info", callback: Optional[Callable] = None):
    if callback:
        callback(msg, level)


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _parse_nmap_vulns(xml_output: str, ip: str, services: list) -> list:
    """Parse nmap XML for NSE script vuln findings."""
    vulns = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return vulns

    for host_el in root.findall("host"):
        ip_found = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip_found = addr.get("addr", "")
        if ip_found != ip:
            continue

        ports_el = host_el.find("ports")
        if not ports_el:
            continue

        for port_el in ports_el.findall("port"):
            portid = int(port_el.get("portid", "0"))
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            svc_name = ""
            svc_el = port_el.find("service")
            if svc_el is not None:
                svc_name = svc_el.get("name", "")

            for script_el in port_el.findall("script"):
                script_id = script_el.get("id", "")
                output = script_el.get("output", "")

                # Check if this script indicates a vulnerability
                is_vuln = (
                    "VULNERABLE" in output.upper() or
                    script_id.startswith("smb-vuln") or
                    script_id.startswith("rdp-vuln") or
                    script_id in NSE_TO_CVE or
                    "State: VULNERABLE" in output
                )
                if not is_vuln:
                    continue

                # Map to CVE
                cve_id = NSE_TO_CVE.get(script_id, "")

                # Try to extract CVE from output
                if not cve_id:
                    cve_match = re.search(r"CVE-\d{4}-\d+", output)
                    if cve_match:
                        cve_id = cve_match.group(0)

                cve_info = CVE_DATA.get(cve_id, {})
                cvss = cve_info.get("score", 7.0)
                title = cve_info.get("title", script_id.replace("-", " ").title())
                remediation = cve_info.get("remediation", "Apply vendor security patches and updates.")

                vulns.append(Vulnerability(
                    cve_id=cve_id or script_id,
                    cvss_score=cvss,
                    severity=_cvss_to_severity(cvss),
                    title=title,
                    description=output[:500],
                    affected_ip=ip,
                    affected_service=svc_name or f"port-{portid}",
                    port=portid,
                    proof=output[:1000],
                    remediation=remediation,
                ))

    return vulns


def _check_common_misconfigs(enum_result: HostEnumResult) -> list:
    """Check for common misconfigurations beyond CVEs."""
    vulns = []
    ip = enum_result.ip

    for svc in enum_result.services:
        # Telnet — plaintext protocol
        if svc.service == "telnet":
            vulns.append(Vulnerability(
                cve_id="MISCONFIG-TELNET",
                cvss_score=7.0,
                severity="high",
                title="Telnet Enabled (Plaintext Protocol)",
                description="Telnet transmits data including credentials in plaintext. Replace with SSH.",
                affected_ip=ip,
                affected_service="telnet",
                port=svc.port,
                proof=f"Telnet service detected on port {svc.port}",
                remediation="Disable Telnet. Use SSH with key-based authentication.",
            ))

        # FTP anonymous login
        if svc.service == "ftp" and "anonymous" in svc.banner.lower():
            vulns.append(Vulnerability(
                cve_id="MISCONFIG-FTP-ANON",
                cvss_score=5.0,
                severity="medium",
                title="FTP Anonymous Login Enabled",
                description="FTP server allows anonymous authentication.",
                affected_ip=ip,
                affected_service="ftp",
                port=svc.port,
                proof=svc.banner[:200],
                remediation="Disable anonymous FTP access. Require authentication.",
            ))

        # Unencrypted HTTP with login forms
        if svc.service == "http" and svc.port in (80, 8080):
            vulns.append(Vulnerability(
                cve_id="MISCONFIG-HTTP",
                cvss_score=4.0,
                severity="medium",
                title="Unencrypted HTTP Service",
                description="HTTP service running without TLS encryption. Credentials and data transmitted in plaintext.",
                affected_ip=ip,
                affected_service="http",
                port=svc.port,
                proof=f"HTTP on port {svc.port}: {svc.banner[:100]}",
                remediation="Enable HTTPS with a valid TLS certificate. Redirect HTTP to HTTPS.",
            ))

        # SMB open to world
        if svc.service == "smb" and svc.port == 445:
            if enum_result.smb_shares:
                readable = [s for s in enum_result.smb_shares if s not in ("IPC$", "ADMIN$")]
                if readable:
                    vulns.append(Vulnerability(
                        cve_id="MISCONFIG-SMB-SHARES",
                        cvss_score=6.5,
                        severity="medium",
                        title="SMB Shares Accessible (Unauthenticated Enumeration)",
                        description=f"SMB shares enumerable without credentials: {', '.join(readable)}",
                        affected_ip=ip,
                        affected_service="smb",
                        port=445,
                        proof=f"Shares: {', '.join(enum_result.smb_shares)}",
                        remediation="Restrict SMB share access. Require authentication. Block SMB at perimeter firewall.",
                    ))

        # WinRM open
        if svc.service == "winrm":
            vulns.append(Vulnerability(
                cve_id="MISCONFIG-WINRM",
                cvss_score=5.5,
                severity="medium",
                title="WinRM (Remote Management) Exposed",
                description="Windows Remote Management service is accessible. May allow remote code execution with valid credentials.",
                affected_ip=ip,
                affected_service="winrm",
                port=svc.port,
                proof=f"WinRM detected on port {svc.port}",
                remediation="Restrict WinRM access to authorized management hosts only. Require HTTPS.",
            ))

        # RDP exposed
        if svc.service == "rdp":
            vulns.append(Vulnerability(
                cve_id="MISCONFIG-RDP-EXPOSED",
                cvss_score=6.0,
                severity="medium",
                title="RDP Exposed to Network",
                description="Remote Desktop Protocol is accessible. Common ransomware attack vector.",
                affected_ip=ip,
                affected_service="rdp",
                port=svc.port,
                proof=f"RDP on port {svc.port}: {svc.banner[:100]}",
                remediation="Restrict RDP to VPN only. Enable Network Level Authentication. Enable account lockout.",
            ))

    # AD users enumerated without auth
    if enum_result.smb_users:
        vulns.append(Vulnerability(
            cve_id="MISCONFIG-AD-USENUM",
            cvss_score=5.3,
            severity="medium",
            title="Active Directory User Enumeration (Unauthenticated)",
            description=f"Domain user accounts can be enumerated without credentials: {', '.join(enum_result.smb_users[:5])}",
            affected_ip=ip,
            affected_service="smb/ldap",
            port=445,
            proof=f"Users: {', '.join(enum_result.smb_users[:10])}",
            remediation="Restrict null session access. Require authentication for LDAP queries.",
        ))

    return vulns


def scan_vulnerabilities(
    enum_results: list,
    log_callback: Optional[Callable] = None,
) -> list:
    """
    Run nmap vuln scripts and check for common misconfigurations.

    Args:
        enum_results: List of HostEnumResult from Phase 2
        log_callback: Optional callable(msg, level)

    Returns:
        List of VulnScanResult
    """
    results = []

    if not enum_results:
        _log("No hosts to scan for vulnerabilities.", "warn", log_callback)
        return results

    _log(f"Starting vulnerability scan on {len(enum_results)} hosts...", "info", log_callback)

    for enum_result in enum_results:
        ip = enum_result.ip
        start = time.time()
        _log(f"Scanning {ip} for vulnerabilities...", "info", log_callback)

        vscan = VulnScanResult(host_ip=ip)
        all_vulns = []

        # Get open ports for targeted scan
        open_ports = [str(s.port) for s in enum_result.services]
        if not open_ports:
            _log(f"  No open ports on {ip} — skipping vuln scan", "warn", log_callback)
            results.append(vscan)
            continue

        port_arg = ",".join(open_ports[:50])  # Limit to first 50 ports

        if shutil.which("nmap"):
            # NSE vulnerability scripts
            cmd = [
                "nmap",
                "--script", "vuln,exploit,auth,default",
                "-p", port_arg,
                "-T4",
                "--script-timeout", "60",
                "-oX", "-",
                ip,
            ]
            _log(f"  Running nmap vuln scripts on {ip}:{port_arg}", "info", log_callback)
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if proc.stdout:
                    nmap_vulns = _parse_nmap_vulns(proc.stdout, ip, enum_result.services)
                    all_vulns.extend(nmap_vulns)
                    if nmap_vulns:
                        _log(f"  nmap found {len(nmap_vulns)} vulnerability/vulnerabilities", "success", log_callback)
                    else:
                        _log(f"  No CVE-level vulnerabilities found via nmap scripts", "info", log_callback)
            except subprocess.TimeoutExpired:
                _log(f"  nmap vuln scan timed out for {ip}", "warn", log_callback)
                vscan.errors.append("nmap vuln scan timed out")
            except Exception as e:
                _log(f"  nmap vuln scan error: {e}", "warn", log_callback)
                vscan.errors.append(str(e))

        # Check for misconfigurations
        misconfig_vulns = _check_common_misconfigs(enum_result)
        all_vulns.extend(misconfig_vulns)
        if misconfig_vulns:
            _log(f"  Found {len(misconfig_vulns)} misconfiguration(s)", "warn", log_callback)

        # Deduplicate and sort by CVSS score
        seen = set()
        for v in all_vulns:
            key = f"{v.cve_id}:{v.port}"
            if key not in seen:
                seen.add(key)
                vscan.vulnerabilities.append(v)

        vscan.vulnerabilities.sort(key=lambda v: v.cvss_score, reverse=True)
        vscan.scan_duration = time.time() - start

        total = len(vscan.vulnerabilities)
        if total:
            critical = sum(1 for v in vscan.vulnerabilities if v.severity == "critical")
            high = sum(1 for v in vscan.vulnerabilities if v.severity == "high")
            _log(f"  {ip}: {total} findings ({critical} critical, {high} high)", "success", log_callback)
        else:
            _log(f"  {ip}: No vulnerabilities found", "info", log_callback)

        results.append(vscan)

    total_vulns = sum(len(r.vulnerabilities) for r in results)
    _log(f"Vulnerability scan complete: {total_vulns} total findings across {len(results)} hosts", "success", log_callback)
    return results
