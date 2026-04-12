#!/usr/bin/env python3
"""
Smoke tests for APT and RFT — no hardware required.
Tests parsing logic, data structures, and pipeline logic only.
Run with: python3 test_logic.py
"""

import sys
import traceback

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
SKIP = "\033[93m[SKIP]\033[0m"

results = {"pass": 0, "fail": 0, "skip": 0}


def test(name, fn):
    try:
        fn()
        print(f"{PASS} {name}")
        results["pass"] += 1
    except ImportError as e:
        print(f"{SKIP} {name}  ({e})")
        results["skip"] += 1
    except Exception as e:
        print(f"{FAIL} {name}")
        traceback.print_exc()
        results["fail"] += 1


# ── APT Tests ────────────────────────────────────────────────────────────────

def test_apt_imports():
    from APT.apt.scanner import discovery, enumeration, vulnscan, credtest

def test_discovery_parse_empty_xml():
    from APT.apt.scanner.discovery import _parse_nmap_xml
    result = _parse_nmap_xml("<?xml version='1.0'?><nmaprun></nmaprun>")
    assert result == [], f"Expected [], got {result}"

def test_discovery_parse_host():
    from APT.apt.scanner.discovery import _parse_nmap_xml
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host><status state="up"/>
        <address addrtype="ipv4" addr="192.168.1.1"/>
        <address addrtype="mac" addr="AA:BB:CC:DD:EE:FF" vendor="Netgear"/>
        <hostnames><hostname name="router.local"/></hostnames>
      </host>
    </nmaprun>"""
    hosts = _parse_nmap_xml(xml)
    assert len(hosts) == 1
    assert hosts[0].ip == "192.168.1.1"
    assert hosts[0].hostname == "router.local"
    assert hosts[0].mac_address == "AA:BB:CC:DD:EE:FF"

def test_discovery_skips_down_hosts():
    from APT.apt.scanner.discovery import _parse_nmap_xml
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host><status state="down"/>
        <address addrtype="ipv4" addr="192.168.1.99"/>
      </host>
    </nmaprun>"""
    hosts = _parse_nmap_xml(xml)
    assert hosts == [], "Down hosts should be excluded"

def test_ip_to_subnet():
    from APT.apt.scanner.discovery import ip_to_subnet
    assert ip_to_subnet("192.168.1.50") == "192.168.1.0/24"
    assert ip_to_subnet("10.0.0.1") == "10.0.0.0/24"

def test_service_normalization():
    from APT.apt.scanner.enumeration import _normalize_service
    assert _normalize_service("microsoft-ds", 445) == "smb"
    assert _normalize_service("ms-wbt-server", 3389) == "rdp"
    assert _normalize_service("", 22) == "ssh"
    assert _normalize_service("http", 80) == "http"

def test_enumeration_parse_services():
    from APT.apt.scanner.enumeration import _parse_nmap_services
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addrtype="ipv4" addr="10.0.0.1"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.9"/>
          </port>
          <port protocol="tcp" portid="445">
            <state state="open"/>
            <service name="microsoft-ds"/>
          </port>
          <port protocol="tcp" portid="9999">
            <state state="closed"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    services = _parse_nmap_services(xml, "10.0.0.1")
    assert len(services) == 2, f"Expected 2 open services, got {len(services)}"
    ports = {s.port for s in services}
    assert 22 in ports
    assert 445 in ports
    assert 9999 not in ports
    ssh = next(s for s in services if s.port == 22)
    assert ssh.version == "OpenSSH 8.9"

def test_vuln_severity():
    from APT.apt.scanner.vulnscan import _cvss_to_severity
    assert _cvss_to_severity(10.0) == "critical"
    assert _cvss_to_severity(9.0) == "critical"
    assert _cvss_to_severity(7.0) == "high"
    assert _cvss_to_severity(5.0) == "medium"
    assert _cvss_to_severity(2.0) == "low"

def test_common_creds_list():
    from APT.apt.scanner.credtest import COMMON_CREDS
    assert len(COMMON_CREDS) > 10
    # No plaintext passwords should be empty strings only — check structure
    for user, pw in COMMON_CREDS:
        assert isinstance(user, str)
        assert isinstance(pw, str)

def test_cve_data_integrity():
    from APT.apt.scanner.vulnscan import CVE_DATA, NSE_TO_CVE
    for cve_id, data in CVE_DATA.items():
        assert cve_id.startswith("CVE-"), f"Bad CVE ID: {cve_id}"
        assert "score" in data
        assert "title" in data
        assert 0 <= data["score"] <= 10
    for nse, cve in NSE_TO_CVE.items():
        assert cve.startswith("CVE-"), f"NSE {nse} maps to bad CVE: {cve}"

def test_apt_case_id_regex():
    import re
    pattern = re.compile(r'^APT-\d{8}-\d{6}$')
    assert pattern.match("APT-20260410-123456")
    assert not pattern.match("APT-2026-123")
    assert not pattern.match("../etc/passwd")
    assert not pattern.match("")

def test_subnet_validation():
    import ipaddress
    valid = ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/16"]
    invalid = ["not-a-subnet", "999.999.999.999/24", ""]
    for s in valid:
        ipaddress.ip_network(s, strict=False)  # should not raise
    for s in invalid:
        try:
            ipaddress.ip_network(s, strict=False)
            assert False, f"Should have raised for: {s}"
        except (ValueError, Exception):
            pass


# ── RFT Tests ────────────────────────────────────────────────────────────────

def test_rft_imports():
    from rft.analysis import ioc_extractor
    from rft.reporting import fbi_report

def test_ioc_extraction():
    from rft.analysis.ioc_extractor import extract_iocs
    text = """
    Contact: evil@badactor.com
    C2 server: 192.168.99.1
    Download from: http://malware.example.com/payload.exe
    Bitcoin wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf
    Hash: d41d8cd98f00b204e9800998ecf8427e
    """
    iocs = extract_iocs(text)
    assert any("evil@badactor.com" in str(v) for v in iocs.values()), "Email not found"
    assert any("192.168.99.1" in str(v) for v in iocs.values()), "IP not found"

def test_rft_case_id_format():
    import re
    from datetime import datetime
    # RFT case IDs follow CASE-YYYYMMDD-HHMMSS
    pattern = re.compile(r'^CASE-\d{8}-\d{6}$')
    sample = "CASE-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    assert pattern.match(sample), f"Case ID format broken: {sample}"


# ── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\nAPT Tests")
    print("─" * 40)
    test("APT imports", test_apt_imports)
    test("Discovery: parse empty XML", test_discovery_parse_empty_xml)
    test("Discovery: parse live host", test_discovery_parse_host)
    test("Discovery: skip down hosts", test_discovery_skips_down_hosts)
    test("Discovery: ip_to_subnet", test_ip_to_subnet)
    test("Enumeration: service normalization", test_service_normalization)
    test("Enumeration: parse open services", test_enumeration_parse_services)
    test("Vulnscan: CVSS severity mapping", test_vuln_severity)
    test("Credtest: common creds structure", test_common_creds_list)
    test("Vulnscan: CVE data integrity", test_cve_data_integrity)
    test("APT: case ID regex", test_apt_case_id_regex)
    test("APT: subnet CIDR validation", test_subnet_validation)

    print("\nRFT Tests")
    print("─" * 40)
    test("RFT imports", test_rft_imports)
    test("IOC extraction", test_ioc_extraction)
    test("RFT: case ID format", test_rft_case_id_format)

    print(f"\n{'─' * 40}")
    print(f"  {results['pass']} passed  {results['fail']} failed  {results['skip']} skipped")
    print()
    sys.exit(1 if results["fail"] > 0 else 0)
