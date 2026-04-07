"""
APT Reporting — Penetration Test Report Generator
Produces executive summary + technical findings in JSON, text, and PDF.
"""

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class PenTestReport:
    # Metadata
    report_id: str
    case_id: str
    generated_at: str
    authorized_by: str
    scope: str
    authorization_notes: str = ""
    examiner: str = "APT Automated Penetration Toolkit"

    # Executive summary numbers
    risk_score: int = 0           # 0-100
    risk_rating: str = "Low"      # Critical / High / Medium / Low
    hosts_discovered: int = 0
    hosts_vulnerable: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    credentials_found: int = 0
    systems_compromised: int = 0

    # Host details
    hosts: list = field(default_factory=list)

    # Vulnerabilities (sorted by severity)
    vulnerabilities: list = field(default_factory=list)

    # Credential findings
    credential_findings: list = field(default_factory=list)

    # Exploit results
    exploit_results: list = field(default_factory=list)

    # Recommendations
    critical_recommendations: list = field(default_factory=list)
    general_recommendations: list = field(default_factory=list)

    # Scan metadata
    scan_start: str = ""
    scan_end: str = ""
    phases_completed: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _calculate_risk_score(report: PenTestReport) -> tuple:
    """Calculate overall risk score (0-100) and rating."""
    score = 0

    # Vulnerability weighting
    score += min(report.critical_vulns * 20, 50)
    score += min(report.high_vulns * 10, 30)
    score += min(report.medium_vulns * 3, 15)
    score += min(report.low_vulns * 1, 5)

    # Bonus for credentials and compromise
    if report.credentials_found > 0:
        score = min(score + 20, 100)
    if report.systems_compromised > 0:
        score = min(score + 30, 100)

    score = min(score, 100)

    if score >= 80:
        rating = "Critical"
    elif score >= 60:
        rating = "High"
    elif score >= 30:
        rating = "Medium"
    else:
        rating = "Low"

    return score, rating


def _generate_recommendations(report: PenTestReport) -> tuple:
    """Generate prioritized recommendations based on findings."""
    critical = []
    general = []

    vuln_cve_ids = {v["cve_id"] for v in report.vulnerabilities}
    services = {v["affected_service"] for v in report.vulnerabilities}

    # Critical CVEs
    if "CVE-2017-0144" in vuln_cve_ids or "CVE-2017-0145" in vuln_cve_ids:
        critical.append("URGENT: Apply MS17-010 patch immediately — EternalBlue allows unauthenticated RCE")
    if "CVE-2019-0708" in vuln_cve_ids:
        critical.append("URGENT: Apply BlueKeep patch (CVE-2019-0708) — allows RCE over RDP without authentication")
    if "CVE-2020-0796" in vuln_cve_ids:
        critical.append("URGENT: Apply SMBGhost patch (KB4551762) — critical SMBv3 RCE vulnerability")

    # Credentials
    if report.credentials_found > 0:
        critical.append(f"URGENT: Change all {report.credentials_found} compromised credential(s) immediately")
        critical.append("Implement strong password policy — minimum 14 characters, complexity requirements")
        critical.append("Enable multi-factor authentication on all remote access (VPN, RDP, SSH)")

    # Systems compromised
    if report.systems_compromised > 0:
        critical.append(f"URGENT: Assume {report.systems_compromised} system(s) are fully compromised — isolate and rebuild")

    # RDP exposed
    if "rdp" in services or "MISCONFIG-RDP-EXPOSED" in vuln_cve_ids:
        critical.append("Restrict RDP access to VPN only — RDP should never be directly internet-exposed")
        general.append("Enable Network Level Authentication (NLA) on all RDP services")
        general.append("Set account lockout after 5 failed RDP attempts")

    # SMB
    if "smb" in services:
        general.append("Disable SMBv1 across all systems — legacy protocol with critical vulnerabilities")
        general.append("Block SMB (ports 139, 445) at the perimeter firewall")
        general.append("Audit SMB share permissions — apply principle of least privilege")

    # Telnet
    if "telnet" in services:
        critical.append("Disable Telnet immediately — replace with SSH (encrypted)")

    # General hardening
    general.append("Implement network segmentation — separate servers, workstations, and IoT devices")
    general.append("Deploy endpoint detection and response (EDR) on all systems")
    general.append("Enable centralized logging and SIEM alerting for authentication failures")
    general.append("Schedule quarterly vulnerability scans and annual penetration tests")
    general.append("Ensure all systems are current on OS and application patches")
    general.append("Implement least-privilege access — users should not have local admin rights")

    if report.hosts_discovered > 5:
        general.append("Maintain an accurate asset inventory — unknown assets cannot be protected")

    return critical, general


def generate_report(
    discovery_result,
    enum_results: list,
    vuln_results: list,
    cred_result,
    exploit_result,
    case_id: str,
    authorized_by: str,
    scope: str,
    authorization_notes: str = "",
    scan_start: str = "",
) -> PenTestReport:
    """Assemble all phase results into a complete penetration test report."""
    now = datetime.now(timezone.utc).isoformat()
    report_id = f"APT-{case_id}-{int(time.time())}"

    report = PenTestReport(
        report_id=report_id,
        case_id=case_id,
        generated_at=now,
        authorized_by=authorized_by,
        scope=scope,
        authorization_notes=authorization_notes,
        scan_start=scan_start or now,
        scan_end=now,
    )

    # Hosts
    if discovery_result:
        report.hosts_discovered = len(discovery_result.hosts)
        for h in discovery_result.hosts:
            host_entry = {
                "ip": h.ip,
                "hostname": h.hostname,
                "os": h.os_guess,
                "mac": h.mac_address,
                "vendor": h.vendor,
                "services": [],
                "vuln_count": 0,
                "risk": "low",
            }
            # Add services from enumeration
            for er in (enum_results or []):
                if er.ip == h.ip:
                    host_entry["services"] = [
                        {"port": s.port, "service": s.service, "version": s.version}
                        for s in er.services
                    ]
                    if er.hostname:
                        host_entry["hostname"] = er.hostname
                    if er.os_info:
                        host_entry["os"] = er.os_info
                    if er.ad_domain:
                        host_entry["domain"] = er.ad_domain
                    if er.smb_shares:
                        host_entry["smb_shares"] = er.smb_shares
                    if er.smb_users:
                        host_entry["smb_users"] = er.smb_users
            report.hosts.append(host_entry)

    # Vulnerabilities
    for vscan in (vuln_results or []):
        for v in vscan.vulnerabilities:
            report.vulnerabilities.append({
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
                "severity": v.severity,
                "title": v.title,
                "description": v.description,
                "affected_ip": v.affected_ip,
                "affected_service": v.affected_service,
                "port": v.port,
                "proof": v.proof[:500],
                "remediation": v.remediation,
            })

    # Sort by CVSS score
    report.vulnerabilities.sort(key=lambda v: v["cvss_score"], reverse=True)

    # Count by severity
    report.critical_vulns = sum(1 for v in report.vulnerabilities if v["severity"] == "critical")
    report.high_vulns = sum(1 for v in report.vulnerabilities if v["severity"] == "high")
    report.medium_vulns = sum(1 for v in report.vulnerabilities if v["severity"] == "medium")
    report.low_vulns = sum(1 for v in report.vulnerabilities if v["severity"] == "low")

    # Mark hosts vulnerable
    vuln_ips = {v["affected_ip"] for v in report.vulnerabilities}
    report.hosts_vulnerable = len(vuln_ips)
    for h in report.hosts:
        if h["ip"] in vuln_ips:
            h["vuln_count"] = sum(1 for v in report.vulnerabilities if v["affected_ip"] == h["ip"])
            worst = max((v["cvss_score"] for v in report.vulnerabilities if v["affected_ip"] == h["ip"]), default=0)
            h["risk"] = "critical" if worst >= 9 else "high" if worst >= 7 else "medium" if worst >= 4 else "low"

    # Credentials
    if cred_result:
        report.credentials_found = len(cred_result.findings)
        for f in cred_result.findings:
            report.credential_findings.append({
                "ip": f.ip,
                "service": f.service,
                "port": f.port,
                "username": f.username,
                "password": f.password,  # stored for report; masked in display
                "access_level": f.access_level,
            })

    # Exploits
    if exploit_result:
        report.systems_compromised = sum(1 for r in exploit_result.results if r.success)
        for r in exploit_result.results:
            report.exploit_results.append({
                "ip": r.ip,
                "cve_id": r.cve_id,
                "module": r.module,
                "success": r.success,
                "session_type": r.session_type,
                "access_level": r.access_level,
                "proof": r.proof[:300],
                "error": r.error,
            })

    # Phases completed
    report.phases_completed = ["discovery", "enumeration", "vulnscan"]
    if cred_result:
        report.phases_completed.append("credtest")
    if exploit_result and exploit_result.results:
        report.phases_completed.append("exploitation")

    # Risk score
    report.risk_score, report.risk_rating = _calculate_risk_score(report)

    # Recommendations
    report.critical_recommendations, report.general_recommendations = _generate_recommendations(report)

    return report


def save_report_json(report: PenTestReport, output_path: str) -> str:
    data = {k: v for k, v in asdict(report).items()}
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    return output_path


def save_report_text(report: PenTestReport, output_path: str) -> str:
    lines = [
        "=" * 70,
        "AUTOMATED PENETRATION TEST REPORT",
        "APT — Automated Penetration Toolkit",
        "=" * 70,
        f"Report ID:       {report.report_id}",
        f"Case ID:         {report.case_id}",
        f"Generated:       {report.generated_at}",
        f"Authorized By:   {report.authorized_by}",
        f"Scope:           {report.scope}",
        f"Auth Notes:      {report.authorization_notes}",
        "",
        "EXECUTIVE SUMMARY",
        "-" * 40,
        f"Risk Rating:     {report.risk_rating} ({report.risk_score}/100)",
        f"Hosts Found:     {report.hosts_discovered}",
        f"Hosts Vulnerable:{report.hosts_vulnerable}",
        f"Critical Vulns:  {report.critical_vulns}",
        f"High Vulns:      {report.high_vulns}",
        f"Medium Vulns:    {report.medium_vulns}",
        f"Credentials:     {report.credentials_found} valid pair(s) found",
        f"Compromised:     {report.systems_compromised} system(s)",
        "",
    ]

    if report.critical_recommendations:
        lines += ["CRITICAL ACTIONS REQUIRED", "-" * 40]
        for i, rec in enumerate(report.critical_recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    lines += ["HOSTS DISCOVERED", "-" * 40]
    for h in report.hosts:
        lines.append(f"\n  {h['ip']}  {h.get('hostname', '')}  [{h.get('os', 'Unknown OS')}]  Risk: {h['risk'].upper()}")
        for s in h.get("services", [])[:10]:
            lines.append(f"    {s['port']}/tcp  {s['service']}  {s.get('version', '')}")

    lines += ["", "VULNERABILITIES", "-" * 40]
    for v in report.vulnerabilities:
        lines += [
            f"\n  [{v['severity'].upper()}] {v['title']}",
            f"  CVE: {v['cve_id']}  CVSS: {v['cvss_score']}",
            f"  Host: {v['affected_ip']}:{v['port']} ({v['affected_service']})",
            f"  {v['description'][:200]}",
            f"  Remediation: {v['remediation']}",
        ]

    if report.credential_findings:
        lines += ["", "CREDENTIAL FINDINGS", "-" * 40]
        for c in report.credential_findings:
            lines.append(f"  {c['service']}://{c['username']}:{'*' * len(c['password'])}@{c['ip']}:{c['port']}  [{c['access_level']}]")

    if report.exploit_results:
        lines += ["", "EXPLOITATION RESULTS", "-" * 40]
        for e in report.exploit_results:
            status = "SUCCESS" if e["success"] else "FAILED"
            lines.append(f"  [{status}] {e['cve_id']} on {e['ip']}  module: {e['module']}")
            if e["success"]:
                lines.append(f"    Access: {e['access_level']}  Session: {e['session_type']}")

    lines += ["", "GENERAL RECOMMENDATIONS", "-" * 40]
    for i, rec in enumerate(report.general_recommendations, 1):
        lines.append(f"{i}. {rec}")

    lines += ["", "=" * 70, "END OF REPORT", "=" * 70]

    with open(output_path, "w") as f:
        f.write("\n".join(lines))
    return output_path


def save_report_pdf(report: PenTestReport, output_path: str) -> Optional[str]:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        return None

    BLUE = colors.HexColor("#2b6cb0")
    BLUE_LIGHT = colors.HexColor("#4299e1")
    RED = colors.HexColor("#f85149")
    ORANGE = colors.HexColor("#db6d28")
    YELLOW = colors.HexColor("#d29922")
    GREEN = colors.HexColor("#3fb950")

    severity_colors = {
        "critical": RED,
        "high": ORANGE,
        "medium": YELLOW,
        "low": GREEN,
        "info": colors.grey,
    }

    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    def h1(text):
        return Paragraph(f"<font color='#{BLUE.hexval()[2:]}' size=16><b>{text}</b></font>", styles["Normal"])

    def h2(text):
        return Paragraph(f"<font color='#{BLUE.hexval()[2:]}' size=12><b>{text}</b></font>", styles["Normal"])

    def body(text):
        return Paragraph(text, styles["Normal"])

    story.append(h1("AUTOMATED PENETRATION TEST REPORT"))
    story.append(Spacer(1, 0.1 * inch))
    story.append(body(f"APT — Automated Penetration Toolkit"))
    story.append(Spacer(1, 0.2 * inch))

    meta = [
        ["Report ID", report.report_id],
        ["Case ID", report.case_id],
        ["Generated", report.generated_at[:19]],
        ["Authorized By", report.authorized_by],
        ["Scope", report.scope],
    ]
    meta_table = Table(meta, colWidths=[1.5 * inch, 5 * inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#161b22")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363d")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.3 * inch))

    # Risk score
    risk_color = {"Critical": RED, "High": ORANGE, "Medium": YELLOW, "Low": GREEN}.get(report.risk_rating, GREEN)
    story.append(h2("EXECUTIVE SUMMARY"))
    story.append(Spacer(1, 0.1 * inch))
    exec_data = [
        ["Risk Rating", f"{report.risk_rating} ({report.risk_score}/100)", "Hosts Found", str(report.hosts_discovered)],
        ["Critical Vulns", str(report.critical_vulns), "High Vulns", str(report.high_vulns)],
        ["Credentials Found", str(report.credentials_found), "Systems Compromised", str(report.systems_compromised)],
    ]
    exec_table = Table(exec_data, colWidths=[1.5 * inch, 1.5 * inch, 1.5 * inch, 1.5 * inch])
    exec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#161b22")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363d")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 0.3 * inch))

    # Vulnerabilities
    if report.vulnerabilities:
        story.append(h2("VULNERABILITIES"))
        story.append(Spacer(1, 0.1 * inch))
        vuln_data = [["Severity", "CVE", "Title", "Host", "CVSS"]]
        for v in report.vulnerabilities[:30]:
            vuln_data.append([
                v["severity"].upper(),
                v["cve_id"][:20],
                v["title"][:40],
                f"{v['affected_ip']}:{v['port']}",
                str(v["cvss_score"]),
            ])
        vuln_table = Table(vuln_data, colWidths=[0.8*inch, 1.2*inch, 2.5*inch, 1.3*inch, 0.5*inch])
        vuln_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BLUE),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#161b22")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363d")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(vuln_table)
        story.append(Spacer(1, 0.3 * inch))

    # Recommendations
    if report.critical_recommendations:
        story.append(h2("CRITICAL ACTIONS"))
        for rec in report.critical_recommendations:
            story.append(body(f"• {rec}"))
        story.append(Spacer(1, 0.2 * inch))

    doc.build(story)
    return output_path
