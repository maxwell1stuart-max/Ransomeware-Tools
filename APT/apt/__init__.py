"""
APT — Automated Penetration Toolkit
Companion tool to the Ransomware Forensics Toolkit (RFT).

Wraps Kali Linux tools into an automated penetration testing pipeline:
  nmap · hydra · metasploit msfrpc · nikto · enum4linux · crackmapexec · whatweb

Pipeline phases:
  1. Discovery       — nmap ping sweep, OS fingerprint
  2. Enumeration     — port scan, service versions, SMB shares, AD users
  3. Vulnerability Scan — nmap NSE vuln scripts, CVE matching
  4. Web Scanning    — nikto, whatweb on HTTP/HTTPS services
  5. Credential Testing — hydra against RDP/SSH/SMB/FTP
  6. Exploitation    — Metasploit msfrpc safe modules
  7. Report          — executive summary + technical findings + CVE list
"""

__version__ = "1.0.0"
__author__ = "APT"
