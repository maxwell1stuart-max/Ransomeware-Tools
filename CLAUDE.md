# Ransomeware-Tools — Project Context for Claude

## What this is
Two separate tools that run as web apps on a Raspberry Pi (Raspberry Pi OS Bookworm, ARM64):

1. **RFT** (`/rft`) — Ransomware Forensics Toolkit. Forensic analysis of infected drives. Flask web UI on port 5000. Run with `sudo rft-gui`.
2. **APT** (`/APT`) — Automated Penetration Toolkit. Network scanning and pen testing. Flask web UI on port 5001. Runs as a systemd service (`apt-gui`).

## Hardware / OS
- Raspberry Pi OS Bookworm (Debian 12), ARM64/aarch64
- NOT Kali Linux — many security tool packages are unavailable or named differently
- Installed tools: nmap, hydra, metasploit (Rapid7 installer), enum4linux-ng (from git)
- netexec: NOT installed — fails on ARM64 because `aardwolf` dependency requires Rust compiler

## Architecture

### APT
```
APT/apt/
  scanner/
    discovery.py    # Phase 1: nmap ping sweep (-sn -T2 --max-rate 50)
    enumeration.py  # Phase 2: nmap service scan + enum4linux/netexec
    vulnscan.py     # Phase 3: nmap NSE vuln scripts → CVE mapping
    credtest.py     # Phase 4: hydra credential testing (39 common creds)
    exploitation.py # Phase 5: Metasploit msfrpc (aggressive mode only)
  web/
    app.py          # Flask app, port 5001
    templates/      # Jinja2 HTML templates
    static/         # CSS + JS
install/install.sh  # Raspberry Pi OS install script
```

### RFT
```
rft/
  forensics/
    safe_mount.py       # Read-only forensic mounting, BitLocker/NTFS detection
    disk_image.py       # Drive imaging (dd-based)
    artifact_collector.py
    timeline.py
    memory_analysis.py
    file_recovery.py
    shadow_copy.py
  analysis/
    ransomware_analyzer.py
    ioc_extractor.py
    log_analyzer.py
  ai/engine.py          # Anthropic Claude API integration for AI analysis
  network/
    scanner.py          # Remote host scanning
    remote_ram.py       # RAM acquisition over network
  reporting/fbi_report.py
  web/
    app.py              # Flask app, port 5000
    launcher.py         # Entry point: sudo rft-gui
    templates/
    static/
install/install.sh
```

## Key decisions made

### Security
- Auth: persistent token stored in `settings.json`, compared with `secrets.compare_digest()`
- Sessions: httponly cookie set on `/login`; token printed once to logs on first run
- All routes protected with `@_require_auth` decorator
- Input validation: CIDR via `ipaddress.ip_network()`, case IDs via regex
- File permissions: `chmod 0o600` on settings.json and findings.json
- Threading: `_cases_lock = threading.Lock()` around shared `active_cases` dict

### Scanning (APT)
- Timing: `-T2 --max-rate 50` (was T4) — reduced to avoid overwhelming consumer switches
- Root detection at runtime: uses `-sS -O` if root, `-sT` if not
- Discovery probes: `-PE -PS22,80,443,445` (reduced from 8 ports)
- Hydra: `-t 2 -w 5 -c 2` (was -t 4 -w 3) — gentler on targets

### Mounting (RFT)
- BitLocker: detected via blkid TYPE="BitLocker" or file(1); raises clear error with dislocker instructions
- Hibernated NTFS: detected via ntfsfix --no-action; tries kernel ntfs3 driver first, then ntfs-3g
- NEVER uses `remove_hiberfile` on live device (writes to evidence drive)
- For hibernated NTFS: recommends `dd` image first, then `remove_hiberfile` on the copy

### Browser/UI
- RFT launcher: skips browser open when running as root (root can't connect to X session)
- APT: no AI key indicator (APT doesn't use AI; removed spurious copy from RFT)
- RFT: AI key (Anthropic) set in Settings page, stored in settings.json

## Updating on the Pi
```bash
cd /path/to/Ransomeware-Tools && git pull
# APT (runs as service):
sudo rsync -a APT/apt/ /opt/apt/apt/
sudo systemctl restart apt-gui
# RFT (on-demand):
sudo rsync -a rft/ /opt/rft/rft/
sudo rft-gui
```

## Token locations
- APT: `sudo cat /opt/apt/settings.json | grep access_token`
- RFT: `sudo cat /opt/rft/settings.json | grep access_token`
- Both printed to logs on first run: `sudo journalctl -u apt-gui | grep "ACCESS TOKEN"`

## Known issues / limitations
- netexec not installable on ARM64 without Rust compiler (`aardwolf` dependency)
- enum4linux-ng installed from git, not PyPI
- nmap requires root for `-sS` (SYN scan) and `-O` (OS detection)
- RFT needs root for disk access — always run with sudo
- BitLocker drives cannot be mounted without recovery key (48-digit, from Microsoft account or AD)
- Hibernated NTFS (Windows Fast Startup) requires full Windows shutdown or dd-then-remove_hiberfile

## Git branch
Active development: `claude/ransomware-forensics-distro-MFW9p`
