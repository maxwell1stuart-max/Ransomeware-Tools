# Ransomware Forensics Toolkit (RFT)

A Raspberry Pi-compatible forensic analysis platform for investigating ransomware incidents. Connect an infected drive, collect evidence, and generate FBI-ready reports — all with AI-powered analysis.

## What It Does

1. **Safe Drive Mounting** — Mounts infected drives with kernel-level write blocking. Never modifies evidence.
2. **Artifact Collection** — Scans for ransom notes, encrypted files, Windows Event Logs, and registry hives.
3. **Event Log Analysis** — Parses `.evtx` files to reconstruct the attack timeline (brute force, RDP, lateral movement).
4. **IOC Extraction** — Extracts Bitcoin wallets, Tor addresses, contact emails, and attacker IPs from ransom notes.
5. **AI Analysis** — Claude Opus 4.6 (with adaptive thinking) provides deep forensic analysis, MITRE ATT&CK mapping, and attack chain reconstruction.
6. **FBI Report Generation** — Structured IC3 complaint in JSON, TXT, and PDF formats.
7. **Learning Knowledge Base** — SQLite database that grows smarter with every case. Pre-seeded with 15+ known ransomware families.

## Hardware Requirements

- Raspberry Pi 4 or 5 (4GB+ RAM recommended)
- 16GB+ microSD card
- USB 3.0 drive enclosure(s) for infected drives
- **Strongly recommended**: Hardware USB write blocker (e.g., Tableau T8u, WiebeTech)

Works on any Linux system (Ubuntu, Debian, Kali).

## Quick Start

### Option A: Install on existing Linux system

```bash
git clone <this-repo>
cd Ransomeware-Tools
sudo bash install/install.sh
```

### Option B: Flash pre-built Pi image

```bash
cd build
./build-distro.sh
# Flash output/rft-forensic-arm64-*.img.gz to SD card
```

### Run an analysis

```bash
# Set API key for AI analysis
export ANTHROPIC_API_KEY="sk-ant-..."

# Connect infected drive via USB, then:
sudo rft analyze

# Or analyze a specific device:
sudo rft analyze --device /dev/sdb

# Quick family identification from a ransom note:
rft identify /path/to/README_LOCKED.txt
```

## Architecture

```
rft/
├── forensics/
│   ├── safe_mount.py         # Write-blocked drive mounting with chain of custody
│   ├── disk_image.py         # Forensic imaging (DD, E01)
│   └── artifact_collector.py # Artifact collection (notes, logs, registry)
├── analysis/
│   ├── ioc_extractor.py      # IOC extraction (BTC, onion, email, IP)
│   ├── log_analyzer.py       # Windows Event Log parsing (EVTX)
│   └── ransomware_analyzer.py# Synthesis — attack chain, family ID, vector
├── ai/
│   └── engine.py             # Claude API integration (adaptive thinking)
├── knowledge_base/
│   ├── manager.py            # SQLite KB — learns from each case
│   └── db_schema.sql         # Database schema
├── reporting/
│   └── fbi_report.py         # FBI IC3 report generator (JSON/TXT/PDF)
├── ui/
│   └── dashboard.py          # Rich terminal UI
└── cli.py                    # Main CLI entry point
```

## AI Analysis

The AI engine uses `claude-opus-4-6` with adaptive thinking enabled. For each incident it:

- Confirms or refines ransomware family identification
- Maps the full attack chain to MITRE ATT&CK techniques
- Analyzes how the attacker gained initial access
- Assesses encryption and recovery feasibility
- Evaluates IOCs for law enforcement value
- Generates the 5 most critical facts for the FBI report

The knowledge base stores AI findings from every case, enabling pattern detection across incidents.

## Supported Ransomware Families

Pre-seeded with intelligence on 15+ families including:
LockBit, ALPHV/BlackCat, Cl0p, Hive, Conti, REvil, Ryuk, BlackBasta, Akira, Play, Royal, Phobos, Dharma, STOP/Djvu, WannaCry

## Commands

```bash
sudo rft analyze                  # Full interactive analysis
sudo rft analyze -d /dev/sdb     # Analyze specific drive
sudo rft analyze -i case.dd      # Analyze a disk image
sudo rft analyze --no-ai         # Skip AI (no API key needed)
rft identify note.txt            # Quick-identify ransomware from note
rft learn                        # Knowledge base statistics
rft export-iocs                  # Export IOC feed (STIX-compatible JSON)
```

## FBI Reporting

After analysis, RFT generates a complete IC3 complaint at:
- `output/reports/<case_id>_fbi_report.txt`
- `output/reports/<case_id>_fbi_report.json`
- `output/reports/<case_id>_fbi_report.pdf`

**File your IC3 report at: https://www.ic3.gov/**

Also report to:
- CISA: https://www.cisa.gov/report or report@cisa.gov
- Your state's cyber crime unit

## Evidence Chain of Custody

Every drive is:
1. Write-protected with `blockdev --setro` before mounting
2. Hashed (SHA-256) before analysis
3. Mounted read-only with `noatime,noexec` flags
4. Re-hashed after analysis to verify integrity
5. All actions logged with timestamps

## Security Notes

- **Hardware write blockers** are strongly preferred over software write blocking
- Never connect infected drives to your primary workstation
- The Raspberry Pi acts as an isolated analysis device
- All analysis output stays on the Pi's local storage

## Development

```bash
pip install -e ".[dev]"
pytest tests/
```

## License

MIT License — Use freely for incident response and forensic education.
