#!/usr/bin/env bash
# APT — Automated Penetration Toolkit installer
# Tested on: Raspberry Pi OS (Debian Bookworm/Bullseye), Ubuntu, Debian
# Run as root: sudo bash install/install.sh
set -e

INSTALL_DIR="/opt/apt"
SERVICE_FILE="/etc/systemd/system/apt-gui.service"
REPORT_DIR="/opt/apt/reports"

echo "=========================================="
echo "  APT — Automated Penetration Toolkit"
echo "=========================================="

# --- sanity checks ---
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Run as root (sudo bash install/install.sh)"
  exit 1
fi

if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found — install with: sudo apt-get install python3"
  exit 1
fi

# --- system dependencies (standard Debian/Raspberry Pi OS repos) ---
echo "[1/6] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
  nmap \
  hydra \
  nikto \
  enum4linux \
  whatweb \
  python3-pip \
  python3-venv \
  pipx \
  git \
  rsync \
  2>/dev/null || true

# netexec / crackmapexec — not in standard Debian repos, install via pipx
if ! command -v netexec &>/dev/null && ! command -v crackmapexec &>/dev/null && ! command -v cme &>/dev/null; then
  echo "  [info] Installing netexec via pipx..."
  pipx install netexec 2>/dev/null || \
  pip3 install netexec --break-system-packages 2>/dev/null || \
  echo "  [warn] netexec install failed — SMB enumeration will be limited"
fi

# metasploit — not in standard Debian repos, requires rapid7 installer
# Only needed for Aggressive exploitation mode
if ! command -v msfconsole &>/dev/null; then
  echo "  [info] Metasploit not found — skipping (optional, needed for Aggressive mode only)"
  echo "         To install: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod +x msfinstall && sudo ./msfinstall"
fi

# rockyou wordlist (optional — APT uses built-in creds, this is for extended testing)
if [[ ! -f /usr/share/wordlists/rockyou.txt ]]; then
  echo "  [info] Downloading rockyou wordlist (optional)..."
  mkdir -p /usr/share/wordlists
  wget -q "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
    -O /usr/share/wordlists/rockyou.txt 2>/dev/null || \
  echo "  [warn] rockyou download failed — APT built-in credentials will still work"
fi

# --- copy project files ---
echo "[2/6] Installing APT to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rsync -a --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
  "$SCRIPT_DIR/" "$INSTALL_DIR/"

# --- create report output dir ---
echo "[3/6] Creating report directory..."
mkdir -p "$REPORT_DIR"
chmod 755 "$REPORT_DIR"

# --- python virtual environment ---
echo "[4/6] Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
"$INSTALL_DIR/venv/bin/pip" install --quiet -e "$INSTALL_DIR"

# --- systemd service ---
echo "[5/6] Installing systemd service..."
cp "$INSTALL_DIR/install/apt-gui.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable apt-gui
systemctl restart apt-gui

# --- done ---
echo "[6/6] Done."
echo ""
echo "APT is running at: http://$(hostname -I | awk '{print $1}'):5001"
echo ""
echo "Access token (required to log in):"
echo "  sudo journalctl -u apt-gui | grep 'ACCESS TOKEN'"
echo "  or: sudo cat /opt/apt/settings.json"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status apt-gui    # check service status"
echo "  sudo journalctl -u apt-gui -f    # follow logs"
echo "  sudo systemctl restart apt-gui   # restart"
echo ""
echo "Optional — install Metasploit for Aggressive exploitation mode:"
echo "  curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall"
echo "  chmod +x msfinstall && sudo ./msfinstall"
