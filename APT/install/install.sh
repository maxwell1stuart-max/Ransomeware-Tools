#!/usr/bin/env bash
# APT — Automated Penetration Toolkit installer
# Run as root on Kali Linux: sudo bash install/install.sh
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
  echo "ERROR: python3 not found"
  exit 1
fi

# --- system dependencies ---
echo "[1/6] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
  nmap \
  hydra \
  metasploit-framework \
  nikto \
  enum4linux \
  crackmapexec \
  whatweb \
  python3-pip \
  python3-venv \
  2>/dev/null || true

# crackmapexec may be netexec on newer Kali
if ! command -v crackmapexec &>/dev/null && ! command -v netexec &>/dev/null && ! command -v cme &>/dev/null; then
  echo "  [warn] crackmapexec not found — trying pipx install..."
  pipx install crackmapexec 2>/dev/null || true
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
echo "Useful commands:"
echo "  sudo systemctl status apt-gui    # check service status"
echo "  sudo journalctl -u apt-gui -f    # follow logs"
echo "  sudo systemctl restart apt-gui   # restart"
echo ""
echo "Required tools not installed by apt-get:"
echo "  msfconsole  — included with metasploit-framework"
echo "  hydra       — installed"
echo "  nmap        — installed"
