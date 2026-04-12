#!/usr/bin/env bash
# =============================================================================
# APT Hotspot Setup
# =============================================================================
# Creates a WiFi hotspot on wlan0 so your phone can connect and control
# APT while the Pi scans the client network via ethernet.
#
# Network layout:
#   Client network ──[eth0]── Pi ──[wlan0 hotspot]── Your phone
#
# Usage:
#   sudo bash setup-hotspot.sh
#   sudo bash setup-hotspot.sh --ssid "MyOps" --password "secret123"
#   sudo bash setup-hotspot.sh --off    # disable hotspot
# =============================================================================

set -euo pipefail

SSID="APT-Ops"
PASSWORD=""
INTERFACE="wlan0"
CON_NAME="apt-hotspot"
DISABLE=false

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'

log()      { echo -e "${CYAN}[APT]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --ssid)     SSID="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --off)      DISABLE=true; shift ;;
        *) log_err "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    log_err "Run as root: sudo bash setup-hotspot.sh"
    exit 1
fi

# ── Disable hotspot ───────────────────────────────────────────────────────────
if $DISABLE; then
    if nmcli connection show "$CON_NAME" &>/dev/null; then
        nmcli connection delete "$CON_NAME"
        log_ok "Hotspot disabled."
    else
        log_warn "No hotspot connection found."
    fi
    exit 0
fi

# ── Check requirements ────────────────────────────────────────────────────────
if ! command -v nmcli &>/dev/null; then
    log_err "NetworkManager not found."
    log_err "Install: sudo apt-get install network-manager"
    exit 1
fi

if ! ip link show "$INTERFACE" &>/dev/null; then
    log_err "Interface $INTERFACE not found. Is WiFi hardware present?"
    exit 1
fi

# Check ethernet is up (we need eth0 for the actual scanning)
if ! ip link show eth0 &>/dev/null || ! ip -4 addr show eth0 | grep -q inet; then
    log_warn "eth0 has no IP address. Plug the Pi into the client network via ethernet"
    log_warn "before running a scan — the hotspot alone won't reach the target network."
fi

# ── Generate password if not provided ────────────────────────────────────────
if [[ -z "$PASSWORD" ]]; then
    PASSWORD=$(openssl rand -base64 16 | tr -d '+/=\n' | head -c 14)
    log "Generated hotspot password: $PASSWORD"
fi

if [[ ${#PASSWORD} -lt 8 ]]; then
    log_err "Password must be at least 8 characters."
    exit 1
fi

# ── Remove existing hotspot connection ───────────────────────────────────────
if nmcli connection show "$CON_NAME" &>/dev/null; then
    log "Removing existing hotspot connection..."
    nmcli connection delete "$CON_NAME"
fi

# ── Create hotspot ────────────────────────────────────────────────────────────
log "Creating WiFi hotspot on $INTERFACE..."

nmcli connection add \
    type wifi \
    ifname "$INTERFACE" \
    con-name "$CON_NAME" \
    autoconnect yes \
    ssid "$SSID" \
    802-11-wireless.mode ap \
    802-11-wireless.band bg \
    ipv4.method shared \
    wifi-sec.key-mgmt wpa-psk \
    wifi-sec.psk "$PASSWORD" \
    > /dev/null

nmcli connection up "$CON_NAME" > /dev/null
log_ok "Hotspot started."

# ── Get assigned IP ───────────────────────────────────────────────────────────
sleep 2  # Give NetworkManager a moment to assign the IP
HOTSPOT_IP=$(ip -4 addr show "$INTERFACE" 2>/dev/null \
    | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || true)

if [[ -z "$HOTSPOT_IP" ]]; then
    HOTSPOT_IP="192.168.x.x  (check: ip addr show $INTERFACE)"
fi

# ── Save credentials to a file for reference ─────────────────────────────────
CREDS_FILE="/opt/apt/hotspot.txt"
cat > "$CREDS_FILE" <<EOF
APT Hotspot Credentials
=======================
SSID:     $SSID
Password: $PASSWORD
APT URL:  http://$HOTSPOT_IP:5001
EOF
chmod 600 "$CREDS_FILE"

# ── Print summary ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         APT Hotspot Active               ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════╣${NC}"
printf   "║  %-8s  %-30s  ║\n" "WiFi:" "$SSID"
printf   "║  %-8s  %-30s  ║\n" "Password:" "$PASSWORD"
printf   "║  %-8s  %-30s  ║\n" "APT URL:" "http://$HOTSPOT_IP:5001"
echo -e "${BOLD}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "  1. Connect your phone to WiFi: $SSID"
echo "  2. Open browser: http://$HOTSPOT_IP:5001"
echo "  3. Plug Pi into client network via ethernet, then start scan"
echo ""
echo "  Credentials saved to: $CREDS_FILE"
echo "  To disable: sudo bash setup-hotspot.sh --off"
echo ""
