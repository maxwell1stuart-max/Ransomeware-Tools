#!/usr/bin/env bash
# =============================================================================
# RFT Installation Script
# =============================================================================
#
# Installs the Ransomware Forensics Toolkit on an existing Linux system.
# Tested on: Ubuntu 22.04/24.04, Debian 11/12, Raspberry Pi OS Bookworm
#
# Usage:
#   sudo bash install.sh
#   sudo bash install.sh --no-apt   # Skip system package installation
#   sudo bash install.sh --dev      # Development install (editable pip)
#
# After installation:
#   sudo rft analyze                # Run the toolkit
#   export ANTHROPIC_API_KEY=...   # Set for AI analysis
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

INSTALL_PACKAGES=true
DEV_MODE=false
PYTHON_MIN="3.10"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()         { echo -e "${CYAN}[RFT]${NC} $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_section() { echo -e "\n${BOLD}── $* ──${NC}"; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-apt)  INSTALL_PACKAGES=false; shift ;;
        --dev)     DEV_MODE=true; shift ;;
        -h|--help) grep '^#' "$0" | head -30 | sed 's/^# //'; exit 0 ;;
        *)         log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# =============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root: sudo bash install.sh"
        exit 1
    fi
}

check_os() {
    log_section "Checking OS compatibility"

    if [[ ! -f /etc/os-release ]]; then
        log_warn "Cannot detect OS. Proceeding anyway..."
        return
    fi

    source /etc/os-release
    log "OS: $PRETTY_NAME"

    case "$ID" in
        ubuntu|debian|raspbian)
            log_ok "Supported OS: $PRETTY_NAME"
            ;;
        *)
            log_warn "Untested OS: $ID. Proceeding anyway..."
            ;;
    esac

    # Check Python version
    if command -v python3 &>/dev/null; then
        PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)"; then
            log_ok "Python $PYTHON_VERSION OK"
        else
            log_error "Python $PYTHON_MIN+ required. Found: $PYTHON_VERSION"
            log_error "Install with: sudo apt-get install python3.11"
            exit 1
        fi
    else
        log_error "Python 3 not found"
        exit 1
    fi
}

install_system_packages() {
    if [[ "$INSTALL_PACKAGES" == "false" ]]; then
        log_warn "Skipping system package installation (--no-apt)"
        return
    fi

    log_section "Installing system packages"

    apt-get update -q

    # Core forensic tools
    PACKAGES=(
        # Forensics
        sleuthkit
        foremost
        binwalk
        # Drive / filesystem
        kpartx
        ntfs-3g
        exfatprogs
        dosfstools
        util-linux
        hdparm
        # Python
        python3
        python3-pip
        python3-venv
        python3-dev
        libssl-dev
        libffi-dev
        # Utilities
        git curl wget jq tmux
        usbutils
    )

    # Try to install optional forensic packages (non-fatal if unavailable)
    OPTIONAL_PACKAGES=(dcfldd ewf-tools yara)

    DEBIAN_FRONTEND=noninteractive apt-get install -y "${PACKAGES[@]}" 2>/dev/null \
        || log_warn "Some packages failed to install. Check the log."

    for pkg in "${OPTIONAL_PACKAGES[@]}"; do
        apt-get install -y "$pkg" 2>/dev/null && log_ok "Installed: $pkg" \
            || log_warn "Optional package not available: $pkg"
    done

    log_ok "System packages installed"
}

install_python_packages() {
    log_section "Installing Python packages"

    # Create virtual environment at /opt/rft/venv
    VENV_DIR="/opt/rft/venv"
    mkdir -p /opt/rft

    if [[ ! -d "$VENV_DIR" ]]; then
        python3 -m venv "$VENV_DIR"
        log_ok "Created virtualenv: $VENV_DIR"
    fi

    # Activate and install
    source "${VENV_DIR}/bin/activate"

    pip install --upgrade pip setuptools wheel -q

    if [[ "$DEV_MODE" == "true" ]]; then
        pip install -e "${PROJECT_ROOT}[dev]" -q
        log_ok "Installed RFT in development mode"
    else
        pip install "${PROJECT_ROOT}" -q
        log_ok "Installed RFT"
    fi

    # Install requirements
    pip install -r "${PROJECT_ROOT}/requirements.txt" -q

    deactivate
    log_ok "Python packages installed in $VENV_DIR"
}

create_wrapper_script() {
    log_section "Creating rft command"

    cat > /usr/local/bin/rft << 'WRAPPER'
#!/usr/bin/env bash
# RFT wrapper — activates venv and runs the CLI
VENV_DIR="/opt/rft/venv"
if [[ -f "${VENV_DIR}/bin/activate" ]]; then
    source "${VENV_DIR}/bin/activate"
fi
exec python3 -m rft.cli "$@"
WRAPPER

    chmod +x /usr/local/bin/rft
    log_ok "Created /usr/local/bin/rft"

    # Also create bash completion
    cat > /etc/bash_completion.d/rft << 'COMPLETION'
# RFT bash completion
_rft_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local commands="analyze learn export-iocs identify"
    COMPREPLY=($(compgen -W "$commands" -- "$cur"))
}
complete -F _rft_complete rft
COMPLETION
    log_ok "Created bash completion"
}

setup_directories() {
    log_section "Setting up directories"

    # RFT home directory
    mkdir -p /opt/rft
    mkdir -p /mnt/forensics     # Default mount point for infected drives
    mkdir -p ~/.rft             # User knowledge base (created at runtime)

    # Copy project files to /opt/rft (for system-wide access)
    if [[ "$PROJECT_ROOT" != "/opt/rft" ]]; then
        cp -r "${PROJECT_ROOT}/rft" /opt/rft/
        log_ok "Copied RFT to /opt/rft"
    fi

    log_ok "Directories configured"
}

configure_udev_rules() {
    log_section "Configuring USB drive detection"

    # Auto-notify when USB storage is attached
    cat > /etc/udev/rules.d/99-rft-forensics.rules << 'UDEV'
# RFT: Notify when USB storage device is connected
SUBSYSTEM=="block", ACTION=="add", ENV{ID_BUS}=="usb", \
    ENV{ID_TYPE}=="disk", \
    RUN+="/usr/local/bin/rft-usb-notify %k"
UDEV

    cat > /usr/local/bin/rft-usb-notify << 'NOTIFY'
#!/usr/bin/env bash
# Called by udev when a USB drive is connected
DEV="/dev/$1"
SIZE=$(blockdev --getsize64 "$DEV" 2>/dev/null | numfmt --to=iec 2>/dev/null || echo "unknown size")
logger -t rft-usb "[RFT ALERT] USB drive detected: $DEV ($SIZE)"
echo "[RFT] USB drive detected: $DEV ($SIZE)" > /dev/console 2>/dev/null || true
echo "[RFT] To analyze: sudo rft analyze --device $DEV" > /dev/console 2>/dev/null || true
NOTIFY

    chmod +x /usr/local/bin/rft-usb-notify
    udevadm control --reload-rules 2>/dev/null || true
    log_ok "udev rules configured"
}

run_self_test() {
    log_section "Running self-test"

    if /usr/local/bin/rft --version 2>/dev/null; then
        log_ok "RFT CLI working"
    else
        log_warn "RFT CLI test failed — check installation"
    fi

    # Test Python imports
    VENV_DIR="/opt/rft/venv"
    if [[ -f "${VENV_DIR}/bin/python3" ]]; then
        "${VENV_DIR}/bin/python3" -c "
import rft.forensics.safe_mount
import rft.analysis.ioc_extractor
import rft.knowledge_base.manager
import rft.reporting.fbi_report
print('All core modules imported successfully')
" 2>/dev/null && log_ok "Module imports OK" || log_warn "Some modules failed to import"
    fi

    # Test knowledge base initialization
    "${VENV_DIR}/bin/python3" -c "
from rft.knowledge_base.manager import KnowledgeBase
kb = KnowledgeBase()
stats = kb.get_statistics()
print(f'Knowledge base: {stats[\"families\"]} families loaded')
kb.close()
" 2>/dev/null && log_ok "Knowledge base initialized" || log_warn "Knowledge base init failed"
}

print_completion() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║   RFT Installation Complete                               ║"
    echo "╠═══════════════════════════════════════════════════════════╣"
    echo "║                                                           ║"
    echo "║   Quick Start:                                            ║"
    echo "║     sudo rft analyze              — Full analysis         ║"
    echo "║     sudo rft identify <note.txt>  — Quick ID              ║"
    echo "║     sudo rft learn                — Knowledge base stats  ║"
    echo "║                                                           ║"
    echo "║   AI Analysis (requires Anthropic API key):               ║"
    echo "║     export ANTHROPIC_API_KEY=\"sk-ant-...\"                 ║"
    echo "║     sudo rft analyze                                      ║"
    echo "║                                                           ║"
    echo "║   Connect infected drive via USB, then:                   ║"
    echo "║     sudo rft analyze                                      ║"
    echo "║                                                           ║"
    echo "║   IMPORTANT: Always use a hardware write blocker!         ║"
    echo "║   Software write-blocking is a fallback only.             ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
}

# =============================================================================
main() {
    log "Starting RFT installation..."
    check_root
    check_os
    install_system_packages
    setup_directories
    install_python_packages
    create_wrapper_script
    configure_udev_rules
    run_self_test
    print_completion
}

main "$@"
