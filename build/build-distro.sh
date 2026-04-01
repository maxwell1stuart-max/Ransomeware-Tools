#!/usr/bin/env bash
# =============================================================================
# RFT Distro Builder
# =============================================================================
#
# Builds a Raspberry Pi OS-based forensic live image with all RFT tools
# pre-installed and configured.
#
# Target: Raspberry Pi 4/5 (ARM64) or any x86_64 system
# Base:   Raspberry Pi OS Bookworm Lite (Debian 12) — minimal, no desktop
#
# Usage:
#   ./build-distro.sh [OPTIONS]
#
# Options:
#   --arch ARM64|AMD64      Target architecture (default: ARM64 for Pi)
#   --output DIR            Output directory for the image
#   --hostname NAME         Hostname for the forensic image
#   --no-cache              Rebuild without Docker cache
#   --quick                 Skip optional heavy packages
#
# Requirements:
#   - Docker (for reproducible builds)
#   - 10GB+ free disk space
#   - Internet connection (downloads packages)
#
# Output:
#   rft-forensic-<arch>-<date>.img.gz  — Compressed disk image
#   rft-forensic-<arch>-<date>.img.sha256 — Integrity hash
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Defaults
ARCH="arm64"
OUTPUT_DIR="${SCRIPT_DIR}/output"
HOSTNAME="rft-forensics"
USE_CACHE=true
QUICK_BUILD=false
BUILD_DATE="$(date +%Y%m%d)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC}   $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --arch)       ARCH="${2,,}"; shift 2 ;;
        --output)     OUTPUT_DIR="$2"; shift 2 ;;
        --hostname)   HOSTNAME="$2"; shift 2 ;;
        --no-cache)   USE_CACHE=false; shift ;;
        --quick)      QUICK_BUILD=true; shift ;;
        -h|--help)    grep '^#' "$0" | head -40 | sed 's/^# //'; exit 0 ;;
        *)            log_error "Unknown option: $1"; exit 1 ;;
    esac
done

IMAGE_NAME="rft-forensic-${ARCH}-${BUILD_DATE}"

# =============================================================================
banner() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║   Ransomware Forensics Toolkit — Distro Builder          ║"
    echo "║   Target: Raspberry Pi OS (${ARCH^^}) — Bookworm              ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
}

check_prerequisites() {
    log_info "Checking build prerequisites..."

    local missing=()
    for tool in docker git curl; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        log_error "Install with: sudo apt-get install ${missing[*]}"
        exit 1
    fi

    # Check Docker is running
    if ! docker info &>/dev/null; then
        log_error "Docker is not running. Start it with: sudo systemctl start docker"
        exit 1
    fi

    # Check disk space (need ~10GB)
    available_gb=$(df -BG "$OUTPUT_DIR" 2>/dev/null | awk 'NR==2{print $4}' | tr -d 'G' || echo "0")
    if [[ "${available_gb:-0}" -lt 8 ]]; then
        log_warn "Low disk space: ${available_gb}GB available, 10GB recommended"
    fi

    log_success "Prerequisites OK"
}

build_docker_image() {
    log_info "Building Docker build environment..."

    local cache_flag=""
    [[ "$USE_CACHE" == "false" ]] && cache_flag="--no-cache"

    docker build $cache_flag \
        -t rft-builder:latest \
        -f "${SCRIPT_DIR}/Dockerfile.builder" \
        "$PROJECT_ROOT"

    log_success "Docker build environment ready"
}

create_rft_image() {
    log_info "Creating RFT disk image (this will take 15-30 minutes)..."

    mkdir -p "$OUTPUT_DIR"

    # Run the build inside Docker for reproducibility
    docker run --rm \
        --privileged \
        -v "${OUTPUT_DIR}:/output" \
        -v "${PROJECT_ROOT}:/rft-src:ro" \
        -e RFT_ARCH="$ARCH" \
        -e RFT_HOSTNAME="$HOSTNAME" \
        -e RFT_QUICK="$QUICK_BUILD" \
        rft-builder:latest \
        /usr/local/bin/build-image.sh

    log_success "Disk image created"
}

compress_and_hash() {
    local img_path="${OUTPUT_DIR}/${IMAGE_NAME}.img"

    if [[ ! -f "$img_path" ]]; then
        log_error "Image not found: $img_path"
        exit 1
    fi

    log_info "Compressing image..."
    gzip -9 -k "$img_path"

    log_info "Computing integrity hashes..."
    sha256sum "${img_path}" > "${img_path}.sha256"
    sha256sum "${img_path}.gz" > "${img_path}.gz.sha256"

    local size
    size=$(du -sh "${img_path}.gz" | cut -f1)
    log_success "Compressed image: ${img_path}.gz (${size})"
    log_success "SHA-256: $(cat "${img_path}.sha256" | cut -d' ' -f1)"
}

print_flash_instructions() {
    local img_gz="${OUTPUT_DIR}/${IMAGE_NAME}.img.gz"
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║   BUILD COMPLETE — Flash to SD card                      ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Image: ${img_gz}"
    echo ""
    echo "  Flash to SD card using Raspberry Pi Imager:"
    echo "    1. Open Raspberry Pi Imager"
    echo "    2. Choose 'Use custom image'"
    echo "    3. Select: ${img_gz}"
    echo "    4. Write to your SD card (16GB+ recommended)"
    echo ""
    echo "  OR using dd (replace /dev/sdX with your SD card device):"
    echo "    zcat ${img_gz} | sudo dd of=/dev/sdX bs=4M status=progress"
    echo ""
    echo "  First boot:"
    echo "    - Connect via HDMI and USB keyboard, OR"
    echo "    - SSH: ssh rft@rft-forensics.local (password: forensics2024)"
    echo "    - Run: sudo rft analyze"
    echo ""
    echo "  SECURITY NOTE: Change the default password on first boot!"
    echo "    passwd rft"
}

# =============================================================================
# DOCKERFILE is embedded here for easy distribution
# =============================================================================
generate_dockerfile() {
    cat > "${SCRIPT_DIR}/Dockerfile.builder" << 'DOCKERFILE'
FROM debian:bookworm-slim

# Install build tools
RUN apt-get update && apt-get install -y \
    debootstrap qemu-user-static binfmt-support \
    kpartx parted dosfstools \
    curl wget git \
    && rm -rf /var/lib/apt/lists/*

# Register ARM64 binary format for cross-compilation
RUN update-binfmts --enable qemu-aarch64 || true

COPY build/build-image-inner.sh /usr/local/bin/build-image.sh
RUN chmod +x /usr/local/bin/build-image.sh

CMD ["/usr/local/bin/build-image.sh"]
DOCKERFILE
    log_info "Generated Dockerfile.builder"
}

generate_inner_build_script() {
    cat > "${SCRIPT_DIR}/build-image-inner.sh" << 'INNERSCRIPT'
#!/usr/bin/env bash
# Inner build script — runs inside Docker container
set -euo pipefail

ARCH="${RFT_ARCH:-arm64}"
HOSTNAME="${RFT_HOSTNAME:-rft-forensics}"
IMG_SIZE_MB=4096  # 4GB base image
IMG_FILE="/output/rft-forensic-${ARCH}-$(date +%Y%m%d).img"

echo "[BUILD] Creating ${ARCH} image: ${IMG_FILE}"

# Create blank image
dd if=/dev/zero of="$IMG_FILE" bs=1M count=$IMG_SIZE_MB status=progress

# Partition: 256MB FAT32 boot + rest ext4 root
parted "$IMG_FILE" --script \
    mklabel msdos \
    mkpart primary fat32 1MiB 257MiB \
    mkpart primary ext4 257MiB 100% \
    set 1 boot on

# Map partitions
LOOP=$(losetup -f --show -P "$IMG_FILE")
BOOT_PART="${LOOP}p1"
ROOT_PART="${LOOP}p2"

# Format
mkfs.vfat -F 32 -n "RFT_BOOT" "$BOOT_PART"
mkfs.ext4 -L "RFT_ROOT" "$ROOT_PART"

# Mount
mkdir -p /mnt/rft/{boot,root}
mount "$ROOT_PART" /mnt/rft/root
mkdir -p /mnt/rft/root/boot/firmware
mount "$BOOT_PART" /mnt/rft/root/boot/firmware

# Bootstrap Debian Bookworm
DEBOOTSTRAP_ARCH="arm64"
[[ "$ARCH" == "amd64" ]] && DEBOOTSTRAP_ARCH="amd64"

debootstrap \
    --arch="$DEBOOTSTRAP_ARCH" \
    --foreign \
    bookworm \
    /mnt/rft/root \
    http://deb.debian.org/debian

# Copy QEMU for ARM emulation
[[ "$DEBOOTSTRAP_ARCH" == "arm64" ]] && \
    cp /usr/bin/qemu-aarch64-static /mnt/rft/root/usr/bin/

# Complete bootstrap in chroot
chroot /mnt/rft/root /debootstrap/debootstrap --second-stage

# Configure the system in chroot
chroot /mnt/rft/root bash << 'CHROOT'
set -e

# Basic system configuration
echo "rft-forensics" > /etc/hostname
echo "127.0.1.1 rft-forensics" >> /etc/hosts

# Sources
cat > /etc/apt/sources.list << 'SOURCES'
deb http://deb.debian.org/debian bookworm main contrib non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free-firmware
SOURCES

apt-get update

# Install core forensic packages
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    sleuthkit foremost dcfldd \
    ntfs-3g exfatprogs dosfstools kpartx \
    python3 python3-pip python3-venv \
    git curl wget jq tmux vim \
    binwalk yara \
    usbutils hdparm \
    openssh-server sudo \
    systemd-sysv \
    --no-install-recommends

# Create RFT user
useradd -m -s /bin/bash -G sudo,disk rft
echo "rft:forensics2024" | chpasswd
echo "rft ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/rft-sudo

# Install RFT Python package
mkdir -p /opt/rft
cp -r /rft-src/* /opt/rft/
cd /opt/rft
pip3 install --break-system-packages -r requirements.txt
pip3 install --break-system-packages -e .

# Create rft command wrapper
cat > /usr/local/bin/rft << 'WRAPPER'
#!/usr/bin/env bash
exec python3 -m rft.cli "$@"
WRAPPER
chmod +x /usr/local/bin/rft

# Configure SSH
systemctl enable ssh

# Auto-mount USB drives (read-only by default)
cat > /etc/udev/rules.d/99-rft-usb.rules << 'UDEV'
# Auto-detect USB storage devices and alert RFT
ACTION=="add", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", RUN+="/usr/local/bin/rft-usb-alert %k"
UDEV

cat > /usr/local/bin/rft-usb-alert << 'ALERT'
#!/usr/bin/env bash
echo "[RFT] USB storage device detected: /dev/$1"
echo "[RFT] Run 'sudo rft analyze --device /dev/$1' to analyze"
ALERT
chmod +x /usr/local/bin/rft-usb-alert

# MOTD
cat > /etc/motd << 'MOTD'

  ╔═══════════════════════════════════════════════════════╗
  ║   Ransomware Forensics Toolkit (RFT) v1.0             ║
  ║   Raspberry Pi Forensic Analysis Platform             ║
  ╠═══════════════════════════════════════════════════════╣
  ║   Quick Start:                                        ║
  ║     sudo rft analyze          — Full analysis         ║
  ║     sudo rft identify <note>  — Quick identification  ║
  ║     sudo rft learn            — Knowledge base stats  ║
  ║                                                       ║
  ║   Set API key for AI analysis:                        ║
  ║     export ANTHROPIC_API_KEY="your-key"               ║
  ║                                                       ║
  ║   REMINDER: Always use hardware write blockers!       ║
  ╚═══════════════════════════════════════════════════════╝

MOTD

CHROOT

# Cleanup and unmount
umount /mnt/rft/root/boot/firmware
umount /mnt/rft/root
losetup -d "$LOOP"

echo "[BUILD] Image complete: $IMG_FILE"
echo "[BUILD] Size: $(du -sh $IMG_FILE | cut -f1)"
INNERSCRIPT

    chmod +x "${SCRIPT_DIR}/build-image-inner.sh"
    log_info "Generated build-image-inner.sh"
}

# =============================================================================
main() {
    banner
    check_prerequisites
    generate_dockerfile
    generate_inner_build_script

    if ! docker image inspect rft-builder:latest &>/dev/null || [[ "$USE_CACHE" == "false" ]]; then
        build_docker_image
    fi

    create_rft_image
    compress_and_hash
    print_flash_instructions
}

main "$@"
