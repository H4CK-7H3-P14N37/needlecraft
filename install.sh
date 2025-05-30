#!/bin/bash

set -e

OS="$(uname -s)"

# Set platform-specific defaults
if [[ "$OS" == "Darwin" ]]; then
    PREFIX="${1:-/opt/needlecraft}"
    BIN_DIR="/opt/homebrew/bin"
else
    PREFIX="${1:-/data/needlecraft}"
    BIN_DIR="/usr/local/bin"
fi

echo "[+] Installing Needlecraft to: $PREFIX"

if [[ "$OS" == "Darwin" ]]; then
    echo "[+] Detected macOS"
    # Ensure Homebrew is installed
    if ! command -v brew >/dev/null 2>&1; then
        echo "[-] Homebrew is not installed. Install it from https://brew.sh/"
        exit 1
    fi

    echo "[+] Installing dependencies with Homebrew..."
    brew install \
        curl unzip python3 git \
        masscan nmap tor ffmpeg \
        cairo pkg-config sslscan

elif [[ "$OS" == "Linux" ]]; then
    echo "[+] Detected Linux"
    if [[ "$EUID" -ne 0 ]]; then
        echo "[-] Please run this script as root (e.g., sudo $0)"
        exit 1
    fi

    apt update
    apt install -y \
        curl unzip xvfb python3 python3-dev python3-venv git make gcc \
        masscan nmap tor ffmpeg sslscan \
        libssl-dev g++ libnss3 libnss3-dev libnss3-tools build-essential cmake \
        libexpat1-dev zlib1g-dev libncurses-dev libbz2-dev liblzma-dev \
        libsqlite3-dev libffi-dev tcl-dev linux-headers-generic libgdbm-dev libreadline-dev \
        tk tk-dev libgdbm-compat-dev libbluetooth-dev python3-pkgconfig libgirepository1.0-dev \
        mariadb-server libmariadb-dev iptables libcairo2-dev
else
    echo "[-] Unsupported OS: $OS"
    exit 1
fi

echo "[+] Creating application directories..."
sudo mkdir -p "$PREFIX/reports"
sudo chown -R `whoami` $PREFIX

echo "[+] Downloading Chrome for Testing and Chromedriver..."
# https://googlechromelabs.github.io/chrome-for-testing/#stable
if [[ "$OS" == "Darwin" ]]; then
    echo "[+] Detected macOS"
    curl -Lo "chrome.zip" "https://storage.googleapis.com/chrome-for-testing-public/137.0.7151.55/mac-arm64/chrome-mac-arm64.zip"
    curl -Lo "chromedriver.zip" "https://storage.googleapis.com/chrome-for-testing-public/137.0.7151.55/mac-arm64/chromedriver-mac-arm64.zip"
elif [[ "$OS" == "Linux" ]]; then
    echo "[+] Detected Linux"
    curl -Lo "chrome.zip" "https://storage.googleapis.com/chrome-for-testing-public/137.0.7151.55/linux64/chrome-linux64.zip"
    curl -Lo "chromedriver.zip" "https://storage.googleapis.com/chrome-for-testing-public/137.0.7151.55/linux64/chromedriver-linux64.zip"
else
    echo "[-] Unsupported OS: $OS"
    exit 1
fi

unzip chromedriver.zip -d "$PREFIX/opt/"
unzip chrome.zip -d "$PREFIX/opt/"
rm -f chromedriver.zip chrome.zip

echo "[+] Setting up Python virtual environment..."
echo `pwd`
python3 -m venv "$PREFIX/env"
"$PREFIX/env/bin/pip" install --upgrade pip setuptools build
"$PREFIX/env/bin/pip" install .

echo "[+] Linking executables to $BIN_DIR..."
ln -sf "$PREFIX/env/bin/exercism" "$BIN_DIR/exercism"
ln -sf "$PREFIX/env/bin/salvare" "$BIN_DIR/salvare"
ln -sf "$PREFIX/env/bin/ncconfig" "$BIN_DIR/ncconfig"


get_default_interface() {
    case "$(uname -s)" in
        Linux)
            ip route | awk '/default/ {print $5}'
            ;;
        Darwin)
            route get default 2>/dev/null | awk '/interface: / {print $2}'
            ;;
        *)
            echo "Unsupported OS"
            return 1
            ;;
    esac
}

echo "[+] Setting up default config.json..."
iface=$(get_default_interface)
$BIN_DIR/ncconfig DEFAULT_ETH $iface
$BIN_DIR/ncconfig REPORT_DIR $PREFIX/reports
$BIN_DIR/ncconfig MASSCAN_PATH `which masscan`
$BIN_DIR/ncconfig DNS_SERVER "1.1.1.1"
$BIN_DIR/ncconfig NMAP_PATH `which nmap`
$BIN_DIR/ncconfig NMAP_TIMING 5
$BIN_DIR/ncconfig BASEDIR $PREFIX
$BIN_DIR/ncconfig PREFIX $PREFIX
$BIN_DIR/ncconfig SSLSCAN_BIN `which sslscan`

echo "[✓] Installation complete."