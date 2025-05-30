#!/bin/bash

OS="$(uname -s)"

if [[ "$OS" == "Darwin" ]]; then
    PREFIX="${1:-/opt/needlecraft}"
    BIN_DIR="/opt/homebrew/bin"
else
    PREFIX="${1:-/data/needlecraft}"
    BIN_DIR="/usr/local/bin"
fi

echo "[!] Removing Needlecraft from: $PREFIX"
rm -rf "$PREFIX"
rm -f "$BIN_DIR/exercism"
rm -f "$BIN_DIR/salvare"
rm -f ./chrome-linux.zip ./chromedriver.zip