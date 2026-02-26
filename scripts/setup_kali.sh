#!/bin/bash
# RTLC2 - Kali Linux Setup Script
# Installs all dependencies needed to build and run the framework

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}"
echo "  ____  _____ _     ____ ____  "
echo " |  _ \|_   _| |   / ___|___ \ "
echo " | |_) | | | | |  | |     __) |"
echo " |  _ <  | | | |__| |___ / __/ "
echo " |_| \_\ |_| |____\____|_____|"
echo -e "${NC}"
echo -e "${CYAN} Kali Linux Setup Script${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This script must be run as root (use sudo)${NC}"
    exit 1
fi

echo -e "${CYAN}[*] Updating package lists...${NC}"
apt-get update -qq

echo -e "${CYAN}[*] Installing build dependencies...${NC}"
apt-get install -y -qq \
    build-essential \
    cmake \
    golang-go \
    protobuf-compiler \
    libprotobuf-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    nodejs \
    npm \
    sqlite3 \
    git \
    curl \
    wget \
    mingw-w64 \
    2>/dev/null

# Install Go protobuf plugins
echo -e "${CYAN}[*] Installing Go protobuf plugins...${NC}"
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest 2>/dev/null || true
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest 2>/dev/null || true

# Ensure Go bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin:/root/go/bin

echo -e "${CYAN}[*] Installing npm dependencies...${NC}"
cd /opt/RTLC2/web && npm install --silent 2>/dev/null || true

echo -e "${CYAN}[*] Building teamserver...${NC}"
cd /opt/RTLC2
export PATH=$PATH:$(go env GOPATH)/bin:/root/go/bin
make teamserver 2>&1 | tail -5

echo -e "${CYAN}[*] Building web UI...${NC}"
cd /opt/RTLC2/web && npm run build 2>&1 | tail -5

echo ""
echo -e "${GREEN}[+] Setup complete!${NC}"
echo ""
echo -e "To start the teamserver:"
echo -e "  cd /opt/RTLC2"
echo -e "  ./build/rtlc2-teamserver -config configs/teamserver.yaml"
echo ""
echo -e "Web UI will be available at: http://<your-ip>:54321"
echo -e "Default credentials: admin / changeme123"
echo ""
