# RTLC2 - Red Team Leaders C2 Framework
# Main Makefile

.PHONY: all teamserver agent clean help setup generate web install

# Environment
export GOROOT := /usr/local/go
export PATH := $(GOROOT)/bin:/var/root/go/bin:$(PATH)

GOOS ?= $(shell GOROOT=/usr/local/go /usr/local/go/bin/go env GOOS 2>/dev/null || echo darwin)
GOARCH ?= $(shell GOROOT=/usr/local/go /usr/local/go/bin/go env GOARCH 2>/dev/null || echo arm64)
VERSION ?= 0.1.0
BUILD_DIR := build
all: teamserver web

# ==================== Team Server ====================
teamserver:
	@echo "[*] Building RTLC2 Team Server..."
	@mkdir -p $(BUILD_DIR)
	cd teamserver && CGO_ENABLED=1 go build -ldflags "-s -w -X main.Version=$(VERSION)" \
		-o ../$(BUILD_DIR)/rtlc2-teamserver ./cmd/teamserver
	@echo "[+] Team Server built: $(BUILD_DIR)/rtlc2-teamserver"

teamserver-linux:
	@echo "[*] Cross-compiling Team Server for Linux..."
	@mkdir -p $(BUILD_DIR)
	cd teamserver && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
		-ldflags "-s -w -X main.Version=$(VERSION)" \
		-o ../$(BUILD_DIR)/rtlc2-teamserver-linux ./cmd/teamserver

# ==================== Agent ====================
agent:
	@echo "[*] Building RTLC2 Agent..."
	@mkdir -p $(BUILD_DIR)
	cd agent && cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
	@cp agent/build/rtlc2-agent $(BUILD_DIR)/ 2>/dev/null || true
	@echo "[+] Agent built"

agent-windows:
	@echo "[*] Cross-compiling Agent for Windows..."
	@mkdir -p $(BUILD_DIR)
	cd agent && \
		x86_64-w64-mingw32-cmake -B build-win -DCMAKE_BUILD_TYPE=Release && \
		cmake --build build-win
	@echo "[+] Windows Agent built"

# ==================== Web UI ====================
web:
	@echo "[*] Building RTLC2 Web UI..."
	cd web && npm install --silent 2>/dev/null && npm run build
	@echo "[+] Web UI built"

# ==================== Install ====================
install: all
	@echo "[*] Installing RTLC2 to /opt/RTLC2..."
	@mkdir -p /opt/RTLC2/bin
	@mkdir -p /opt/RTLC2/configs
	@mkdir -p /opt/RTLC2/data
	@cp -f $(BUILD_DIR)/rtlc2-teamserver /opt/RTLC2/bin/ 2>/dev/null || true
	@cp -rf web/dist /opt/RTLC2/web/dist 2>/dev/null || true
	@test -f /opt/RTLC2/configs/teamserver.yaml || cp -f configs/teamserver.yaml /opt/RTLC2/configs/ 2>/dev/null || true
	@echo "[+] Install complete. Binary: /opt/RTLC2/bin/rtlc2-teamserver"

# ==================== Payload Generation Scripts ====================
generate: scripts/generate_agent.sh scripts/generate_powershell.sh
	@echo "[+] Payload generation scripts available in scripts/"
	@echo "    ./scripts/generate_agent.sh   - Build native agent (macOS/Linux)"
	@echo "    ./scripts/generate_powershell.sh - Generate PowerShell stager (Windows)"

# ==================== Utilities ====================
clean:
	@echo "[*] Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf agent/build agent/build-win
	@echo "[+] Clean complete"

setup:
	@echo "[*] Installing build dependencies..."
	cd teamserver && GOROOT=/usr/local/go /usr/local/go/bin/go mod tidy
	@echo "[+] Go module dependencies installed"
	@echo ""
	@echo "[+] Setup complete. Run: make teamserver"

help:
	@echo ""
	@echo "  RTLC2 Build System - Red Team Leaders C2"
	@echo "  ========================================="
	@echo ""
	@echo "  make setup             - Install build dependencies (run first)"
	@echo "  make teamserver        - Build team server (Go)"
	@echo "  make teamserver-linux  - Cross-compile team server for Linux"
	@echo "  make agent             - Build native agent (C++)"
	@echo "  make agent-windows     - Cross-compile agent for Windows"
	@echo "  make generate          - Show payload generation scripts"
	@echo "  make web               - Build web UI (React/TypeScript)"
	@echo "  make install           - Build everything and install to /opt/RTLC2"
	@echo "  make clean             - Remove all build artifacts"
	@echo "  make all               - Build teamserver + web UI"
	@echo ""
