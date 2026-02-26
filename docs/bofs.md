# RTLC2 BOF Arsenal Documentation

Beacon Object Files (BOFs) are small, single-purpose compiled object files in COFF format that execute inside the agent process. They provide modular post-exploitation capabilities without writing additional executables to disk.

---

## 1. What are BOFs?

BOFs are compiled C object files (`.o` files) that follow the COFF (Common Object File Format) specification. Instead of being linked into a full executable, they are loaded directly into the agent's memory at runtime.

### Advantages

- **No disk writes**: BOFs execute entirely in memory
- **Small footprint**: Typically 1-20 KB per BOF
- **Modular**: Each BOF is a standalone capability
- **Compatible**: Uses the same BOF format as Cobalt Strike, Sliver, and other frameworks
- **No new processes**: Executes within the agent process (no fork-and-run unless explicitly chosen)

### How BOFs Work

1. The operator selects a BOF and provides arguments via the Web UI or API
2. The server sends the `.o` file and packed arguments to the agent as a type 7 (BOF) task
3. The agent's COFF parser loads the object file into memory
4. External symbol references are resolved against the 58 Beacon API functions
5. The entry function (default: `go`) is called with the argument buffer
6. Output captured by `BeaconOutput`/`BeaconPrintf` is returned as the task result
7. Memory is freed after execution

---

## 2. BOF Metadata Schema

Each BOF has an accompanying JSON metadata file:

```json
{
  "name": "BOF Display Name",
  "category": "recon",
  "author": "Author Name",
  "description": "Detailed description of what this BOF does.",
  "source": "https://github.com/example/bof-repo",
  "args": [
    {
      "name": "target",
      "type": "string",
      "description": "Target IP address or hostname"
    },
    {
      "name": "port",
      "type": "int",
      "description": "Target port number"
    },
    {
      "name": "timeout",
      "type": "short",
      "description": "Connection timeout in milliseconds"
    }
  ],
  "platforms": ["windows"],
  "opsec": "Uses direct socket connections. Moderate detection risk."
}
```

### Argument Types

| Type | Size | Description |
|------|------|-------------|
| `string` | Variable | Null-terminated ASCII string |
| `wstring` | Variable | Null-terminated wide (UTF-16) string |
| `int` | 4 bytes | 32-bit integer |
| `short` | 2 bytes | 16-bit integer |

### OPSEC Ratings

Each BOF has an OPSEC assessment describing its detection risk:

| Rating | Color | Description |
|--------|-------|-------------|
| Safe | Green | Uses only benign APIs. Minimal detection risk. Suitable for cautious environments. |
| Moderate | Yellow | Uses APIs that may be monitored. Some EDR products may flag the behavior. |
| Noisy | Red | Creates artifacts, touches disk, or calls heavily monitored APIs. High detection risk. |

---

## 3. BOF Categories and Arsenal

RTLC2 includes 67 BOFs organized into 6 categories.

### 3.1 Reconnaissance (24 BOFs)

BOFs for host and network enumeration:

| BOF | Description | OPSEC |
|-----|-------------|-------|
| Whoami | Enumerate current user context, privileges, and group memberships using token APIs | Safe |
| Port Scanner | TCP port scanner with custom port ranges and timeout | Moderate |
| Netstat | List active network connections and listening ports | Safe |
| ARP | Display the ARP cache table | Safe |
| IPConfig Full | Detailed network interface configuration including DNS servers | Safe |
| DNS Cache | Dump the local DNS resolver cache | Safe |
| Env | List all environment variables | Safe |
| Uptime | Query system uptime | Safe |
| Locale | Get system locale and language settings | Safe |
| Resources | Enumerate system resources (CPU, memory, disk usage) | Safe |
| TaskList | Enumerate running processes with details (user, session, memory) | Safe |
| ListDNS | Enumerate DNS records for a domain | Moderate |
| NSLookup | Perform DNS lookups (A, AAAA, MX, NS, TXT records) | Safe |
| Domain Trusts | Enumerate Active Directory domain trust relationships | Moderate |
| LDAP Query | Execute custom LDAP queries against domain controllers | Moderate |
| ADCS Enum | Enumerate Active Directory Certificate Services templates and CAs | Moderate |
| Schtasks Query | Query scheduled tasks on local or remote hosts | Safe |
| CACLs | Enumerate file/folder ACLs and permissions | Safe |
| Driver Sigs | Enumerate loaded kernel drivers and their signatures | Safe |
| Shares Enum | Enumerate network shares on remote hosts | Moderate |
| Services Enum | Enumerate services on local or remote hosts | Moderate |
| Users Enum | Enumerate domain users and local accounts | Moderate |
| Groups Enum | Enumerate domain and local groups | Moderate |
| Registry Enum | Read registry keys and values | Safe |

### 3.2 Credential (9 BOFs)

BOFs for credential harvesting and abuse:

| BOF | Description | OPSEC |
|-----|-------------|-------|
| HashDump | Dump SAM database hashes from the local system | Noisy |
| Kerberoast | Request TGS tickets for SPNs to crack offline | Moderate |
| Kerberoast BOF | Alternative Kerberoasting implementation with output formatting | Moderate |
| NanoDump | Minidump of LSASS process memory using syscalls | Noisy |
| PatchIt | Patch credential guard to allow plaintext credential extraction | Noisy |
| SA WiFi | Extract saved WiFi passwords from the system | Safe |
| SA Vault | Dump Windows Credential Vault contents | Moderate |
| DCSync | Replicate directory service data (requires domain admin) | Noisy |
| ZeroLogon | CVE-2020-1472 Netlogon exploit for domain controller compromise | Noisy |
| Shadow Dump | Dump NTDS.dit shadow copies for offline hash extraction | Noisy |

### 3.3 Lateral Movement (8 BOFs)

BOFs for moving laterally across the network:

| BOF | Description | OPSEC |
|-----|-------------|-------|
| WMI Exec | Execute commands on remote hosts via WMI | Moderate |
| PSExec BOF | Execute commands via SMB service creation (PsExec-style) | Noisy |
| Schtask Create | Create a scheduled task on a remote host | Moderate |
| SC Create | Create a service on a remote host | Noisy |
| SC Start | Start a service on a remote host | Moderate |
| SC Stop | Stop a service on a remote host | Moderate |
| SC Delete | Delete a service from a remote host | Moderate |
| Reg Save | Save a remote registry hive to a file (SAM, SYSTEM, SECURITY) | Noisy |
| WinRM BOF | Execute commands via WinRM on remote hosts | Moderate |

### 3.4 Evasion (10 BOFs)

BOFs for defense evasion and security product manipulation:

| BOF | Description | OPSEC |
|-----|-------------|-------|
| Unhook NTDLL | Restore clean ntdll.dll from disk or KnownDlls | Safe |
| ETW Patch | Patch EtwEventWrite to disable ETW logging | Safe |
| AMSI Patch | Patch AmsiScanBuffer to bypass AMSI | Safe |
| Syscalls Inject | Process injection using direct syscalls | Moderate |
| Callback Injection | Inject shellcode via callback functions (EnumWindows, etc.) | Moderate |
| Module Stomp | Load shellcode into a legitimate module's memory region | Moderate |
| PPID Spoof | Spoof parent process ID for new process creation | Safe |
| Block DLLs | Set process mitigation policy to block non-Microsoft DLLs in child processes | Safe |
| Disable Defender | Attempt to disable Windows Defender real-time protection | Noisy |
| Unhook BOF | Alternative NTDLL unhooking using suspended process technique | Safe |
| ETW Disable | Disable ETW via NtTraceEvent patch | Safe |

### 3.5 Persistence (10 BOFs)

BOFs for establishing persistence:

| BOF | Description | OPSEC |
|-----|-------------|-------|
| Registry Persist | Add a Run key entry for persistence | Moderate |
| Startup Folder | Copy payload to the Startup folder | Moderate |
| Scheduled Task | Create a scheduled task for persistence | Moderate |
| WMI Persist | Create a WMI event subscription for persistence | Moderate |
| COM Hijack | Hijack a COM class for DLL loading persistence | Moderate |
| DLL Hijack | Plant a DLL for search order hijacking | Moderate |
| Service Persist | Install a Windows service for persistence | Noisy |
| Schtask Persist | Create a persistent scheduled task (separate implementation) | Moderate |
| TypeLib Hijacking | Hijack a TypeLib registration for persistence | Moderate |
| AppInit DLLs | Register a DLL via AppInit_DLLs registry key | Noisy |

### 3.6 .NET / Execution (8 BOFs)

BOFs for .NET assembly and tool execution:

| BOF | Description | OPSEC |
|-----|-------------|-------|
| Inline Execute Assembly | Execute a .NET assembly inline within the BOF context | Moderate |
| ASRENum | Enumerate users with AS-REP roasting vulnerability | Moderate |
| SharpHound BOF | Run BloodHound collection via BOF | Noisy |
| Seatbelt BOF | Run Seatbelt security checks via BOF | Moderate |
| Rubeus BOF | Run Rubeus Kerberos abuse tool via BOF | Moderate |
| Certify BOF | Run Certify ADCS abuse tool via BOF | Moderate |
| SharpView BOF | Run SharpView domain enumeration via BOF | Moderate |
| Watson BOF | Run Watson privilege escalation finder via BOF | Safe |

---

## 4. BOF Loader Internals

### COFF Parser

The agent's BOF loader (`src/bof/loader.cpp`) implements a full COFF parser:

```
COFF Object File Layout:
+-------------------+
| COFF Header       |  20 bytes: machine, sections, symbols, characteristics
+-------------------+
| Section Headers   |  40 bytes each: name, size, offset, relocations
+-------------------+
| Section Data      |  .text (code), .data, .rdata, .bss
+-------------------+
| Relocation Tables |  Per-section fixup entries
+-------------------+
| Symbol Table      |  Function and variable symbols
+-------------------+
| String Table      |  Long symbol names
+-------------------+
```

### Loading Process

1. **Parse header**: Validate COFF magic, read section count and symbol table pointer
2. **Allocate sections**: For each section, allocate memory with appropriate permissions:
   - `.text`: Read-Write-Execute (RWX) -- contains executable code
   - `.data`, `.bss`: Read-Write (RW) -- contains mutable data
   - `.rdata`: Read-only (R) -- contains constant data
3. **Copy section data**: Copy raw data from the COFF into allocated memory
4. **Resolve symbols**: Walk the symbol table and resolve external symbols:
   - Beacon API functions (58 functions) are resolved by name
   - Win32 API functions are resolved via `GetProcAddress`
5. **Apply relocations**: Process each section's relocation table to fix up addresses
6. **Call entry point**: Invoke the `go` function (or custom entry name) with packed arguments
7. **Capture output**: `BeaconOutput`/`BeaconPrintf` calls are captured in an output buffer
8. **Cleanup**: Free all allocated section memory

### Beacon API Functions (58 total)

The complete set of Beacon API functions implemented by the RTLC2 agent:

**Output (2 functions):**
- `BeaconOutput(int type, const char* data, int len)` -- Send output to the operator
- `BeaconPrintf(int type, const char* fmt, ...)` -- Printf-style output

**Data Parsing (5 functions):**
- `BeaconDataParse(void* parser, char* buffer, int size)` -- Initialize argument parser
- `BeaconDataInt(void* parser)` -- Read a 32-bit integer
- `BeaconDataShort(void* parser)` -- Read a 16-bit integer
- `BeaconDataExtract(void* parser, int* out_len)` -- Extract a string
- `BeaconDataLength(void* parser)` -- Get remaining data length

**Token Manipulation (2 functions):**
- `BeaconUseToken(void* token)` -- Impersonate a token
- `BeaconRevertToken(void)` -- Revert to original token

**Utility (3 functions):**
- `BeaconIsAdmin(void)` -- Check if running with admin privileges
- `BeaconGetSpawnTo(int x86, char* buffer, int length)` -- Get spawn-to process path
- `BeaconCleanupProcess(void* process_info)` -- Clean up a spawned process

**Format Buffer (7 functions):**
- `BeaconFormatAlloc(void* format, int maxsz)` -- Allocate a format buffer
- `BeaconFormatReset(void* format)` -- Reset a format buffer
- `BeaconFormatFree(void* format)` -- Free a format buffer
- `BeaconFormatAppend(void* format, const char* data, int len)` -- Append raw data
- `BeaconFormatPrintf(void* format, const char* fmt, ...)` -- Printf into buffer
- `BeaconFormatToString(void* format, int* size)` -- Get buffer as string
- `BeaconFormatInt(void* format, int value)` -- Append integer to buffer

**Process Injection (3 functions):**
- `BeaconSpawnTemporaryProcess(int x86, int ignoreToken, void* si, void* pi)` -- Spawn a temporary process for injection
- `BeaconInjectProcess(void* pi, int pid, char* payload, int len, int offset, char* arg, int argLen)` -- Inject into an existing process
- `BeaconInjectTemporaryProcess(void* pi, char* payload, int len, int offset, char* arg, int argLen)` -- Inject into the temporary process

**Helper (1 function):**
- `toWideChar(const char* src, wchar_t* dst, int max)` -- Convert ASCII to UTF-16

---

## 5. Using BOFs

### Executing via Web UI

1. Open the **BOF** panel from the sidebar
2. Browse by category tab or use the search bar
3. Click on a BOF to expand its details
4. Select the target agent from the dropdown
5. Fill in the required arguments
6. Review the OPSEC rating
7. Click **Execute**
8. View the output in the agent's task console

### Executing via API

```bash
curl -X POST http://localhost:54321/api/v1/bofs/execute \
  -H "Authorization: <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "a1b2c3d4",
    "bof_name": "Port Scanner",
    "category": "recon",
    "args": {
      "target": "10.0.0.0/24",
      "ports": "22,80,443,445,3389",
      "timeout": "1000"
    }
  }'
```

### Multi-Agent Execution

The Web UI supports executing a BOF against multiple agents simultaneously:

1. Select the BOF and configure arguments
2. Instead of selecting a single agent, use the multi-agent selector
3. The server queues the BOF task for each selected agent
4. Results appear in each agent's task console

---

## 6. Uploading Custom BOFs

### Writing a Custom BOF

BOFs are standard C source files compiled as object files. The entry function must be named `go` (or a custom name specified at execution time).

```c
#include "beacon.h"

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    char* target = BeaconDataExtract(&parser, NULL);
    int port = BeaconDataInt(&parser);

    // Your code here

    BeaconPrintf(CALLBACK_OUTPUT, "Target: %s, Port: %d\n", target, port);
}
```

Compile as a COFF object file:

```bash
# For Windows targets (cross-compile from Linux)
x86_64-w64-mingw32-gcc -c -o my_bof.o my_bof.c

# For 32-bit
i686-w64-mingw32-gcc -c -o my_bof_x86.o my_bof.c
```

### Uploading via Web UI

1. Open the **BOF** panel
2. Click **Upload BOF**
3. Select the `.o` file
4. Fill in metadata (name, category, description, arguments, OPSEC rating)
5. Click **Upload**

### Uploading via API

```bash
curl -X POST http://localhost:54321/api/v1/bofs/upload \
  -H "Authorization: <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my_custom_bof",
    "category": "recon",
    "data": "<base64-encoded-.o-file>",
    "metadata": "{\"name\":\"My Custom BOF\",\"category\":\"recon\",\"author\":\"Operator\",\"description\":\"Custom reconnaissance BOF\",\"args\":[{\"name\":\"target\",\"type\":\"string\",\"description\":\"Target host\"}],\"platforms\":[\"windows\"],\"opsec\":\"Safe - read-only operations\"}"
  }'
```

---

## 7. BOF Directory Structure

BOFs are stored in the `teamserver/bofs/` directory, organized by category:

```
teamserver/bofs/
  recon/
    whoami.json           Metadata
    whoami.o              Compiled object file
    portscan.json
    portscan.o
    ...

  credential/
    hashdump.json
    hashdump.o
    ...

  lateral/
    wmi_exec.json
    wmi_exec.o
    ...

  evasion/
    unhook_ntdll.json
    unhook_ntdll.o
    ...

  persistence/
    registry_persist.json
    registry_persist.o
    ...

  dotnet/
    inline_execute_assembly.json
    inline_execute_assembly.o
    ...
```

The server scans all category directories on startup and loads metadata from `.json` files. The `compiled` field in the API response indicates whether the corresponding `.o` file exists.

---

## 8. Compatibility

The RTLC2 BOF loader is compatible with BOFs written for:

- **Cobalt Strike**: Full Beacon API compatibility
- **Sliver**: COFF-compatible BOFs
- **TrustedSec SA**: Situation Awareness BOFs
- **Other frameworks**: Any COFF object file using the standard Beacon API

When using third-party BOFs, verify:

1. The BOF targets the correct architecture (x64 vs x86)
2. The BOF uses standard Beacon API functions (no custom extensions)
3. The argument format matches (use the metadata to document expected arguments)
4. Test in a controlled environment before operational use
