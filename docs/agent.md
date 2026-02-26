# RTLC2 Agent Documentation

The RTLC2 agent is a C++17 implant designed for cross-platform operation with a primary focus on Windows targets. All configuration is embedded at compile time, producing a standalone binary with no external dependencies.

---

## 1. Build System

### Requirements

- CMake 3.16 or later
- C++17 compatible compiler (GCC, Clang, or MSVC)
- OpenSSL and libcurl (Linux/macOS builds)
- x86_64-w64-mingw32 toolchain (Windows cross-compilation)

### Building

```bash
# Native build (Linux/macOS)
cd agent
cmake -B build -DCMAKE_BUILD_TYPE=Release \
  -DRTLC2_C2_HOST="192.168.1.100" \
  -DRTLC2_C2_PORT="443" \
  -DRTLC2_AES_KEY="<64-hex-char-key>" \
  -DRTLC2_USE_TLS="1"
cmake --build build

# Windows cross-compilation
x86_64-w64-mingw32-cmake -B build-win -DCMAKE_BUILD_TYPE=Release \
  -DRTLC2_C2_HOST="192.168.1.100" \
  -DRTLC2_AES_KEY="<64-hex-char-key>"
cmake --build build-win

# Using the Makefile wrapper
make agent                    # Native
make agent-windows            # Windows cross-compile
```

### Compiler Flags

| Compiler | Flags |
|----------|-------|
| MSVC | `/W4 /O2 /MT`, `_CRT_SECURE_NO_WARNINGS`, `WIN32_LEAN_AND_MEAN` |
| GCC/Clang | `-Wall -Wextra -O2` |
| MinGW | `-static -static-libgcc -static-libstdc++` |

Release builds are stripped of symbols automatically.

### Platform Definitions

| Platform | Define |
|----------|--------|
| Windows | `RTLC2_WINDOWS` |
| Linux | `RTLC2_LINUX` |
| macOS | `RTLC2_MACOS` |

---

## 2. CMake Build Options

### Connection Settings

| Option | Default | Description |
|--------|---------|-------------|
| `RTLC2_C2_HOST` | `127.0.0.1` | C2 server hostname or IP |
| `RTLC2_C2_PORT` | `443` | C2 server port |
| `RTLC2_USE_TLS` | `0` | Enable TLS (1=yes, 0=no) |
| `RTLC2_AES_KEY` | (empty) | AES-256 master key (64 hex chars). Must match server. |
| `RTLC2_USER_AGENT` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` | HTTP User-Agent string |
| `RTLC2_SLEEP_INTERVAL` | `5` | Default sleep interval in seconds |
| `RTLC2_JITTER` | `10` | Default jitter percentage (0-100) |

### OPSEC Options

| Option | Default | Description |
|--------|---------|-------------|
| `RTLC2_SLEEP_MASK` | `0` | Sleep obfuscation method: 0=basic Sleep(), 1=Ekko (timer-based), 2=Foliage (APC-based) |
| `RTLC2_STACK_SPOOF` | `0` | Enable return address spoofing on API calls |
| `RTLC2_ETW_PATCH` | `0` | Patch ETW functions at startup |
| `RTLC2_UNHOOK_NTDLL` | `0` | Replace hooked ntdll.dll with clean copy at startup |
| `RTLC2_SYSCALL_METHOD` | `none` | Syscall method: `none`, `direct`, `indirect`, `hells_gate` |
| `RTLC2_AMSI_PATCH` | `0` | Patch AMSI at startup |
| `RTLC2_HEAP_ENCRYPT` | `0` | Encrypt heap during sleep |
| `RTLC2_ETWTI_PATCH` | `0` | Patch ETW Threat Intelligence provider at startup |
| `RTLC2_MODULE_STOMP` | `0` | Use module stomping for shellcode execution |
| `RTLC2_DEBUG` | `0` | Enable debug output to stderr |

### Evasion Toggles (Payload Generator)

| Option | Default | Description |
|--------|---------|-------------|
| `RTLC2_EVASION_DELAY_EXEC` | `0` | Delay execution (milliseconds, 0=disabled) |
| `RTLC2_EVASION_ENV_KEYING` | `0` | Environment keying |
| `RTLC2_EVASION_DIRECT_SYSCALLS` | `0` | Direct syscalls |
| `RTLC2_EVASION_INDIRECT_SYSCALLS` | `0` | Indirect syscalls |
| `RTLC2_EVASION_ETW_BLINDING` | `0` | ETW blinding |
| `RTLC2_EVASION_HOOK_BYPASS` | `0` | User-mode hook bypass |

### Working Hours and Kill Date

| Option | Default | Description |
|--------|---------|-------------|
| `RTLC2_KILL_DATE` | `0` | Unix timestamp for agent self-termination (0=disabled) |
| `RTLC2_WORK_START_HOUR` | `0` | Start of working hours (24h format, 0=disabled) |
| `RTLC2_WORK_END_HOUR` | `0` | End of working hours (24h format) |
| `RTLC2_WORK_DAYS` | `127` | Working days bitmask: bit 0=Sunday, bit 1=Monday, ..., bit 6=Saturday. 127=all days. |
| `RTLC2_SPAWN_TO` | `C:\Windows\System32\RuntimeBroker.exe` | Process to spawn for fork-and-run operations |

### Transport Settings

| Option | Default | Description |
|--------|---------|-------------|
| `RTLC2_TRANSPORT_TYPE` | `http` | Transport protocol: `http`, `tcp`, `dns`, `doh` |
| `RTLC2_DOH_RESOLVER` | `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS resolver URL |
| `RTLC2_FRONT_DOMAIN` | (empty) | CDN domain for domain fronting (empty=disabled) |

### Environment Keying

| Option | Default | Description |
|--------|---------|-------------|
| `RTLC2_ENV_KEY_DOMAIN` | (empty) | Required domain name. Agent exits if domain does not match. |
| `RTLC2_ENV_KEY_USER` | (empty) | Required username. Agent exits if username does not match. |
| `RTLC2_ENV_KEY_FILE` | (empty) | Required file marker. Agent exits if file does not exist. |

### String Obfuscation

| Option | Default | Description |
|--------|---------|-------------|
| `RTLC2_OBFSTR_SEED` | (random 8-digit number) | XOR seed for compile-time string obfuscation. Auto-generated each build. |

---

## 3. Task Types

The agent supports 41 task types (0-40). Each task is identified by an integer type code that must match between agent and server.

| Type | Name | Description | Key Parameters |
|------|------|-------------|----------------|
| 0 | Unknown | Invalid/unrecognized task | -- |
| 1 | Shell | Execute a shell command and return output | `data` = command string |
| 2 | Upload | Upload a file from the server to the agent | `path` = destination path, `data` = file content (base64) |
| 3 | Download | Download a file from the agent to the server | `data` = file path on agent |
| 4 | Sleep | Change sleep interval and jitter | `data` = seconds, `jitter` = percentage |
| 5 | Exit | Graceful agent shutdown | -- |
| 6 | Inject | Process injection (shellcode into remote process) | `pid`, `method` (crt/apc/earlybird/threadless), `tid`, `dll`, `func` |
| 7 | BOF | Execute a Beacon Object File | `data` = COFF .o bytes, `function` = entry name, `args` = packed args |
| 8 | Assembly | Execute a .NET assembly in-memory | `data` = assembly bytes (base64), `args` = arguments |
| 9 | Screenshot | Capture a screenshot of the active desktop | -- |
| 10 | Keylog | Start, stop, or dump the keylogger | `data` = `start`, `stop`, or `dump` |
| 11 | PS | List running processes | -- |
| 12 | LS | List directory contents | `data` = directory path |
| 13 | CD | Change working directory | `data` = target path |
| 14 | PWD | Print current working directory | -- |
| 15 | Whoami | Get current user context | -- |
| 16 | IPConfig | Get network interface configuration | -- |
| 17 | HashDump | Dump credentials from the system | `method` = dump method |
| 18 | Token | Token manipulation (list, steal, make, impersonate, revert) | `action`, `pid`, `user`, `pass`, `domain` |
| 19 | Pivot | Lateral movement execution | `method` (psexec/wmi/scshell/winrm/dcom), `target`, `extra` |
| 20 | PortScan | TCP port scanner | `data` = target, `ports` = port range, `timeout`, `threads` |
| 21 | Socks | SOCKS5 proxy management | `action` (start/stop), `port` |
| 22 | SelfDestruct | Agent self-destruction with artifact cleanup | -- |
| 23 | Module | Dynamic module load and execute | `action`, `args` |
| 24 | Clipboard | Clipboard monitoring | `data` = `start` or `stop` |
| 25 | RegWrite | Windows registry write operations | `action` (write/delete), key, value, data |
| 26 | ServiceCtl | Windows service control | `action` (create/start/stop/delete/query), service name, binary path |
| 27 | Jobs | Job management (list running jobs, kill by ID) | `data` = `list` or `kill <id>` |
| 28 | Persist | Install persistence mechanism | `technique`, `name`, `path`, `args`, `hklm` (bool) |
| 29 | Unpersist | Remove a persistence mechanism | `technique`, `name`, `path` |
| 30 | PrivEsc | Privilege escalation | `method` (fodhelper/eventvwr/token) |
| 31 | FileCopy | Copy a file | `data` = `src\|dst` |
| 32 | FileMove | Move/rename a file | `data` = `src\|dst` |
| 33 | FileDelete | Delete a file | `data` = file path |
| 34 | MkDir | Create a directory | `data` = directory path |
| 35 | RegQuery | Registry query | `data` = registry key path |
| 36 | EnvVar | Get/set environment variables | `data` = variable name (get) or `name=value` (set) |
| 37 | RPortFwd | Reverse port forward | `action` (start/stop), `lport`, `rhost`, `rport` |
| 38 | RunAs | Run command as another user | `user`, `pass`, `domain`, `data` = command |
| 39 | PowerShell | Execute PowerShell script/command | `data` = script or command |
| 40 | LOLBAS | Execute using Living-off-the-Land Binaries | `method` (mshta/certutil/bitsadmin/...), `data` = payload |

---

## 4. Transport Types

The agent supports 6 transport channels, selected at compile time via `RTLC2_TRANSPORT_TYPE`.

### 4.1 HTTP / HTTPS

- **File**: `src/transport/http.cpp`
- Default transport. Uses WinHTTP (Windows) or libcurl (POSIX).
- Supports malleable C2 profiles (custom User-Agent, headers, URIs, body transforms).
- Domain fronting via `RTLC2_FRONT_DOMAIN`.
- TLS certificate validation can be disabled with `RTLC2_USE_TLS`.

### 4.2 TCP

- **File**: `src/transport/tcp.cpp`
- Raw TCP transport with length-prefixed messages.
- Format: `[4-byte length][encrypted payload]`
- Suitable for internal network pivoting.

### 4.3 DNS

- **File**: `src/transport/dns.cpp`
- Encodes data in DNS TXT record queries.
- Low-bandwidth but highly covert.
- Chunked encoding for large payloads.

### 4.4 DNS-over-HTTPS (DoH)

- **File**: `src/transport/doh.cpp`
- DNS tunneling over HTTPS to a DoH resolver (default: Cloudflare).
- Bypasses network-level DNS inspection.
- Resolver configurable via `RTLC2_DOH_RESOLVER`.

### 4.5 SMB (Windows only)

- **File**: `src/transport/smb.cpp`
- Named pipe transport for lateral movement.
- Agent listens on a named pipe; parent agent forwards data.
- No direct internet connectivity required.

### 4.6 P2P

- **File**: `src/transport/p2p.cpp`
- Peer-to-peer transport using named pipes (Windows) or Unix domain sockets (POSIX).
- Allows agent chaining without direct server connectivity.

---

## 5. Evasion Modules

### 5.1 AMSI Bypass (Windows)

**File**: `src/evasion/amsi.cpp`

Four techniques to disable the Antimalware Scan Interface:

| Technique | Method |
|-----------|--------|
| PatchAmsiScanBuffer | Patches `AmsiScanBuffer` to return `E_INVALIDARG` (`0x80070057`). Prevents any scan from executing. |
| PatchAmsiOpenSession | Patches `AmsiOpenSession` to return `E_FAIL` (`0x80004005`). Prevents session creation. |
| PatchAmsiScanString | Patches `AmsiScanString` to return clean result. Targets string-based scans. |
| NullAmsiContext | Corrupts the AMSI context pointer to invalidate the entire provider chain. |

### 5.2 ETW Patching (Windows)

**File**: `src/evasion/etw.cpp`

Five ETW function patches to blind security monitoring:

| Function | Effect |
|----------|--------|
| `EtwEventWrite` | Primary ETW event writer. Patched to return `STATUS_SUCCESS` (xor eax,eax; ret). |
| `EtwEventWriteFull` | Extended event writer. Same patch. |
| `EtwEventWriteEx` | Ex variant. Same patch. |
| `EtwEventWriteTransfer` | Transfer event writer. Same patch. |
| `NtTraceEvent` | Kernel-level ETW entry point (ntdll). Same patch. |

### 5.3 NTDLL Unhooking (Windows)

**File**: `src/evasion/unhook.cpp`

Three methods to restore a clean copy of ntdll.dll:

| Method | Description |
|--------|-------------|
| File-based | Read `C:\Windows\System32\ntdll.dll` from disk, map the `.text` section, overwrite the in-memory hooked copy. |
| KnownDlls | Open `\KnownDlls\ntdll.dll` section object, map it, and copy the `.text` section over the hooked version. |
| Suspended process | Spawn a suspended process, read its clean ntdll `.text` section (before EDR hooks are applied), and use it to restore the current process's ntdll. |

### 5.4 Stack Spoofing (Windows)

**File**: `src/evasion/stack_spoof.cpp`, `src/evasion/spoof_call.S` (x64), `src/evasion/spoof_call_x86.S` (x86)

Spoofs the return address on the call stack to appear as if API calls originate from legitimate modules. Uses assembly trampolines to manipulate the stack frame before calling target functions.

### 5.5 PPID Spoofing (Windows)

**File**: `src/evasion/ppid_spoof.cpp`

Spawns child processes with a spoofed parent process ID using `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. The child appears to be spawned by a legitimate system process (e.g., explorer.exe, svchost.exe).

### 5.6 Heap Encryption (Windows)

**File**: `src/evasion/heap_encrypt.cpp`

Two timer-based sleep obfuscation techniques that encrypt the agent's memory during sleep:

| Technique | `RTLC2_SLEEP_MASK` | Method |
|-----------|---------------------|--------|
| Ekko | 1 | Uses `CreateTimerQueueTimer` and `NtContinue` context swaps to ROP into `SystemFunction032` (RC4), encrypting the agent's image section, sleeping via `WaitForSingleObject`, then decrypting. |
| Foliage | 2 | Similar to Ekko but uses APCs queued to the current thread instead of timer callbacks. Chains `NtProtectVirtualMemory` -> `SystemFunction032` -> sleep -> decrypt -> restore. |

### 5.7 Module Stomping (Windows)

**File**: `src/evasion/module_stomp.cpp`

Loads a legitimate signed DLL (e.g., `mstscax.dll`) into memory, then overwrites its `.text` section with shellcode. The memory region retains the backing of a legitimate module, evading scanners that check memory regions for PE signatures.

### 5.8 Anti-Sandbox (Cross-platform)

**File**: `src/evasion/sandbox.cpp`

Six environment checks to detect analysis environments:

| Check | Method |
|-------|--------|
| Sleep timing | Calls `Sleep(2000)` and measures actual elapsed time. Sandboxes that fast-forward sleep will mismatch. |
| CPU count | Checks if fewer than 2 logical processors are present. |
| RAM size | Checks if physical memory is below 2 GB. |
| Disk size | Checks if primary disk is below 60 GB. |
| Username | Checks for common sandbox usernames (sandbox, malware, virus, test, john doe). |
| Process list | Checks for analysis tool processes (vmtoolsd, vboxservice, procmon, wireshark, x64dbg, ollydbg). |

### 5.9 Hardware Breakpoint Hooks (Windows)

**File**: `src/evasion/hw_bp_hook.cpp`

Uses hardware debug registers (DR0-DR3) to set breakpoints on API functions. When a breakpoint fires, the Vectored Exception Handler (VEH) redirects execution to a hook function. This avoids modifying any code bytes, making the hooks invisible to integrity checks.

### 5.10 Threadless Injection (Windows)

**File**: `src/evasion/threadless_inject.cpp`

Hijacks an existing thread's execution flow by modifying the thread context (instruction pointer) to execute shellcode. Does not create a new remote thread, evading thread-creation monitoring.

### 5.11 Argument Spoofing (Windows)

**File**: `src/evasion/argue.cpp`

Spawns a process with benign command-line arguments visible in the PEB, then patches the PEB `ProcessParameters.CommandLine` buffer with the real arguments after creation. Evades command-line logging by EDR products.

### 5.12 Sleep Obfuscation

**File**: `src/evasion/sleep.cpp`

Manages the agent's sleep cycle with optional obfuscation (see Heap Encryption above). The basic mode uses `Sleep()` (Windows) or `usleep()` (POSIX) with jitter randomization.

### 5.13 Process Injection (Windows)

**File**: `src/evasion/injection.cpp`

Four injection methods, all with optional syscall support:

| Method | Description |
|--------|-------------|
| CreateRemoteThread | Classic: VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread. Enhanced with direct/indirect syscall variants. |
| APC Queue | Allocate memory in target, queue an APC to an alertable thread via `QueueUserAPC`. |
| Early Bird | Create a suspended process, inject shellcode, queue APC to the main thread, resume. Executes before EDR hooks are installed. |
| Threadless | Redirect an existing thread's execution context (see section 5.10). |

### 5.14 Environment Keying

**Build options**: `RTLC2_ENV_KEY_DOMAIN`, `RTLC2_ENV_KEY_USER`, `RTLC2_ENV_KEY_FILE`

The agent checks the execution environment at startup:

| Key | Check |
|-----|-------|
| Domain | Compares the computer's domain name against the required value. |
| User | Compares the current username against the required value. |
| File | Checks for the existence of a marker file at the specified path. |

If any check fails, the agent exits silently without performing any C2 communication.

---

## 6. Syscalls

### 6.1 Hell's Gate / Halo's Gate Resolver

**File**: `src/syscalls/resolver.cpp`

Resolves syscall numbers at runtime by walking the ntdll export table:

- **Hell's Gate**: Reads the syscall number directly from the function prologue (`mov r10, rcx; mov eax, <ssn>`).
- **Halo's Gate**: If the function is hooked (prologue modified), walks neighboring syscall stubs up and down to extrapolate the correct syscall number.

### 6.2 Syscall Gates

Architecture-specific assembly stubs:

| File | Architecture | Description |
|------|-------------|-------------|
| `src/syscalls/syscall_gate.S` | x64 | `syscall` instruction with SSN in EAX |
| `src/syscalls/syscall_gate_x86.S` | x86 | `int 0x2e` or `sysenter` with SSN in EAX |
| `src/syscalls/syscall_gate_arm64.S` | ARM64 | `svc #0` with SSN in X8 |

### 6.3 Syscall Methods

| Method (`RTLC2_SYSCALL_METHOD`) | Description |
|---------------------------------|-------------|
| `none` | Use standard Win32 API calls (no syscalls) |
| `direct` | Execute `syscall` instruction from within the agent's memory |
| `indirect` | Jump to the `syscall` instruction inside ntdll.dll (avoids executing syscall from non-ntdll memory) |
| `hells_gate` | Use Hell's Gate/Halo's Gate to dynamically resolve SSNs, then execute via direct or indirect gate |

---

## 7. Cryptography

### 7.1 AES-256-GCM

**File**: `src/crypto/aes.cpp`

- Key: 256-bit (32 bytes), hex-encoded in config
- Nonce: 12 bytes, randomly generated per encryption
- Tag: 16 bytes, appended to ciphertext
- Uses BCrypt (Windows) or OpenSSL (POSIX)

### 7.2 XOR

**File**: `src/crypto/xor.cpp`

Simple XOR cipher for lightweight obfuscation of configuration strings and small data blobs.

### 7.3 String Obfuscation

**File**: `src/crypto/obfuscation.cpp`

Compile-time XOR obfuscation of string literals. The XOR key is derived from `RTLC2_OBFSTR_SEED`. Strings are decrypted at runtime when accessed.

### 7.4 DJB2 API Hashing

Used for resolving Win32 API functions by hash instead of name. The DJB2 algorithm (`hash = hash * 33 + c`) produces a 32-bit hash of the function name. Combined with PEB module resolution to walk loaded modules and their exports.

### 7.5 Shellcode Encoder

**File**: `src/crypto/shellcode_encoder.cpp`

Encodes shellcode with configurable encoding schemes and generates a decoder stub prepended to the output. The decoder runs first to decode the shellcode in-place before execution.

---

## 8. Persistence

**Files**: `src/modules/persistence.cpp` (dispatcher), `src/modules/persistence_win.cpp`, `src/modules/persistence_posix.cpp`

### Windows (8 methods)

| Technique | MITRE | Description |
|-----------|-------|-------------|
| RegistryRunKey | T1547.001 | Write to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` or `HKLM` equivalent |
| ScheduledTask | T1053.005 | Create a scheduled task via COM TaskScheduler interface |
| WMISubscription | T1546.003 | WMI event subscription (event filter + consumer + binding) |
| ServiceInstall | T1543.003 | Install a Windows service |
| StartupFolder | T1547.001 | Copy executable to `shell:startup` folder |
| COMHijack | T1546.015 | Hijack a COM class registration in the registry |
| DLLSearchOrder | T1574.001 | Plant a DLL in a directory searched before the legitimate one |
| RegistryLogonScript | T1037.001 | Set a logon script in `HKCU\Environment\UserInitMprLogonScript` |

### Linux (3 methods)

| Technique | Description |
|-----------|-------------|
| Crontab | Add entry to user crontab (`crontab -l; echo "@reboot /path/to/agent"`) |
| SystemdService | Create a systemd user service in `~/.config/systemd/user/` |
| BashRC | Append execution line to `~/.bashrc` |

### macOS (4 methods)

| Technique | Description |
|-----------|-------------|
| Crontab | Same as Linux |
| BashRC | Append to `~/.zshrc` or `~/.bashrc` |
| LaunchAgent | Create a plist in `~/Library/LaunchAgents/` |
| LaunchDaemon | Create a plist in `/Library/LaunchDaemons/` (requires root) |

---

## 9. Privilege Escalation

**File**: `src/modules/privesc.cpp`

| Method | Platform | Description |
|--------|----------|-------------|
| Fodhelper | Windows | UAC bypass via `fodhelper.exe` registry hijack (`ms-settings` handler). Elevates from medium to high integrity. |
| Eventvwr | Windows | UAC bypass via `eventvwr.msc` registry hijack (`mscfile` handler). Similar to fodhelper. |
| Token Abuse | Windows | Duplicate a SYSTEM token from a privileged process and impersonate it. Requires SeDebugPrivilege. |

---

## 10. Job System

**File**: `src/core/jobs.cpp`

The job manager runs long-lived tasks as background threads:

- Each job has a unique integer ID, a name, and a stop flag
- Jobs run in their own thread, periodically checking the stop flag
- The `Jobs` task (type 27) lists running jobs or kills a specific job by ID
- Keylogger, clipboard monitor, SOCKS proxy, and port forwarder use the job system

---

## 11. BOF Loader

**File**: `src/bof/loader.cpp`, `include/bof.h`

See [BOF Arsenal](bofs.md) for the full BOF catalog.

The in-process BOF loader:

1. Parses the COFF header, sections, symbols, and relocations
2. Allocates memory for each section (RWX for `.text`, RW for data)
3. Resolves external symbols against the 58 Beacon API functions
4. Applies relocations (section-relative)
5. Calls the entry point function (default: `go`)
6. Captures output via `BeaconOutput`/`BeaconPrintf`

Compatible with Cobalt Strike, Sliver, and other frameworks that produce standard COFF BOFs.

---

## 12. Execution Engines

### 12.1 .NET CLR Hosting

**File**: `src/execution/dotnet.cpp` (Windows only)

Loads and executes .NET assemblies in-memory:

1. Optionally patches AMSI and ETW before CLR initialization
2. Initializes the CLR runtime (selectable version: v2.0/v4.0)
3. Creates an isolated AppDomain
4. Loads the assembly from a byte array (no disk write)
5. Invokes the entry point with supplied arguments
6. Captures stdout/stderr output
7. Unloads the AppDomain

### 12.2 Reflective PE Loader

**File**: `src/execution/pe_loader.cpp` (Windows only)

Loads PE files (EXE/DLL) entirely in memory:

1. Allocates memory for the PE image
2. Maps sections to their virtual addresses
3. Processes relocations (base relocation table)
4. Resolves imports (IAT patching)
5. Calls TLS callbacks and DllMain/entry point

### 12.3 Shellcode Executor

**File**: `src/execution/shellcode_exec.cpp`

Executes raw shellcode in-memory using configurable injection methods:

- Local execution: VirtualAlloc -> memcpy -> CreateThread
- Remote injection: See Process Injection (section 5.13)
- Module stomping: See section 5.7

### 12.4 PowerShell

**File**: `src/execution/powershell.cpp`

| Platform | Method |
|----------|--------|
| Windows | Spawns a hidden `powershell.exe` process with `-NoProfile -WindowStyle Hidden -EncodedCommand <base64>`. Uses argument spoofing if enabled. |
| Linux/macOS | Spawns `pwsh` subprocess with `-NoProfile -EncodedCommand <base64>`. Falls back to `pwsh -c` if encoding fails. |

### 12.5 LOLBAS Execution

**File**: `src/modules/lolbas.cpp`

Executes commands using Living-off-the-Land Binaries and Scripts:

| Binary | Usage |
|--------|-------|
| mshta | VBScript/JScript execution via `mshta vbscript:...` |
| certutil | File download via `-urlcache -split -f`, decode via `-decode` |
| bitsadmin | Background file transfer via BITS |
| regsvr32 | Scriptlet execution via `/s /n /u /i:<url> scrobj.dll` |
| rundll32 | JavaScript execution via `javascript:` URI |
| wmic | Process creation via `process call create` |
| msiexec | MSI package installation from URL |

---

## 13. Linked Libraries

### Windows

| Library | Purpose |
|---------|---------|
| winhttp | HTTP/HTTPS transport |
| ws2_32 | Winsock (TCP, DNS, SOCKS) |
| crypt32 | Certificate operations |
| advapi32 | Registry, services, tokens, security |
| ntdll | Native API (syscalls) |
| shlwapi | Path manipulation |
| dbghelp | Debug helpers |
| netapi32 | Network management (shares, users) |
| wbemuuid | WMI COM interfaces |
| ole32 | COM runtime |
| oleaut32 | COM automation |
| shell32 | Shell operations |
| bcrypt | Cryptographic primitives (AES) |
| taskschd | Task Scheduler COM interface |

### Linux / macOS

| Library | Purpose |
|---------|---------|
| OpenSSL (SSL + Crypto) | TLS transport, AES encryption |
| libcurl | HTTP/HTTPS transport |
| pthread | Threading |

---

## 14. Source File Reference

### Core

| File | Purpose |
|------|---------|
| `src/main.cpp` | Entry point, configuration, agent creation and startup |
| `src/core/agent.cpp` | Agent class: registration, check-in loop, task dispatch |
| `src/core/task.cpp` | Task execution dispatcher (routes task types to handlers) |
| `src/core/jobs.cpp` | Background job manager |

### Transport (6 files)

`src/transport/http.cpp`, `tcp.cpp`, `dns.cpp`, `doh.cpp`, `smb.cpp`, `p2p.cpp`

### Crypto (4 files)

`src/crypto/aes.cpp`, `xor.cpp`, `obfuscation.cpp`, `shellcode_encoder.cpp`

### Evasion (14 files)

`src/evasion/amsi.cpp`, `etw.cpp`, `etwti.cpp`, `unhook.cpp`, `stack_spoof.cpp`, `ppid_spoof.cpp`, `heap_encrypt.cpp`, `module_stomp.cpp`, `sandbox.cpp`, `hw_bp_hook.cpp`, `threadless_inject.cpp`, `argue.cpp`, `sleep.cpp`, `injection.cpp`

### Evasion Assembly (4 files)

`src/evasion/spoof_call.S` (x64), `spoof_call_x86.S`, `src/syscalls/syscall_gate.S` (x64), `syscall_gate_x86.S`, `syscall_gate_arm64.S`

### Syscalls (2 files)

`src/syscalls/resolver.cpp`, `syscalls.cpp`

### Execution (4 files)

`src/execution/dotnet.cpp`, `pe_loader.cpp`, `shellcode_exec.cpp`, `powershell.cpp`

### Modules (20 files)

`src/modules/shell_win.cpp`, `shell_posix.cpp`, `sysinfo_win.cpp`, `sysinfo_posix.cpp`, `token.cpp`, `credentials.cpp`, `keylogger.cpp`, `portscan.cpp`, `recon.cpp`, `migrate.cpp`, `lolbas.cpp`, `socks5.cpp`, `clipboard.cpp`, `registry_write.cpp`, `services.cpp`, `portfwd.cpp`, `lateral.cpp`, `persistence.cpp`, `persistence_win.cpp`, `persistence_posix.cpp`, `privesc.cpp`, `rportfwd.cpp`

### BOF Loader (1 file)

`src/bof/loader.cpp`
