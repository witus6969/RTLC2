// ═══════════════════════════════════════════════════════════════
//  Payload Generator Static Data
//  ALL field names MUST match Go server JSON struct tags in payload.go
// ═══════════════════════════════════════════════════════════════

export interface FormatOption {
  display: string;
  key: string;
  extension: string;
  supportedOS: string[];
}

export interface ArchOption {
  display: string;
  key: string;
  supportedOS: string[];
}

export interface ShellcodeFormatOption {
  display: string;
  key: string;
  supportedOS: string[];
}

export interface EvasionCategory {
  key: string;       // MUST match Go EvasionConfig JSON tag
  label: string;
  windowsOnly: boolean;
  techniques: { name: string; field: string; defaultOn: boolean }[];
}

// Go server valid formats: exe, dll, shellcode, powershell, hta, macro, service_exe, loader, loader_dll
export const ALL_FORMATS: FormatOption[] = [
  { display: 'Windows EXE', key: 'exe', extension: '.exe', supportedOS: ['windows'] },
  { display: 'Windows DLL', key: 'dll', extension: '.dll', supportedOS: ['windows'] },
  { display: 'Windows Service EXE', key: 'service_exe', extension: '.exe', supportedOS: ['windows'] },
  { display: 'Shellcode Loader (EXE)', key: 'loader', extension: '.exe', supportedOS: ['windows'] },
  { display: 'Shellcode Loader (DLL)', key: 'loader_dll', extension: '.dll', supportedOS: ['windows'] },
  { display: 'Raw Shellcode', key: 'shellcode', extension: '.bin', supportedOS: ['windows', 'linux', 'macos'] },
  { display: 'PowerShell Script', key: 'powershell', extension: '.ps1', supportedOS: ['windows'] },
  { display: 'HTA Application', key: 'hta', extension: '.hta', supportedOS: ['windows'] },
  { display: 'VBA Macro', key: 'macro', extension: '.vba', supportedOS: ['windows'] },
  { display: 'Linux ELF', key: 'exe', extension: '', supportedOS: ['linux'] },
  { display: 'Linux Loader (ELF)', key: 'loader', extension: '', supportedOS: ['linux'] },
  { display: 'macOS Mach-O', key: 'exe', extension: '', supportedOS: ['macos'] },
  { display: 'macOS Loader', key: 'loader', extension: '', supportedOS: ['macos'] },
];

// Go server valid archs: x64, x86, arm64
export const ALL_ARCHS: ArchOption[] = [
  { display: 'x64', key: 'x64', supportedOS: ['windows', 'linux', 'macos'] },
  { display: 'x86', key: 'x86', supportedOS: ['windows', 'linux'] },
  { display: 'arm64', key: 'arm64', supportedOS: ['linux', 'macos'] },
];

// Go server valid shellcode formats: raw, c_array, python, csharp, powershell
export const ALL_SHELLCODE_FORMATS: ShellcodeFormatOption[] = [
  { display: 'Raw (.bin)', key: 'raw', supportedOS: ['windows', 'linux', 'macos'] },
  { display: 'C Array (.h)', key: 'c_array', supportedOS: ['windows', 'linux', 'macos'] },
  { display: 'Python (.py)', key: 'python', supportedOS: ['windows', 'linux', 'macos'] },
  { display: 'C# Byte Array (.cs)', key: 'csharp', supportedOS: ['windows'] },
  { display: 'PowerShell (.ps1)', key: 'powershell', supportedOS: ['windows'] },
];

// ═══════════════════════════════════════════════════════════════
// Evasion Categories - field names match Go EvasionConfig JSON tags
// Category keys match Go EvasionConfig struct JSON tags exactly
// ═══════════════════════════════════════════════════════════════

export const EVASION_CATEGORIES: EvasionCategory[] = [
  {
    // Go: EvasionExecution -> json:"execution"
    key: 'execution', label: 'Execution', windowsOnly: false,
    techniques: [
      { name: 'In-memory execution', field: 'in_memory', defaultOn: true },
      { name: 'Avoid disk writes', field: 'no_disk', defaultOn: true },
      { name: 'Staged memory chunks', field: 'staged_chunks', defaultOn: true },
      { name: 'Delayed execution', field: 'delay_exec', defaultOn: true },
      { name: 'Environment keying', field: 'env_keying', defaultOn: false },
      { name: 'Timestomping', field: 'time_stomp', defaultOn: false },
      { name: 'Polymorphic code', field: 'polymorphic', defaultOn: false },
      { name: 'Metamorphic engine', field: 'metamorphic', defaultOn: false },
      { name: 'JIT compilation', field: 'jit_compile', defaultOn: false },
      { name: 'Thread pool execution', field: 'thread_pool', defaultOn: false },
    ],
  },
  {
    // Go: EvasionAppLocker -> json:"applocker"
    key: 'applocker', label: 'AppLocker', windowsOnly: true,
    techniques: [
      { name: 'DLL sideloading', field: 'dll_sideload', defaultOn: false },
      { name: 'MSBuild execution', field: 'msbuild_exec', defaultOn: false },
      { name: 'InstallUtil execution', field: 'installutil_exec', defaultOn: false },
      { name: 'RegSvr32 execution', field: 'regsvr_exec', defaultOn: false },
      { name: 'RunDLL32 execution', field: 'rundll32_exec', defaultOn: false },
      { name: 'MSHTA execution', field: 'mshta', defaultOn: false },
      { name: 'CMSTP execution', field: 'cmstp', defaultOn: false },
      { name: 'Whitelist bypass', field: 'whitelist_bypass', defaultOn: false },
      { name: 'Trusted folder abuse', field: 'trusted_folder', defaultOn: false },
      { name: 'Alternate data streams', field: 'alternate_data_stream', defaultOn: false },
    ],
  },
  {
    // Go: EvasionTrustedPath -> json:"trusted_path"
    key: 'trusted_path', label: 'Trusted Path', windowsOnly: true,
    techniques: [
      { name: 'System directory abuse', field: 'system_dir', defaultOn: false },
      { name: 'Program Files abuse', field: 'program_files', defaultOn: false },
      { name: 'WindowsApps abuse', field: 'windows_apps', defaultOn: false },
      { name: 'Signed temp abuse', field: 'temp_signed', defaultOn: false },
      { name: 'Recycle bin abuse', field: 'recycle_bin', defaultOn: false },
      { name: 'WinSxS abuse', field: 'winsxs', defaultOn: false },
      { name: 'Driver store abuse', field: 'driver_store', defaultOn: false },
      { name: 'Global assembly cache', field: 'global_assembly', defaultOn: false },
      { name: 'COM surrogate abuse', field: 'com_surrogate', defaultOn: false },
      { name: 'Print spooler abuse', field: 'print_spooler', defaultOn: false },
    ],
  },
  {
    // Go: EvasionMemoryLoaders -> json:"memory_loaders"
    key: 'memory_loaders', label: 'Memory Loaders', windowsOnly: true,
    techniques: [
      { name: 'Reflective DLL loading', field: 'reflective_dll', defaultOn: true },
      { name: 'Manual PE mapping', field: 'manual_map', defaultOn: false },
      { name: 'Module overloading', field: 'module_overload', defaultOn: false },
      { name: 'Transacted hollowing', field: 'transacted_hollow', defaultOn: false },
      { name: 'Ghostly hollowing', field: 'ghostly_hollow', defaultOn: false },
      { name: 'Phantom DLL', field: 'phantom_dll', defaultOn: false },
      { name: 'Process doppelganging', field: 'doppelganging', defaultOn: false },
      { name: 'Herpaderping', field: 'herpaderping', defaultOn: false },
      { name: 'Process hollowing', field: 'process_hollow', defaultOn: true },
      { name: 'Memory module loading', field: 'memory_module', defaultOn: false },
    ],
  },
  {
    // Go: EvasionProcessInjection -> json:"process_injection"
    key: 'process_injection', label: 'Injection', windowsOnly: true,
    techniques: [
      { name: 'Classic injection (CRT)', field: 'classic_injection', defaultOn: true },
      { name: 'APC queue injection', field: 'apc_queue_injection', defaultOn: false },
      { name: 'Thread hijacking', field: 'thread_hijack', defaultOn: false },
      { name: 'Early-bird APC', field: 'early_bird', defaultOn: true },
      { name: 'Atom bombing', field: 'atom_bombing', defaultOn: false },
      { name: 'NtCreateSection', field: 'nt_create_section', defaultOn: false },
      { name: 'Kernel callback', field: 'kernel_callback', defaultOn: false },
      { name: 'Fiber injection', field: 'fiber_injection', defaultOn: false },
      { name: 'Enclave injection', field: 'enclave_injection', defaultOn: false },
      { name: 'Pool party', field: 'pool_party', defaultOn: false },
    ],
  },
  {
    // Go: EvasionAMSIScript -> json:"amsi_script"
    key: 'amsi_script', label: 'AMSI/Script', windowsOnly: true,
    techniques: [
      { name: 'AMSI patch', field: 'amsi_patch', defaultOn: true },
      { name: 'AMSI scan buffer', field: 'amsi_scan_buffer', defaultOn: false },
      { name: 'AMSI provider hijack', field: 'amsi_provider_hijack', defaultOn: false },
      { name: 'WLDP bypass', field: 'wldp_bypass', defaultOn: false },
      { name: 'Script block logging', field: 'script_block', defaultOn: false },
      { name: 'CLM bypass', field: 'clm_bypass', defaultOn: false },
      { name: 'PowerShell hollowing', field: 'powershell_hollow', defaultOn: false },
      { name: '.NET patching', field: 'dotnet_patch', defaultOn: false },
      { name: 'Script obfuscation', field: 'script_obfuscate', defaultOn: false },
      { name: 'JScript bypass', field: 'jscript_bypass', defaultOn: false },
    ],
  },
  {
    // Go: EvasionLOLBins -> json:"lolbins"
    key: 'lolbins', label: 'LOLBins', windowsOnly: true,
    techniques: [
      { name: 'CertUtil download', field: 'certutil', defaultOn: false },
      { name: 'BitsAdmin transfer', field: 'bitsadmin', defaultOn: false },
      { name: 'MpCmdRun download', field: 'mpcmdrun', defaultOn: false },
      { name: 'Esentutl copy', field: 'esentutl', defaultOn: false },
      { name: 'Expand download', field: 'expand_dl', defaultOn: false },
      { name: 'Extract download', field: 'extract_dl', defaultOn: false },
      { name: 'HH execution', field: 'hh', defaultOn: false },
      { name: 'IE4uInit execution', field: 'ie4uinit', defaultOn: false },
      { name: 'Replace download', field: 'replace_dl', defaultOn: false },
      { name: 'XCopy transfer', field: 'xcopy', defaultOn: false },
    ],
  },
  {
    // Go: EvasionEDRBehavioral -> json:"edr_behavioral"
    key: 'edr_behavioral', label: 'EDR Evasion', windowsOnly: false,
    techniques: [
      { name: 'User-mode hook bypass', field: 'user_mode_hook_bypass', defaultOn: false },
      { name: 'Kernel callback evasion', field: 'kernel_callbacks', defaultOn: false },
      { name: 'ETW blinding', field: 'etw_blinding', defaultOn: true },
      { name: 'Stack spoofing', field: 'stack_spoofing', defaultOn: false },
      { name: 'Call stack masking', field: 'call_stack_mask', defaultOn: false },
      { name: 'Return address spoof', field: 'return_addr_spoof', defaultOn: false },
      { name: 'Indirect syscall', field: 'indirect_syscall', defaultOn: false },
      { name: 'Timestamp manipulation', field: 'timestamp_manip', defaultOn: false },
      { name: 'Threadless injection', field: 'threadless_inject', defaultOn: false },
      { name: 'HW breakpoints', field: 'hw_breakpoints', defaultOn: false },
    ],
  },
  {
    // Go: EvasionDotNet -> json:"dotnet"
    key: 'dotnet', label: '.NET', windowsOnly: true,
    techniques: [
      { name: 'In-memory assembly', field: 'in_memory_assembly', defaultOn: false },
      { name: 'AppDomain manager', field: 'app_domain_manager', defaultOn: false },
      { name: 'CLR hosting', field: 'clr_hosting', defaultOn: false },
      { name: 'Dynamic invoke', field: 'dynamic_invoke', defaultOn: false },
      { name: 'Reflection obfuscation', field: 'reflection_obfusc', defaultOn: false },
      { name: 'Assembly.Load bytes', field: 'assembly_load_byte', defaultOn: false },
      { name: 'Type confusion', field: 'type_confusion', defaultOn: false },
      { name: 'GC manipulation', field: 'garbage_collector', defaultOn: false },
      { name: 'Mixed-mode assembly', field: 'mixed_assembly', defaultOn: false },
      { name: 'Profiler attach', field: 'profiler_attach', defaultOn: false },
    ],
  },
  {
    // Go: EvasionSyscalls -> json:"syscalls"
    key: 'syscalls', label: 'Syscalls', windowsOnly: true,
    techniques: [
      { name: 'Direct syscalls', field: 'direct_syscalls', defaultOn: true },
      { name: 'Indirect syscalls', field: 'indirect_syscalls', defaultOn: true },
      { name: 'Syscall stub', field: 'syscall_stub', defaultOn: false },
      { name: 'Syscall randomize', field: 'syscall_randomize', defaultOn: false },
      { name: 'Syscall unhook', field: 'syscall_unhook', defaultOn: false },
      { name: 'Syscall gate', field: 'syscall_gate', defaultOn: false },
      { name: "Hell's Gate", field: 'hells_gate', defaultOn: false },
      { name: "Halo's Gate", field: 'halos_gate', defaultOn: false },
      { name: "Tartarus Gate", field: 'tartarus_gate', defaultOn: false },
      { name: 'Recycled Gate', field: 'recycled_gate', defaultOn: false },
    ],
  },
];

// OPSEC options that are Windows-only (field names match Go OpsecConfig JSON tags)
export const WINDOWS_ONLY_OPSEC = ['stack_spoof', 'module_stomping', 'etw_patch', 'unhook_ntdll', 'thread_stack_spoof'];
