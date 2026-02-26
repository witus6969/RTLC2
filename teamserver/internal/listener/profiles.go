package listener

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

// ProfileManager manages C2 traffic profiles.
type ProfileManager struct {
	profiles map[string]*MalleableProfile
	mu       sync.RWMutex
}

func NewProfileManager() *ProfileManager {
	pm := &ProfileManager{
		profiles: make(map[string]*MalleableProfile),
	}
	pm.loadBuiltinProfiles()
	// Load profiles from the default profiles directory
	if err := pm.LoadProfilesFromDir("/opt/RTLC2/profiles"); err != nil {
		log.Warnf("Failed to load profiles from /opt/RTLC2/profiles: %v", err)
	}
	return pm
}

func (pm *ProfileManager) loadBuiltinProfiles() {
	builtins := []*MalleableProfile{
		DefaultProfile(),
		SlackProfile(),
		TeamsProfile(),
		GoogleDriveProfile(),
		OneDriveProfile(),
		CloudflareProfile(),
		JQueryProfile(),
	}
	for _, p := range builtins {
		pm.profiles[strings.ToLower(p.Name)] = p
	}
}

func (pm *ProfileManager) GetProfile(name string) (*MalleableProfile, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	p, ok := pm.profiles[strings.ToLower(name)]
	return p, ok
}

func (pm *ProfileManager) GetAllProfiles() []*MalleableProfile {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	result := make([]*MalleableProfile, 0, len(pm.profiles))
	for _, p := range pm.profiles {
		result = append(result, p)
	}
	return result
}

func (pm *ProfileManager) LoadFromFile(path string) (*MalleableProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile file: %v", err)
	}

	var profile MalleableProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse profile: %v", err)
	}

	if profile.Name == "" {
		profile.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}

	pm.mu.Lock()
	pm.profiles[strings.ToLower(profile.Name)] = &profile
	pm.mu.Unlock()

	log.Infof("Loaded custom C2 profile: %s", profile.Name)
	return &profile, nil
}

func (pm *ProfileManager) LoadCustomProfiles(dir string) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Warnf("Failed to create profiles directory: %v", err)
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Warnf("Failed to read profiles directory: %v", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".json" || ext == ".yaml" || ext == ".yml" {
			if _, err := pm.LoadFromFile(filepath.Join(dir, entry.Name())); err != nil {
				log.Warnf("Failed to load profile %s: %v", entry.Name(), err)
			}
		}
	}
}

func (pm *ProfileManager) SaveProfile(profile *MalleableProfile, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}

	filename := strings.ToLower(strings.ReplaceAll(profile.Name, " ", "_")) + ".json"
	path := filepath.Join(dir, filename)

	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}

	pm.mu.Lock()
	pm.profiles[strings.ToLower(profile.Name)] = profile
	pm.mu.Unlock()

	return nil
}

// LoadProfilesFromDir reads all .json files in dirPath, parses each as a
// MalleableProfile, and adds them to the profile manager.
func (pm *ProfileManager) LoadProfilesFromDir(dirPath string) error {
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("failed to create profiles directory %s: %w", dirPath, err)
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read profiles directory %s: %w", dirPath, err)
	}

	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".json" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dirPath, entry.Name()))
		if err != nil {
			log.Warnf("Failed to read profile file %s: %v", entry.Name(), err)
			continue
		}

		var profile MalleableProfile
		if err := json.Unmarshal(data, &profile); err != nil {
			log.Warnf("Failed to parse profile file %s: %v", entry.Name(), err)
			continue
		}

		if profile.Name == "" {
			profile.Name = strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		}

		pm.mu.Lock()
		pm.profiles[strings.ToLower(profile.Name)] = &profile
		pm.mu.Unlock()
		count++
	}

	if count > 0 {
		log.Infof("Loaded %d C2 profiles from %s", count, dirPath)
	}
	return nil
}

// ExportProfile marshals a named profile to JSON bytes.
func (pm *ProfileManager) ExportProfile(name string) ([]byte, error) {
	pm.mu.RLock()
	p, ok := pm.profiles[strings.ToLower(name)]
	pm.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("profile not found: %s", name)
	}
	return json.MarshalIndent(p, "", "  ")
}

// DeleteProfile removes a profile by name. Returns an error if the profile
// is a built-in profile or does not exist.
func (pm *ProfileManager) DeleteProfile(name string) error {
	key := strings.ToLower(name)
	builtins := []string{"default", "slack", "microsoft teams", "google drive", "onedrive", "cloudflare", "jquery cdn"}
	for _, b := range builtins {
		if key == b {
			return fmt.Errorf("cannot delete built-in profile: %s", name)
		}
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if _, ok := pm.profiles[key]; !ok {
		return fmt.Errorf("profile not found: %s", name)
	}
	delete(pm.profiles, key)
	return nil
}

// ===================== Built-in Profiles =====================

func SlackProfile() *MalleableProfile {
	return &MalleableProfile{
		Name:      "Slack",
		UserAgent: "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
		RequestHeaders: map[string]string{
			"Accept":           "application/json",
			"Accept-Language":  "en-US,en;q=0.9",
			"Accept-Encoding":  "gzip, deflate, br",
			"Content-Type":     "application/json; charset=utf-8",
			"Authorization":    "Bearer xoxb-not-a-real-token",
			"X-Slack-No-Retry": "1",
		},
		ResponseHeaders: map[string]string{
			"Content-Type":                "application/json; charset=utf-8",
			"Server":                      "Apache",
			"X-Slack-Req-Id":              "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			"X-Content-Type-Options":      "nosniff",
			"Strict-Transport-Security":   "max-age=31536000; includeSubDomains; preload",
			"Access-Control-Allow-Origin": "*",
		},
		URIs: []string{
			"/api/chat.postMessage",
			"/api/conversations.list",
			"/api/users.info",
			"/api/files.upload",
			"/api/rtm.connect",
			"/api/chat.update",
		},
		BodyTransform: "base64",
	}
}

func TeamsProfile() *MalleableProfile {
	return &MalleableProfile{
		Name:      "Microsoft Teams",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.6.00.4472 Chrome/120.0.0.0 Electron/28.1.0 Safari/537.36",
		RequestHeaders: map[string]string{
			"Accept":               "application/json, text/plain, */*",
			"Accept-Language":      "en-US",
			"Accept-Encoding":      "gzip, deflate, br",
			"Content-Type":         "application/json",
			"Authorization":        "Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6IjB4ZGVhZGJlZWYi",
			"X-Ms-Client-Version": "49/1.0.0.2024",
			"X-Ms-Client-Env":     "prod",
		},
		ResponseHeaders: map[string]string{
			"Content-Type":              "application/json; charset=utf-8",
			"Server":                    "Microsoft-IIS/10.0",
			"X-Powered-By":             "ASP.NET",
			"X-Ms-Request-Id":          "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
			"X-Content-Type-Options":    "nosniff",
		},
		URIs: []string{
			"/v1.0/me/chats",
			"/v1.0/me/joinedTeams",
			"/beta/me/chats/messages",
			"/v1.0/teams/messages",
			"/v1.0/me/presence",
			"/api/mt/emea/beta/users/fetch",
		},
		BodyTransform: "base64",
	}
}

func GoogleDriveProfile() *MalleableProfile {
	return &MalleableProfile{
		Name:      "Google Drive",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		RequestHeaders: map[string]string{
			"Accept":              "*/*",
			"Accept-Language":     "en-US,en;q=0.9",
			"Accept-Encoding":     "gzip, deflate, br",
			"Authorization":       "Bearer ya29.a0AfH6SMBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			"X-Goog-Api-Client": "gdcl/7.0.0 gl-python/3.11.0",
		},
		ResponseHeaders: map[string]string{
			"Content-Type":         "application/json; charset=UTF-8",
			"Server":               "ESF",
			"X-Goog-Trace-Id":     "a1b2c3d4e5f67890abcdef1234567890",
			"X-Frame-Options":      "SAMEORIGIN",
			"X-XSS-Protection":     "0",
			"Cache-Control":        "no-cache, no-store, max-age=0, must-revalidate",
			"Alt-Svc":              "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000",
		},
		URIs: []string{
			"/upload/drive/v3/files",
			"/drive/v3/files",
			"/drive/v3/changes",
			"/drive/v3/about",
			"/drive/v2/files",
			"/o/oauth2/token",
		},
		BodyTransform: "base64",
	}
}

func OneDriveProfile() *MalleableProfile {
	return &MalleableProfile{
		Name:      "OneDrive",
		UserAgent: "OneDrive/24.005.0113.0003 (Windows; Windows NT 10.0)",
		RequestHeaders: map[string]string{
			"Accept":          "application/json",
			"Accept-Language": "en-US",
			"Accept-Encoding": "gzip, deflate, br",
			"Authorization":   "Bearer EwAIA+pvBAAUAAAAAAAAAAAAAAAAAAgZR+l",
			"X-RequestStats":  "IsFromCache:False",
			"Prefer":          "respond-async",
		},
		ResponseHeaders: map[string]string{
			"Content-Type":              "application/json;odata.metadata=minimal",
			"Server":                    "Microsoft-IIS/10.0",
			"X-MSDAVEXT_Error":          "917656; Access denied",
			"X-Powered-By":             "ASP.NET",
			"Strict-Transport-Security": "max-age=31536000",
			"X-Content-Type-Options":    "nosniff",
		},
		URIs: []string{
			"/v1.0/me/drive/root/children",
			"/v1.0/me/drive/items",
			"/v1.0/me/drive/special/approot",
			"/v1.0/drives",
			"/v1.0/me/drive/root/delta",
			"/v1.0/me/drive/activities",
		},
		BodyTransform: "base64",
	}
}

func CloudflareProfile() *MalleableProfile {
	return &MalleableProfile{
		Name:      "Cloudflare",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		RequestHeaders: map[string]string{
			"Accept":                     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language":            "en-US,en;q=0.5",
			"Accept-Encoding":            "gzip, deflate, br",
			"DNT":                        "1",
			"Upgrade-Insecure-Requests":  "1",
			"Sec-Fetch-Dest":             "document",
			"Sec-Fetch-Mode":             "navigate",
			"Sec-Fetch-Site":             "none",
		},
		ResponseHeaders: map[string]string{
			"Content-Type":           "text/html; charset=UTF-8",
			"Server":                 "cloudflare",
			"CF-Cache-Status":        "DYNAMIC",
			"CF-RAY":                 "84a1b2c3d4e5f678-IAD",
			"Alt-Svc":                "h3=\":443\"; ma=86400",
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
		},
		URIs: []string{
			"/cdn-cgi/trace",
			"/cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1",
			"/cdn-cgi/rum",
			"/api/v4/zones",
			"/client/v4/accounts",
			"/cdn-cgi/bm/cv/result",
		},
		BodyTransform: "base64",
	}
}

func JQueryProfile() *MalleableProfile {
	return &MalleableProfile{
		Name:      "jQuery CDN",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		RequestHeaders: map[string]string{
			"Accept":          "*/*",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Referer":         "https://www.example.com/",
			"Origin":          "https://www.example.com",
			"Sec-Fetch-Dest":  "script",
			"Sec-Fetch-Mode":  "cors",
			"Sec-Fetch-Site":  "cross-site",
		},
		ResponseHeaders: map[string]string{
			"Content-Type":                "application/javascript; charset=utf-8",
			"Server":                      "NetDNA-cache/2.2",
			"Cache-Control":               "max-age=315360000",
			"Access-Control-Allow-Origin": "*",
			"X-Cache":                     "HIT",
			"X-Cache-Hits":                "742",
			"Timing-Allow-Origin":         "*",
		},
		URIs: []string{
			"/jquery-3.7.1.min.js",
			"/jquery-3.7.1.min.map",
			"/jquery-migrate-3.4.1.min.js",
			"/jquery-ui-1.13.2.min.js",
			"/jquery.validate.min.js",
			"/jquery.form.min.js",
		},
		BodyTransform: "xor",
	}
}
