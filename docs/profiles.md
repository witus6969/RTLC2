# RTLC2 C2 Profiles Documentation

Malleable C2 profiles allow operators to shape the network traffic between agents and listeners to mimic legitimate services. This makes C2 communications harder to detect by network security monitoring tools.

---

## 1. Overview

A malleable profile defines:

- **User-Agent**: The HTTP User-Agent header string
- **Request headers**: Custom HTTP headers sent by the agent
- **Response headers**: Custom HTTP headers returned by the listener
- **URIs**: URL paths used for C2 communication
- **Body transform**: How the C2 payload is encoded in the HTTP body

When a profile is applied to a listener, all agent-listener HTTP communication conforms to the profile's specification, making the traffic appear as legitimate web service communication.

---

## 2. Profile JSON Schema

```json
{
  "name": "Profile Name",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",
  "request_headers": {
    "Accept": "application/json",
    "Accept-Encoding": "gzip, deflate",
    "Content-Type": "application/json",
    "X-Custom-Header": "value"
  },
  "response_headers": {
    "Content-Type": "application/json",
    "Server": "nginx/1.24.0",
    "X-Powered-By": "Express",
    "Cache-Control": "no-cache"
  },
  "uris": ["/api/v1/data", "/api/v2/sync", "/health/check"],
  "body_transform": "base64"
}
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique profile name for identification |
| `user_agent` | string | Yes | HTTP User-Agent string. Should match a real browser, SDK, or service client. |
| `request_headers` | object | No | Key-value pairs of HTTP headers added to agent requests |
| `response_headers` | object | No | Key-value pairs of HTTP headers added to listener responses |
| `uris` | string[] | No | Array of URI paths for C2 callbacks. The listener randomly selects from these. |
| `body_transform` | string | No | Body encoding: `base64`, `prepend`, `append`, or `none` |

### Body Transform Options

| Transform | Description |
|-----------|-------------|
| `base64` | C2 payload is base64-encoded in the HTTP body. Looks like a typical API payload. |
| `prepend` | Legitimate-looking content is prepended before the C2 payload |
| `append` | Legitimate-looking content is appended after the C2 payload |
| `none` | Raw C2 payload in the HTTP body (encrypted, but no additional encoding) |

---

## 3. Built-In Profiles

RTLC2 ships with 23 built-in profiles organized into three categories.

### Normal (Legitimate Services) -- 8 Profiles

These profiles mimic real commercial web services:

| Profile | File | User-Agent | Description |
|---------|------|------------|-------------|
| Amazon AWS | `amazon.json` | `aws-sdk-java/2.20.0 Linux/5.15.0 OpenJDK_64-Bit_Server_VM/17.0.6+10` | Mimics AWS SDK API calls with AMZ headers, Signature V4 auth header |
| GitHub API | `github_api.json` | GitHub API client UA | Mimics GitHub REST API v3 requests |
| StackOverflow | `stackoverflow.json` | Standard browser UA | Mimics StackOverflow web browsing |
| Wikipedia | `wikipedia.json` | Standard browser UA | Mimics Wikipedia API requests |
| Dropbox | `dropbox.json` | Dropbox client UA | Mimics Dropbox sync API calls |
| Zoom | `zoom.json` | Zoom client UA | Mimics Zoom meeting client API |
| Windows Update | `windows_update.json` | Windows Update agent UA | Mimics WSUS/WU client requests |
| Office 365 | `office365.json` | Office client UA | Mimics Microsoft 365 API calls |

### APT (Advanced Persistent Threat) -- 8 Profiles

These profiles replicate known threat actor traffic patterns:

| Profile | File | Emulates | Description |
|---------|------|----------|-------------|
| APT29/CozyBear | `apt29_cozy.json` | SVR (Russia) | HTTPS with cloud service mimicry, OneDrive-like headers |
| APT28/FancyBear | `apt28_fancy.json` | GRU (Russia) | Short URIs, minimal headers, Google service fronting |
| APT32/OceanLotus | `apt32_ocean.json` | Vietnam | WordPress/Joomla plugin-style URIs |
| APT41/DoubleDragon | `apt41_double.json` | China | CDN-style traffic patterns, CloudFront headers |
| Turla/Snake | `turla_snake.json` | FSB (Russia) | Complex URI patterns, satellite link mimicry |
| Lazarus | `lazarus.json` | North Korea | Job portal/recruitment site mimicry |
| FIN7 | `fin7.json` | FIN7 (Cybercrime) | Retail/POS system API patterns |
| HAFNIUM | `hafnium.json` | China | Exchange Web Services (EWS) API patterns |

### Crimeware -- 7 Profiles

These profiles replicate commodity malware traffic patterns:

| Profile | File | Emulates | Description |
|---------|------|----------|-------------|
| Cobalt Strike Default | `cobalt_strike.json` | Cobalt Strike | Default CS beacon profile (useful for blending with existing CS traffic) |
| TrickBot | `trickbot.json` | TrickBot | Banking trojan C2 patterns |
| Emotet | `emotet.json` | Emotet | Spam botnet C2 patterns |
| QakBot | `qakbot.json` | QakBot/QBot | Banking trojan C2 with specific URI patterns |
| IcedID | `icedid.json` | IcedID/BokBot | Stealer/loader C2 patterns |
| BumbleBee | `bumblebee.json` | BumbleBee | Loader malware C2 patterns |
| Sliver Default | `sliver_default.json` | Sliver C2 | Default Sliver implant traffic pattern |

---

## 4. Using Profiles

### Applying a Profile to a Listener (Web UI)

1. Open the **Listener Manager** panel
2. Click **Create Listener** or edit an existing one
3. In the listener configuration dialog, select a profile from the **Malleable Profile** dropdown
4. The listener will shape all HTTP responses according to the profile
5. Agents connecting to this listener will use the profile's request headers and User-Agent

### Applying a Profile via API

Profiles can be applied to listeners by including profile data in the listener creation request. The listener's HTTP handler will use the profile's response headers for all responses.

### Viewing Profiles

**Web UI**: Open the **Profiles** panel from the sidebar. Browse by category tab.

**API**:
```bash
# List all profiles
curl -H "Authorization: <token>" http://localhost:54321/api/v1/profiles

# Get a specific profile
curl -H "Authorization: <token>" http://localhost:54321/api/v1/profiles/Amazon%20AWS
```

---

## 5. Creating Custom Profiles

### Via Web UI

1. Open the **Profiles** panel
2. Switch to the **Custom** tab
3. Use the JSON editor to define your profile
4. Click **Save**

### Via API

```bash
curl -X POST http://localhost:54321/api/v1/profiles \
  -H "Authorization: <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Custom CDN",
    "user_agent": "CDN-Gateway/2.1",
    "request_headers": {
      "Accept": "application/octet-stream",
      "X-Request-ID": "auto",
      "X-Forwarded-For": "10.0.0.1"
    },
    "response_headers": {
      "Content-Type": "application/octet-stream",
      "Server": "CloudFront",
      "X-Cache": "Hit from cloudfront",
      "X-Amz-Cf-Pop": "IAD89-C1"
    },
    "uris": ["/cdn/assets/v2", "/static/js/bundle.min.js", "/api/edge/sync"],
    "body_transform": "base64"
  }'
```

### Via File

Create a JSON file in the `profiles/` directory:

```bash
cat > profiles/my_custom.json << 'EOF'
{
  "name": "My Custom Profile",
  "user_agent": "CustomApp/1.0",
  "request_headers": { "Accept": "text/html" },
  "response_headers": { "Server": "Apache/2.4.52" },
  "uris": ["/index.php", "/wp-content/uploads/", "/xmlrpc.php"],
  "body_transform": "base64"
}
EOF
```

The server loads custom profiles from the `profiles/` directory on startup.

### Deleting a Profile

**Web UI**: Open the profile and click **Delete** (only custom profiles can be deleted).

**API**:
```bash
curl -X DELETE -H "Authorization: <token>" \
  http://localhost:54321/api/v1/profiles/My%20Custom%20Profile
```

---

## 6. Profile Design Guidelines

### Matching Real Traffic

For effective evasion, profiles should closely match real service traffic:

1. **User-Agent**: Use exact User-Agent strings from the service you are mimicking. Capture real UA strings with browser developer tools or Wireshark.

2. **Headers**: Include all standard headers the real service uses. Missing headers or extra headers can be detected by traffic analysis.

3. **URIs**: Use realistic URI paths. Avoid random strings. Match the URL structure of the mimicked service.

4. **Body Transform**: Use `base64` when the mimicked service uses JSON APIs (base64 content in JSON fields is common). Use `none` when mimicking binary data transfers.

5. **Response Headers**: Match the real server's response headers exactly, including `Server`, `X-Powered-By`, and any service-specific headers.

### OPSEC Considerations

- Test profiles against your target network's security stack before deployment
- Monitor for any IDS/IPS signatures that match your chosen profile
- Rotate profiles periodically during long engagements
- Consider using domain fronting with CDN profiles for additional concealment
- APT profiles may attract attention from threat intelligence teams specifically looking for those patterns
