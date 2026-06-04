# BurpGate

**AI gateway for Burp Suite — expose Burp's full toolchain to MCP clients.**

BurpGate is a Burp Suite extension that runs a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server inside Burp, giving AI coding agents (Claude, Cursor, etc.) direct access to Burp's security testing capabilities — proxy history, scanner, repeater, collaborator, decoder, site map, and more.

## Overview

BurpGate bridges AI-assisted workflows with web security testing. Instead of copying requests between tools, your AI agent can browse proxy history, send test payloads, start scans, check Collaborator, inspect messages in real time — all through natural language.

BurpGate speaks **SSE MCP** natively and ships with a **Stdio proxy** for clients that only support stdio transport.

## Tool Reference (72 total)

### HTTP
| Tool | Params | Description |
|------|--------|-------------|
| `send_http1_request` | content, targetHostname, targetPort, usesHttps, normalizeLineEndings | Raw HTTP/1.1 request |
| `send_http2_request` | pseudoHeaders, headers, requestBody, targetHostname, targetPort, usesHttps | HTTP/2 with pseudo-headers |
| `send_http_requests_batch` | requests (list), normalizeLineEndings | Parallel batch HTTP/1.1 |
| `resend_with_replacements` | content, replacements (list of regex+replacement), targetHostname, targetPort, usesHttps, normalizeLineEndings | Regex replacements then resend |

### Repeater
| Tool | Params | Description |
|------|--------|-------------|
| `create_repeater_tab` | tabName, content, targetHostname, targetPort, usesHttps, normalizeLineEndings | HTTP/1.1 Repeater tab |
| `create_repeater_tab_http2` | tabName, pseudoHeaders, headers, requestBody, targetHostname, targetPort, usesHttps | HTTP/2 Repeater tab |
| `send_to_intruder` | tabName, content, targetHostname, targetPort, usesHttps, normalizeLineEndings | Send to Intruder |

### Proxy History (paginated)
| Tool | Params | Description |
|------|--------|-------------|
| `get_proxy_http_history` | count, offset | Paginated HTTP history |
| `get_proxy_http_history_regex` | regex, count, offset | Regex-filtered HTTP history |
| `get_proxy_websocket_history` | count, offset | Paginated WS history |
| `get_proxy_websocket_history_regex` | regex, count, offset | Regex-filtered WS history |

### Scanner (Pro only)
| Tool | Params | Description |
|------|--------|-------------|
| `start_crawl_scan` | seedUrls | Start crawl scan |
| `start_audit_scan` | seedUrls, auditConfigType (active/passive) | Start audit scan |
| `get_scan_status` | scanId | Check scan progress |
| `get_scanner_issues` | count, offset | List all scanner issues |
| `get_audit_scan_issues` | scanId | Issues from audit scan |
| `delete_scan` | scanId | Delete scan |
| `import_bcheck` | script | Import BCheck script |
| `generate_scanner_report` | reportFormat (html/xml), outputPath | Generate report |

### Collaborator (Pro only)
| Tool | Params | Description |
|------|--------|-------------|
| `generate_collaborator_payload` | customData | OOB payload with optional custom data |
| `get_collaborator_interactions` | payloadId | Poll DNS/HTTP/SMTP interactions |

### Organizer
| Tool | Params | Description |
|------|--------|-------------|
| `get_organizer_items` | count, offset | Paginated organizer items |
| `get_organizer_items_regex` | regex, count, offset | Regex-filtered items |
| `send_to_organizer` | request, targetHostname, targetPort, usesHttps | Send request to organizer |

### Site Map
| Tool | Params | Description |
|------|--------|-------------|
| `get_site_map_entries` | count, offset, urlPrefix | Paginated entries with prefix filter |
| `add_to_site_map` | request, responseBody, targetHostname, targetPort, usesHttps | Add request+response |

### Scope
| Tool | Params | Description |
|------|--------|-------------|
| `is_in_scope` | url | Check if URL is in scope |
| `include_in_scope` | url | Add URL to scope |
| `exclude_from_scope` | url | Remove URL from scope |

### Utility
| Tool | Params | Description |
|------|--------|-------------|
| `url_encode` / `url_decode` | content | URL encoding/decoding |
| `base64_encode` / `base64_decode` | content | Base64 encoding/decoding |
| `html_encode` / `html_decode` | data | HTML encoding/decoding |
| `generate_random_string` | length, characterSet | Random string generator |
| `generate_digest` | data, algorithm (SHA_256/SHA_512/MD5) | Cryptographic hash |
| `compress` / `decompress` | data, compressionType (GZIP/DEFLATE/BROTLI) | Compression |
| `export_curl` | content, insecure | HTTP request → curl command |
| `convert_body` | body, fromFormat, toFormat | JSON ↔ URL-encoded ↔ XML |

### JSON
| Tool | Params | Description |
|------|--------|-------------|
| `json_validate` | json | Validate JSON string |
| `json_read` | json, path | Read value at dot-notation path |
| `json_add` | json, path, value | Add value at path |
| `json_update` | json, path, value | Update value at path |
| `json_remove` | json, path | Remove value at path |

### Config
| Tool | Params | Description |
|------|--------|-------------|
| `output_project_options` | (none) | Export project config as JSON |
| `output_user_options` | (none) | Export user config as JSON |
| `set_project_options` | json | Import project config (gated) |
| `set_user_options` | json | Import user config (gated) |
| `set_task_execution_engine_state` | running | Pause/resume task engine |
| `set_proxy_intercept_state` | intercepting | Toggle proxy intercept |

### Data Management
| Tool | Params | Description |
|------|--------|-------------|
| `save_request` | name, content, targetHostname, targetPort, usesHttps | Save request to named store |
| `get_saved_request` | name | Retrieve named request |
| `list_saved_requests` | (none) | List all saved request names |
| `delete_saved_request` | name | Delete named request |
| `get_request_by_id` | id | Lookup proxy history by ID |
| `get_cookies` | (none) | List cookie jar contents |
| `set_cookie` | domain, name, value, path, expiration | Set cookie in jar |

### Analysis
| Tool | Params | Description |
|------|--------|-------------|
| `rank_responses` | items (list) | Rank responses by interestingness |
| `analyze_response_variations` | responses (list) | Identify variant vs invariant attributes |
| `analyze_response_keywords` | keywords, responses (list) | Keyword presence analysis |

### Misc
| Tool | Params | Description |
|------|--------|-------------|
| `execute_command` | command, useShell | Shell command (gated, off by default) |
| `import_bambda` | script | Import Bambda filter |
| `create_websocket` | path, initialMessage, targetHostname, targetPort, usesHttps | WebSocket connection |
| `get_project_info` | (none) | Project name + ID |
| `get_command_line_args` | (none) | Burp startup arguments |
| `get_proxy_intercept_state` | (none) | Check if intercept enabled |
| `get_active_editor_contents` | (none) | Read active message editor |
| `set_active_editor_contents` | text | Write active message editor |
| `send_to_comparer` | items (list) | Send to Comparer |
| `send_to_decoder` | data | Send to Decoder |

## Configuration

All settings in Burp's MCP tab. Persisted across restarts via Burp extension storage.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| Enabled | bool | true | MCP server on/off |
| Host | string | 127.0.0.1 | Server bind address |
| Port | int | 9876 | SSE server port |
| Config editing | bool | false | Enable set_project_options / set_user_options |
| Shell execution | bool | false | Enable execute_command tool |
| Require HTTP approval | bool | true | Gate HTTP requests with dialog |
| Require data approval | bool | true | Gate history/WS/organizer access |
| Always allow HTTP history | bool | false | Skip history approval |
| Always allow WS history | bool | false | Skip WebSocket history approval |
| Always allow Organizer | bool | false | Skip organizer approval |
| Filter config credentials | bool | true | Strip passwords from config export |
| Auto-approve targets | string | "" | Newline-separated trusted hosts (supports wildcard `*.example.com`) |

## Security Model

### Layered Permissions
1. **Config gating** — shell execution & config editing disabled by default
2. **Approval dialogs** — HTTP requests & data access show modal prompts
3. **Auto-approve targets** — trusted hosts bypass dialogs (hostname, port, wildcard patterns)
4. **Config credential filtering** — passwords/certificate keys redacted from exports

### Target Validation (TargetValidation.kt)
- Max 255 characters
- No whitespace or commas
- Valid port range (1–65535)
- Valid IPv6 format
- Comma-injection rejected explicitly
- Wildcard only on subdomains (`*.example.com` valid, `*` or `*.com` invalid)

### HttpRequestSecurity
- Modal approval dialog: Allow Once / Always Allow Host / Always Allow Host:Port / Deny
- Auto-approve: exact host, host:port, wildcard domains, case-insensitive matching
- `checkHttpRequestPermission` used by all HTTP-related tools

### DataAccessSecurity
- Three resource types: HTTP_HISTORY, WEBSOCKET_HISTORY, ORGANIZER
- Allow Once / Always Allow [type] / Deny
- Persistent "always allow" per type via config booleans

### Server Security (KtorServerManager.kt)
- **Anti-DNS-rebinding**: Origin, Host, Referer validated — only localhost/127.0.0.1 allowed
- **Anti-browser-access**: User-Agent checked — browser UAs (Mozilla, Chrome, Safari, etc.) blocked
- **Security headers**: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Content-Security-Policy: default-src 'none'`
- **CORS**: restricted to localhost, methods GET/POST, headers Content-Type/Accept/Last-Event-ID

### Credential Filtering (SecurityUtils.kt)
- Keys: `password`, `certificate_password`, `hashed_key` (case-insensitive)
- Redacted with `*****`
- Recursive JSON traversal
- Fail-closed on malformed JSON

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  AI Client (Claude, etc.)            │
│                  MCP Protocol (Stdio/SSE)            │
└──────────┬──────────────────────────┬───────────────┘
           │                          │
      Stdio Proxy                SSE Direct
      (mcp-proxy-all.jar)       (localhost:9876)
           │                          │
┌──────────▼──────────────────────────▼───────────────┐
│                  BurpGate Extension                  │
│               (runs inside Burp Suite)               │
│                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │ Ktor SSE     │  │ MCP Protocol │  │ 72 Tools  │  │
│  │ Server       │  │ Handler      │  │           │  │
│  └──────────────┘  └──────────────┘  └───────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │ Security     │  │ Config/UI    │  │ Proxy Jar │  │
│  │ Filters      │  │ Panels       │  │ Manager   │  │
│  └──────────────┘  └──────────────┘  └───────────┘  │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │         Burp Suite Montoya API                  │  │
│  └────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### Tech Stack
- **Language**: Kotlin 2.2.21 (JVM 21)
- **Server**: Ktor 3.3.1 (Netty engine)
- **MCP SDK**: io.modelcontextprotocol:kotlin-sdk 0.7.4
- **Burp API**: Montoya API 2026.4 (compile-only)
- **Build**: Gradle 9.5.1 with Kotlin DSL
- **Test**: JUnit 5 + MockK 1.14.11

### Source Layout
```
src/main/kotlin/net/portswigger/mcp/
├── ExtensionBase.kt          # Entry point, BurpExtension init
├── KtorServerManager.kt      # Ktor server, CORS, security, MCP setup
├── ServerManager.kt          # ServerState sealed class, interface
├── SwingDispatcher.kt        # Swing EDT coroutine dispatcher
├── config/
│   ├── McpConfig.kt          # All config properties + persistence
│   ├── ConfigUi.kt           # Main UI panel builder
│   ├── ConfigValidation.kt   # Host/port validation
│   ├── TargetValidation.kt   # Auto-approve target format rules
│   ├── Dialogs.kt            # Approval/confirm/input dialogs
│   ├── Design.kt             # ToggleSwitch, buttons, design tokens
│   ├── Anchor.kt             # Clickable hyperlinks
│   └── components/           # UI panels (Server, Advanced, AutoApprove, etc.)
├── tools/
│   ├── McpTool.kt            # mcpTool DSL, Paginated interface
│   └── Tools.kt              # All 72 tool implementations
├── schema/
│   ├── JsonSchema.kt         # Auto JSON schema from Kotlin types
│   └── serialization.kt      # Serializable DTOs (Issue, HttpService, etc.)
├── security/
│   ├── HttpRequestSecurity.kt # HTTP approval + auto-approve
│   ├── DataAccessSecurity.kt  # Data access approval
│   └── SecurityUtils.kt       # Credential redaction
└── providers/
    ├── Provider.kt            # CI/Config provider interfaces
    ├── ProxyJarManager.kt     # Proxy JAR extraction + SHA-256 integrity
    └── ClaudeDesktopProvider.kt # Claude Desktop auto-configuration
```

## Installation

### Prerequisites
- Java 21+ (`java --version`)
- Burp Suite Professional or Community
- `jar` command (`jar --version`)

### Build
```bash
git clone https://github.com/Nixon-H/BurpGate.git
cd BurpGate
./gradlew embedProxyJar
```

Output: `build/libs/burp-mcp-all.jar`

### Load into Burp
1. Extensions tab → Add
2. Extension Type: Java
3. Select `build/libs/burp-mcp-all.jar`
4. Click Next

### Quick Start
1. In Burp's MCP tab, check **Enabled**
2. Click **Install for Claude Desktop** (auto-configures the proxy)
3. Restart Claude — AI now has access to Burp

## HTTP Line Ending Normalization

BurpGate handles malformed line endings from MCP clients:
- Detects `\r\n\r\n`, `\n\n` (actual), `\\r\\n\\r\\n`, `\\n\\n` (literal escape sequences)
- Prelude: `\\r\\n` → `\n`, `\\n` → `\n`, stray `\r` removed, `\n` → `\r\n`
- Body after first blank line preserved exactly as-is
- Earliest separator wins (actual wins over escaped)

## Development

### Build & Test
```bash
./gradlew test                          # all tests
./gradlew test --tests "*ToolsKtTest"   # unit tests only
./gradlew embedProxyJar                 # deployable JAR
```

### Adding a Tool
1. Define a `@Serializable` data class in Tools.kt (extend `HttpServiceParams` or `Paginated` as needed)
2. Register with `mcpTool<MyParams>("description") { ... }` — tool name auto-derived (camelCase → snake_case)
3. Add tests in ToolsKtTest.kt

### CI/CD
- GitHub Actions on push/PR: test + build + CodeQL
- Dependency submission on main branch pushes
- Weekly upstream sync from PortSwigger/mcp-server (auto-PR with safe merge)

## Transport

### SSE (direct)
```
http://127.0.0.1:9876/sse
```

### Stdio Proxy (Claude Desktop)
```json
{
  "mcpServers": {
    "burp": {
      "command": "/path/to/java",
      "args": ["-jar", "/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
    }
  }
}
```

## FAQ

**Need Burp Professional?** No — Community works for most tools. Scanner & Collaborator require Pro.

**Data sent externally?** No — all communication stays local. Server binds to 127.0.0.1.

**Why truncation?** Tool outputs capped at 5000 chars to keep AI context manageable. Use pagination for larger datasets.

**Why 6 Dependabot alerts?** False positives from Kotlin plugin internal dependencies (Log4j, Jackson, Plexus) — declared as compileOnly stubs with fixed versions, not actually shipped.
