# BurpGate

**AI gateway for Burp Suite — expose Burp's full toolchain to MCP clients.**

BurpGate is a Burp Suite extension that runs a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server inside Burp, giving AI coding agents (Claude, etc.) direct access to Burp's suite of security testing capabilities — proxy history, scanner, repeater, collaborator, decoder, site map, and more.

---

## Overview

BurpGate bridges the gap between AI-assisted workflows and manual web security testing. Instead of copying requests between tools, your AI agent can:

- Browse proxy history and replay requests
- Send test payloads through Intruder
- Start crawl and audit scans
- Check Collaborator for out-of-band interactions
- Inspect and edit messages in real time
- And much more — all through natural language.

BurpGate speaks **SSE MCP** natively and ships with a **Stdio proxy** for clients that only support stdio transport.

---

## Features

### Core
- **AI-native**: exposes 40+ Burp tools as MCP tools
- **Dual transport**: SSE (direct) + Stdio proxy (for Claude Desktop etc.)
- **One-click install**: auto-configures Claude Desktop from the extension UI
- **Configurable permissions**: approval dialogs for sensitive operations (history access, request sending, config editing)

### Exposed Tool Categories

| Category | Tools |
|----------|-------|
| **HTTP** | send HTTP/1.1 & HTTP/2 requests, create Repeater tabs, send to Intruder |
| **Proxy** | browse history (with regex filter), paginated results |
| **Scanner** | start crawl/audit scans, track status, delete scans, import BChecks, generate reports |
| **Collaborator** | generate payloads, poll for DNS/HTTP/SMTP interactions |
| **Repeater** | create tabs, resend with string replacements |
| **Organizer** | list items, send requests |
| **WebSocket** | create connections, browse history |
| **Site Map** | browse entries, add requests/responses |
| **Scope** | check, include, exclude URLs |
| **Utility** | URL/base64 encode/decode, HTML encode/decode, JSON tools, compression, hashing, random strings, curl export, body conversion |
| **Config** | read/write project & user options, toggle intercept & task engine |
| **Data** | save/retrieve named requests, batch HTTP, rank responses, analyze variations & keywords |

### Security
- Request approval gating with auto-approve for trusted targets
- Data access approval (HTTP history, WebSocket history, Organizer items)
- Shell execution disabled by default
- Config editing opt-in

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  AI Client (Claude, etc.)            │
│                  MCP Protocol (Stdio/SSE)            │
└──────────┬──────────────────────────┬───────────────┘
           │                          │
     Stdio Proxy                SSE Direct
           │                          │
┌──────────▼──────────────────────────▼───────────────┐
│                  BurpGate Extension                  │
│               (runs inside Burp Suite)               │
│                                                      │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────┐  │
│  │ Ktor SSE   │  │ MCP Protocol │  │ 40+ Tool    │  │
│  │ Server     │  │ Handler      │  │ Impls       │  │
│  └────────────┘  └──────────────┘  └─────────────┘  │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │         Burp Suite Montoya API                  │  │
│  └────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

BurpGate runs as a Java extension inside Burp Suite, using the Montoya API to access all Burp subsystems. The MCP server is powered by [Ktor Server](https://ktor.io/) and the [Kotlin MCP SDK](https://github.com/modelcontextprotocol/kotlin-sdk). A lightweight Stdio proxy (separate JAR) bridges the gap for clients that require stdio transport.

---

## Installation

### Prerequisites

- **Java 21+** — verify with `java --version`
- **Burp Suite Professional or Community** — Professional unlocks scanner & collaborator tools
- **`jar` command** — verify with `jar --version`

### Build the Extension

```bash
git clone https://github.com/PortSwigger/mcp-server.git
cd mcp-server
./gradlew embedProxyJar
```

The combined JAR is written to `build/libs/burp-mcp-all.jar`.

### Load into Burp Suite

1. Open Burp Suite → **Extensions** tab
2. Click **Add**
3. Set **Extension Type** → `Java`
4. Select `build/libs/burp-mcp-all.jar`
5. Click **Next**

The MCP tab will appear in Burp's UI once loaded.

---

## Quick Start

1. **Enable the server** — In Burp's MCP tab, check **Enabled**
2. **Configure your client** — Click the **Install for Claude Desktop** button, or manually wire up the proxy (see below)
3. **Restart Claude** — AI now has access to your Burp session

Example Claude prompt:

> "Check my proxy history for the last 5 requests, resend each one to Repeater, and look for interesting variations in the responses."

---

## Configuration

All configuration is in Burp's **MCP tab**.

| Setting | Description | Default |
|---------|-------------|---------|
| Enabled | Toggle the MCP server on/off | off |
| Host | Bind address | `127.0.0.1` |
| Port | SSE server port | `9876` |
| Config editing | Expose tools that modify Burp config | off |
| Shell execution | Allow `execute_command` tool | off |
| Require HTTP request approval | Gate HTTP requests with dialog | on |
| Require data access approval | Gate history/WS/organizer access with dialog | on |
| Auto-approve targets | Newline-separated list of allowed hosts | empty |
| Filter credentials | Strip credentials from config export | on |

---

## MCP Integration

### SSE (direct)

BurpGate runs an SSE MCP server at:

```
http://127.0.0.1:9876/sse
```

Configure your MCP client with this URL for direct SSE transport.

### Stdio Proxy (Claude Desktop)

Claude Desktop requires stdio transport. BurpGate bundles a proxy JAR that bridges stdio → SSE.

**Automatic**: Click "Install for Claude Desktop" in the MCP tab — this extracts the proxy JAR and configures Claude.

**Manual**:
1. Extract the proxy JAR from the extension (use the MCP tab's installer, or find it in the extension's directory)
2. Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "burp": {
      "command": "/path/to/burp/java",
      "args": [
        "-jar", "/path/to/mcp-proxy-all.jar",
        "--sse-url", "http://127.0.0.1:9876"
      ]
    }
  }
}
```

---

## Building from Source

```bash
./gradlew build
```

This compiles all Kotlin sources and runs the test suite.

To produce the deployable JAR (with embedded proxy):

```bash
./gradlew embedProxyJar
```

Output: `build/libs/burp-mcp-all.jar`

---

## Running Tests

```bash
./gradlew test
```

To run a specific test class:

```bash
./gradlew test --tests "net.portswigger.mcp.tools.ToolsKtTest"
```

Test reports are written to `build/reports/tests/test/`.

---

## Tool Reference

BurpGate registers the following MCP tools. Tools marked (Pro) require Burp Suite Professional.

### HTTP
- `send_http1_request` — raw HTTP/1.1 request
- `send_http2_request` — HTTP/2 with pseudo-headers
- `send_http_requests_batch` — parallel multiple requests
- `resend_with_replacements` — regex replacement + resend

### Repeater
- `create_repeater_tab` — HTTP/1.1 Repeater tab
- `create_repeater_tab_http2` — HTTP/2 Repeater tab
- `send_to_intruder` — send to Intruder

### Proxy
- `get_proxy_http_history` / `get_proxy_http_history_regex` — paginated history
- `get_proxy_websocket_history` / `get_proxy_websocket_history_regex` — WS history
- `send_to_comparer` / `send_to_decoder`

### Scanner (Pro)
- `start_crawl_scan` / `start_audit_scan`
- `get_scan_status` / `delete_scan`
- `get_audit_scan_issues` / `get_scanner_issues`
- `import_bcheck` / `generate_scanner_report`

### Collaborator (Pro)
- `generate_collaborator_payload` — OOB payload with optional custom data
- `get_collaborator_interactions` — poll for DNS/HTTP/SMTP

### Utility
- `url_encode` / `url_decode`
- `base64_encode` / `base64_decode`
- `generate_random_string`
- `html_encode` / `html_decode`
- `json_validate` / `json_read` / `json_add` / `json_update` / `json_remove`
- `generate_digest` / `compress` / `decompress`
- `export_curl` — request → curl command
- `convert_body` — JSON ↔ URL-encoded ↔ XML conversion

### Site Map
- `get_site_map_entries` — paginated with optional prefix filter
- `add_to_site_map` — add request + optional response

### Scope
- `is_in_scope` / `include_in_scope` / `exclude_from_scope`

### Organizer
- `get_organizer_items` / `get_organizer_items_regex` — paginated
- `send_to_organizer`

### WebSocket
- `create_websocket` — with optional initial message

### Config
- `output_project_options` / `output_user_options`
- `set_project_options` / `set_user_options`
- `set_task_execution_engine_state`
- `set_proxy_intercept_state`

### Data
- `save_request` / `get_saved_request` / `list_saved_requests` / `delete_saved_request`
- `get_request_by_id` — lookup by proxy history ID
- `get_cookies` / `set_cookie`
- `rank_responses` — anomaly detection ranking
- `analyze_response_variations` / `analyze_response_keywords`

### Misc
- `get_project_info` / `get_command_line_args`
- `get_active_editor_contents` / `set_active_editor_contents`
- `import_bambda`
- `execute_command` — gated behind config

---

## Creating Custom Tools

Tools are defined in `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`.

```kotlin
@Serializable
data class MyToolParams(val input: String) : HttpServiceParams

mcpTool<MyToolParams>("Description for the LLM.") {
    // tool logic — return a String
    "processed: $input"
}
```

- The tool name is auto-derived from the data class name (camelCase → snake_case)
- Extend `HttpServiceParams` for tools that need target host/port/HTTPS
- Extend `Paginated` for tools that return lists (auto-pagination)

---

## Development

### Linting & Formatting

The project does not currently enforce a Kotlin formatter. Follow the existing code style in `src/main/kotlin/` when making changes.

### CI

The project uses GitHub Actions. See `.github/workflows/` for the full pipeline:
- Build and test on every push/PR
- Publish releases on tag

### Release Process

1. Update version in `gradle.properties`
2. Tag the commit: `git tag vX.Y.Z`
3. Push tag: `git push origin vX.Y.Z`
4. CI builds the JAR and creates a GitHub Release

---

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Commit your changes (`git commit -am 'feat: add widget'`)
4. Push the branch (`git push origin feat/my-feature`)
5. Open a Pull Request

Guidelines:
- Follow existing code style in `src/main/kotlin/`
- Add tests for new tools (`ToolsKtTest`)
- Keep tool descriptions LLM-friendly
- Use `checkHttpRequestPermission` for HTTP tools
- Use `checkDataAccessOrDeny` for data-access tools

---

## Security

### Reporting Vulnerabilities

Found a security issue? **Do not open a public issue.** Email the maintainers directly or report through the project's security advisory process.

### Permission Model

BurpGate uses a layered permission model:

1. **Config gating** — sensitive features (shell execution, config editing) are disabled by default
2. **Approval dialogs** — HTTP requests and data access (history, organizer, websockets) show approval prompts
3. **Auto-approve targets** — trusted hosts bypass approval dialogs
4. **Config filtering** — credentials are stripped from exported configs by default

---

## FAQ

**Q: Do I need Burp Suite Professional?**  
A: No — Community edition works for most tools. Scanner and Collaborator tools require Professional.

**Q: Can I use this with Cursor, VS Code, or other AI tools?**  
A: Yes — any MCP-compatible client can connect to the SSE endpoint.

**Q: Why are some history entries truncated?**  
A: Tool outputs are capped at 5000 characters per entry to keep AI context manageable. Use pagination for larger datasets.

**Q: Does BurpGate send my data to third parties?**  
A: No — all communication stays local between Burp and your AI client. The server binds to `127.0.0.1` by default.

**Q: How do I disable a tool I don't want exposed?**  
A: BurpGate doesn't support per-tool toggles yet. Disable the server entirely or configure client-side tool filtering.

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| "Cannot invoke ... ObjectFactoryLocator" | Montoya API not fully initialized | Restart Burp and reload the extension |
| Client can't connect | Port conflict | Change port in MCP tab |
| Scanner tools missing | Community edition | Upgrade to Professional |
| Config editing returns "disabled" | Config editing opt-in | Enable in MCP tab |
| Shell execution fails | Feature disabled | Enable in MCP tab |

---

## License

This project is licensed under the same terms as the original Burp Suite MCP Server extension. See the source headers for details.
