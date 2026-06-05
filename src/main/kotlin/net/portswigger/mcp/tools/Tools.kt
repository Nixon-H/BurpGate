package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.ByteArray
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.ScanTask
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.scanner.bchecks.BChecks
import burp.api.montoya.scanner.ReportFormat
import burp.api.montoya.sitemap.SiteMapFilter
import burp.api.montoya.utilities.DigestAlgorithm
import burp.api.montoya.utilities.CompressionType
import burp.api.montoya.utilities.HtmlEncoding
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation
import java.nio.file.Paths
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.KeyboardFocusManager
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

private val http2ForbiddenHeaders = setOf(
    "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade",
    "http2-settings"
)

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    return (fixedPseudoHeaders + headers.filterKeys { it.lowercase() !in http2ForbiddenHeaders })
        .map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: return normalizePrelude(content)
    return normalizePrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")   // Literal \r\n escape sequences → LF
    .replace("\\n", "\n")      // Remaining literal \n → LF
    .replace("\\r", "")        // Remaining literal \r → remove
    .replace("\r", "")          // Actual CR → remove
    .replace("\n", "\r\n")      // All LF → proper CRLF

private data class ScanEntry(
    val type: String,
    val label: String,
    val task: ScanTask
)

private val scanTasks = ConcurrentHashMap<String, ScanEntry>()
private val scanIdCounter = AtomicInteger(0)
private val savedRequests = ConcurrentHashMap<String, SavedRequest>()
val proxyInterceptRules = ConcurrentHashMap<String, ProxyInterceptRuleEntry>()
var proxyHandlerRegistration: Registration? = null

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = if (normalizeLineEndings) normalizeHttpContent(content) else content

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = if (normalizeLineEndings) normalizeHttpContent(content) else content
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = if (normalizeLineEndings) normalizeHttpContent(content) else content
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner.") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        mcpTool<StartCrawlScan>("Starts a new crawl scan with the specified seed URLs and returns a scan ID for tracking progress. Professional edition only.") {
            val crawlConfig = CrawlConfiguration.crawlConfiguration(*seedUrls.toTypedArray())
            val crawl = api.scanner().startCrawl(crawlConfig)
            val scanId = "scan-" + scanIdCounter.incrementAndGet()
            scanTasks[scanId] = ScanEntry("crawl", seedUrls.firstOrNull() ?: "unknown", crawl)
            api.logging().logToOutput("MCP started crawl scan: $scanId")
            "Scan started. ID: $scanId, Type: crawl, Seeds: ${seedUrls.joinToString(", ")}"
        }

        mcpTool<GetScanStatus>("Gets the current status of a scan by its scan ID (returned from start_crawl_scan or start_audit_scan).") {
            val entry = scanTasks[scanId] ?: return@mcpTool "Scan not found: $scanId"
            """Scan ID: $scanId
Type: ${entry.type}
Label: ${entry.label}
Status: ${entry.task.statusMessage()}
Requests: ${entry.task.requestCount()}
Errors: ${entry.task.errorCount()}"""
        }

        mcpTool<DeleteScan>("Deletes a scan by its scan ID, freeing associated resources.") {
            val entry = scanTasks.remove(scanId) ?: return@mcpTool "Scan not found: $scanId"
            entry.task.delete()
            api.logging().logToOutput("MCP deleted scan: $scanId")
            "Scan deleted: $scanId"
        }

        mcpTool<StartAuditScan>("Starts an audit scan (not crawl) with the specified seed URLs and audit configuration. Returns a scan ID for tracking. Professional edition only.") {
            val auditConfig = when (auditConfigType.lowercase()) {
                "active" -> AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)
                "passive" -> AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS)
                else -> AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)
            }
            val audit = api.scanner().startAudit(auditConfig)
            val scanId = "scan-" + scanIdCounter.incrementAndGet()
            scanTasks[scanId] = ScanEntry("audit", seedUrls.firstOrNull() ?: "unknown", audit)
            api.logging().logToOutput("MCP started audit scan: $scanId")
            "Audit scan started. ID: $scanId, Config: $auditConfigType, Seeds: ${seedUrls.joinToString(", ")}"
        }

        mcpTool<GetAuditScanIssues>("Retrieves all issues found by an audit scan, identified by its scan ID.") {
            val entry = scanTasks[scanId] ?: return@mcpTool "Scan not found: $scanId"
            if (entry.type != "audit") return@mcpTool "Scan $scanId is not an audit scan"
            val audit = entry.task as? Audit ?: return@mcpTool "Failed to read audit results"
            val issues = audit.issues()
            if (issues.isEmpty()) return@mcpTool "No issues found"
            issues.joinToString("\n\n") { Json.encodeToString(it.toSerializableForm()) }
        }

        mcpTool<ImportBcheck>("Imports a BCheck script into Burp Scanner. Returns import status and any errors. Professional edition only.") {
            val result = api.scanner().bChecks().importBCheck(script)
            if (result.status().name == "SUCCESS") {
                "BCheck imported successfully"
            } else {
                "BCheck import failed. Errors:\n${result.importErrors().joinToString("\n")}"
            }
        }

        mcpTool<GenerateScannerReport>("Generates a scanner report in the specified format. Returns the report content. Professional edition only.") {
            val format = when (reportFormat.lowercase()) {
                "html" -> ReportFormat.HTML
                "xml" -> ReportFormat.XML
                else -> ReportFormat.HTML
            }
            val path = Paths.get(outputPath)
            api.scanner().generateReport(api.siteMap().issues(), format, path)
            "Report generated at: $outputPath"
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetOrganizerItems>("Displays items within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        api.organizer().items().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetOrganizerItemsRegex>("Displays items matching a specified regex within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.organizer().items { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }

    mcpPaginatedTool<GetSiteMapEntries>("Retrieves entries from the Burp Site Map, with optional URL prefix filter. Use this to discover pages, endpoints, and parameters Burp has identified.") {
        val entries = if (urlPrefix != null) {
            api.siteMap().requestResponses(SiteMapFilter.prefixFilter(urlPrefix))
        } else {
            api.siteMap().requestResponses()
        }
        entries.asSequence().map {
            val reqStr = it.request()?.toString() ?: "<no request>"
            val respStr = it.response()?.toString() ?: "<no response>"
            truncateIfNeeded(Json.encodeToString(mapOf(
                "url" to it.request().url(),
                "request" to reqStr,
                "response" to respStr,
                "notes" to (it.annotations()?.notes() ?: "")
            )))
        }
    }

    mcpTool<AddToSiteMap>("Adds an HTTP request and optional response to the Burp Site Map.") {
        val fixedContent = normalizeHttpContent(request)
        val httpRequest = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val httpResponse = responseBody?.let { HttpResponse.httpResponse(it) }
        val entry = HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse)
        api.siteMap().add(entry)
        api.logging().logToOutput("MCP added entry to site map: $targetHostname:$targetPort")
        "Added to site map"
    }

    mcpTool<IsInScope>("Checks if a URL is within Burp's target scope.") {
        api.scope().isInScope(url).toString()
    }

    mcpTool<IncludeInScope>("Adds a URL to Burp's target scope.") {
        api.scope().includeInScope(url)
        api.logging().logToOutput("MCP added URL to scope: $url")
        "Added to scope"
    }

    mcpTool<ExcludeFromScope>("Removes a URL from Burp's target scope.") {
        api.scope().excludeFromScope(url)
        api.logging().logToOutput("MCP removed URL from scope: $url")
        "Removed from scope"
    }

    mcpTool<SendToComparer>("Sends one or more data items to Burp Comparer for visual comparison.") {
        val byteArrays = items.map { ByteArray.byteArray(it) }.toTypedArray()
        api.comparer().sendToComparer(*byteArrays)
        "Sent ${items.size} items to Comparer"
    }

    mcpTool<SendToDecoder>("Sends data to Burp Decoder for decoding/encoding.") {
        api.decoder().sendToDecoder(ByteArray.byteArray(data))
        "Sent to Decoder"
    }

    mcpTool("get_cookies", "Lists all cookies currently in Burp's Cookie Jar.") {
        val cookies = api.http().cookieJar().cookies()
        if (cookies.isEmpty()) {
            "No cookies in Cookie Jar"
        } else {
            cookies.joinToString("\n\n") { Json.encodeToString(it.toSerializableForm()) }
        }
    }

    mcpTool<SetCookie>("Sets a cookie in Burp's Cookie Jar.") {
        val expiry = expiration?.let { java.time.ZonedDateTime.parse(it) } ?: java.time.ZonedDateTime.now().plusYears(1)
        api.http().cookieJar().setCookie(domain, name, value, path, expiry)
        api.logging().logToOutput("MCP set cookie: $name=$value for $domain")
        "Cookie set"
    }

    mcpTool<GenerateDigest>("Generates a cryptographic digest (hash) of the input data using the specified algorithm.") {
        val algo = try { DigestAlgorithm.valueOf(algorithm.uppercase().replace("-", "_")) } catch (_: Exception) { DigestAlgorithm.SHA_256 }
        val result = api.utilities().cryptoUtils().generateDigest(ByteArray.byteArray(data), algo)
        result.toString()
    }

    mcpTool<Compress>("Compresses the input data using the specified compression type (GZIP, DEFLATE, BROTLI).") {
        val ctype = try { CompressionType.valueOf(compressionType.uppercase()) } catch (_: Exception) { CompressionType.GZIP }
        val result = api.utilities().compressionUtils().compress(ByteArray.byteArray(data), ctype)
        result.toString()
    }

    mcpTool<Decompress>("Decompresses the input data using the specified compression type (GZIP, DEFLATE, BROTLI).") {
        val ctype = try { CompressionType.valueOf(compressionType.uppercase()) } catch (_: Exception) { CompressionType.GZIP }
        val result = api.utilities().compressionUtils().decompress(ByteArray.byteArray(data), ctype)
        result.toString()
    }

    mcpTool<HtmlEncode>("HTML-encodes the input string, optionally with a specific encoding mode.") {
        api.utilities().htmlUtils().encode(data)
    }

    mcpTool<HtmlDecode>("HTML-decodes the input string.") {
        api.utilities().htmlUtils().decode(data)
    }

    mcpTool<JsonValidate>("Validates whether a string is valid JSON.") {
        api.utilities().jsonUtils().isValidJson(json).toString()
    }

    mcpTool<JsonRead>("Reads a value from a JSON document at the specified path (dot-notation, e.g. 'data.items[0].id').") {
        api.utilities().jsonUtils().read(json, path)
    }

    mcpTool<JsonAdd>("Adds a value to a JSON document at the specified path.") {
        api.utilities().jsonUtils().add(json, path, value)
    }

    mcpTool<JsonUpdate>("Updates a value in a JSON document at the specified path.") {
        api.utilities().jsonUtils().update(json, path, value)
    }

    mcpTool<JsonRemove>("Removes a value from a JSON document at the specified path.") {
        api.utilities().jsonUtils().remove(json, path)
    }

    mcpTool<SendHttpRequestsBatch>("Sends multiple HTTP/1.1 requests in parallel and returns their responses.") {
        val results = requests.map { req ->
            val request = HttpRequest.httpRequest(
                HttpService.httpService(req.targetHostname, req.targetPort, req.usesHttps),
                if (normalizeLineEndings) normalizeHttpContent(req.content) else req.content
            )
            val response = api.http().sendRequest(request)
            "Request to ${req.targetHostname}:${req.targetPort}\nResponse:\n${response?.toString() ?: "<no response>"}"
        }
        results.joinToString("\n\n---\n\n")
    }

    mcpTool<CreateWebsocket>("Creates a WebSocket connection to the specified target and optionally sends an initial message.") {
        val service = HttpService.httpService(targetHostname, targetPort, usesHttps)
        val wsCreation = api.websockets().createWebSocket(service, path)
        val status = wsCreation.status().name
        val ws = wsCreation.webSocket()
        if (ws.isPresent && initialMessage != null) {
            ws.get().sendTextMessage(initialMessage)
        }
        "WebSocket creation: $status${ws.map { " (connected)" }.orElse("")}"
    }

    mcpTool<SendToOrganizer>("Sends an HTTP request and its response to Burp Organizer for later review.") {
        val fixedContent = normalizeHttpContent(request)
        val httpRequest = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.organizer().sendToOrganizer(httpRequest)
        api.logging().logToOutput("MCP sent request to Organizer: $targetHostname:$targetPort")
        "Sent to Organizer"
    }

    mcpTool("get_project_info", "Returns the current Burp project name and ID.") {
        "Name: ${api.project().name()}\nID: ${api.project().id()}"
    }

    mcpTool("get_proxy_intercept_state", "Checks whether Burp Proxy intercept is currently enabled.") {
        "Intercept enabled: ${api.proxy().isInterceptEnabled()}"
    }

    mcpTool("get_command_line_args", "Returns the command-line arguments Burp was started with.") {
        val args = api.burpSuite().commandLineArguments()
        if (args.isEmpty()) "No command-line arguments" else args.joinToString("\n")
    }

    mcpTool<ExecuteCommand>("Executes a shell command. Only available when shell execution is enabled in Burp MCP config. Output is limited to prevent hangs — use for quick commands. UseShell=true for commands requiring pipes/redirects (dangerouslyExecute). false for safe arg-based execution.") {
        if (!config.allowShellExecution) return@mcpTool "Shell execution is disabled. Enable it in Burp MCP config"

        val output = if (useShell) {
            api.utilities().shellUtils().dangerouslyExecute(command)
        } else {
            @Suppress("SpreadOperator")
            api.utilities().shellUtils().execute(*command.split("\\s+".toRegex()).toTypedArray())
        }
        output.ifEmpty { "(no output)" }
    }

    mcpTool<RankResponses>("Ranks HTTP responses by interestingness using Burp's anomaly detection algorithm. Useful for finding outlier responses that may indicate bugs. Provide request/response pairs to analyze.") {
        val pairs = items.map { item ->
            val httpRequest = HttpRequest.httpRequest(
                HttpService.httpService(item.targetHostname, item.targetPort, item.usesHttps),
                normalizeHttpContent(item.request)
            )
            val httpResponse = item.response?.let { HttpResponse.httpResponse(it) }
            HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse)
        }
        val ranked = api.utilities().rankingUtils().rank(pairs)
        if (ranked.isEmpty()) return@mcpTool "No results to rank"
        ranked.joinToString("\n\n---\n\n") { r ->
            "Rank: ${r.rank()}\nURL: ${r.requestResponse().request()?.url()}\nRequest:\n${r.requestResponse().request()}\nResponse:\n${r.requestResponse().response()}"
        }
    }

    mcpTool<AnalyzeResponseVariations>("Analyzes a set of HTTP responses to identify which attributes vary vs stay constant. Useful for identifying dynamic tokens, CSRF tokens, and unique identifiers in responses.") {
        val analyzer = api.http().createResponseVariationsAnalyzer()
        responses.forEach { resp -> analyzer.updateWith(HttpResponse.httpResponse(resp)) }
        val variants = analyzer.variantAttributes()
        val invariants = analyzer.invariantAttributes()
        buildString {
            if (variants.isNotEmpty()) {
                appendLine("Variant attributes:")
                variants.forEach { appendLine("  - ${it.name}") }
            }
            if (invariants.isNotEmpty()) {
                appendLine("Invariant attributes:")
                invariants.forEach { appendLine("  - ${it.name}") }
            }
            if (variants.isEmpty() && invariants.isEmpty()) {
                append("No attributes detected")
            }
        }
    }

    mcpTool<AnalyzeResponseKeywords>("Analyzes a set of HTTP responses for specified keywords. Returns which keywords vary between responses, which are constant, and counts per keyword.") {
        val analyzer = api.http().createResponseKeywordsAnalyzer(keywords)
        responses.forEach { resp -> analyzer.updateWith(HttpResponse.httpResponse(resp)) }
        val variants = analyzer.variantKeywords()
        val invariants = analyzer.invariantKeywords()
        buildString {
            if (variants.isNotEmpty()) {
                appendLine("Variant keywords:")
                variants.forEach { appendLine("  - $it") }
            }
            if (invariants.isNotEmpty()) {
                appendLine("Invariant keywords:")
                invariants.forEach { appendLine("  - $it") }
            }
            if (variants.isEmpty() && invariants.isEmpty()) {
                append("No keywords analyzed")
            }
        }
    }

    mcpTool<ImportBambda>("Imports a Bambda filter script into Burp. Bambda scripts are Java-based filters that can be applied in Burp's UI for advanced traffic filtering.") {
        val result = api.bambda().importBambda(script)
        val status = result.status().name
        val errors = result.importErrors()
        if (errors.isEmpty()) {
            "Bambda imported: $status"
        } else {
            "Bambda imported: $status\nErrors:\n${errors.joinToString("\n")}"
        }
    }

    mcpTool<ExportCurl>("Converts an HTTP request to a curl command for PoC reporting. Takes a raw HTTP request string and generates an executable curl command with all headers and body.") {
        val normalized = normalizeHttpContent(content)
        val lines = normalized.lines()
        if (lines.isEmpty()) return@mcpTool "Error: empty request"

        val requestLine = lines.first().split(" ")
        if (requestLine.size < 2) return@mcpTool "Error: invalid request line"
        val method = requestLine[0]
        val path = requestLine[1]

        val headerLines = mutableListOf<String>()
        var body = ""
        var foundBlank = false
        for (line in lines.drop(1)) {
            if (!foundBlank && line.isBlank()) {
                foundBlank = true
                continue
            }
            if (!foundBlank) {
                headerLines.add(line)
            } else {
                body = if (body.isEmpty()) line else "$body\n$line"
            }
        }

        val host = headerLines.firstOrNull { it.startsWith("Host:", true) }
            ?.substringAfter("Host:", "")
            ?.trim()
            ?: "localhost"

        val scheme = if (content.contains("https", true) || path.startsWith("https")) "https" else "http"
        val hostPort = "$scheme://$host"
        val url = if (path.startsWith("/")) "$hostPort$path" else path

        val sb = StringBuilder("curl -X $method")
        if (insecure) sb.append(" -k")
        sb.append(" '$url'")

        headerLines.forEach { h ->
            if (!h.startsWith("Host:", true) && !h.startsWith("Content-Length:", true)) {
                val colonIdx = h.indexOf(':')
                if (colonIdx > 0) {
                    val hName = h.substring(0, colonIdx).trim()
                    val hVal = h.substring(colonIdx + 1).trim()
                    sb.append(" -H '$hName: $hVal'")
                }
            }
        }

        if (body.isNotEmpty()) {
            sb.append(" -d '${body.replace("'", "'\\''")}'")
        }

        sb.toString()
    }

    mcpTool<GetRequestById>("Looks up a proxy history entry by its ID and returns the full HTTP request and response. The ID corresponds to the entry index in Burp's proxy history.") {
        val entry = api.proxy().history().firstOrNull { it.id() == id }
            ?: return@mcpTool "Error: no proxy history entry found with ID $id"

        buildString {
            appendLine("Request:")
            appendLine(entry.request()?.toString() ?: "<no request>")
            val resp = entry.response()
            if (resp != null) {
                appendLine("\nResponse:")
                appendLine(resp.toString())
            } else {
                appendLine("\nResponse: <no response>")
            }
        }
    }

    mcpTool<ConvertBody>("Converts HTTP request body between formats: JSON, URL-encoded, and XML. Detects input format automatically if not specified. Handles nested JSON objects for URL-encoded conversion.") {
        val inputBody = body
        val effectiveFrom = fromFormat.ifBlank { detectBodyFormat(inputBody) }
        val effectiveTo = toFormat.ifBlank {
            when (effectiveFrom) {
                "json" -> "urlencoded"
                "urlencoded" -> "json"
                else -> "urlencoded"
            }
        }

        when {
            effectiveFrom == "json" && effectiveTo == "urlencoded" -> jsonToUrlencoded(inputBody)
            effectiveFrom == "urlencoded" && effectiveTo == "json" -> urlencodedToJson(inputBody)
            effectiveFrom == effectiveTo -> inputBody
            else -> "Error: unsupported conversion from '$effectiveFrom' to '$effectiveTo'"
        }
    }

    mcpTool<SaveRequest>("Saves an HTTP request in the extension's in-memory store with a name for later retrieval via get_saved_request. Overwrites any existing entry with the same name.") {
        savedRequests[name] = SavedRequest(content, targetHostname, targetPort, usesHttps)
        "Saved request '$name'"
    }

    mcpTool<GetSavedRequest>("Retrieves a previously saved HTTP request by name from the extension's in-memory store. Returns the full request content and target details.") {
        val saved = savedRequests[name] ?: return@mcpTool "Error: no saved request found with name '$name'"
        buildString {
            appendLine("Request:")
            appendLine(saved.content)
            appendLine("\nTarget: ${saved.targetHostname}:${saved.targetPort} (${if (saved.usesHttps) "HTTPS" else "HTTP"})")
        }
    }

    mcpTool<ListSavedRequests>("Lists all saved request names in the extension's in-memory store.") {
        val names = savedRequests.keys.toList()
        if (names.isEmpty()) return@mcpTool "No saved requests"
        names.joinToString("\n")
    }

    mcpTool<DeleteSavedRequest>("Deletes a previously saved HTTP request from the extension's in-memory store by name.") {
        if (savedRequests.remove(name) != null) "Deleted saved request '$name'"
        else "Error: no saved request found with name '$name'"
    }

    mcpTool<RegisterProxyInterceptRule>("Registers a proxy intercept rule that drops or spoofs responses for matching requests. Url pattern supports wildcard (*). Action: 'continue', 'drop', or 'spoof'. For spoof, provide responseBody.") {
        if (proxyInterceptRules.containsKey(name)) return@mcpTool "Error: rule '$name' already exists"

        val ruleAction = when (action.lowercase()) {
            "continue" -> burp.api.montoya.http.handler.RequestAction.CONTINUE
            "drop" -> burp.api.montoya.http.handler.RequestAction.DROP
            "spoof" -> burp.api.montoya.http.handler.RequestAction.SPOOF_RESPONSE
            else -> return@mcpTool "Error: invalid action '$action'. Use 'continue', 'drop', or 'spoof'"
        }

        proxyInterceptRules[name] = ProxyInterceptRuleEntry(name, urlPattern, ruleAction, responseBody)

        if (proxyHandlerRegistration == null) {
            proxyHandlerRegistration = api.http().registerHttpHandler(object : HttpHandler {
                override fun handleHttpRequestToBeSent(request: HttpRequestToBeSent): RequestToBeSentAction {
                    val url = request.httpService().toString()
                    for (rule in proxyInterceptRules.values) {
                        if (url.contains(rule.urlPattern.trim('*'))) {
                            return when (rule.action) {
                                burp.api.montoya.http.handler.RequestAction.DROP -> RequestToBeSentAction.drop()
                                burp.api.montoya.http.handler.RequestAction.SPOOF_RESPONSE -> {
                                    val resp = if (rule.responseBody != null) {
                                        HttpResponse.httpResponse(rule.responseBody)
                                    } else {
                                        HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\nSpoofed response")
                                    }
                                    RequestToBeSentAction.spoof(resp)
                                }
                                else -> RequestToBeSentAction.continueWith(request)
                            }
                        }
                    }
                    return RequestToBeSentAction.continueWith(request)
                }

                override fun handleHttpResponseReceived(response: HttpResponseReceived): ResponseReceivedAction {
                    return ResponseReceivedAction.continueWith(response)
                }
            })
        }

        "Registered proxy intercept rule '$name' (action: ${ruleAction.name}, pattern: $urlPattern)"
    }

    mcpTool<ListProxyInterceptRules>("Lists all registered proxy intercept rules with their action and URL pattern.") {
        val names = proxyInterceptRules.keys.toList()
        if (names.isEmpty()) return@mcpTool "No proxy intercept rules registered"
        names.joinToString("\n") { name ->
            val rule = proxyInterceptRules[name]!!
            "${rule.name}: ${rule.action.name} (pattern: ${rule.urlPattern})"
        }
    }

    mcpTool<ClearProxyInterceptRules>("Removes all registered proxy intercept rules.") {
        val count = proxyInterceptRules.size
        proxyInterceptRules.clear()
        proxyHandlerRegistration?.deregister()
        proxyHandlerRegistration = null
        "Cleared $count proxy intercept rule(s)"
    }

    mcpTool<ResendWithReplacements>("Resends an HTTP/1.1 request after applying regex string replacements. Useful for LLM-driven Repeater-style tweaking without reconstructing the full request. Applies replacements in order.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        var modified = if (normalizeLineEndings) normalizeHttpContent(content) else content
        replacements.forEach { (pattern, replacement) ->
            modified = modified.replace(Regex(pattern), replacement)
        }

        api.logging().logToOutput("MCP resend with replacements: $targetHostname:$targetPort")
        val request = HttpRequest.httpRequest(toMontoyaService(), modified)
        val response = api.http().sendRequest(request)
        buildString {
            appendLine("Modified request:")
            appendLine(modified)
            appendLine("\nResponse:")
            appendLine(response?.toString() ?: "<no response>")
        }
    }
}

private fun detectBodyFormat(body: String): String {
    val trimmed = body.trim()
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) return "json"
    if (trimmed.contains("=") && trimmed.contains("&")) return "urlencoded"
    if (trimmed.startsWith("<")) return "xml"
    return "urlencoded"
}

private fun jsonToUrlencoded(json: String): String {
    val element = Json.parseToJsonElement(json.trim())
    if (element !is kotlinx.serialization.json.JsonObject) return "Error: expected a JSON object"
    return element.entries.joinToString("&") { (key, value) ->
        val v = when (value) {
            is kotlinx.serialization.json.JsonPrimitive -> value.content
            else -> value.toString()
        }
        "${key.urlEncoded()}=${v.urlEncoded()}"
    }
}

private fun urlencodedToJson(urlencoded: String): String {
    val pairs = urlencoded.split("&").mapNotNull { pair ->
        val eqIdx = pair.indexOf('=')
        if (eqIdx < 0) {
            val k = pair.urlDecoded()
            "$k" to ""
        } else {
            val k = pair.substring(0, eqIdx).urlDecoded()
            val v = pair.substring(eqIdx + 1).urlDecoded()
            k to v
        }
    }
    val entries = pairs.joinToString(",\n    ") { (k, v) ->
        "\"$k\": \"${v.replace("\"", "\\\"")}\""
    }
    return "{\n    $entries\n}"
}

private fun String.urlEncoded(): String = java.net.URLEncoder.encode(this, "UTF-8")
private fun String.urlDecoded(): String = java.net.URLDecoder.decode(this, "UTF-8")

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
    val normalizeLineEndings: Boolean = true
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
    val normalizeLineEndings: Boolean = true
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
    val normalizeLineEndings: Boolean = true
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItems(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItemsRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)

@Serializable
data class StartCrawlScan(
    val seedUrls: List<String>
)

@Serializable
data class GetScanStatus(
    val scanId: String
)

@Serializable
data class DeleteScan(
    val scanId: String
)

@Serializable
data class GetSiteMapEntries(
    override val count: Int,
    override val offset: Int,
    val urlPrefix: String? = null
) : Paginated

@Serializable
data class AddToSiteMap(
    val request: String,
    val responseBody: String? = null,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class IsInScope(
    val url: String
)

@Serializable
data class IncludeInScope(
    val url: String
)

@Serializable
data class ExcludeFromScope(
    val url: String
)

@Serializable
data class SendToComparer(
    val items: List<String>
)

@Serializable
data class SendToDecoder(
    val data: String
)

@Serializable
data class SetCookie(
    val domain: String,
    val name: String,
    val value: String,
    val path: String = "/",
    val expiration: String? = null
)

@Serializable
data class StartAuditScan(
    val seedUrls: List<String>,
    val auditConfigType: String = "active"
)

@Serializable
data class GetAuditScanIssues(
    val scanId: String
)

@Serializable
data class ImportBcheck(
    val script: String
)

@Serializable
data class GenerateScannerReport(
    val reportFormat: String = "html",
    val outputPath: String
)

@Serializable
data class GenerateDigest(
    val data: String,
    val algorithm: String = "SHA_256"
)

@Serializable
data class Compress(
    val data: String,
    val compressionType: String = "GZIP"
)

@Serializable
data class Decompress(
    val data: String,
    val compressionType: String = "GZIP"
)

@Serializable
data class HtmlEncode(
    val data: String
)

@Serializable
data class HtmlDecode(
    val data: String
)

@Serializable
data class JsonValidate(
    val json: String
)

@Serializable
data class JsonRead(
    val json: String,
    val path: String
)

@Serializable
data class JsonAdd(
    val json: String,
    val path: String,
    val value: String
)

@Serializable
data class JsonUpdate(
    val json: String,
    val path: String,
    val value: String
)

@Serializable
data class JsonRemove(
    val json: String,
    val path: String
)

@Serializable
data class BatchHttpRequestItem(
    val content: String,
    val targetHostname: String,
    val targetPort: Int,
    val usesHttps: Boolean
)

@Serializable
data class SendHttpRequestsBatch(
    val requests: List<BatchHttpRequestItem>,
    val normalizeLineEndings: Boolean = true
)

@Serializable
data class CreateWebsocket(
    val path: String,
    val initialMessage: String? = null,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToOrganizer(
    val request: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class ExecuteCommand(
    val command: String,
    val useShell: Boolean = true
)

@Serializable
data class RankResponseItem(
    val request: String,
    val response: String? = null,
    val targetHostname: String,
    val targetPort: Int,
    val usesHttps: Boolean
)

@Serializable
data class RankResponses(
    val items: List<RankResponseItem>
)

@Serializable
data class AnalyzeResponseVariations(
    val responses: List<String>
)

@Serializable
data class AnalyzeResponseKeywords(
    val keywords: List<String>,
    val responses: List<String>
)

@Serializable
data class ImportBambda(
    val script: String
)

@Serializable
data class ExportCurl(
    val content: String,
    val insecure: Boolean = false
)

@Serializable
data class GetRequestById(
    val id: Int
)

@Serializable
data class ConvertBody(
    val body: String,
    val fromFormat: String = "",
    val toFormat: String = ""
)

private data class SavedRequest(
    val content: String,
    val targetHostname: String,
    val targetPort: Int,
    val usesHttps: Boolean
)

@Serializable
data class SaveRequest(
    val name: String,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class GetSavedRequest(
    val name: String
)

@Serializable
object ListSavedRequests

@Serializable
data class DeleteSavedRequest(
    val name: String
)

data class ProxyInterceptRuleEntry(
    val name: String,
    val urlPattern: String,
    val action: burp.api.montoya.http.handler.RequestAction,
    val responseBody: String? = null
)

@Serializable
data class RegisterProxyInterceptRule(
    val name: String,
    val urlPattern: String,
    val action: String,
    val responseBody: String? = null
)

@Serializable
object ListProxyInterceptRules

@Serializable
object ClearProxyInterceptRules

@Serializable
data class RegexReplacement(
    val pattern: String,
    val replacement: String
)

@Serializable
data class ResendWithReplacements(
    val content: String,
    val replacements: List<RegexReplacement>,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
    val normalizeLineEndings: Boolean = true
) : HttpServiceParams
