package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine
import burp.api.montoya.collaborator.*
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpProtocol
import burp.api.montoya.http.message.Cookie
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.ScanTask
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.scanner.bchecks.BChecks
import burp.api.montoya.scanner.bchecks.BCheckImportResult
import burp.api.montoya.scanner.ReportFormat
import burp.api.montoya.utilities.CryptoUtils
import burp.api.montoya.utilities.CompressionUtils
import burp.api.montoya.utilities.HtmlUtils
import burp.api.montoya.utilities.json.JsonUtils
import burp.api.montoya.utilities.DigestAlgorithm
import burp.api.montoya.utilities.CompressionType
import burp.api.montoya.websocket.WebSockets
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus
import burp.api.montoya.websocket.extension.ExtensionWebSocket
import burp.api.montoya.project.Project
import burp.api.montoya.utilities.rank.RankingUtils
import burp.api.montoya.utilities.rank.RankedHttpRequestResponse
import burp.api.montoya.utilities.rank.RankingAlgorithm
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer
import burp.api.montoya.bambda.Bambda
import burp.api.montoya.bambda.BambdaImportResult
import burp.api.montoya.sitemap.SiteMapFilter
import burp.api.montoya.utilities.Base64Utils
import burp.api.montoya.utilities.RandomUtils
import burp.api.montoya.utilities.URLUtils
import burp.api.montoya.utilities.Utilities
import io.mockk.*
import java.net.InetAddress
import java.time.ZonedDateTime
import java.util.Optional
import io.modelcontextprotocol.kotlin.sdk.CallToolResultBase
import io.modelcontextprotocol.kotlin.sdk.TextContent
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import net.portswigger.mcp.KtorServerManager
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.TestSseMcpClient
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.CookieDetails
import net.portswigger.mcp.schema.HttpRequestResponse
import net.portswigger.mcp.schema.toSerializableForm
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import javax.swing.JTextArea

class ToolsKtTest {
    
    private val client = TestSseMcpClient()
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val serverManager = KtorServerManager(api)
    private val testPort = findAvailablePort()
    private var serverStarted = false
    private val config: McpConfig
    private val mockHeaders = mutableListOf<HttpHeader>()
    private val capturedRequest = slot<HttpRequest>()

    init {
        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean("enabled") } returns true
            every { getBoolean("configEditingTooling") } returns true
            every { getBoolean("allowShellExecution") } returns false
            every { getBoolean("requireHttpRequestApproval") } returns false
            every { getBoolean("requireDataAccessApproval") } returns false
            every { getBoolean("_alwaysAllowHttpHistory") } returns false
            every { getBoolean("_alwaysAllowWebSocketHistory") } returns false
            every { getBoolean("_alwaysAllowOrganizer") } returns false
            every { getString("host") } returns "127.0.0.1"
            every { getString("_autoApproveTargets") } returns ""
            every { getInteger("port") } returns testPort
            every { setBoolean(any(), any()) } returns Unit
            every { setString(any(), any()) } returns Unit
            every { setInteger(any(), any()) } returns Unit
        }
        val mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
            every { logToOutput(any<String>()) } returns Unit
        }

        config = McpConfig(persistedObject, mockLogging)
        
        mockkStatic(HttpHeader::class)
        mockkStatic(burp.api.montoya.http.HttpService::class)
        mockkStatic(HttpRequest::class)
    }

    private fun CallToolResultBase?.expectTextContent(
        expected: String? = null,
    ): String {
        assertNotNull(this, "Tool result cannot be null")
        val result = this!!

        val content = result.content
        assertNotNull(content, "Tool result content cannot be null")

        val nonNullContent = content
        assertEquals(1, nonNullContent.size, "Expected exactly one content element")

        val textContent = nonNullContent.firstOrNull() as? TextContent
        assertNotNull(textContent, "Expected content to be TextContent")

        val text = textContent!!.text
        assertNotNull(text, "Text content cannot be null")

        if (expected != null) {
            assertEquals(expected, text, "Text content doesn't match expected value")
        }

        return text!!
    }

    private fun setupHttpHeaderMocks() {
        every { HttpHeader.httpHeader(any<String>(), any<String>()) } answers {
            val name = firstArg<String>()
            val value = secondArg<String>()
            mockk<HttpHeader>().also {
                every { it.name() } returns name
                every { it.value() } returns value
                mockHeaders.add(it)
            }
        }
    }

    @BeforeEach
    fun setup() {
        setupHttpHeaderMocks()
        mockkStatic(burp.api.montoya.http.HttpService::class)
        every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } returns mockk()
        mockkStatic(HttpRequest::class)

        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}")
            assertNotNull(client.ping(), "Ping should return a result")
        }
    }

    private fun findAvailablePort() = ServerSocket(0).use { it.localPort }

    @AfterEach
    fun tearDown() {
        runBlocking { if (client.isConnected()) client.close() }
        serverManager.stop {}
    }

    @Nested
    inner class SavedRequestToolsTests {
        @Test
        fun `list saved requests should return message when empty`() {
            runBlocking {
                val result = client.callTool("list_saved_requests", emptyMap())
                delay(100)
                result.expectTextContent("No saved requests")
            }
        }

        @Test
        fun `save and get saved request should work`() {
            runBlocking {
                val saveResult = client.callTool("save_request", mapOf(
                    "name" to "test-req",
                    "content" to "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "targetHostname" to "example.com",
                    "targetPort" to 80,
                    "usesHttps" to false
                ))
                delay(100)
                saveResult.expectTextContent("Saved request 'test-req'")

                val getResult = client.callTool("get_saved_request", mapOf("name" to "test-req"))
                delay(100)
                val text = getResult.expectTextContent()
                assertTrue(text.contains("GET /test"))
                assertTrue(text.contains("example.com:80"))
            }
        }

        @Test
        fun `get saved request should return error for unknown name`() {
            runBlocking {
                val result = client.callTool("get_saved_request", mapOf("name" to "nonexistent"))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("Error"))
            }
        }

        @Test
        fun `list saved requests should work`() {
            runBlocking {
                client.callTool("save_request", mapOf(
                    "name" to "list-test-1",
                    "content" to "GET /a HTTP/1.1\r\nHost: x.com\r\n\r\n",
                    "targetHostname" to "x.com",
                    "targetPort" to 443,
                    "usesHttps" to true
                ))
                delay(50)
                val result = client.callTool("list_saved_requests", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("list-test-1"))
            }
        }

        @Test
        fun `delete saved request should work`() {
            runBlocking {
                client.callTool("save_request", mapOf(
                    "name" to "delete-test",
                    "content" to "GET /del HTTP/1.1\r\nHost: x.com\r\n\r\n",
                    "targetHostname" to "x.com",
                    "targetPort" to 443,
                    "usesHttps" to true
                ))
                delay(50)
                val deleteResult = client.callTool("delete_saved_request", mapOf("name" to "delete-test"))
                delay(100)
                deleteResult.expectTextContent("Deleted saved request 'delete-test'")
            }
        }

        @Test
        fun `delete saved request should return error for unknown name`() {
            runBlocking {
                val result = client.callTool("delete_saved_request", mapOf("name" to "nonexistent"))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("Error"))
            }
        }
    }

    @Nested
    inner class ResendWithReplacementsTests {
        @Test
        fun `resend with replacements should modify and send request`() {
            val httpService = mockk<burp.api.montoya.http.Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequestMock = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
            every { api.http() } returns httpService
            every { httpService.sendRequest(any()) } returns httpResponse
            every { httpResponse.toString() } returns "HTTP/1.1 200 OK\r\n\r\npatched"

            val contentSlot = slot<String>()

            mockkStatic(HttpRequest::class)
            mockkStatic(burp.api.montoya.http.HttpService::class)
            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                mockk<burp.api.montoya.http.message.requests.HttpRequest>().also {
                    every { it.toString() } returns secondArg<String>()
                }
            }
            every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } returns mockk()

            runBlocking {
                val result = client.callTool("resend_with_replacements", mapOf(
                    "content" to "GET /old-path HTTP/1.1\r\nHost: target.com\r\n\r\n",
                    "replacements" to listOf(mapOf("pattern" to "old-path", "replacement" to "new-path")),
                    "targetHostname" to "target.com",
                    "targetPort" to 80,
                    "usesHttps" to false
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("new-path"))
            }

            unmockkStatic(HttpRequest::class)
            unmockkStatic(burp.api.montoya.http.HttpService::class)
        }

        @Test
        fun `resend with multiple replacements should apply all`() {
            val httpService = mockk<burp.api.montoya.http.Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequestMock = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
            every { api.http() } returns httpService
            every { httpService.sendRequest(any()) } returns httpResponse
            every { httpResponse.toString() } returns "HTTP/1.1 200 OK\r\n\r\nfinal"

            val contentSlot = slot<String>()

            mockkStatic(HttpRequest::class)
            mockkStatic(burp.api.montoya.http.HttpService::class)
            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                mockk<burp.api.montoya.http.message.requests.HttpRequest>().also {
                    every { it.toString() } returns secondArg<String>()
                }
            }
            every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } returns mockk()

            runBlocking {
                val result = client.callTool("resend_with_replacements", mapOf(
                    "content" to "GET /old-path HTTP/1.1\r\nHost: target.com\r\n\r\nuuid",
                    "replacements" to listOf(
                        mapOf("pattern" to "old-path", "replacement" to "new-path"),
                        mapOf("pattern" to "uuid", "replacement" to "replaced-uuid")
                    ),
                    "targetHostname" to "target.com",
                    "targetPort" to 80,
                    "usesHttps" to false
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("new-path"))
                assertTrue(text.contains("replaced-uuid"))
            }

            unmockkStatic(HttpRequest::class)
            unmockkStatic(burp.api.montoya.http.HttpService::class)
        }

        @Test
        fun `resend with empty replacements should still work`() {
            val httpService = mockk<burp.api.montoya.http.Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequestMock = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
            every { api.http() } returns httpService
            every { httpService.sendRequest(any()) } returns httpResponse
            every { httpResponse.toString() } returns "HTTP/1.1 200 OK\r\n\r\noriginal"

            val contentSlot = slot<String>()

            mockkStatic(HttpRequest::class)
            mockkStatic(burp.api.montoya.http.HttpService::class)
            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                mockk<burp.api.montoya.http.message.requests.HttpRequest>().also {
                    every { it.toString() } returns secondArg<String>()
                }
            }
            every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } returns mockk()

            runBlocking {
                val result = client.callTool("resend_with_replacements", mapOf(
                    "content" to "GET /path HTTP/1.1\r\nHost: target.com\r\n\r\n",
                    "replacements" to emptyList<Map<String, String>>(),
                    "targetHostname" to "target.com",
                    "targetPort" to 80,
                    "usesHttps" to false
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("GET /path"))
            }

            unmockkStatic(HttpRequest::class)
            unmockkStatic(burp.api.montoya.http.HttpService::class)
        }
    }

    @Nested
    inner class HttpToolsTests {
        @Test
        fun `http1 line endings should be normalized`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpResponse.toString() } returns "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            every { httpService.sendRequest(capture(capturedRequest)) } returns httpResponse

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\nHost: example.com\n\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { httpService.sendRequest(any<HttpRequest>()) }
            assertEquals("GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n", capturedRequest.captured.toString(), "Request body should match")
        }

        @Test
        fun `http1 request should handle no response`() {
            val httpService = mockk<Http>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpService.sendRequest(any()) } returns null

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }

        @Test
        fun `http2 request should be formatted properly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val requestSlot = slot<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            every { httpResponse.toString() } returns "HTTP/2 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            every { api.http() } returns httpService
            every { httpService.sendRequest(capture(requestSlot), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "authority" to "example.com", "scheme" to "https", "method" to "GET", ":path" to "/test"
            )
            val headers = mapOf(
                "User-Agent" to "Test Agent", "Accept" to "*/*"
            )
            val requestBody = "Test body"

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { HttpRequest.http2Request(any(), any(), any<String>()) }
            
            assertEquals("Test body", bodySlot.captured, "Request body should match")
            
            val pseudoHeaderList = headersSlot.captured.filter { it.name().startsWith(":") }
            val normalHeaderList = headersSlot.captured.filter { !it.name().startsWith(":") }
            
            assertTrue(pseudoHeaderList.any { it.name() == ":scheme" && it.value() == "https" })
            assertTrue(pseudoHeaderList.any { it.name() == ":method" && it.value() == "GET" })
            assertTrue(pseudoHeaderList.any { it.name() == ":path" && it.value() == "/test" })
            assertTrue(pseudoHeaderList.any { it.name() == ":authority" && it.value() == "example.com" })
            
            assertTrue(normalHeaderList.any { it.name() == "user-agent" && it.value() == "Test Agent" })
            assertTrue(normalHeaderList.any { it.name() == "accept" && it.value() == "*/*" })
        }
        
        @Test
        fun `http2 request should handle null response`() {
            val httpService = mockk<Http>()
            val httpRequest = mockk<HttpRequest>()

            every { HttpRequest.http2Request(any(), any(), any<String>()) } returns httpRequest
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns null

            val pseudoHeaders = mapOf("method" to "GET", "path" to "/test")
            val headers = mapOf("User-Agent" to "Test Agent")

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }
        
        @Test
        fun `http2 pseudo headers should be ordered correctly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), any<String>()) } returns httpRequest
            every { httpResponse.toString() } returns "HTTP/2 200 OK"
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "path" to "/test",
                ":authority" to "example.com", 
                "method" to "GET",
                "scheme" to "https"
            )

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(emptyMap<String, String>()),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )
                
                delay(100)
                assertNotNull(result)
            }
            
            val pseudoHeaderNames = headersSlot.captured
                .filter { it.name().startsWith(":") }
                .map { it.name() }
            
            val expectedOrder = listOf(":scheme", ":method", ":path", ":authority")
            for (i in 0 until minOf(expectedOrder.size, pseudoHeaderNames.size)) {
                assertEquals(expectedOrder[i], pseudoHeaderNames[i],
                    "Pseudo headers should follow the order: scheme, method, path, authority")
            }
        }

        @Test
        fun `create repeater tab http2 should build http2 request`() {
            val repeater = mockk<burp.api.montoya.repeater.Repeater>(relaxed = true)
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            every { api.repeater() } returns repeater

            val pseudoHeaders = mapOf(
                "method" to "POST", "path" to "/api/x", "authority" to "example.com", "scheme" to "https"
            )
            val headers = mapOf("Content-Type" to "application/json")
            val requestBody = "{\"k\":\"v\"}"

            runBlocking {
                val result = client.callTool(
                    "create_repeater_tab_http2", mapOf(
                        "tabName" to "h2-tab",
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                assertNotNull(result)
            }

            verify(exactly = 1) { repeater.sendToRepeater(httpRequest, "h2-tab") }
            assertEquals("{\"k\":\"v\"}", bodySlot.captured, "Request body should be passed through unchanged")

            val pseudoHeaderNames = headersSlot.captured.filter { it.name().startsWith(":") }.map { it.name() }
            assertEquals(listOf(":scheme", ":method", ":path", ":authority"), pseudoHeaderNames)
            assertTrue(headersSlot.captured.any { it.name() == "content-type" && it.value() == "application/json" })
        }
    }

    @Nested
    inner class UtilityToolsTests {
        @Test
        fun `url encode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.encode(any<String>()) } returns "test+string+with+spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_encode", mapOf(
                        "content" to "test string with spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test+string+with+spaces")
            }
            
            verify(exactly = 1) { urlUtils.encode(any<String>()) }
        }
        
        @Test
        fun `url decode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.decode(any<String>()) } returns "test string with spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_decode", mapOf(
                        "content" to "test+string+with+spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test string with spaces")
            }
            
            verify(exactly = 1) { urlUtils.decode(any<String>()) }
        }
        
        @Test
        fun `base64 encode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.encodeToString(any<String>()) } returns "dGVzdCBzdHJpbmc="
            
            runBlocking {
                val result = client.callTool(
                    "base64_encode", mapOf(
                        "content" to "test string"
                    )
                )
                
                delay(100)
                result.expectTextContent("dGVzdCBzdHJpbmc=")
            }
            
            verify(exactly = 1) { base64Utils.encodeToString(any<String>()) }
        }
        
        @Test
        fun `base64 decode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            val burpByteArray = mockk<ByteArray>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.decode(any<String>()) } returns burpByteArray
            every { burpByteArray.toString() } returns "test string"
            
            runBlocking {
                val result = client.callTool(
                    "base64_decode", mapOf(
                        "content" to "dGVzdCBzdHJpbmc="
                    )
                )
                
                delay(100)
                result.expectTextContent("test string")
            }
            
            verify(exactly = 1) { base64Utils.decode(any<String>()) }
        }
        
        @Test
        fun `generate random string should work properly`() {
            val randomUtils = mockk<RandomUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.randomUtils() } returns randomUtils
            every { randomUtils.randomString(any<Int>(), any<String>()) } returns "1a2b3c1a2b"
            
            runBlocking {
                val result = client.callTool(
                    "generate_random_string", mapOf(
                        "length" to 10,
                        "characterSet" to "abc123"
                    )
                )
                
                delay(100)
                result.expectTextContent("1a2b3c1a2b")
            }
            
            verify(exactly = 1) { randomUtils.randomString(any<Int>(), any<String>()) }
        }
    }
    
    @Nested
    inner class DigestToolsTests {
        @Test
        fun `generate digest should return hex string`() {
            val cryptoUtils = mockk<CryptoUtils>()
            val utilities = mockk<Utilities>()
            val digestBytes = mockk<ByteArray> {
                every { getBytes() } returns byteArrayOf(0xab.toByte(), 0xcd.toByte(), 0xef.toByte())
            }

            every { api.utilities() } returns utilities
            every { utilities.cryptoUtils() } returns cryptoUtils
            every { cryptoUtils.generateDigest(any(), any()) } returns digestBytes

            mockkStatic(ByteArray::class)
            every { ByteArray.byteArray(any<String>()) } returns mockk(relaxed = true)

            runBlocking {
                val result = client.callTool("generate_digest", mapOf(
                    "data" to "hello",
                    "algorithm" to "SHA-256"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.matches(Regex("^[0-9a-fA-F]+$")), "Digest should be hex-encoded, got: $text")
                assertEquals("abcdef", text.lowercase())
            }

            verify(exactly = 1) { cryptoUtils.generateDigest(any(), any()) }
            unmockkStatic(ByteArray::class)
        }
    }

    @Nested
    inner class ConfigurationToolsTests {
        @Test
        fun `set task execution engine state should work properly`() {
            val taskExecutionEngine = mockk<TaskExecutionEngine>()
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            every { taskExecutionEngine.state = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now running")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.RUNNING }
            
            clearMocks(taskExecutionEngine, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now paused")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.PAUSED }
        }
        
        @Test
        fun `set proxy intercept state should work properly`() {
            val proxy = mockk<Proxy>()
            
            every { api.proxy() } returns proxy
            every { proxy.enableIntercept() } just runs
            every { proxy.disableIntercept() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been enabled")
            }
            
            verify(exactly = 1) { proxy.enableIntercept() }
            
            clearMocks(proxy, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been disabled")
            }
            
            verify(exactly = 1) { proxy.disableIntercept() }
        }
        
        @Test
        fun `config editing tools should respect config settings`() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { api.logging().logToOutput(any()) } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("Project configuration has been applied")
            }
            
            verify(exactly = 1) { burpSuite.importProjectOptionsFromJson(any()) }
            
            clearMocks(burpSuite, answers = false)
            
            every { config.configEditingTooling } returns false
            
            runBlocking {
                
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'")
            }
            
            verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
        }
    }

    @Nested
    inner class EditorTests {
        @Test
        fun `get active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `get active editor contents should return text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.text } returns "Editor content"
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("Editor content")
            }
        }
        
        @Test
        fun `set active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `set active editor contents should handle non-editable editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns false
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<Current editor is not editable>")
            }
        }
        
        @Test
        fun `set active editor contents should update text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns true
            every { textArea.text = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("Editor text has been set")
            }
            
            verify(exactly = 1) { textArea.text = "New content" }
        }
    }
    
    @Nested
    inner class PaginatedToolsTests {
        @Test
        fun `get proxy history should paginate properly`() {
            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                mockk<ProxyHttpRequestResponse>(),
                mockk<ProxyHttpRequestResponse>(),
                mockk<ProxyHttpRequestResponse>()
            )
            
            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory
            
            mockkStatic("net.portswigger.mcp.schema.SerializationKt")
            
            every { proxyHistory[0].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item1 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 1 notes"
            )
            every { proxyHistory[1].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item2 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 2 notes"
            )
            every { proxyHistory[2].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item3 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 3 notes"
            )
            
            runBlocking {
                val result1 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 0
                    )
                )
                
                delay(100)
                val text1 = result1.expectTextContent()
                assertTrue(text1.contains("GET /item1"))
                assertTrue(text1.contains("GET /item2"))
                assertFalse(text1.contains("GET /item3"))
                
                val result2 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 2
                    )
                )
                
                delay(100)
                val text2 = result2.expectTextContent()
                assertTrue(text2.contains("GET /item3"))
                
                val result3 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 3
                    )
                )
                
                delay(100)
                assertEquals("Reached end of items", result3.expectTextContent())
            }
        }
    }
    
    @Nested
    inner class CollaboratorToolsTests {
        private val collaborator = mockk<Collaborator>()
        private val collaboratorClient = mockk<CollaboratorClient>()
        private val collaboratorServer = mockk<CollaboratorServer>()

        @BeforeEach
        fun setupCollaborator() {
            mockkStatic(InteractionFilter::class)

            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val version = mockk<burp.api.montoya.core.Version>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.version() } returns version
            every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
            every { burpSuite.taskExecutionEngine() } returns mockk(relaxed = true)
            every { burpSuite.exportProjectOptionsAsJson() } returns "{}"
            every { burpSuite.exportUserOptionsAsJson() } returns "{}"
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { burpSuite.importUserOptionsFromJson(any()) } just runs

            every { api.collaborator() } returns collaborator
            every { collaborator.createClient() } returns collaboratorClient
            every { collaboratorClient.server() } returns collaboratorServer
            every { collaboratorServer.address() } returns "burpcollaborator.net"

            serverManager.stop {}
            serverStarted = false
            serverManager.start(config) { state ->
                if (state is ServerState.Running) serverStarted = true
            }

            runBlocking {
                var attempts = 0
                while (!serverStarted && attempts < 30) {
                    delay(100)
                    attempts++
                }
                if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")
                client.connectToServer("http://127.0.0.1:${testPort}")
            }
        }

        @AfterEach
        fun cleanupCollaborator() {
            unmockkStatic(InteractionFilter::class)
        }

        private fun mockInteraction(
            id: String,
            type: InteractionType,
            clientIp: String = "10.0.0.1",
            clientPort: Int = 54321,
            customData: String? = null,
            dnsDetails: DnsDetails? = null,
            httpDetails: HttpDetails? = null,
            smtpDetails: SmtpDetails? = null
        ): Interaction {
            val interactionId = mockk<InteractionId>()
            every { interactionId.toString() } returns id

            return mockk<Interaction>().also {
                every { it.id() } returns interactionId
                every { it.type() } returns type
                every { it.timeStamp() } returns ZonedDateTime.parse("2025-01-01T12:00:00Z")
                every { it.clientIp() } returns InetAddress.getByName(clientIp)
                every { it.clientPort() } returns clientPort
                every { it.customData() } returns Optional.ofNullable(customData)
                every { it.dnsDetails() } returns Optional.ofNullable(dnsDetails)
                every { it.httpDetails() } returns Optional.ofNullable(httpDetails)
                every { it.smtpDetails() } returns Optional.ofNullable(smtpDetails)
            }
        }

        @Test
        fun `generate payload should return payload and server info`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "abc123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "abc123"
            every { collaboratorClient.generatePayload() } returns payload

            runBlocking {
                val result = client.callTool("generate_collaborator_payload", emptyMap())
                delay(100)
                result.expectTextContent(
                    "Payload: abc123.burpcollaborator.net\n" +
                    "Payload ID: abc123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload() }
        }

        @Test
        fun `generate payload with custom data should pass custom data`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "custom123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "custom123"
            every { collaboratorClient.generatePayload(any<String>()) } returns payload

            runBlocking {
                val result = client.callTool(
                    "generate_collaborator_payload", mapOf(
                        "customData" to "mydata"
                    )
                )
                delay(100)
                result.expectTextContent(
                    "Payload: custom123.burpcollaborator.net\n" +
                    "Payload ID: custom123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload("mydata") }
        }

        @Test
        fun `get interactions should return dns interaction details`() {
            val dnsDetails = mockk<DnsDetails>().also {
                every { it.queryType() } returns DnsQueryType.A
                every { it.query() } returns null
            }
            val interaction = mockInteraction("int-001", InteractionType.DNS, dnsDetails = dnsDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"id\":\"int-001\""))
                assertTrue(text.contains("\"type\":\"DNS\""))
                assertTrue(text.contains("\"queryType\":\"A\""))
                assertTrue(text.contains("\"query\":null"))
                assertTrue(text.contains("\"clientIp\":\"10.0.0.1\""))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return http interaction details`() {
            val mockRequest = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
            every { mockRequest.toString() } returns "GET / HTTP/1.1"
            val mockResponse = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            every { mockResponse.toString() } returns "HTTP/1.1 200 OK"
            val mockRequestResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            every { mockRequestResponse.request() } returns mockRequest
            every { mockRequestResponse.response() } returns mockResponse

            val httpDetails = mockk<HttpDetails>().also {
                every { it.protocol() } returns HttpProtocol.HTTP
                every { it.requestResponse() } returns mockRequestResponse
            }
            val interaction = mockInteraction("int-002", InteractionType.HTTP, httpDetails = httpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"HTTP\""))
                assertTrue(text.contains("\"protocol\":\"HTTP\""))
                assertTrue(text.contains("GET / HTTP/1.1"))
                assertTrue(text.contains("HTTP/1.1 200 OK"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return smtp interaction details`() {
            val smtpDetails = mockk<SmtpDetails>().also {
                every { it.protocol() } returns SmtpProtocol.SMTP
                every { it.conversation() } returns "EHLO test\r\n250 OK"
            }
            val interaction = mockInteraction("int-003", InteractionType.SMTP, smtpDetails = smtpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"SMTP\""))
                assertTrue(text.contains("\"protocol\":\"SMTP\""))
                assertTrue(text.contains("EHLO test"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions with payloadId should use filter`() {
            val mockFilter = mockk<InteractionFilter>()
            every { InteractionFilter.interactionIdFilter("abc123") } returns mockFilter
            every { collaboratorClient.getInteractions(mockFilter) } returns emptyList()

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions", mapOf(
                        "payloadId" to "abc123"
                    )
                )
                delay(100)
                result.expectTextContent("No interactions detected")
            }

            verify(exactly = 1) { collaboratorClient.getInteractions(mockFilter) }
        }

        @Test
        fun `get interactions should return no interactions message when empty`() {
            every { collaboratorClient.getAllInteractions() } returns emptyList()

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                result.expectTextContent("No interactions detected")
            }
        }
    }

    @Test
    fun `tool name conversion should work properly`() {
        assertEquals("send_http1_request", "SendHttp1Request".toLowerSnakeCase())
        assertEquals("test_case_conversion", "TestCaseConversion".toLowerSnakeCase())
        assertEquals("multiple_upper_case_letters", "MultipleUpperCaseLetters".toLowerSnakeCase())
    }

    @Nested
    inner class ScopeToolsTests {
        private val scope = mockk<burp.api.montoya.scope.Scope>()

        @BeforeEach
        fun setup() {
            every { api.scope() } returns scope
        }

        @Test
        fun `is in scope should return true for scoped url`() {
            every { scope.isInScope(any<String>()) } returns true

            runBlocking {
                val result = client.callTool("is_in_scope", mapOf("url" to "https://example.com"))
                delay(100)
                result.expectTextContent("true")
            }

            verify(exactly = 1) { scope.isInScope("https://example.com") }
        }

        @Test
        fun `is in scope should return false for unscoped url`() {
            every { scope.isInScope(any<String>()) } returns false

            runBlocking {
                val result = client.callTool("is_in_scope", mapOf("url" to "https://example.com"))
                delay(100)
                result.expectTextContent("false")
            }
        }

        @Test
        fun `include in scope should add url`() {
            every { scope.includeInScope(any<String>()) } just runs

            runBlocking {
                val result = client.callTool("include_in_scope", mapOf("url" to "https://example.com"))
                delay(100)
                result.expectTextContent("Added to scope")
            }

            verify(exactly = 1) { scope.includeInScope("https://example.com") }
        }

        @Test
        fun `exclude from scope should remove url`() {
            every { scope.excludeFromScope(any<String>()) } just runs

            runBlocking {
                val result = client.callTool("exclude_from_scope", mapOf("url" to "https://example.com"))
                delay(100)
                result.expectTextContent("Removed from scope")
            }

            verify(exactly = 1) { scope.excludeFromScope("https://example.com") }
        }
    }

    @Nested
    inner class ComparerDecoderToolsTests {

        @Test
        fun `send to comparer should work`() {
            val comparer = mockk<burp.api.montoya.comparer.Comparer>()
            every { api.comparer() } returns comparer
            every { comparer.sendToComparer(*anyVararg<ByteArray>()) } just runs
            mockkStatic(ByteArray::class)
            every { ByteArray.byteArray(any<String>()) } returns mockk()

            runBlocking {
                val result = client.callTool("send_to_comparer", mapOf(
                    "items" to listOf("data1", "data2")
                ))
                delay(100)
                result.expectTextContent("Sent 2 items to Comparer")
            }

            verify(exactly = 1) { comparer.sendToComparer(*anyVararg<ByteArray>()) }
            unmockkStatic(ByteArray::class)
        }

        @Test
        fun `send to decoder should work`() {
            val decoder = mockk<burp.api.montoya.decoder.Decoder>()
            every { api.decoder() } returns decoder
            every { decoder.sendToDecoder(any()) } just runs
            mockkStatic(ByteArray::class)
            every { ByteArray.byteArray(any<String>()) } returns mockk()

            runBlocking {
                val result = client.callTool("send_to_decoder", mapOf("data" to "SGVsbG8="))
                delay(100)
                result.expectTextContent("Sent to Decoder")
            }

            verify(exactly = 1) { decoder.sendToDecoder(any()) }
            unmockkStatic(ByteArray::class)
        }
    }

    @Nested
    inner class CookieJarToolsTests {
        private val cookieJar = mockk<burp.api.montoya.http.sessions.CookieJar>()
        private val http = mockk<Http>()

        @BeforeEach
        fun setup() {
            every { api.http() } returns http
            every { http.cookieJar() } returns cookieJar
        }

        @Test
        fun `get cookies should return empty message when no cookies`() {
            every { cookieJar.cookies() } returns emptyList()

            runBlocking {
                val result = client.callTool("get_cookies", emptyMap())
                delay(100)
                result.expectTextContent("No cookies in Cookie Jar")
            }
        }

        @Test
        fun `get cookies should list cookies`() {
            val cookie = mockk<Cookie>()
            every { cookie.name() } returns "session"
            every { cookie.value() } returns "abc123"
            every { cookie.domain() } returns "example.com"
            every { cookie.path() } returns "/"
            every { cookie.expiration() } returns Optional.of(ZonedDateTime.parse("2026-12-31T23:59:59Z"))
            every { cookieJar.cookies() } returns listOf(cookie)

            mockkStatic("net.portswigger.mcp.schema.SerializationKt")
            every { cookie.toSerializableForm() } returns CookieDetails(
                name = "session", value = "abc123", domain = "example.com",
                path = "/", expiration = "2026-12-31T23:59:59Z"
            )

            runBlocking {
                val result = client.callTool("get_cookies", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("session"))
                assertTrue(text.contains("abc123"))
                assertTrue(text.contains("example.com"))
            }

            unmockkStatic("net.portswigger.mcp.schema.SerializationKt")
        }

        @Test
        fun `get cookies should handle null path`() {
            val cookie = mockk<Cookie>()
            every { cookie.name() } returns "test"
            every { cookie.value() } returns "val"
            every { cookie.domain() } returns "example.com"
            every { cookie.path() } returns null
            every { cookie.expiration() } returns Optional.empty()
            every { cookieJar.cookies() } returns listOf(cookie)

            runBlocking {
                val result = client.callTool("get_cookies", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("test"))
                assertTrue(text.contains("val"))
                assertTrue(text.contains("path"))
            }
        }

        @Test
        fun `set cookie should call cookie jar`() {
            every { cookieJar.setCookie(any(), any(), any(), any(), any()) } just runs

            runBlocking {
                val result = client.callTool("set_cookie", mapOf(
                    "domain" to "example.com",
                    "name" to "session",
                    "value" to "abc123",
                    "path" to "/"
                ))
                delay(100)
                result.expectTextContent("Cookie set")
            }

            verify(exactly = 1) { cookieJar.setCookie(any(), any(), any(), any(), any()) }
        }
    }

    @Nested
    inner class SiteMapToolsTests {
        private val siteMap = mockk<burp.api.montoya.sitemap.SiteMap>()

        @BeforeEach
        fun setup() {
            every { api.siteMap() } returns siteMap
        }

        @Test
        fun `get site map entries should return items`() {
            val entry = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val request = mockk<HttpRequest>()
            every { request.url() } returns "https://example.com/"
            every { request.toString() } returns "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            every { entry.request() } returns request
            every { entry.response() } returns null
            val annotations = mockk<burp.api.montoya.core.Annotations>()
            every { annotations.notes() } returns ""
            every { entry.annotations() } returns annotations
            every { siteMap.requestResponses() } returns listOf(entry)

            runBlocking {
                val result = client.callTool("get_site_map_entries", mapOf(
                    "count" to 10, "offset" to 0
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("https://example.com"))
                assertTrue(text.contains("GET / HTTP/1.1"))
            }
        }

        @Test
        fun `get site map entries with url prefix should filter`() {
            mockkStatic(SiteMapFilter::class)
            val filter = mockk<SiteMapFilter>()
            every { SiteMapFilter.prefixFilter(any()) } returns filter

            val entry = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val request = mockk<HttpRequest>()
            every { request.url() } returns "https://example.com/admin"
            every { request.toString() } returns "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
            every { entry.request() } returns request
            every { entry.response() } returns null
            val annotations = mockk<burp.api.montoya.core.Annotations>()
            every { annotations.notes() } returns ""
            every { entry.annotations() } returns annotations
            every { siteMap.requestResponses(filter) } returns listOf(entry)

            runBlocking {
                val result = client.callTool("get_site_map_entries", mapOf(
                    "count" to 10, "offset" to 0, "urlPrefix" to "https://example.com/admin"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("/admin"))
            }

            verify(exactly = 1) { siteMap.requestResponses(filter) }
            unmockkStatic(SiteMapFilter::class)
        }

        @Test
        fun `add to site map should work`() {
            val httpRequest = mockk<HttpRequest>()
            every { httpRequest.toString() } returns "GET / HTTP/1.1"
            mockkStatic(HttpRequest::class)
            every { HttpRequest.httpRequest(any(), any<String>()) } returns httpRequest
            mockkStatic(burp.api.montoya.http.message.HttpRequestResponse::class)
            every { burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(any(), any()) } returns mockk()
            every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } returns mockk()
            every { siteMap.add(any<burp.api.montoya.http.message.HttpRequestResponse>()) } just runs

            runBlocking {
                val result = client.callTool("add_to_site_map", mapOf(
                    "request" to "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "targetHostname" to "example.com",
                    "targetPort" to 80,
                    "usesHttps" to false
                ))
                delay(100)
                result.expectTextContent("Added to site map")
            }

            verify(exactly = 1) { siteMap.add(any<burp.api.montoya.http.message.HttpRequestResponse>()) }
            unmockkStatic(HttpRequest::class)
            unmockkStatic(burp.api.montoya.http.message.HttpRequestResponse::class)
        }

        @Test
        fun `add to site map with response should work`() {
            mockkStatic(HttpRequest::class)
            every { HttpRequest.httpRequest(any(), any<String>()) } returns mockk()
            mockkStatic(burp.api.montoya.http.message.responses.HttpResponse::class)
            every { burp.api.montoya.http.message.responses.HttpResponse.httpResponse(any<String>()) } returns mockk()
            mockkStatic(burp.api.montoya.http.message.HttpRequestResponse::class)
            every { burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(any(), any()) } returns mockk()
            every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } returns mockk()
            every { siteMap.add(any<burp.api.montoya.http.message.HttpRequestResponse>()) } just runs

            runBlocking {
                val result = client.callTool("add_to_site_map", mapOf(
                    "request" to "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "responseBody" to "HTTP/1.1 200 OK\r\n\r\nbody",
                    "targetHostname" to "example.com",
                    "targetPort" to 80,
                    "usesHttps" to false
                ))
                delay(100)
                result.expectTextContent("Added to site map")
            }

            verify(exactly = 1) { siteMap.add(any<burp.api.montoya.http.message.HttpRequestResponse>()) }
            unmockkStatic(HttpRequest::class)
            unmockkStatic(burp.api.montoya.http.message.responses.HttpResponse::class)
            unmockkStatic(burp.api.montoya.http.message.HttpRequestResponse::class)
        }
    }

    @Nested
    inner class ScannerToolsTests {
        private val scanner = mockk<burp.api.montoya.scanner.Scanner>()
        private val crawlTask = mockk<Crawl>()

        @BeforeEach
        fun setup() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val version = mockk<burp.api.montoya.core.Version>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.version() } returns version
            every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
            every { burpSuite.taskExecutionEngine() } returns mockk(relaxed = true)
            every { api.scanner() } returns scanner
            mockkStatic(CrawlConfiguration::class)

            serverManager.stop {}
            serverStarted = false
            serverManager.start(config) { state ->
                if (state is ServerState.Running) serverStarted = true
            }

            runBlocking {
                var attempts = 0
                while (!serverStarted && attempts < 30) {
                    delay(100)
                    attempts++
                }
                if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")
                client.connectToServer("http://127.0.0.1:${testPort}")
            }
        }

        @AfterEach
        fun cleanup() {
            unmockkStatic(CrawlConfiguration::class)
        }

        @Test
        fun `start crawl scan should work`() {
            val crawlConfig = mockk<CrawlConfiguration>()
            every { CrawlConfiguration.crawlConfiguration(any<String>()) } returns crawlConfig
            every { scanner.startCrawl(crawlConfig) } returns crawlTask
            every { crawlTask.statusMessage() } returns "Running"
            every { crawlTask.requestCount() } returns 10
            every { crawlTask.errorCount() } returns 0

            runBlocking {
                val result = client.callTool("start_crawl_scan", mapOf(
                    "seedUrls" to listOf("https://example.com")
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("Scan started"))
                assertTrue(text.contains("scan-"))
            }

            verify(exactly = 1) { scanner.startCrawl(crawlConfig) }
        }

        @Test
        fun `get scan status should return scan info`() {
            val crawlConfig = mockk<CrawlConfiguration>()
            every { CrawlConfiguration.crawlConfiguration(any<String>()) } returns crawlConfig
            every { scanner.startCrawl(crawlConfig) } returns crawlTask
            every { crawlTask.statusMessage() } returns "Running"
            every { crawlTask.requestCount() } returns 42
            every { crawlTask.errorCount() } returns 0

            runBlocking {
                val startResult = client.callTool("start_crawl_scan", mapOf(
                    "seedUrls" to listOf("https://example.com")
                ))
                delay(100)
                val startText = startResult.expectTextContent()
                val scanId = startText.substringAfter("ID: ").substringBefore(",").trim()

                val result = client.callTool("get_scan_status", mapOf("scanId" to scanId))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains(scanId))
                assertTrue(text.contains("Running"))
                assertTrue(text.contains("42"))
            }
        }

        @Test
        fun `delete scan should remove and return not found on re-delete`() {
            val crawlConfig = mockk<CrawlConfiguration>()
            every { CrawlConfiguration.crawlConfiguration(any<String>()) } returns crawlConfig
            every { scanner.startCrawl(crawlConfig) } returns crawlTask
            every { crawlTask.delete() } just runs
            every { crawlTask.statusMessage() } returns "Running"
            every { crawlTask.requestCount() } returns 0
            every { crawlTask.errorCount() } returns 0

            runBlocking {
                val startResult = client.callTool("start_crawl_scan", mapOf(
                    "seedUrls" to listOf("https://example.com")
                ))
                delay(100)
                val startText = startResult.expectTextContent()
                val scanId = startText.substringAfter("ID: ").substringBefore(",").trim()

                val deleteResult = client.callTool("delete_scan", mapOf("scanId" to scanId))
                delay(100)
                deleteResult.expectTextContent("Scan deleted: $scanId")

                val notFoundResult = client.callTool("delete_scan", mapOf("scanId" to scanId))
                delay(100)
                notFoundResult.expectTextContent("Scan not found: $scanId")
            }

            verify(exactly = 1) { crawlTask.delete() }
        }

        @Test
        fun `get scan status should return not found for unknown id`() {
            runBlocking {
                val result = client.callTool("get_scan_status", mapOf("scanId" to "scan-999"))
                delay(100)
                result.expectTextContent("Scan not found: scan-999")
            }
        }

        @Test
        fun `delete scan should return not found for unknown id`() {
            runBlocking {
                val result = client.callTool("delete_scan", mapOf("scanId" to "scan-999"))
                delay(100)
                result.expectTextContent("Scan not found: scan-999")
            }
        }
    }
    
    @Nested
    inner class AuditScanToolsTests {
        private val scanner = mockk<burp.api.montoya.scanner.Scanner>()
        private val auditTask = mockk<Audit>()

        @BeforeEach
        fun setup() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val version = mockk<burp.api.montoya.core.Version>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.version() } returns version
            every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
            every { burpSuite.taskExecutionEngine() } returns mockk(relaxed = true)
            every { burpSuite.exportProjectOptionsAsJson() } returns "{}"
            every { burpSuite.exportUserOptionsAsJson() } returns "{}"
            every { api.scanner() } returns scanner
            mockkStatic(AuditConfiguration::class)

            serverManager.stop {}
            serverStarted = false
            serverManager.start(config) { state ->
                if (state is ServerState.Running) serverStarted = true
            }

            runBlocking {
                var attempts = 0
                while (!serverStarted && attempts < 30) {
                    delay(100)
                    attempts++
                }
                if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")
                client.connectToServer("http://127.0.0.1:${testPort}")
            }
        }

        @AfterEach
        fun cleanup() {
            unmockkStatic(AuditConfiguration::class)
        }

        @Test
        fun `start audit scan should work`() {
            val auditConfig = mockk<AuditConfiguration>()
            every { AuditConfiguration.auditConfiguration(any()) } returns auditConfig
            every { scanner.startAudit(auditConfig) } returns auditTask

            runBlocking {
                val result = client.callTool("start_audit_scan", mapOf(
                    "seedUrls" to listOf("https://example.com"),
                    "auditConfigType" to "active"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("Audit scan started"))
                assertTrue(text.contains("scan-"))
            }

            verify(exactly = 1) { scanner.startAudit(auditConfig) }
        }

        @Test
        fun `get audit scan issues should return issues`() {
            val auditConfig = mockk<AuditConfiguration>()
            every { AuditConfiguration.auditConfiguration(any()) } returns auditConfig
            every { scanner.startAudit(auditConfig) } returns auditTask
            val issue = mockk<burp.api.montoya.scanner.audit.issues.AuditIssue>()
            val severity = mockk<burp.api.montoya.scanner.audit.issues.AuditIssueSeverity>()
            every { issue.name() } returns "SQL Injection"
            every { issue.severity() } returns severity
            every { severity.name } returns "HIGH"
            every { issue.detail() } returns "Found SQLi"
            every { issue.remediation() } returns "Sanitize input"
            every { issue.baseUrl() } returns "https://example.com"
            val httpService = mockk<burp.api.montoya.http.HttpService>()
            every { httpService.host() } returns "example.com"
            every { httpService.port() } returns 443
            every { httpService.secure() } returns true
            every { issue.httpService() } returns httpService
            val confidence = mockk<burp.api.montoya.scanner.audit.issues.AuditIssueConfidence>()
            every { confidence.name } returns "CERTAIN"
            every { issue.confidence() } returns confidence
            every { issue.requestResponses() } returns emptyList()
            every { issue.collaboratorInteractions() } returns emptyList()
            val definition = mockk<burp.api.montoya.scanner.audit.issues.AuditIssueDefinition>()
            every { definition.name() } returns "sql-injection"
            every { definition.background() } returns null
            every { definition.remediation() } returns null
            every { definition.typeIndex() } returns 0
            every { issue.definition() } returns definition
            every { auditTask.issues() } returns listOf(issue)

            runBlocking {
                val startResult = client.callTool("start_audit_scan", mapOf(
                    "seedUrls" to listOf("https://example.com")
                ))
                delay(100)
                val scanId = startResult.expectTextContent().substringAfter("ID: ").substringBefore(",").trim()

                val result = client.callTool("get_audit_scan_issues", mapOf("scanId" to scanId))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("SQL Injection"))
                assertTrue(text.contains("HIGH"))
            }
        }

        @Test
        fun `get audit scan issues should return not found for unknown`() {
            runBlocking {
                val result = client.callTool("get_audit_scan_issues", mapOf("scanId" to "scan-999"))
                delay(100)
                result.expectTextContent("Scan not found: scan-999")
            }
        }
    }

    @Nested
    inner class BCheckToolsTests {
        @Test
        fun `import bcheck should return success`() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val version = mockk<burp.api.montoya.core.Version>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.version() } returns version
            every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
            every { burpSuite.taskExecutionEngine() } returns mockk(relaxed = true)
            every { burpSuite.exportProjectOptionsAsJson() } returns "{}"
            every { burpSuite.exportUserOptionsAsJson() } returns "{}"

            val scanner = mockk<burp.api.montoya.scanner.Scanner>()
            val bChecks = mockk<BChecks>()
            val result = mockk<BCheckImportResult>()
            val resultStatus = mockk<BCheckImportResult.Status>()
            every { api.scanner() } returns scanner
            every { scanner.bChecks() } returns bChecks
            every { result.status() } returns resultStatus
            every { resultStatus.name } returns "SUCCESS"
            every { bChecks.importBCheck(any<String>()) } returns result

            serverManager.stop {}
            serverStarted = false
            serverManager.start(config) { state ->
                if (state is ServerState.Running) serverStarted = true
            }
            runBlocking {
                var attempts = 0
                while (!serverStarted && attempts < 30) {
                    delay(100)
                    attempts++
                }
                client.connectToServer("http://127.0.0.1:${testPort}")
            }

            runBlocking {
                val result = client.callTool("import_bcheck", mapOf(
                    "script" to "def check:\n  description = \"Test\"\n  # ..."
                ))
                delay(100)
                result.expectTextContent("BCheck imported successfully")
            }

            verify(exactly = 1) { bChecks.importBCheck(any<String>()) }
        }
    }

    @Nested
    inner class CryptoUtilToolsTests {
        @Test
        fun `generate digest should hash input`() {
            val cryptoUtils = mockk<CryptoUtils>()
            val utilities = mockk<burp.api.montoya.utilities.Utilities>()
            val burpByteArray = mockk<ByteArray>()

            every { api.utilities() } returns utilities
            every { utilities.cryptoUtils() } returns cryptoUtils
            mockkStatic(ByteArray::class)
            every { ByteArray.byteArray(any<String>()) } returns burpByteArray
            every { cryptoUtils.generateDigest(any(), any()) } returns burpByteArray
            every { burpByteArray.toString() } returns "abc123def456"

            runBlocking {
                val result = client.callTool("generate_digest", mapOf(
                    "data" to "hello",
                    "algorithm" to "SHA_256"
                ))
                delay(100)
                assertTrue(result.expectTextContent().contains("abc123def456"))
            }

            verify(exactly = 1) { cryptoUtils.generateDigest(any(), any<DigestAlgorithm>()) }
            unmockkStatic(ByteArray::class)
        }
    }

    @Nested
    inner class CompressionToolsTests {
        @Test
        fun `compress and decompress should work`() {
            val compressionUtils = mockk<CompressionUtils>()
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<burp.api.montoya.utilities.Utilities>()
            val burpByteArray = mockk<ByteArray>()
            val base64Decoded = mockk<ByteArray>()

            every { api.utilities() } returns utilities
            every { utilities.compressionUtils() } returns compressionUtils
            every { utilities.base64Utils() } returns base64Utils
            mockkStatic(ByteArray::class)
            every { ByteArray.byteArray(any<String>()) } returns burpByteArray
            every { compressionUtils.compress(any(), any()) } returns burpByteArray
            every { compressionUtils.decompress(any(), any()) } returns base64Decoded
            every { base64Utils.encodeToString(burpByteArray) } returns "base64-encoded-data"
            every { base64Utils.decode(any<String>()) } returns base64Decoded
            every { base64Decoded.toString() } returns "original-data"

            runBlocking {
                val result = client.callTool("compress", mapOf(
                    "data" to "test data",
                    "compressionType" to "GZIP"
                ))
                delay(100)
                assertEquals("base64-encoded-data", result.expectTextContent())
            }

            verify(exactly = 1) { compressionUtils.compress(any(), any<CompressionType>()) }
            verify(exactly = 1) { base64Utils.encodeToString(burpByteArray) }
            unmockkStatic(ByteArray::class)
        }
    }

    @Nested
    inner class HtmlToolsTests {
        @Test
        fun `html encode and decode should work`() {
            val htmlUtils = mockk<HtmlUtils>()
            val utilities = mockk<burp.api.montoya.utilities.Utilities>()

            every { api.utilities() } returns utilities
            every { utilities.htmlUtils() } returns htmlUtils
            every { htmlUtils.encode(any<String>()) } returns "&lt;test&gt;"
            every { htmlUtils.decode(any<String>()) } returns "<test>"

            runBlocking {
                val encoded = client.callTool("html_encode", mapOf("data" to "<test>"))
                delay(100)
                encoded.expectTextContent("&lt;test&gt;")

                val decoded = client.callTool("html_decode", mapOf("data" to "&lt;test&gt;"))
                delay(100)
                decoded.expectTextContent("<test>")
            }

            verify(exactly = 1) { htmlUtils.encode("<test>") }
            verify(exactly = 1) { htmlUtils.decode("&lt;test&gt;") }
        }
    }

    @Nested
    inner class JsonToolsTests {
        @Test
        fun `json validate should work`() {
            val jsonUtils = mockk<JsonUtils>()
            val utilities = mockk<burp.api.montoya.utilities.Utilities>()

            every { api.utilities() } returns utilities
            every { utilities.jsonUtils() } returns jsonUtils
            every { jsonUtils.isValidJson(any<String>()) } returns true

            runBlocking {
                val result = client.callTool("json_validate", mapOf("json" to "{\"a\":1}"))
                delay(100)
                result.expectTextContent("true")
            }

            verify(exactly = 1) { jsonUtils.isValidJson("{\"a\":1}") }
        }

        @Test
        fun `json read should work`() {
            runBlocking {
                val result = client.callTool("json_read", mapOf(
                    "json" to "{\"data\":\"value1\"}", "path" to "data"
                ))
                delay(100)
                result.expectTextContent("\"value1\"")
            }
        }

        @Test
        fun `json add should work`() {
            runBlocking {
                val result = client.callTool("json_add", mapOf(
                    "json" to "{\"a\":1}", "path" to "b", "value" to "2"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"a\""))
                assertTrue(text.contains("\"b\""))
            }
        }

        @Test
        fun `json read should support array indices in dot path`() {
            runBlocking {
                val result = client.callTool("json_read", mapOf(
                    "json" to """{"data":{"items":[{"id":1},{"id":2}]}}""",
                    "path" to "data.items[0].id"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertEquals("1", text.trim())
            }
        }

        @Test
        fun `json add should support array append`() {
            runBlocking {
                val result = client.callTool("json_add", mapOf(
                    "json" to """{"items":["a","b"]}""",
                    "path" to "items[-]",
                    "value" to """"c""""
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains(""""c""""), "Result should contain new item 'c', got: $text")
                assertTrue(text.contains(""""a""""), "Result should keep existing item 'a'")
                assertTrue(text.contains(""""b""""), "Result should keep existing item 'b'")
            }
        }
    }

    @Nested
    inner class BatchHttpToolsTests {
        @Test
        fun `batch http should send multiple requests`() {
            val httpService = mockk<burp.api.montoya.http.Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()

            every { api.http() } returns httpService
            mockkStatic(HttpRequest::class)
            mockkStatic(burp.api.montoya.http.HttpService::class)
            every { HttpRequest.httpRequest(any(), any<String>()) } returns httpRequest
            every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } returns mockk()
            every { httpResponse.toString() } returns "HTTP/1.1 200 OK\r\n\r\nbody"
            every { httpService.sendRequest(any()) } returns httpResponse

            runBlocking {
                val result = client.callTool("send_http_requests_batch", mapOf(
                    "requests" to listOf(mapOf(
                        "content" to "GET / HTTP/1.1\r\nHost: a.com\r\n\r\n",
                        "targetHostname" to "a.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    ), mapOf(
                        "content" to "GET / HTTP/1.1\r\nHost: b.com\r\n\r\n",
                        "targetHostname" to "b.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    ))
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("a.com"))
                assertTrue(text.contains("b.com"))
            }

            verify(exactly = 2) { httpService.sendRequest(any()) }
            unmockkStatic(HttpRequest::class)
            unmockkStatic(burp.api.montoya.http.HttpService::class)
        }
    }

    @Nested
    inner class WebSocketToolsTests {
        @Test
        fun `create websocket should work`() {
            val webSockets = mockk<WebSockets>()
            val wsCreation = mockk<ExtensionWebSocketCreation>()

            every { api.websockets() } returns webSockets
            every { webSockets.createWebSocket(any(), any<String>()) } returns wsCreation
            val status = mockk<ExtensionWebSocketCreationStatus>()
            every { status.name } returns "SUCCESS"
            every { wsCreation.status() } returns status
            val ws = mockk<ExtensionWebSocket>()
            every { wsCreation.webSocket() } returns java.util.Optional.of(ws)
            every { ws.sendTextMessage(any()) } just runs

            runBlocking {
                val result = client.callTool("create_websocket", mapOf(
                    "path" to "/ws",
                    "initialMessage" to "hello",
                    "targetHostname" to "example.com",
                    "targetPort" to 443,
                    "usesHttps" to true
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("SUCCESS"))
            }

            verify(exactly = 1) { ws.sendTextMessage("hello") }
        }
    }

    @Nested
    inner class OrganizerToolsTests {
        @Test
        fun `send to organizer should work`() {
            val organizer = mockk<burp.api.montoya.organizer.Organizer>()
            val httpRequest = mockk<HttpRequest>()

            every { api.organizer() } returns organizer
            every { organizer.sendToOrganizer(any<HttpRequest>()) } just runs
            mockkStatic(HttpRequest::class)
            every { HttpRequest.httpRequest(any(), any<String>()) } returns httpRequest

            runBlocking {
                val result = client.callTool("send_to_organizer", mapOf(
                    "request" to "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "targetHostname" to "example.com",
                    "targetPort" to 80,
                    "usesHttps" to false
                ))
                delay(100)
                result.expectTextContent("Sent to Organizer")
            }

            verify(exactly = 1) { organizer.sendToOrganizer(any<HttpRequest>()) }
            unmockkStatic(HttpRequest::class)
        }
    }

    @Nested
    inner class MiscInfoToolsTests {
        @Test
        fun `get project info should work`() {
            val project = mockk<Project>()
            every { api.project() } returns project
            every { project.name() } returns "Test Project"
            every { project.id() } returns "proj-123"

            runBlocking {
                val result = client.callTool("get_project_info", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("Test Project"))
                assertTrue(text.contains("proj-123"))
            }
        }

        @Test
        fun `get proxy intercept state should work`() {
            val proxy = mockk<burp.api.montoya.proxy.Proxy>()
            every { api.proxy() } returns proxy
            every { proxy.isInterceptEnabled() } returns true

            runBlocking {
                val result = client.callTool("get_proxy_intercept_state", emptyMap())
                delay(100)
                result.expectTextContent("Intercept enabled: true")
            }

            verify(exactly = 1) { proxy.isInterceptEnabled() }
        }

        @Test
        fun `get command line args should work`() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.commandLineArguments() } returns listOf("--headless", "--project=test.burp")

            runBlocking {
                val result = client.callTool("get_command_line_args", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("--headless"))
                assertTrue(text.contains("--project=test.burp"))
            }

            verify(exactly = 1) { burpSuite.commandLineArguments() }
        }

        @Test
        fun `execute command should gate when disabled`() {
            runBlocking {
                val result = client.callTool("execute_command", mapOf(
                    "command" to "echo test",
                    "useShell" to true
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("Shell execution is disabled"))
            }
        }
    }

    @Nested
    inner class RankToolsTests {
        @Test
        fun `rank responses should rank items`() {
            val rankingUtils = mockk<RankingUtils>()
            val utilities = mockk<burp.api.montoya.utilities.Utilities>()
            every { api.utilities() } returns utilities
            every { utilities.rankingUtils() } returns rankingUtils

            val rankedItem = mockk<RankedHttpRequestResponse>()
            val requestResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
            every { rankedItem.rank() } returns 42
            every { rankedItem.requestResponse() } returns requestResponse
            every { requestResponse.request() } returns httpRequest
            every { httpRequest.url() } returns "https://example.com/interesting"
            every { httpRequest.toString() } returns "GET /interesting HTTP/1.1\r\nHost: example.com\r\n\r\n"
            every { requestResponse.response() } returns null
            every { rankingUtils.rank(any<Collection<burp.api.montoya.http.message.HttpRequestResponse>>()) } returns listOf(rankedItem)

            mockkStatic(HttpRequest::class)
            mockkStatic(HttpResponse::class)
            mockkStatic(burp.api.montoya.http.message.HttpRequestResponse::class)
            mockkStatic(burp.api.montoya.http.HttpService::class)
            every { HttpRequest.httpRequest(any(), any<String>()) } returns httpRequest
                every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } returns mockk()
            every { burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(any(), any()) } returns requestResponse

            runBlocking {
                val result = client.callTool("rank_responses", mapOf(
                    "items" to listOf(mapOf(
                        "request" to "GET /interesting HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    ))
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("42"))
                assertTrue(text.contains("interesting"))
            }

            verify(exactly = 1) { rankingUtils.rank(any()) }
            unmockkStatic(HttpRequest::class)
            unmockkStatic(HttpResponse::class)
            unmockkStatic(burp.api.montoya.http.message.HttpRequestResponse::class)
            unmockkStatic(burp.api.montoya.http.HttpService::class)
        }

        @Test
        fun `rank responses should work with minimal item fields`() {
            val rankingUtils = mockk<RankingUtils>()
            val utilities = mockk<Utilities>()
            every { api.utilities() } returns utilities
            every { utilities.rankingUtils() } returns rankingUtils

            val rankedItem = mockk<RankedHttpRequestResponse>()
            val requestResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            every { rankedItem.rank() } returns 1
            every { rankedItem.requestResponse() } returns requestResponse
            every { requestResponse.request() } returns httpRequest
            every { httpRequest.url() } returns "https://example.com/"
            every { httpRequest.toString() } returns "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            every { requestResponse.response() } returns null
            every { rankingUtils.rank(any<Collection<burp.api.montoya.http.message.HttpRequestResponse>>()) } returns listOf(rankedItem)

            mockkStatic(HttpRequest::class)
            mockkStatic(HttpResponse::class)
            mockkStatic(burp.api.montoya.http.message.HttpRequestResponse::class)
            mockkStatic(burp.api.montoya.http.HttpService::class)
            every { HttpRequest.httpRequest(any(), any<String>()) } returns httpRequest
            every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } returns mockk()
            every { burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(any(), any()) } returns requestResponse

            runBlocking {
                val result = client.callTool("rank_responses", mapOf(
                    "items" to listOf(mapOf(
                        "request" to "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    ))
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("1"))
            }

            verify(exactly = 1) { rankingUtils.rank(any()) }
            unmockkStatic(HttpRequest::class)
            unmockkStatic(HttpResponse::class)
            unmockkStatic(burp.api.montoya.http.message.HttpRequestResponse::class)
            unmockkStatic(burp.api.montoya.http.HttpService::class)
        }
    }

    @Nested
    inner class VariationAnalysisToolsTests {
        @Test
        fun `analyze response variations should work`() {
            val http = mockk<burp.api.montoya.http.Http>()
            val analyzer = mockk<ResponseVariationsAnalyzer>(relaxed = true)
            every { api.http() } returns http
            every { http.createResponseVariationsAnalyzer() } returns analyzer
            every { analyzer.variantAttributes() } returns setOf(
                mockk<burp.api.montoya.http.message.responses.analysis.AttributeType>().also {
                    every { it.name } returns "CONTENT_LENGTH"
                }
            )
            every { analyzer.invariantAttributes() } returns setOf(
                mockk<burp.api.montoya.http.message.responses.analysis.AttributeType>().also {
                    every { it.name } returns "STATUS_CODE"
                }
            )
            mockkStatic(HttpResponse::class)
            every { HttpResponse.httpResponse(any<String>()) } returns mockk<HttpResponse>()

            runBlocking {
                val result = client.callTool("analyze_response_variations", mapOf(
                    "responses" to listOf("HTTP/1.1 200 OK\r\n\r\nbody1", "HTTP/1.1 200 OK\r\n\r\nbody2")
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("CONTENT_LENGTH"))
                assertTrue(text.contains("STATUS_CODE"))
            }

            verify(exactly = 2) { analyzer.updateWith(any()) }
            unmockkStatic(HttpResponse::class)
        }
    }

    @Nested
    inner class KeywordAnalysisToolsTests {
        @Test
        fun `analyze response keywords should work`() {
            val http = mockk<burp.api.montoya.http.Http>()
            val analyzer = mockk<ResponseKeywordsAnalyzer>(relaxed = true)
            every { api.http() } returns http
            every { http.createResponseKeywordsAnalyzer(any<List<String>>()) } returns analyzer
            every { analyzer.variantKeywords() } returns setOf("token")
            every { analyzer.invariantKeywords() } returns setOf("Welcome")
            mockkStatic(HttpResponse::class)
            every { HttpResponse.httpResponse(any<String>()) } returns mockk<HttpResponse>()

            runBlocking {
                val result = client.callTool("analyze_response_keywords", mapOf(
                    "keywords" to listOf("token", "Welcome", "admin", "error"),
                    "responses" to listOf("HTTP/1.1 200 OK\r\n\r\nWelcome back", "HTTP/1.1 200 OK\r\n\r\nWelcome admin")
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("token"))
                assertTrue(text.contains("Welcome"))
            }

            verify(exactly = 2) { analyzer.updateWith(any()) }
            unmockkStatic(HttpResponse::class)
        }
    }

    @Nested
    inner class BambdaToolsTests {
        @Test
        fun `import bambda should work`() {
            val bambda = mockk<Bambda>()
            val result = mockk<BambdaImportResult>()
            val status = mockk<BambdaImportResult.Status>()
            every { api.bambda() } returns bambda
            every { bambda.importBambda(any<String>()) } returns result
            every { result.status() } returns status
            every { status.name } returns "LOADED_WITHOUT_ERRORS"
            every { result.importErrors() } returns emptyList()

            runBlocking {
                val result = client.callTool("import_bambda", mapOf(
                    "script" to "request.annotations().notes().contains(\"test\")"
                ))
                delay(100)
                result.expectTextContent("Bambda imported: LOADED_WITHOUT_ERRORS")
            }

            verify(exactly = 1) { bambda.importBambda(any<String>()) }
        }
    }

    @Nested
    inner class ExportCurlTests {
        @Test
        fun `export curl should generate curl command`() {
            runBlocking {
                val result = client.callTool("export_curl", mapOf(
                    "content" to "GET /foo HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("curl -X GET"))
                assertTrue(text.contains("example.com"))
                assertTrue(text.contains("http://"))
            }
        }

        @Test
        fun `export curl with insecure flag should add -k`() {
            runBlocking {
                val result = client.callTool("export_curl", mapOf(
                    "content" to "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "insecure" to true
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains(" -k "))
            }
        }

        @Test
        fun `export curl with body should add -d`() {
            runBlocking {
                val result = client.callTool("export_curl", mapOf(
                    "content" to "POST /bar HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\n\r\nhello world"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains(" -d 'hello world'"))
            }
        }

        @Test
        fun `export curl should handle empty request`() {
            runBlocking {
                val result = client.callTool("export_curl", mapOf(
                    "content" to ""
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("Error"))
            }
        }
    }

    @Nested
    inner class GetRequestByIdTests {
        @Test
        fun `get request by id should return entry`() {
            val proxy = mockk<burp.api.montoya.proxy.Proxy>()
            val entry = mockk<burp.api.montoya.proxy.ProxyHttpRequestResponse>()
            val httpRequest = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
            val httpResponse = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(entry)
            every { entry.id() } returns 42
            every { entry.request() } returns httpRequest
            every { entry.response() } returns httpResponse
            every { httpRequest.toString() } returns "GET /secret HTTP/1.1\r\nHost: internal\r\n\r\n"
            every { httpResponse.toString() } returns "HTTP/1.1 200 OK\r\n\r\nflag"

            runBlocking {
                val result = client.callTool("get_request_by_id", mapOf("id" to 42))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("GET /secret"))
                assertTrue(text.contains("flag"))
            }
        }

        @Test
        fun `get request by id should return not found for unknown id`() {
            val proxy = mockk<burp.api.montoya.proxy.Proxy>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns emptyList()

            runBlocking {
                val result = client.callTool("get_request_by_id", mapOf("id" to 999))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("Error"))
                assertTrue(text.contains("999"))
            }
        }
    }

    @Nested
    inner class ConvertBodyTests {
        @Test
        fun `convert body from json to urlencoded should work`() {
            runBlocking {
                val result = client.callTool("convert_body", mapOf(
                    "body" to """{"name":"test","value":"123"}""",
                    "fromFormat" to "json",
                    "toFormat" to "urlencoded"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("name=test"))
                assertTrue(text.contains("value=123"))
            }
        }

        @Test
        fun `convert body from urlencoded to json should work`() {
            runBlocking {
                val result = client.callTool("convert_body", mapOf(
                    "body" to "name=test&value=123",
                    "fromFormat" to "urlencoded",
                    "toFormat" to "json"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"name\""))
                assertTrue(text.contains("\"test\""))
                assertTrue(text.contains("\"value\""))
                assertTrue(text.contains("\"123\""))
            }
        }

        @Test
        fun `convert body should auto-detect json format`() {
            runBlocking {
                val result = client.callTool("convert_body", mapOf(
                    "body" to """{"key":"value"}"""
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("key=value"))
            }
        }

        @Test
        fun `convert body should auto-detect urlencoded format`() {
            runBlocking {
                val result = client.callTool("convert_body", mapOf(
                    "body" to "a=1&b=2"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"a\""))
                assertTrue(text.contains("\"1\""))
            }
        }

        @Test
        fun `convert body should handle uppercase format names`() {
            runBlocking {
                val result = client.callTool("convert_body", mapOf(
                    "body" to """{"x":"y"}""",
                    "fromFormat" to "JSON",
                    "toFormat" to "URL-ENCODED"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("x=y"))
            }
        }

        @Test
        fun `convert body should handle mixed case format names`() {
            runBlocking {
                val result = client.callTool("convert_body", mapOf(
                    "body" to "a=1&b=2",
                    "fromFormat" to "UrlEncoded",
                    "toFormat" to "Json"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"a\""))
            }
        }
    }

    @Test
    fun `edition specific tools should only register in professional edition`() {
        val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
        val version = mockk<burp.api.montoya.core.Version>()
        
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        
        every { version.edition() } returns BurpSuiteEdition.COMMUNITY_EDITION
        runBlocking {
            val tools = client.listTools()
            assertFalse(tools.any { it.name == "get_scanner_issues" })
            assertFalse(tools.any { it.name == "generate_collaborator_payload" })
            assertFalse(tools.any { it.name == "get_collaborator_interactions" })
            assertFalse(tools.any { it.name == "start_crawl_scan" })
            assertFalse(tools.any { it.name == "get_scan_status" })
            assertFalse(tools.any { it.name == "delete_scan" })
            assertFalse(tools.any { it.name == "start_audit_scan" })
            assertFalse(tools.any { it.name == "get_audit_scan_issues" })
            assertFalse(tools.any { it.name == "import_bcheck" })
            assertFalse(tools.any { it.name == "generate_scanner_report" })
        }

        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL

        serverManager.stop {}
        serverStarted = false
        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}")

            val tools = client.listTools()
            assertTrue(tools.any { it.name == "get_scanner_issues" })
            assertTrue(tools.any { it.name == "generate_collaborator_payload" })
            assertTrue(tools.any { it.name == "get_collaborator_interactions" })
            assertTrue(tools.any { it.name == "start_crawl_scan" })
            assertTrue(tools.any { it.name == "get_scan_status" })
            assertTrue(tools.any { it.name == "delete_scan" })
            assertTrue(tools.any { it.name == "start_audit_scan" })
            assertTrue(tools.any { it.name == "get_audit_scan_issues" })
            assertTrue(tools.any { it.name == "import_bcheck" })
            assertTrue(tools.any { it.name == "generate_scanner_report" })
        }
    }

    @Nested
    inner class ProxyInterceptRuleToolsTests {

        @Test
        fun `list rules should return empty when none registered`() {
            runBlocking {
                val result = client.callTool("list_proxy_intercept_rules", emptyMap())
                delay(100)
                result.expectTextContent("No proxy intercept rules registered")
            }
        }

        @BeforeEach
        fun cleanup() {
            proxyInterceptRules.clear()
        }

        @Test
        fun `register and list proxy intercept rule should work`() {
            runBlocking {
                val regResult = client.callTool("register_proxy_intercept_rule", mapOf(
                    "name" to "block-malicious",
                    "urlPattern" to "evil.com",
                    "action" to "drop"
                ))
                delay(100)
                val regText = regResult.expectTextContent()
                assertTrue(regText.contains("Registered proxy intercept rule 'block-malicious'"))

                val listResult = client.callTool("list_proxy_intercept_rules", emptyMap())
                delay(100)
                val listText = listResult.expectTextContent()
                assertTrue(listText.contains("block-malicious"))
            }
        }

        @Test
        fun `register spoof rule should work`() {
            runBlocking {
                val result = client.callTool("register_proxy_intercept_rule", mapOf(
                    "name" to "spoof-test",
                    "urlPattern" to "test.com",
                    "action" to "spoof",
                    "responseBody" to "HTTP/1.1 403 Forbidden\r\n\r\nBlocked"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("Registered proxy intercept rule 'spoof-test'"))
            }
        }

        @Test
        fun `register duplicate rule should return error`() {
            runBlocking {
                client.callTool("register_proxy_intercept_rule", mapOf(
                    "name" to "dup-rule",
                    "urlPattern" to "example.com",
                    "action" to "continue"
                ))
                delay(50)

                val result = client.callTool("register_proxy_intercept_rule", mapOf(
                    "name" to "dup-rule",
                    "urlPattern" to "example.com",
                    "action" to "drop"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("Error"))
            }
        }

        @Test
        fun `invalid action should return error`() {
            runBlocking {
                val result = client.callTool("register_proxy_intercept_rule", mapOf(
                    "name" to "bad-action",
                    "urlPattern" to "test.com",
                    "action" to "invalid"
                ))
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("Error"))
            }
        }

        @Test
        fun `clear rules should remove all rules`() {
            runBlocking {
                client.callTool("register_proxy_intercept_rule", mapOf(
                    "name" to "clear-test",
                    "urlPattern" to "test.com",
                    "action" to "drop"
                ))
                delay(50)

                val clearResult = client.callTool("clear_proxy_intercept_rules", emptyMap())
                delay(100)
                val text = clearResult.expectTextContent()
                assertTrue(text.contains("Cleared"))

                val listResult = client.callTool("list_proxy_intercept_rules", emptyMap())
                delay(100)
                listResult.expectTextContent("No proxy intercept rules registered")
            }
        }
    }
}