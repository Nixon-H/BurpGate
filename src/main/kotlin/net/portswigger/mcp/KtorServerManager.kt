package net.portswigger.mcp.server

import burp.api.montoya.MontoyaApi
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.modelcontextprotocol.kotlin.sdk.Implementation
import io.modelcontextprotocol.kotlin.sdk.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import net.portswigger.mcp.ServerManager
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.registerTools
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class KtorServerManager(private val api: MontoyaApi) : ServerManager {

    private var server: EmbeddedServer<*, *>? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    override fun start(config: McpConfig, callback: (ServerState) -> Unit) {
        callback(ServerState.Starting)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null

                val mcpServer = Server(
                    serverInfo = Implementation("burp-suite", "1.0.0"),
                    options = ServerOptions(
                        capabilities = ServerCapabilities(
                            tools = ServerCapabilities.Tools(listChanged = false)
                        )
                    )
                )

                server = embeddedServer(Netty, port = config.port, host = config.host) {
                    mcp {
                        mcpServer
                    }

                    mcpServer.registerTools(api, config)
                }.apply {
                    start(wait = false)
                }

                api.logging().logToOutput("Started MCP server on ${config.host}:${config.port}")
                callback(ServerState.Running)

            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun stop(callback: (ServerState) -> Unit) {
        callback(ServerState.Stopping)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null
                api.logging().logToOutput("Stopped MCP server")
                callback(ServerState.Stopped)
            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun shutdown() {
        stop { }
        executor.shutdown()
        executor.awaitTermination(10, TimeUnit.SECONDS)
    }
}