package net.portswigger.mcp.providers

import burp.api.montoya.logging.Logging
import kotlinx.serialization.json.*
import net.portswigger.mcp.config.McpConfig
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import javax.swing.JFileChooser
import kotlin.io.path.exists
import kotlin.io.path.isDirectory
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.name
import kotlin.io.path.readText
import kotlin.io.path.writeText

interface Provider {
    val name: String
    val installButtonText: String
    val confirmationText: String?
    fun install(config: McpConfig): String?
}

class ClaudeDesktopProvider(private val logging: Logging, private val proxyJarManager: ProxyJarManager) : Provider {

    private val claudeConfigFileName = "claude_desktop_config.json"
    private val serverName = "burp"

    override val name = "Claude Desktop"
    override val installButtonText = "Install to $name"
    override val confirmationText =
        "Install to $name?\nThis will create an entry within $name's MCP configuration file ($claudeConfigFileName)"

    override fun install(config: McpConfig): String {
        val proxyJarFile = proxyJarManager.getProxyJar()

        val path = configFilePath() ?: error("Could not find Claude config path")
        val content = Json.parseToJsonElement(path.readText()).jsonObject.toMutableMap()

        val javaPath = javaPath()
        logging.logToOutput("Using Java from: $javaPath")

        val sseUrl = "http://${config.host}:${config.port}"
        val burpServerConfig = buildJsonObject {
            put("command", JsonPrimitive(javaPath))
            put("args", buildJsonArray {
                add(JsonPrimitive("-jar"))
                add(JsonPrimitive(proxyJarFile.toString()))
                add(JsonPrimitive("--sse-url"))
                add(JsonPrimitive(sseUrl))
            })
        }

        val mcpServers = content["mcpServers"]?.jsonObject?.toMutableMap() ?: mutableMapOf()
        mcpServers[serverName] = burpServerConfig
        content["mcpServers"] = JsonObject(mcpServers)

        val json = Json {
            prettyPrint = true
            encodeDefaults = true
        }
        path.writeText(json.encodeToString(JsonObject.serializer(), JsonObject(content)))

        logging.logToOutput("Installed Burp MCP Server to Claude Desktop config")

        return "Installation successful. Please restart $name if it is currently running."
    }

    private fun configFilePath(): Path? {
        val os = System.getProperty("os.name").lowercase()
        val home = System.getProperty("user.home")

        val candidatePaths = when {
            os.contains("win") -> windowsCandidatePaths(home)
            os.contains("mac") || os.contains("darwin") -> listOf(
                Path.of(home, "Library", "Application Support", "Claude")
            )
            os.contains("linux") -> listOf(Path.of(home, ".config", "Claude"))
            else -> return null
        }

        val existingPaths = candidatePaths.filter { it.exists() }
        if (existingPaths.size > 1) {
            logging.logToOutput("Warning: multiple Claude Desktop config directories found; using ${existingPaths.first()}: $existingPaths")
        }
        val basePath = existingPaths.firstOrNull() ?: return null

        val configFile = basePath.resolve(claudeConfigFileName)
        if (!configFile.exists()) {
            createDefaultConfig(configFile)
        }

        return configFile
    }

    internal fun windowsCandidatePaths(home: String): List<Path> {
        val traditional = Path.of(home, "AppData", "Roaming", "Claude")

        // Windows Store installs place config under a package directory with a random suffix:
        // AppData\Local\Packages\Claude_<suffix>\LocalCache\Roaming\Claude
        val packagesDir = Path.of(home, "AppData", "Local", "Packages")
        val storePaths = if (packagesDir.exists()) {
            packagesDir.listDirectoryEntries()
                .filter { it.isDirectory() && it.name.startsWith("Claude_") }
                .map { it.resolve("LocalCache").resolve("Roaming").resolve("Claude") }
        } else {
            emptyList()
        }

        return listOf(traditional) + storePaths
    }

    private fun createDefaultConfig(path: Path): Boolean {
        try {
            val defaultConfig = buildJsonObject {
                put("mcpServers", buildJsonObject {})
            }

            val json = Json {
                prettyPrint = true
                encodeDefaults = true
            }

            path.writeText(json.encodeToString(JsonObject.serializer(), defaultConfig))
            logging.logToOutput("Created default Claude Desktop config at $path")
            return true
        } catch (e: Exception) {
            logging.logToError("Failed to create default Claude Desktop config: ${e.message}")
            return false
        }
    }

    private fun javaPath(): String {
        val javaHome = System.getProperty("java.home")
        val os = System.getProperty("os.name").lowercase()

        return if (os.contains("win")) {
            "$javaHome\\bin\\java.exe"
        } else {
            "$javaHome/bin/java"
        }
    }
}

class ManualProxyInstallerProvider(private val logging: Logging, private val proxyJarManager: ProxyJarManager) :
    Provider {
    override val name = "Proxy jar"
    override val installButtonText = "Extract server proxy jar"
    override val confirmationText = null

    override fun install(config: McpConfig): String? {
        val proxyJarFile = proxyJarManager.getProxyJar()

        val fileChooser = JFileChooser().apply {
            dialogTitle = "Save proxy jar"
            selectedFile = File("mcp-proxy.jar")
        }

        if (fileChooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) {
            return null
        }

        val destinationFile = fileChooser.selectedFile
        try {
            Files.copy(proxyJarFile, destinationFile.toPath(), StandardCopyOption.REPLACE_EXISTING)
            logging.logToOutput("MCP proxy jar saved successfully to ${destinationFile.absolutePath}")
        } catch (ex: Exception) {
            logging.logToError("Failed to save installer: ${ex.message}")
            throw ex
        }

        return "Extracted proxy jar to $destinationFile"
    }
}

class ClaudeCodeCliProvider(private val logging: Logging, private val proxyJarManager: ProxyJarManager) : Provider {

    override val name = "Claude Code CLI"
    override val installButtonText = "Install to $name"
    override val confirmationText = "Install to $name?\nThis will add Burp's MCP server via `claude mcp add`."

    override fun install(config: McpConfig): String {
        val proxyJarFile = proxyJarManager.getProxyJar()
        val sseUrl = "http://${config.host}:${config.port}"

        val claudeCmd = findClaudeCommand() ?: error("claude command not found on PATH")
        val javaPath = javaPath()

        val process = ProcessBuilder(
            claudeCmd, "mcp", "add", "burp",
            "--", javaPath, "-jar", proxyJarFile.toString(), "--sse-url", sseUrl
        ).redirectErrorStream(true).start()

        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        logging.logToOutput("claude mcp add output: $output")

        if (exitCode != 0) {
            error("Failed to install: $output")
        }

        return "Installation successful. Burp MCP server is now available in Claude Code CLI.\nRestart Claude Code if currently running."
    }

    private fun findClaudeCommand(): String? {
        val path = System.getenv("PATH") ?: return null
        for (dir in path.split(File.pathSeparator)) {
            val cmd = File(dir, "claude")
            if (cmd.exists()) return cmd.absolutePath
            val cmdExe = File(dir, "claude.exe")
            if (cmdExe.exists()) return cmdExe.absolutePath
        }
        return null
    }

    private fun javaPath(): String {
        val javaHome = System.getProperty("java.home")
        return if (System.getProperty("os.name").lowercase().contains("win")) {
            "$javaHome\\bin\\java.exe"
        } else {
            "$javaHome/bin/java"
        }
    }
}

class OpencodeProvider(private val logging: Logging, private val proxyJarManager: ProxyJarManager) : Provider {

    override val name = "Opencode"
    override val installButtonText = "Install to $name"
    override val confirmationText = "Install to $name?\nThis will add Burp's MCP server to opencode's global config."

    override fun install(config: McpConfig): String {
        val proxyJarFile = proxyJarManager.getProxyJar()
        val sseUrl = "http://${config.host}:${config.port}"
        val javaPath = javaPath()

        val configDir = Path.of(System.getProperty("user.home"), ".config", "opencode")
        Files.createDirectories(configDir)
        val configFile = configDir.resolve("opencode.json")

        val existing = if (configFile.exists()) {
            try {
                Json.parseToJsonElement(configFile.readText()).jsonObject.toMutableMap()
            } catch (_: Exception) {
                mutableMapOf()
            }
        } else {
            mutableMapOf()
        }

        val mcpSection = (existing["mcp"]?.jsonObject?.toMutableMap() ?: mutableMapOf()).toMutableMap()
        mcpSection["burp"] = buildJsonObject {
            put("type", JsonPrimitive("local"))
            put("command", buildJsonArray {
                add(JsonPrimitive(javaPath))
                add(JsonPrimitive("-jar"))
                add(JsonPrimitive(proxyJarFile.toString()))
                add(JsonPrimitive("--sse-url"))
                add(JsonPrimitive(sseUrl))
            })
            put("enabled", JsonPrimitive(true))
        }
        existing["mcp"] = JsonObject(mcpSection)

        if ("\$schema" !in existing) {
            existing["\$schema"] = JsonPrimitive("https://opencode.ai/config.json")
        }

        val json = Json {
            prettyPrint = true
            encodeDefaults = true
        }
        configFile.writeText(json.encodeToString(JsonObject.serializer(), JsonObject(existing)))

        logging.logToOutput("Installed Burp MCP Server to Opencode config at $configFile")
        return "Installation successful. Restart Opencode for changes to take effect."
    }

    private fun javaPath(): String {
        val javaHome = System.getProperty("java.home")
        return if (System.getProperty("os.name").lowercase().contains("win")) {
            "$javaHome\\bin\\java.exe"
        } else {
            "$javaHome/bin/java"
        }
    }
}