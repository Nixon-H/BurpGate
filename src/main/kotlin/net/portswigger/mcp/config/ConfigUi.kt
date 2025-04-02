package net.portswigger.mcp.config

import io.ktor.util.network.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.Swing
import net.portswigger.mcp.providers.Provider
import java.awt.*
import java.awt.Component.CENTER_ALIGNMENT
import java.awt.event.ItemEvent
import javax.swing.*
import javax.swing.BorderFactory.createEmptyBorder
import javax.swing.Box.*
import javax.swing.JOptionPane.*
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import kotlin.concurrent.thread

class ConfigUi(private val config: McpConfig, private val providers: List<Provider>) {

    class WarningLabel(content: String = "") : JLabel(content) {
        init {
            foreground = UIManager.getColor("Burp.warningBarBackground")
            isVisible = false
            alignmentX = Component.LEFT_ALIGNMENT
        }

        override fun updateUI() {
            super.updateUI()
            foreground = UIManager.getColor("Burp.warningBarBackground")
        }
    }

    private val panel = JPanel(BorderLayout())
    val component: JComponent get() = panel

    private val enabledCheckBox = JCheckBox("Enabled").apply { alignmentX = Component.LEFT_ALIGNMENT }
    private val validationErrorLabel = WarningLabel()

    private val hostField = JTextField(15)
    private val portField = JTextField(5)
    private val reinstallNotice = WarningLabel("Make sure to reinstall after changing server settings")

    private var toggleListener: ((Boolean) -> Unit)? = null
    private var suppressToggleEvents: Boolean = false
    private var installationAvailable: Boolean = false

    init {
        enabledCheckBox.isSelected = config.enabled
        hostField.text = config.host
        portField.text = config.port.toString()

        buildUi()

        enabledCheckBox.addItemListener {
            if (suppressToggleEvents) {
                return@addItemListener
            }

            val checked = it.stateChange == ItemEvent.SELECTED

            if (checked) {
                val error = getValidationError()

                if (error != null) {
                    validationErrorLabel.text = error
                    validationErrorLabel.isVisible = true

                    suppressToggleEvents = true
                    enabledCheckBox.isSelected = false
                    suppressToggleEvents = false
                    return@addItemListener
                }
            }

            validationErrorLabel.isVisible = false

            toggleListener?.invoke(checked)
        }

        trackChanges(hostField)
        trackChanges(portField)
    }

    fun onEnabledToggled(listener: (Boolean) -> Unit) {
        toggleListener = listener
    }

    fun getConfig(): McpConfig {
        config.host = hostField.text
        config.port = hostField.text.toIntOrNull() ?: config.port
        return config
    }

    fun updateServerState(state: ServerState) {
        CoroutineScope(Dispatchers.Swing).launch {
            suppressToggleEvents = true

            val enableAdvancedOptions = state is ServerState.Stopped || state is ServerState.Failed

            hostField.isEnabled = enableAdvancedOptions
            portField.isEnabled = enableAdvancedOptions

            installationAvailable = false

            when (state) {
                ServerState.Starting, ServerState.Stopping -> {
                    enabledCheckBox.isEnabled = false
                }

                ServerState.Running -> {
                    enabledCheckBox.isEnabled = true
                    enabledCheckBox.isSelected = true

                    installationAvailable = true
                }

                ServerState.Stopped -> {
                    enabledCheckBox.isEnabled = true
                    enabledCheckBox.isSelected = false
                }

                is ServerState.Failed -> {
                    enabledCheckBox.isEnabled = true
                    enabledCheckBox.isSelected = false

                    val friendlyMessage = when (state.exception) {
                        is UnresolvedAddressException -> "Unable to resolve address"
                        else -> state.exception.message ?: state.exception.javaClass.simpleName
                    }

                    showMessageDialog(
                        panel,
                        "Failed to start Burp MCP server: $friendlyMessage",
                        "Error",
                        ERROR_MESSAGE
                    )
                }
            }

            suppressToggleEvents = false
        }
    }

    private fun getValidationError(): String? {
        val host = hostField.text.trim()
        val port = portField.text.trim().toIntOrNull()

        if (host.isBlank() || !host.matches(Regex("^[a-zA-Z0-9.-]+$"))) {
            return "Host must be a non-empty alphanumeric string"
        }

        if (port == null) {
            return "Port must be a valid number"
        }

        if (port < 1024 || port > 65535) {
            return "Port is not within valid range"
        }

        return null
    }

    private fun trackChanges(field: JTextField) {
        field.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent?) = handle()
            override fun removeUpdate(e: DocumentEvent?) = handle()
            override fun changedUpdate(e: DocumentEvent?) = handle()
            fun handle() {
                reinstallNotice.isVisible = true
            }
        })
    }

    private fun buildUi() {
        val leftPanel = JPanel(GridBagLayout())

        val headerBox = createVerticalBox().apply {
            add(object : JLabel("Burp MCP Server") {
                init {
                    font = font.deriveFont(Font.BOLD, 24f)
                    alignmentX = CENTER_ALIGNMENT
                }

                override fun getForeground() = UIManager.getColor("Burp.burpTitle")
            })
            add(createVerticalStrut(25))
            add(JLabel("Burp MCP Server exposes Burp tooling to AI clients.").apply {
                alignmentX = CENTER_ALIGNMENT
            })
            add(createVerticalStrut(15))
            add(
                Anchor(
                    text = "Learn more about the Model Context Protocol",
                    url = "https://modelcontextprotocol.io/introduction"
                ).apply { alignmentX = CENTER_ALIGNMENT }
            )
        }

        leftPanel.add(headerBox)

        val rightPanel = object : JPanel() {
            init {
                applyStyles()
            }

            override fun updateUI() {
                super.updateUI()
                applyStyles()
            }

            private fun applyStyles() {
                background = UIManager.getColor("Burp.backgrounder")
            }
        }.apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            border = createEmptyBorder(15, 15, 15, 15)
        }

        val configEditingToolingCheckBox = JCheckBox("Enable tools that can edit your config").apply {
            alignmentX = Component.LEFT_ALIGNMENT
            isSelected = config.configEditingTooling
            addItemListener { event -> config.configEditingTooling = event.stateChange == ItemEvent.SELECTED }
        }

        rightPanel.add(enabledCheckBox)
        rightPanel.add(createVerticalStrut(10))
        rightPanel.add(configEditingToolingCheckBox)
        rightPanel.add(validationErrorLabel)
        rightPanel.add(createVerticalStrut(15))

        val advancedPanel = JPanel(GridBagLayout()).apply {
            border = BorderFactory.createTitledBorder("Advanced options")
            isOpaque = false
        }

        val gbc = GridBagConstraints().apply {
            insets = Insets(5, 5, 5, 5)
            anchor = GridBagConstraints.WEST
        }

        advancedPanel.add(JLabel("Server host:"), gbc)
        gbc.gridx = 1
        advancedPanel.add(hostField, gbc)

        gbc.gridx = 0
        gbc.gridy = 1
        advancedPanel.add(JLabel("Server port:"), gbc)
        gbc.gridx = 1
        advancedPanel.add(portField, gbc)

        val advancedWrapper = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply {
            isOpaque = false
            add(advancedPanel)
            alignmentX = Component.LEFT_ALIGNMENT
        }

        rightPanel.add(advancedWrapper)
        rightPanel.add(createVerticalGlue())
        rightPanel.add(reinstallNotice)
        rightPanel.add(createVerticalStrut(10))

        val installOptions = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.X_AXIS)
            alignmentX = Component.LEFT_ALIGNMENT
            isOpaque = false
        }

        providers.forEach { provider ->
            val item = JButton(provider.installButtonText)
            item.addActionListener {
                if (!installationAvailable) {
                    showMessageDialog(
                        panel,
                        "Please start the Burp MCP server first.",
                        "Burp MCP server",
                        INFORMATION_MESSAGE
                    )
                    return@addActionListener
                }
                thread {
                    try {
                        val result = provider.install(config)
                        CoroutineScope(Dispatchers.Swing).launch {
                            reinstallNotice.isVisible = false

                            if (result != null) {
                                showMessageDialog(
                                    panel,
                                    result,
                                    "Burp MCP server",
                                    INFORMATION_MESSAGE
                                )
                            }
                        }
                    } catch (e: Exception) {
                        CoroutineScope(Dispatchers.Swing).launch {
                            showMessageDialog(
                                panel,
                                "Failed to install for ${provider.name}: ${e.message ?: e.javaClass.simpleName}",
                                "${provider.name} install",
                                ERROR_MESSAGE
                            )
                        }
                    }
                }
            }
            installOptions.add(item)
            installOptions.add(createHorizontalStrut(10))
        }

        installOptions.add(
            Anchor(
                text = "Manual install steps",
                url = "https://github.com/PortSwigger/mcp-server?tab=readme-ov-file#manual-installations"
            )
        )
        installOptions.maximumSize = installOptions.preferredSize

        rightPanel.add(installOptions)

        val columnsPanel = JPanel(GridBagLayout())
        val c = GridBagConstraints().apply {
            fill = GridBagConstraints.BOTH
            weighty = 1.0
        }

        c.gridx = 0
        c.gridy = 0
        c.weightx = 0.35
        columnsPanel.add(leftPanel, c)

        c.gridx = 1
        c.weightx = 0.65
        columnsPanel.add(rightPanel, c)

        panel.add(columnsPanel, BorderLayout.CENTER)
    }
}