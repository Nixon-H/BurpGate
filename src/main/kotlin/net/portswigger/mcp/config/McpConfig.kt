package net.portswigger.mcp.config

import burp.api.montoya.persistence.PersistedObject
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

class McpConfig(storage: PersistedObject) {

    var enabled by storage.boolean(true)
    var configEditingTooling by storage.boolean(false)
    var host by storage.string("127.0.0.1")
    var port by storage.int(9876)
}

fun PersistedObject.boolean(default: Boolean = false) =
    PersistedDelegate(
        getter = { key -> getBoolean(key) ?: default },
        setter = { key, value -> setBoolean(key, value) }
    )

fun PersistedObject.string(default: String) =
    PersistedDelegate(
        getter = { key -> getString(key) ?: default },
        setter = { key, value -> setString(key, value) }
    )

fun PersistedObject.int(default: Int) =
    PersistedDelegate(
        getter = { key -> getInteger(key) ?: default },
        setter = { key, value -> setInteger(key, value) }
    )

class PersistedDelegate<T>(
    private val getter: (name: String) -> T,
    private val setter: (name: String, value: T) -> Unit
) : ReadWriteProperty<Any, T> {
    override fun getValue(thisRef: Any, property: KProperty<*>) = getter(property.name)
    override fun setValue(thisRef: Any, property: KProperty<*>, value: T) = setter(property.name, value)
}