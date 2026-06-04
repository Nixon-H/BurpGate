import java.time.Instant

abstract class EmbedProxyJarTask : DefaultTask() {
    @get:InputFile
    abstract val shadowJarFile: RegularFileProperty

    @get:InputDirectory
    abstract val projectDir: DirectoryProperty

    @get:Inject
    abstract val execOperations: ExecOperations

    @TaskAction
    fun embedJar() {
        val shadowJar = shadowJarFile.get().asFile
        val libsDir = projectDir.dir("libs").get().asFile
        val proxyJarFile = File(libsDir, "mcp-proxy-all.jar")

        if (!proxyJarFile.exists()) {
            throw GradleException("Proxy JAR not found at: ${proxyJarFile.absolutePath}")
        }

        execOperations.exec {
            workingDir(projectDir.get().asFile)
            commandLine("jar", "uf", shadowJar.absolutePath, "-C", libsDir.absolutePath, proxyJarFile.name)
        }

        logger.lifecycle("Embedded proxy JAR into ${shadowJar.name}")
    }
}

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ktor)
    java
}

group = providers.gradleProperty("group").get()
version = providers.gradleProperty("version").get()
description = providers.gradleProperty("description").get()

val cveFixes = mapOf(
    "io.netty:netty-codec-http" to libs.versions.netty.get(),
    "io.netty:netty-codec-http2" to libs.versions.netty.get(),
    "io.netty:netty-codec-compression" to libs.versions.netty.get(),
    "io.netty:netty-transport-native-epoll" to libs.versions.netty.get(),
    "org.bouncycastle:bcprov-jdk18on" to libs.versions.bouncycastle.get(),
    "org.bouncycastle:bcpkix-jdk18on" to libs.versions.bouncycastle.get(),
    "org.bouncycastle:bcpg-jdk18on" to libs.versions.bouncycastle.get(),
    "org.apache.logging.log4j:log4j-core" to "2.26.0",
    "com.fasterxml.jackson.core:jackson-core" to "2.18.6",
    "org.codehaus.plexus:plexus-utils" to "4.0.3",
    "io.opentelemetry:opentelemetry-api" to libs.versions.opentelemetry.get()
)

configurations.configureEach {
    resolutionStrategy.eachDependency {
        val fix = cveFixes["${requested.group}:${requested.name}"]
        if (fix != null) {
            useVersion(fix)
        }
    }
}

dependencies {
    compileOnly(libs.burp.montoya.api)

    implementation(libs.bundles.ktor.server)
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.mcp.kotlin.sdk)

    // Ensure Dependabot resolves these CVE-affected deps (also in cveFixes map above)
    compileOnly("org.apache.logging.log4j:log4j-core:2.26.0")
    compileOnly("com.fasterxml.jackson.core:jackson-core:2.18.6")
    compileOnly("org.codehaus.plexus:plexus-utils:4.0.3")

    testImplementation(libs.bundles.test.framework)
    testImplementation(libs.bundles.ktor.test)
    testImplementation(libs.burp.montoya.api)
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(providers.gradleProperty("java.toolchain.version").get().toInt()))
    }
}

kotlin {
    jvmToolchain {
        languageVersion.set(JavaLanguageVersion.of(providers.gradleProperty("java.toolchain.version").get().toInt()))
    }

    compilerOptions {
        apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
        languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        freeCompilerArgs.addAll(
            "-Xjsr305=strict"
        )
    }
}

application {
    mainClass.set("net.portswigger.mcp.ExtensionBase")
}

tasks {
    test {
        useJUnitPlatform()
        systemProperty("file.encoding", "UTF-8")

        testLogging {
            events("passed", "skipped", "failed")
            showExceptions = true
            showCauses = true
            showStackTraces = true
        }
    }

    jar {
        enabled = false
    }

    shadowJar {
        archiveClassifier.set("")
        mergeServiceFiles()

        manifest {
            attributes(
                mapOf(
                    "Implementation-Title" to project.name,
                    "Implementation-Version" to project.version,
                    "Built-By" to System.getProperty("user.name"),
                    "Built-Date" to Instant.now().toString(),
                    "Built-JDK" to "${System.getProperty("java.version")} (${System.getProperty("java.vendor")} ${
                        System.getProperty("java.vm.version")
                    })",
                    "Created-By" to "Gradle ${gradle.gradleVersion}"
                )
            )
        }


        exclude("META-INF/*.SF")
        exclude("META-INF/*.DSA")
        exclude("META-INF/*.RSA")
        exclude("META-INF/INDEX.LIST")
        exclude("META-INF/DEPENDENCIES")
        exclude("META-INF/NOTICE*")
        exclude("META-INF/LICENSE*")
        exclude("module-info.class")

        duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    }

    register<EmbedProxyJarTask>("embedProxyJar") {
        group = "build"
        description = "Embeds the MCP proxy JAR into the shadow JAR"
        dependsOn(shadowJar)
        shadowJarFile.set(shadowJar.flatMap { it.archiveFile })
        projectDir.set(layout.projectDirectory)
    }

    build {
        dependsOn(shadowJar)
    }

    withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }
}

tasks.wrapper {
    gradleVersion = "9.2.0"
    distributionType = Wrapper.DistributionType.BIN
}