import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.1.21"
    `java-library`
    `maven-publish`
}

group = "com.e2ecrypto"
version = "1.2.0"   // same protocol version as the e2e-crypto JS package

repositories {
    mavenCentral()
}

dependencies {
    // X25519 + Ed25519 (pure Java, works on every Android version and JVM)
    api("org.bouncycastle:bcprov-jdk18on:1.78.1")
    // JSON (runtime API only, no compiler plugin needed)
    api("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")

    testImplementation(kotlin("test"))
}

java {
    // Java 11 bytecode: usable from Android (AGP 7+) and any JVM 11+
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
    withSourcesJar()
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_11) }
}

tasks.test {
    useJUnitPlatform()
    // Cross-language vectors produced by the JS package (see ../testing/interop)
    systemProperty("interop.vectors", System.getProperty("interop.vectors") ?: "")
    systemProperty("interop.replies", System.getProperty("interop.replies") ?: "")
    testLogging { events("passed", "failed"); showStandardStreams = true }
}

publishing {
    publications {
        create<MavenPublication>("maven") { from(components["java"]) }
    }
}
