// JVM-only check of the Android app's platform-free Kotlin (ime, security, evidence,
// substrate). Compiles those sources and runs their JUnit tests without an Android SDK,
// so CI can hold them to a test rather than to a description. Android-only code
// (bluetooth/) is excluded; it needs an instrumented run on the device.
plugins {
    kotlin("jvm") version "2.0.21"
}

repositories {
    mavenCentral()
}

val appSrc = layout.projectDirectory.dir("../app/src")

sourceSets {
    main {
        kotlin {
            srcDir(appSrc.dir("main/kotlin"))
            exclude("**/bluetooth/**")
        }
    }
    test {
        kotlin {
            srcDir(appSrc.dir("test/kotlin"))
        }
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

tasks.test {
    testLogging {
        events("passed", "failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
