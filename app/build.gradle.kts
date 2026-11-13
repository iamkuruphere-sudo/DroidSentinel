import java.io.File

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.fullstopsolution.droidsentinel"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.fullstopsolution.droidsentinel"
        minSdk = 33
        targetSdk = 37
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    val releaseStoreFile = providers.environmentVariable("RELEASE_STORE_FILE").orNull
    val releaseStoreFilePath = releaseStoreFile?.let { file(it).absolutePath }
    val releaseStorePassword = providers.environmentVariable("RELEASE_STORE_PASSWORD").orNull
    val releaseKeyAlias = providers.environmentVariable("RELEASE_KEY_ALIAS").orNull
    val releaseKeyPassword = providers.environmentVariable("RELEASE_KEY_PASSWORD").orNull
    val releaseSigningConfigured = listOf(
        releaseStoreFile,
        releaseStorePassword,
        releaseKeyAlias,
        releaseKeyPassword
    ).all { !it.isNullOrBlank() }

    if (releaseSigningConfigured) {
        signingConfigs {
            create("release") {
                storeFile = File(requireNotNull(releaseStoreFilePath))
                storePassword = requireNotNull(releaseStorePassword)
                keyAlias = requireNotNull(releaseKeyAlias)
                keyPassword = requireNotNull(releaseKeyPassword)
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
                enableV4Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (releaseSigningConfigured) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    tasks.configureEach {
        if (name == "preReleaseBuild") {
            doFirst {
                check(releaseSigningConfigured) {
                    "Release signing is not configured. Set RELEASE_STORE_FILE, RELEASE_STORE_PASSWORD, " +
                        "RELEASE_KEY_ALIAS, and RELEASE_KEY_PASSWORD in the protected build environment."
                }
                check(File(requireNotNull(releaseStoreFilePath)).isFile) {
                    "Release keystore not found at RELEASE_STORE_FILE. Provide the protected keystore file."
                }
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)

    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}
