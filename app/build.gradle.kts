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

    // Release signing credentials must be provided via environment variables or gradle properties.
    // Credentials and keystores are never hardcoded or tracked in version control.
    val releaseKeystorePath: String? = System.getenv("RELEASE_KEYSTORE_PATH")
        ?: project.findProperty("RELEASE_KEYSTORE_PATH") as? String
    val releaseKeystorePassword: String? = System.getenv("RELEASE_KEYSTORE_PASSWORD")
        ?: project.findProperty("RELEASE_KEYSTORE_PASSWORD") as? String
    val releaseKeyAlias: String? = System.getenv("RELEASE_KEY_ALIAS")
        ?: project.findProperty("RELEASE_KEY_ALIAS") as? String
    val releaseKeyPassword: String? = System.getenv("RELEASE_KEY_PASSWORD")
        ?: project.findProperty("RELEASE_KEY_PASSWORD") as? String

    val isReleaseSigningConfigured = !releaseKeystorePath.isNullOrEmpty() &&
            !releaseKeystorePassword.isNullOrEmpty() &&
            !releaseKeyAlias.isNullOrEmpty() &&
            !releaseKeyPassword.isNullOrEmpty() &&
            file(releaseKeystorePath).exists()

    signingConfigs {
        if (isReleaseSigningConfigured) {
            create("release") {
                storeFile = file(releaseKeystorePath!!)
                storePassword = releaseKeystorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
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
            if (isReleaseSigningConfigured) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
        debug {
            // Standard debug signing identity; never sign debug builds with production keys
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
