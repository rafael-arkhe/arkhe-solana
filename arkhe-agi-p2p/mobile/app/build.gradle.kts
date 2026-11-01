plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}

android {
    namespace = "space.arkhe.mobile"
    compileSdk = 35

    defaultConfig {
        applicationId = "space.arkhe.mobile"
        minSdk = 33
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
