plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.zy.twofa"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.zy.twofa"
        // minSdk 26：直接使用自适应图标（无需多套位图资源），
        // WebViewAssetLoader 与现代 WebView 特性也已足够
        minSdk = 26
        targetSdk = 34
        // 固定版本号：发版时手动递增（与 package.json 的 version 同步）
        versionCode = 1
        versionName = "1.0.0"
    }

    // 固定发布签名：与 ZYEmail / RemoteFileManager / ZYNotificationHistory 共用
    // 同一个 keystore（KEYSTORE_PATH 等环境变量由 CI 从 Actions Secrets 注入）。
    // 本地未设置 KEYSTORE_PATH 时不启用签名配置，debug/unsigned 构建不受影响。
    signingConfigs {
        create("release") {
            val ksPath = System.getenv("KEYSTORE_PATH")
            if (ksPath != null) {
                storeFile = file(ksPath)
                storePassword = System.getenv("KEYSTORE_PASSWORD") ?: ""
                keyAlias = System.getenv("KEY_ALIAS") ?: ""
                keyPassword = System.getenv("KEY_PASSWORD") ?: ""
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // 仅在提供签名文件时启用固定签名，保证所有版本的签名证书一致，
            // 用户可以稳定地覆盖安装与升级（配置方法见 docs/SIGNING.md）。
            if (System.getenv("KEYSTORE_PATH") != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = false
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.webkit:webkit:1.8.0")
}
