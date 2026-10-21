// ZY2fa Android 壳工程：把纯前端的 2FA 应用打包成完全离线的 App。
// 插件版本与 ZYEmail / RemoteFileManager 保持一致（AGP 8.2.0 + Kotlin 1.9.23）。
buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:8.2.0")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.23")
    }
}

tasks.register("clean", Delete::class) {
    delete(rootProject.layout.buildDirectory)
}
