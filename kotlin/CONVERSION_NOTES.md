# JavaScript → Kotlin 转换说明

将 `js/` 下的 6 个文件（约 3000 行）转换为面向 **Android** 的 Kotlin 代码，
功能逻辑与行为保持一致，并按 Kotlin 惯用写法重写。

## 文件对照

| 源文件 (js/) | 目标 (kotlin/app/src/main/java/com/zy2fa/app/) | 说明 |
|---|---|---|
| `utils.js` | `core/Utils.kt` | `object Utils` 单例；btoa/atob→Base64，execCommand→ClipboardManager，Blob 下载→MediaStore |
| `totp.js` | `core/Totp.kt` | WebCrypto HMAC→`javax.crypto.Mac`；错误类→`TotpError(code, message)` |
| `store.js` | `core/Store.kt` | 动态对象→`data class Account`；JSON 校验→`JSONObject` + 显式规整 |
| `vault.js` | `core/Vault.kt` | localStorage→SharedPreferences；AES-GCM/PBKDF2→`javax.crypto` |
| `ui.js` | `ui/Ui.kt` | `<dialog>`→MaterialAlertDialog，snackbar→Snackbar，下拉菜单→PopupMenu |
| `app.js` | `app/AppController.kt` | 状态机/业务逻辑 1:1；DOM 渲染→RecyclerView Adapter；setInterval→协程循环 |

## 主要差异说明

### 1. 类型系统
- JS 的 `number` 拆分为 `Int`（秒数、位数）、`Long`（时间戳、TOTP counter）、`Double`（字节统计）。
  JS 用 `Number.isSafeInteger` 守护的 2^53 范围，Kotlin 的 `Long` 天然满足。
- `null` / `undefined` 统一为可空类型 `String?` + 空安全调用（`?.`、`?:`），编译期即可发现空指针。
- JS 随手传的普通对象拆成两类：**可信形态 → 数据类**（`Account`、`TotpResult`、`StepInfo`、
  `OtpAuthParsed` 等，自动获得 equals/copy/destructuring）；**不可信输入 → `JSONObject`**，
  经 `normalizeAccount` 显式校验后映射为数据类。
- `class XxxError extends Error` → 继承 `RuntimeException` 的专用异常类，并携带机器可读的 `code`/`field` 字段。
- `Object.freeze` 常量 → `val` + 不可变 `List`/`Map`；私有字段 `#key` → `private var`。
- `data class` 中含 `ByteArray` 时需手工重写 equals/hashCode（见 `Account`）。

### 2. 异步处理
- **WebCrypto 全部是 Promise**（importKey/deriveKey/encrypt/decrypt），因此 JS 的
  `totp.js` 与 `vault.js` 全是 async 函数。JVM 的 `javax.crypto` 是**同步 API**：
  - 纯计算（HOTP/HMAC）退化为普通函数，不再需要 async；
  - PBKDF2（21 万次迭代）与磁盘读写较慢，`Vault` 对外仍保留 `suspend` 签名，
    内部固定 `withContext(Dispatchers.IO)`，调用方语义与 JS 版一致。
- `new Promise(resolve => ...)` 的 `confirmDialog` 用
  `suspendCancellableCoroutine` + `MaterialAlertDialogBuilder` 实现，Esc/外部点击同样返回 false。
- `setInterval(tick, 200)` → 协程 `while (isActive) { delay(200); tick() }`，随 `scope.cancel()` 一并停止。
- 回调式 DOM 事件（addEventListener）→ Android 监听器；业务回调统一 `scope.launch` 进主协程。
- JS 的 `inFlight` Set 防并发与 `commit()` 快照回滚逻辑原样保留（协程下依然正确）。

### 3. 平台映射
- localStorage → SharedPreferences；`QuotaExceededError` 分支在 Android 无对应语义，保留兜底。
- hash 路由（`#/codes`）→ 底部导航项点击直接调 `setRoute()`；`document.hidden` → Activity 生命周期。
- `Intl.Collator('zh-Hans-CN')` → `java.text.Collator`（无 numeric 选项，PRIMARY≈base 敏感度）。
- `crypto.randomUUID()` → `UUID.randomUUID()`；`URL`/`URLSearchParams` → `android.net.Uri`
  （Uri 不抛解析异常、自动百分号解码，个别错误分支保留为防御性代码）。

## 构建（Gradle 依赖参考）

```kotlin
// app/build.gradle.kts
dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
```

需要配套的 XML 资源：`item_account_card`、`item_banner`、`dialog_account`、`dialog_pin`，
元素 id 与 JS 版 `index.html` 一一对应（代码中已按同名 id 引用）。
