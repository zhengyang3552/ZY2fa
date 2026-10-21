package com.zy2fa.app.core

import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.util.Base64
import kotlinx.coroutines.delay
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.floor
import kotlin.math.ln

/**
 * ZY2fa · 通用工具（对应 js/utils.js）
 *
 * JS 是无类型脚本 + DOM 环境；Kotlin 是静态类型 + Android View 环境。
 * - DOM 查询助手（$/$$）在 Android 中没有对应物，由 View 系统与 findViewById 取代，故不保留。
 * - clipboard/execCommand 回退链在 Android 上不需要：ClipboardManager 是唯一且可靠的方式。
 * - btoa/atob 换成 android.util.Base64。
 */
object Utils {

    /* -------------------------------------------------------------- 转义 */

    /** 转义将拼入 HTML 模板的文本（Android 上仅用于 WebView/导出场景）。 */
    fun esc(value: Any?): String {
        val s = value?.toString() ?: ""
        val sb = StringBuilder(s.length)
        for (ch in s) {
            when (ch) {
                '&' -> sb.append("&amp;")
                '<' -> sb.append("&lt;")
                '>' -> sb.append("&gt;")
                '"' -> sb.append("&quot;")
                '\'' -> sb.append("&#39;")
                else -> sb.append(ch)
            }
        }
        return sb.toString()
    }

    /* --------------------------------------------------------------- id */

    /** 对应 crypto.randomUUID()：Android 上 UUID.randomUUID() 即 v4 随机 UUID。 */
    fun uid(): String = java.util.UUID.randomUUID().toString()

    /* ----------------------------------------------------------- 格式化 */

    /** "123456" → "123 456"，帮助肉眼分段。 */
    fun groupCode(code: String?): String {
        val value = code ?: ""
        val mid = (value.length + 1) / 2   // Math.ceil(len/2)
        return "${value.take(mid)} ${value.drop(mid)}".trim()
    }

    /** 账户头像的至多两个首字母。 */
    fun initials(issuer: String?, label: String?): String {
        val source = (issuer?.takeIf { it.isNotEmpty() } ?: label ?: "?").trim()
        if (source.isEmpty()) return "?"
        val words = source.split(Regex("[\\s\\-_.@]+")).filter { it.isNotEmpty() }
        if (words.size >= 2) {
            return (words[0].first().toString() + words[1].first().toString()).uppercase()
        }
        return source.take(2).uppercase()
    }

    fun formatBytes(bytes: Double): String {
        if (bytes.isNaN() || bytes.isInfinite() || bytes <= 0) return "0 B"
        val units = arrayOf("B", "KB", "MB")
        val i = minOf(units.size - 1, floor(ln(bytes) / ln(1024.0)).toInt())
        val value = bytes / 1024.0.pow(i)
        return if (value >= 10 || i == 0) "${value.toLong()} ${units[i]}"
        else "%.1f %s".format(Locale.US, value, units[i])
    }

    fun formatRelative(ts: Long?): String {
        if (ts == null || ts == 0L) return "—"
        val diff = System.currentTimeMillis() - ts
        if (diff < 60_000) return "刚刚"
        if (diff < 3_600_000) return "${diff / 60_000} 分钟前"
        if (diff < 86_400_000) return "${diff / 3_600_000} 小时前"
        val days = diff / 86_400_000
        if (days < 30) return "$days 天前"
        // 对应 new Date(ts).toLocaleDateString('zh-CN')
        val fmt = SimpleDateFormat("yyyy/M/d", Locale.CHINA)
        return fmt.format(Date(ts))
    }

    /* -------------------------------------------------------------- 杂项 */

    fun clamp(v: Int, lo: Int, hi: Int): Int = minOf(hi, maxOf(lo, v))

    /**
     * 尾沿防抖。JS 用闭包 + setTimeout；Kotlin 用 Handler.postDelayed，
     * 返回一个新的 () -> Unit，多次调用只保留最后一次。
     */
    fun debounce(wait: Long = 160, action: () -> Unit): () -> Unit {
        val handler = Handler(Looper.getMainLooper())
        var pending: Runnable? = null
        return {
            pending?.let(handler::removeCallbacks)
            val r = Runnable { action() }
            pending = r
            handler.postDelayed(r, wait)
        }
    }

    /** 对应 sleep(ms) = new Promise(r => setTimeout(r, ms))。 */
    suspend fun sleep(ms: Long) = delay(ms)

    /** 粗略 PIN 强度：0-4。长度主导，字符多样性加成。 */
    fun pinStrength(pin: String?): Int {
        val value = pin ?: ""
        if (value.isEmpty()) return 0
        if (Regex("^\\d+$").containsMatchIn(value)) {
            return when {
                value.length < 6 -> 1
                value.length < 8 -> 2
                value.length < 12 -> 3
                else -> 4
            }
        }
        var score = if (value.length >= 6) 2 else 1
        if (value.length >= 10) score += 1
        if (Regex("[^A-Za-z0-9]").containsMatchIn(value) ||
            (Regex("[A-Z]").containsMatchIn(value) && Regex("[a-z]").containsMatchIn(value))
        ) score += 1
        return clamp(score, 0, 4)
    }

    /* ----------------------------------------------------------- 剪贴板 */

    /**
     * 复制文本。JS 需要在 async Clipboard API 与 execCommand 回退之间切换；
     * Android 只需 ClipboardManager（主线程调用），失败时抛出可读异常。
     */
    fun copyText(context: Context, text: String?) {
        val value = text ?: ""
        if (value.isEmpty()) throw IllegalStateException("没有可复制的内容")
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        try {
            cm.setPrimaryClip(ClipData.newPlainText("ZY2fa", value))
        } catch (e: Exception) {
            throw IllegalStateException("复制失败，请手动选择文本复制", e)
        }
    }

    /* ----------------------------------------------------------- 下载 */

    /**
     * 对应 downloadFile()：JS 用 Blob + 隐形 <a> 点击；Android 用 MediaStore
     * 写入系统「下载」目录（API 29+），旧版本回退到应用私有 Downloads 目录。
     */
    fun downloadFile(context: Context, filename: String, content: String, mime: String = "application/json") {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, filename)
                put(MediaStore.Downloads.MIME_TYPE, mime)
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val uri = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: throw IllegalStateException("无法创建下载文件")
            context.contentResolver.openOutputStream(uri)?.use { out ->
                out.write(content.toByteArray(Charsets.UTF_8))
            } ?: throw IllegalStateException("无法写入下载文件")
            values.clear()
            values.put(MediaStore.Downloads.IS_PENDING, 0)
            context.contentResolver.update(uri, values, null, null)
        } else {
            val dir = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
                ?: context.filesDir
            File(dir, filename).writeText(content, Charsets.UTF_8)
        }
    }

    /* ----------------------------------------------------------- base64 */

    fun bytesToBase64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)

    fun base64ToBytes(b64: String?): ByteArray =
        Base64.decode(b64 ?: "", Base64.DEFAULT)

    private fun Double.pow(n: Int): Double = Math.pow(this, n.toDouble())
}
