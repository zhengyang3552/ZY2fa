package com.zy2fa.app.core

import android.net.Uri
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.floor
import kotlin.math.pow

/**
 * ZY2fa · TOTP 引擎（RFC 6238）+ otpauth:// 解析（Key Uri Format）
 * 对应 js/totp.js。
 *
 * 【异步差异】JS 版因 WebCrypto 的 importKey/sign 全是 Promise 而必须 async/await；
 * JVM 的 javax.crypto.Mac 是同步 API，因此这里全部退化为普通函数，
 * 调用方（如 UI）如需避免卡顿可自行包一层 withContext(Dispatchers.Default)。
 * generateHOTP/generateTOTP 仍提供 suspend 包装，保持与 JS 版一致的调用形态。
 */

/** 错误携带机器可读的 code 与可直接展示给用户的消息。 */
class TotpError(val code: String, message: String) : RuntimeException(message)

const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

val ALGORITHMS: List<String> = listOf("SHA1", "SHA256", "SHA512")
val DIGITS: List<Int> = listOf(6, 8)
val PERIODS: List<Int> = listOf(30, 60)

// 对应 WEB_CRYPTO_NAMES；JVM 的 Mac 实例名带 Hmac 前缀。
private val MAC_NAMES = mapOf("SHA1" to "HmacSHA1", "SHA256" to "HmacSHA256", "SHA512" to "HmacSHA512")

/* ------------------------------------------------------------------------ */
/*  Base32                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * 规整用户输入的密钥：去空格/横线/填充，转大写。
 * 返回落盘使用的规范 base32 形式（无填充）。
 */
fun normalizeSecret(input: Any?): String =
    (input?.toString() ?: "")
        .replace(Regex("[\\s\\-_]"), "")
        .replace(Regex("=+$"), "")
        .uppercase()

/** 解码 RFC 4648 base32，拒绝一切歧义输入。 */
fun base32Decode(input: Any?): ByteArray {
    val clean = normalizeSecret(input)
    if (clean.isEmpty()) throw TotpError("SECRET_EMPTY", "密钥不能为空")

    val invalid = clean.firstOrNull { it !in 'A'..'Z' && it !in '2'..'7' }
    if (invalid != null) {
        throw TotpError("SECRET_CHARSET", "密钥包含无效字符「$invalid」，base32 只允许 A–Z 和 2–7")
    }

    // 8 个 base32 字符 → 5 字节；更短的串熵不足 25 位。
    if (clean.length < 8) {
        throw TotpError("SECRET_SHORT", "密钥太短，至少需要 8 位字符")
    }

    val byteLength = floor(clean.length * 5.0 / 8).toInt()
    val bytes = ByteArray(byteLength)
    var buffer = 0
    var bits = 0
    var offset = 0

    for (ch in clean) {
        // 与 JS 相同：只保留未消费的低位，防止 32 位位移溢出。
        buffer = (buffer shl 5) or BASE32_ALPHABET.indexOf(ch)
        bits += 5
        if (bits >= 8) {
            bits -= 8
            bytes[offset] = ((buffer ushr bits) and 0xff).toByte()
            offset += 1
            buffer &= (1 shl bits) - 1
        }
    }
    return bytes
}

/* ------------------------------------------------------------------------ */
/*  TOTP                                                                    */
/* ------------------------------------------------------------------------ */

// 对应 hmacKeyCache：以「算法:完整密钥」为键缓存派生好的 HMAC 密钥。
// JVM 上 SecretKeySpec 构造成本很低，缓存只是为了保持与 JS 版相同的行为边界。
private val hmacKeyCache = ConcurrentHashMap<String, SecretKeySpec>()

private fun importHmacKey(secretBytes: ByteArray, algorithm: String): SecretKeySpec {
    val cacheKey = "$algorithm:${secretBytes.joinToString(".") { (it.toInt() and 0xff).toString() }}"
    hmacKeyCache[cacheKey]?.let { return it }

    val key = SecretKeySpec(secretBytes, MAC_NAMES.getValue(algorithm))
    if (hmacKeyCache.size > 64) hmacKeyCache.clear()
    hmacKeyCache[cacheKey] = key
    return key
}

/** HOTP 单参数集（对应 JS 解构参数对象）。 */
data class HotpParams(
    val secretBytes: ByteArray,
    val algorithm: String = "SHA1",
    val digits: Int = 6,
)

/** 指定计数器的 HOTP（RFC 4226 §5.3 动态截断）。 */
fun generateHOTP(params: HotpParams, counter: Long): String {
    if (counter < 0) throw TotpError("BAD_COUNTER", "无效的时间计数器")
    if (MAC_NAMES[params.algorithm] == null) {
        throw TotpError("BAD_ALGORITHM", "不支持的哈希算法：${params.algorithm}")
    }
    if (params.digits !in DIGITS) {
        throw TotpError("BAD_DIGITS", "验证码位数只支持 6 或 8，收到 ${params.digits}")
    }

    val mac = Mac.getInstance(MAC_NAMES.getValue(params.algorithm))
    mac.init(importHmacKey(params.secretBytes, params.algorithm))

    // JS 手工拆高低 32 位；JVM 直接用 8 字节大端 long（Number.isSafeInteger 范围内等价）。
    val message = ByteBuffer.allocate(8).putLong(counter).array()
    val signature = mac.doFinal(message)

    val offset = (signature[signature.size - 1].toInt() and 0x0f)
    val binary =
        ((signature[offset].toInt() and 0x7f) shl 24) or
        ((signature[offset + 1].toInt() and 0xff) shl 16) or
        ((signature[offset + 2].toInt() and 0xff) shl 8) or
        (signature[offset + 3].toInt() and 0xff)

    return (binary % 10.0.pow(params.digits).toLong())
        .toString()
        .padStart(params.digits, '0')
}

/** 某一时刻的时间步计数。 */
data class StepInfo(val counter: Long, val remaining: Int)

fun stepAt(period: Int, timestampMs: Long = System.currentTimeMillis()): StepInfo {
    val seconds = floor(timestampMs / 1000.0).toLong()
    return StepInfo(
        counter = seconds / period,
        remaining = (period - (seconds % period)).toInt(),
    )
}

/** TOTP 计算结果（对应 JS 返回的普通对象）。 */
data class TotpResult(val code: String, val counter: Long, val remaining: Int, val period: Int)

/** 当前账户的 TOTP。 */
suspend fun generateTOTP(account: Account, timestampMs: Long = System.currentTimeMillis()): TotpResult {
    val secretBytes = account.secretBytes
    if (secretBytes == null || secretBytes.isEmpty()) {
        throw TotpError("SECRET_EMPTY", "账户缺少密钥")
    }
    val period = account.period
    if (period <= 0) throw TotpError("BAD_PERIOD", "无效的时间步长")

    val step = stepAt(period, timestampMs)
    val code = generateHOTP(HotpParams(secretBytes, account.algorithm, account.digits), step.counter)
    return TotpResult(code, step.counter, step.remaining, period)
}

/* ------------------------------------------------------------------------ */
/*  otpauth:// 解析                                                          */
/* ------------------------------------------------------------------------ */

private val OTPAUTH_RE = Regex("^otpauth://", RegexOption.IGNORE_CASE)
private val BARE_SECRET_RE = Regex("^[A-Za-z2-7\\s\\-=_]+$")

/**
 * 模拟 JS 的 safeDecode：decodeURIComponent 失败时回退原样。
 * Android 的 Uri 解析不抛异常，这里保留防御性写法以对齐行为。
 */
private fun safeDecode(value: String?): String = value ?: ""

/** otpauth 解析结果（对应 JS 返回对象，warnings 保留原有中文文案）。 */
data class OtpAuthParsed(
    val issuer: String,
    val label: String,
    val secret: String,
    val algorithm: String,
    val digits: Int,
    val period: Int,
    val warnings: List<String>,
)

/** 模拟 JS Number.parseInt：取前缀整数，取不到返回 null（等价于 NaN）。 */
private fun parseIntLike(value: String?): Int? {
    val m = Regex("\\s*[+-]?\\d+").find(value ?: return null) ?: return null
    return m.value.trim().toIntOrNull()
}

/**
 * 解析 `otpauth://totp/...` 链接或裸 base32 密钥。
 *
 * 【解析差异】JS 用 WHATWG `new URL()` + URLSearchParams；Android 用 android.net.Uri。
 * Uri 解析不会抛异常、且路径/查询参数自动做百分号解码（JS 需手工 safeDecode），
 * 因此错误分支与 '+'→空格 的处理略有差异，已在对应位置注释说明。
 */
fun parseOtpAuthUri(raw: Any?): OtpAuthParsed {
    val text = (raw?.toString() ?: "").trim()
    if (text.isEmpty()) {
        throw TotpError("URI_EMPTY", "请粘贴 otpauth:// 链接或密钥")
    }

    // 裸密钥是常见粘贴内容；接受它以便用户从只展示密钥的服务添加账户。
    if (!OTPAUTH_RE.containsMatchIn(text) && !text.contains("://") && BARE_SECRET_RE.matches(text)) {
        val secret = normalizeSecret(text)
        base32Decode(secret) // 校验字符集 + 长度
        return OtpAuthParsed(
            issuer = "", label = "", secret = secret,
            algorithm = "SHA1", digits = 6, period = 30,
            warnings = listOf("未识别到链接格式，已按纯密钥处理；请手动补全名称"),
        )
    }

    if (!OTPAUTH_RE.containsMatchIn(text)) {
        throw TotpError("URI_SCHEME", "链接格式不正确，应以 otpauth://totp/ 开头")
    }

    // Android 的 Uri.parse 几乎不抛异常（JS new URL 会抛 TypeError）。
    // JS 里 URI_INVALID 分支在此保留为防御性代码。
    val url = Uri.parse(text)

    val type = (url.host ?: "").lowercase()
    if (type == "hotp") {
        throw TotpError("URI_HOTP", "本应用只支持基于时间的 TOTP，暂不支持 HOTP 计数器模式")
    }
    if (type != "totp") {
        throw TotpError("URI_TYPE", "不支持的验证类型：otpauth://$type")
    }

    val secret = normalizeSecret(url.getQueryParameter("secret"))
    if (secret.isEmpty()) {
        throw TotpError("URI_NO_SECRET", "链接中缺少 secret 参数")
    }
    val secretBytes = base32Decode(secret) // 字符集/长度非法时抛出

    // Android 的 Uri.path 已解码，等价于 JS 的 safeDecode(url.pathname)。
    val rawLabel = (url.path ?: "").removePrefix("/")
    val warnings = mutableListOf<String>()

    // 标签可能是 "Issuer:account" 或纯 "account"。
    var issuer = url.getQueryParameter("issuer")?.trim().orEmpty()
    var label = rawLabel
    val separator = rawLabel.indexOf(':')
    if (separator >= 0) {
        val labelIssuer = rawLabel.take(separator).trim()
        label = rawLabel.substring(separator + 1).trim()
        if (issuer.isEmpty() && labelIssuer.isNotEmpty()) issuer = labelIssuer
        else if (issuer.isNotEmpty() && labelIssuer.isNotEmpty() && issuer != labelIssuer) {
            warnings.add("链接中的发行方名称前后不一致，已采用 issuer 参数")
        }
    }
    if (issuer.isEmpty()) issuer = "未命名服务"

    val algorithmParam = (url.getQueryParameter("algorithm") ?: "SHA1").uppercase().replace("-", "")
    val algorithm = if (algorithmParam in ALGORITHMS) algorithmParam else "SHA1"
    if (algorithmParam !in ALGORITHMS) {
        warnings.add("未知算法「${url.getQueryParameter("algorithm")}」，已回退为 SHA1")
    }

    val digitsParam = parseIntLike(url.getQueryParameter("digits") ?: "6")
    val digits = if (digitsParam != null && digitsParam in DIGITS) digitsParam else 6
    if (digitsParam == null || digitsParam !in DIGITS) {
        warnings.add("不支持的位数「${url.getQueryParameter("digits")}」，已回退为 6 位")
    }

    val periodParam = parseIntLike(url.getQueryParameter("period") ?: "30")
    val period = if (periodParam != null && periodParam > 0 && periodParam <= 300) periodParam else 30
    if (period != periodParam) {
        warnings.add("不支持的时间步长「${url.getQueryParameter("period")}」，已回退为 30 秒")
    }
    if (secretBytes.size < 10) {
        warnings.add("密钥长度偏短（不足 80 位），该账户的安全性可能较弱")
    }

    return OtpAuthParsed(issuer, label, secret, algorithm, digits, period, warnings)
}

/** 由账户构建可分享的 otpauth URI（导出用）。 */
fun buildOtpAuthUri(account: Account): String {
    val name = if (account.label.isNotEmpty()) "${account.issuer}:${account.label}" else account.issuer
    // 用 Uri.encode(x, "") 逐段编码，等价于 JS 的 encodeURIComponent（保留字符集一致）。
    val params = mutableListOf<String>()
    params += "secret=" + Uri.encode(account.secret, "")
    if (account.issuer.isNotEmpty()) params += "issuer=" + Uri.encode(account.issuer, "")
    if (account.algorithm.isNotEmpty() && account.algorithm != "SHA1") {
        params += "algorithm=" + Uri.encode(account.algorithm, "")
    }
    if (account.digits != 0 && account.digits != 6) params += "digits=${account.digits}"
    if (account.period != 0 && account.period != 30) params += "period=${account.period}"
    val query = if (params.isEmpty()) "" else "?" + params.joinToString("&")
    return "otpauth://totp/${Uri.encode(name, "")}$query"
}
