package com.zy2fa.app.core

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.text.Collator
import java.time.Instant
import java.util.Locale
import java.util.Objects

/**
 * ZY2fa · 数据模型（对应 js/store.js）
 * 账户记录的校验、规整、迁移、搜索与排序。存储不在这里处理 —— 见 Vault.kt。
 *
 * 【类型差异】JS 的动态对象在 Kotlin 中拆成两类：
 * - 可信形态 → 数据类 [Account]（空安全、不可变）；
 * - 不可信输入（JSON 导入等）→ [JSONObject] + 显式校验，映射回数据类。
 */
data class Account(
    val id: String,
    val issuer: String,
    val label: String,
    val secret: String,
    val algorithm: String = "SHA1",
    val digits: Int = 6,
    val period: Int = 30,
    val createdAt: Long = 0,
    val updatedAt: Long = 0,
    /** 解码后的密钥字节；仅驻内存，永不序列化（对应 JS 附加的 secretBytes 字段）。 */
    val secretBytes: ByteArray? = null,
) {
    // ByteArray 会破坏 data class 默认 equals/hashCode，这里手工按内容实现。
    override fun equals(other: Any?): Boolean =
        other is Account &&
            other.id == id && other.issuer == issuer && other.label == label &&
            other.secret == secret && other.algorithm == algorithm &&
            other.digits == digits && other.period == period &&
            other.createdAt == createdAt && other.updatedAt == updatedAt

    override fun hashCode(): Int = Objects.hash(
        id, issuer, label, secret, algorithm, digits, period, createdAt, updatedAt,
    )
}

class ValidationError(val field: String, message: String) : RuntimeException(message)

object Store {

    const val SCHEMA_VERSION = 1
    const val APP_TAG = "ZY2fa"

    private const val LIMIT_ISSUER = 64
    private const val LIMIT_LABEL = 128
    private const val LIMIT_SECRET = 256
    const val LIMIT_ACCOUNTS = 300

    private fun text(value: Any?, max: Int): String =
        (value?.toString() ?: "").trim().replace(Regex("\\s+"), " ").take(max)

    /* -------------------------------------------------------------------- */
    /*  规整                                                                */
    /* -------------------------------------------------------------------- */

    /**
     * 把不可信记录强制转换为有效账户，失败抛 [ValidationError]。
     * `lenient` 把不可用的可选字段降级为默认值而不是抛出
     * （供导入使用：单个异常字段不应拒绝整份备份）。
     */
    fun normalizeAccount(raw: JSONObject, lenient: Boolean = false): Account {
        val secret = normalizeSecret(raw.opt("secret"))
        if (secret.isEmpty()) throw ValidationError("secret", "密钥不能为空")
        if (secret.length > LIMIT_SECRET) throw ValidationError("secret", "密钥长度超出限制")

        try {
            base32Decode(secret)
        } catch (e: TotpError) {
            if (!lenient) throw ValidationError("secret", e.message ?: "密钥无效")
            throw e
        }

        var issuer = text(raw.opt("issuer"), LIMIT_ISSUER)
        var label = text(raw.opt("label"), LIMIT_LABEL)

        // 两者都没有的记录仍需要可渲染的名字。
        if (issuer.isEmpty() && label.isEmpty()) {
            if (lenient) issuer = "未命名服务"
            else throw ValidationError("issuer", "请填写服务名称")
        }
        if (issuer.isEmpty()) issuer = label

        val algorithmRaw = (raw.optString("algorithm", "SHA1")).uppercase().replace("-", "")
        val algorithm = if (algorithmRaw in ALGORITHMS) algorithmRaw else "SHA1"

        val digitsNum = parseIntLike(raw.opt("digits") ?: 6) ?: 6
        val digits = if (digitsNum in DIGITS) digitsNum else 6

        val periodNum = parseIntLike(raw.opt("period") ?: 30)
        val period = if (periodNum != null) clamp(periodNum, 5, 300) else 30

        val now = System.currentTimeMillis()
        val createdAtRaw = raw.optDouble("createdAt", Double.NaN)
        val createdAt = if (!createdAtRaw.isNaN() && createdAtRaw > 0) createdAtRaw.toLong() else now

        val idRaw = raw.opt("id")
        val id = if (idRaw is String && idRaw.length >= 8) idRaw else uid()

        val updatedAtRaw = raw.optDouble("updatedAt", Double.NaN)
        val updatedAt = if (!updatedAtRaw.isNaN()) updatedAtRaw.toLong() else createdAt

        return Account(
            id = id, issuer = issuer, label = label, secret = secret,
            algorithm = algorithm, digits = digits, period = period,
            createdAt = createdAt, updatedAt = updatedAt,
        )
    }

    /** 便捷重载：直接从 otpauth 解析结果规整（对应 JS 传入普通对象）。 */
    fun normalizeAccount(parsed: OtpAuthParsed, lenient: Boolean = false): Account =
        normalizeAccount(
            JSONObject().apply {
                put("issuer", parsed.issuer)
                put("label", parsed.label)
                put("secret", parsed.secret)
                put("algorithm", parsed.algorithm)
                put("digits", parsed.digits)
                put("period", parsed.period)
            },
            lenient,
        )

    /** 附加解码后的密钥，TOTP 引擎无需每次渲染重新解码。 */
    fun withSecretBytes(account: Account): Account =
        try {
            account.copy(secretBytes = base32Decode(account.secret))
        } catch (e: TotpError) {
            account.copy(secretBytes = null)
        }

    /* -------------------------------------------------------------------- */
    /*  重复与冲突解决                                                       */
    /* -------------------------------------------------------------------- */

    private fun identity(a: Account): String =
        "${a.secret}|${a.issuer.lowercase()}|${a.label.lowercase()}"

    fun findDuplicate(accounts: List<Account>, candidate: Account): Account? =
        accounts.firstOrNull { identity(it) == identity(candidate) }

    /** 同密钥不同标签 —— 几乎总是同一账户被重复导入。 */
    fun findSecretClash(accounts: List<Account>, candidate: Account): Account? =
        accounts.firstOrNull { it.secret == candidate.secret && identity(it) != identity(candidate) }

    /* -------------------------------------------------------------------- */
    /*  查询                                                                */
    /* -------------------------------------------------------------------- */

    data class SortOption(val value: String, val label: String)

    val SORT_OPTIONS: List<SortOption> = listOf(
        SortOption("created", "添加时间"),
        SortOption("name", "名称"),
        SortOption("issuer", "按服务"),
    )

    /**
     * 过滤并排序。
     * 【排序差异】JS 用 Intl.Collator('zh-Hans-CN', {numeric, sensitivity:'base'})；
     * Java Collator 无 numeric 选项，PRIMARY 强度等价于 base 敏感度，
     * 拼音/数字混合排序可能有细微差别。
     */
    fun filterAndSort(accounts: List<Account>, query: String = "", sort: String = "created"): List<Account> {
        val needle = query.trim().lowercase()
        val collator = Collator.getInstance(Locale.SIMPLIFIED_CHINESE).apply {
            strength = Collator.PRIMARY
        }

        val matched = if (needle.isNotEmpty()) {
            accounts.filter {
                it.issuer.lowercase().contains(needle) || it.label.lowercase().contains(needle)
            }
        } else {
            accounts.toList()
        }

        return matched.sortedWith { a, b ->
            when (sort) {
                "name" -> collator.compare(a.issuer, b.issuer).takeIf { it != 0 }
                    ?: collator.compare(a.label, b.label)
                "issuer" -> collator.compare(a.label, b.label).takeIf { it != 0 }
                    ?: collator.compare(a.issuer, b.issuer)
                else -> b.createdAt.compareTo(a.createdAt) // 最新在前
            } ?: 0
        }
    }

    /* -------------------------------------------------------------------- */
    /*  导出                                                                */
    /* -------------------------------------------------------------------- */

    /** 序列化为不含 secretBytes 的纯 JSON（导出/落盘共用）。 */
    fun accountToPlainJson(a: Account): JSONObject = JSONObject().apply {
        put("id", a.id)
        put("issuer", a.issuer)
        put("label", a.label)
        put("secret", a.secret)
        put("algorithm", a.algorithm)
        put("digits", a.digits)
        put("period", a.period)
        put("createdAt", a.createdAt)
        put("updatedAt", a.updatedAt)
    }

    fun buildBackup(accounts: List<Account>): JSONObject = JSONObject().apply {
        put("app", APP_TAG)
        put("version", SCHEMA_VERSION)
        put("exportedAt", Instant.now().toString())
        put("encrypted", false)
        put("count", accounts.size)
        put("accounts", JSONArray(accounts.map { accountToPlainJson(it) }))
    }

    /* -------------------------------------------------------------------- */
    /*  导入                                                                */
    /* -------------------------------------------------------------------- */

    data class SkippedRow(val index: Int, val reason: String)

    data class ImportResult(val accounts: List<Account>, val skipped: List<SkippedRow>)

    data class MergeResult(
        val accounts: List<Account>,
        val added: Int,
        val duplicates: Int,
        val overflow: Int,
    )

    /**
     * 解析多种可能形态的导入内容：
     *   1. ZY2fa 备份对象           { app, accounts: [...] }
     *   2. 通用对象                 { accounts: [...] } / { tokens: [...] }
     *   3. 裸账户对象数组
     *   4. 裸 otpauth:// 字符串数组
     *   5. 按行分隔的 otpauth:// 或 base32 密钥（纯文本导出）
     *
     * 单行失败从不整体抛出 —— 以 skipped + 原因上报，部分有效文件仍可导入。
     */
    fun parseImportPayload(input: String): ImportResult {
        val raw = input.trim()
        if (raw.isEmpty()) throw ValidationError("payload", "导入内容为空")

        val rows: List<Any?> = if (raw.startsWith("[") || raw.startsWith("{")) {
            val parsed: Any = try {
                if (raw.startsWith("[")) JSONArray(raw) else JSONObject(raw)
            } catch (e: JSONException) {
                throw ValidationError("payload", "JSON 解析失败：${e.message}")
            }
            when (parsed) {
                is JSONArray -> (0 until parsed.length()).map { parsed.opt(it) }
                is JSONObject -> {
                    val candidate = parsed.optJSONArray("accounts")
                        ?: parsed.optJSONArray("tokens")
                        ?: parsed.optJSONArray("items")
                    if (candidate == null) {
                        throw ValidationError("payload", "未在文件中找到 accounts 数组")
                    }
                    if (parsed.optBoolean("encrypted")) {
                        throw ValidationError("payload", "该备份已加密，请先解密后再导入")
                    }
                    (0 until candidate.length()).map { candidate.opt(it) }
                }
                else -> throw ValidationError("payload", "无法识别的文件格式")
            }
        } else {
            // 纯文本导出：每行一个 otpauth 链接（或密钥）。
            val lines = raw.split(Regex("\r?\n"))
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
            if (lines.isEmpty()) throw ValidationError("payload", "没有找到可导入的内容")
            lines
        }

        if (rows.size > LIMIT_ACCOUNTS) {
            throw ValidationError("payload", "单次最多导入 $LIMIT_ACCOUNTS 个账户，文件包含 ${rows.size} 个")
        }

        val accounts = mutableListOf<Account>()
        val skipped = mutableListOf<SkippedRow>()

        rows.forEachIndexed { index, row ->
            try {
                when (row) {
                    is String -> {
                        val uri = row.trim()
                        if (uri.isEmpty()) return@forEachIndexed
                        val parsedUri = parseOtpAuthUri(uri)
                        accounts += normalizeAccount(parsedUri, lenient = true)
                    }
                    is JSONObject -> accounts += normalizeAccount(row, lenient = true)
                    else -> throw ValidationError("account", "无法解析")
                }
            } catch (e: Exception) {
                skipped += SkippedRow(index + 1, e.message ?: "无法解析")
            }
        }

        if (accounts.isEmpty()) {
            val detail = if (skipped.isNotEmpty()) "：${skipped[0].reason}" else ""
            throw ValidationError("payload", "没有可导入的有效账户$detail")
        }

        return ImportResult(accounts, skipped)
    }

    /** 将导入账户合并进现有列表，按身份去重。 */
    fun mergeAccounts(existing: List<Account>, incoming: List<Account>): MergeResult {
        val result = existing.toMutableList()
        var added = 0
        var duplicates = 0

        for (candidate in incoming) {
            if (findDuplicate(result, candidate) != null) {
                duplicates += 1
                continue
            }
            if (result.size >= LIMIT_ACCOUNTS) {
                return MergeResult(result, added, duplicates, incoming.size - added - duplicates)
            }
            // 全新 id：导入永远不能覆盖无关的本地记录。
            result += candidate.copy(id = uid(), updatedAt = System.currentTimeMillis())
            added += 1
        }
        return MergeResult(result, added, duplicates, 0)
    }

    /* -------------------------------------------------------------------- */
    /*  PIN 策略                                                            */
    /* -------------------------------------------------------------------- */

    const val PIN_MIN_LENGTH = 6

    fun validatePin(pin: String?, confirm: String? = null): String {
        val value = pin ?: ""
        if (value.isEmpty()) throw ValidationError("pin", "请输入密码")
        if (value.length < PIN_MIN_LENGTH) {
            throw ValidationError("pin", "密码至少需要 $PIN_MIN_LENGTH 位")
        }
        if (value.length > 128) throw ValidationError("pin", "密码过长")
        if (confirm != null && value != confirm) {
            throw ValidationError("confirm", "两次输入的密码不一致")
        }
        return value
    }

    /** 模拟 JS Number.parseInt 语义：取前缀整数，取不到返回 null（等价 NaN）。 */
    fun parseIntLike(value: Any?): Int? {
        if (value == null) return null
        val s = value.toString()
        val m = Regex("\\s*[+-]?\\d+").find(s) ?: return null
        return m.value.trim().toIntOrNull()
    }
}
