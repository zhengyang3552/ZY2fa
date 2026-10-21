package com.zy2fa.app.core

import android.content.SharedPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * ZY2fa · 保险库（对应 js/vault.js）
 * 账户密钥的落盘持久化，支持可选的 PIN 加密。
 *
 * 存储键下可以有两种信封：
 *   plain : { v, mode: 'plain', accounts: [...] }
 *   pin   : { v, mode: 'pin', kdf: {...}, cipher: { iv, data } }
 *
 * 开启 PIN 后，密钥永不明文落盘：accounts 数据块用 PBKDF2-SHA256 从 PIN 派生的
 * 密钥做 AES-256-GCM 加密。GCM 认证标签兼任 PIN 校验 —— 错误 PIN 表现为解密
 * 失败，而不是与存储哈希比对，因此除 KDF 本身外没有可离线爆破的目标。
 *
 * 【平台差异】
 * - localStorage → SharedPreferences（同一 KV 语义；SharedPreferences 无配额错误，
 *   JS 的 QuotaExceededError 分支不再出现，保留 STORAGE_WRITE 兜底）。
 * - WebCrypto（全部 Promise 化）→ javax.crypto（同步 API）。PBKDF2 21 万次迭代
 *   耗时数百毫秒，因此对外仍以 suspend 函数暴露，内部固定切到 Dispatchers.IO。
 * - btoa/atob → java.util.Base64。
 * - 私有字段 #key 等 → Kotlin private 属性；getter → 计算属性。
 */

class VaultError(val code: String, message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

/** 检测受限存储环境（Android 上基本恒为可用，保留以对齐 JS 行为）。 */
fun isStorageAvailable(): Boolean = true

class Vault(private val prefs: SharedPreferences) {

    companion object {
        const val STORAGE_KEY = "zy2fa.vault.v1"
        const val RECOVERY_PREFIX = "zy2fa.recovered."
        private const val KDF_ITERATIONS = 210_000 // OWASP 2023 对 PBKDF2-HMAC-SHA256 的建议
        private const val CIPHER_AAD = "ZY2fa:v1"
        private const val KEY_BITS = 256
        private const val GCM_TAG_BITS = 128
    }

    /** 上次加载时被丢弃的行（密钥无效等）。 */
    data class VaultIssue(val index: Int, val reason: String)

    data class InitResult(
        val mode: String,
        val accounts: List<Account>,
        val locked: Boolean,
        val issues: List<VaultIssue> = emptyList(),
        val recovered: String? = null,
        val reason: String? = null,
    )

    data class UnlockResult(
        val accounts: List<Account>,
        val issues: List<VaultIssue> = emptyList(),
    )

    private var key: SecretKey? = null
    private var envelope: JSONObject? = null
    private var plainAccounts: List<Account> = emptyList() // plain 模式下已规整的账户
    private var _issues: List<VaultIssue> = emptyList()
    private var _recovered: String? = null

    /** 'plain' | 'pin' | 'empty' */
    val mode: String
        get() {
            val e = envelope ?: return "empty"
            return if (e.optString("mode") == "pin") "pin" else "plain"
        }

    val isLocked: Boolean get() = mode == "pin" && key == null
    val isEncrypted: Boolean get() = mode == "pin"
    val issues: List<VaultIssue> get() = _issues
    val recoveredPayload: String? get() = _recovered

    val updatedAt: Long?
        get() {
            val e = envelope ?: return null
            return if (e.has("updatedAt") && !e.isNull("updatedAt")) e.optLong("updatedAt") else null
        }

    /* -------------------------------------------------------------------- */
    /*  存储读写                                                            */
    /* -------------------------------------------------------------------- */

    private fun readRaw(): String? =
        try {
            prefs.getString(STORAGE_KEY, null)
        } catch (e: Exception) {
            throw VaultError("STORAGE_READ", "无法读取本地存储，请检查浏览器是否禁用了站点数据", e)
        }

    private fun writeRaw(value: String) {
        try {
            prefs.edit().putString(STORAGE_KEY, value).apply()
        } catch (e: Exception) {
            // JS 里此处还区分 QuotaExceededError → 'QUOTA'；SharedPreferences 无配额语义。
            throw VaultError("STORAGE_WRITE", "写入本地存储失败，本次修改未保存", e)
        }
    }

    /* -------------------------------------------------------------------- */
    /*  加密助手                                                            */
    /* -------------------------------------------------------------------- */

    /** PBKDF2-SHA256 派生 AES-256 密钥（同步，调用方需在 IO 线程）。 */
    private fun deriveKey(pin: String, salt: ByteArray, iterations: Int): SecretKey {
        val spec = PBEKeySpec(pin.toCharArray(), salt, iterations, KEY_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
    }

    private fun aesGcm(opmode: Int, key: SecretKey, iv: ByteArray, aad: String, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(opmode, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        return cipher.doFinal(data)
    }

    private fun randomBytes(n: Int): ByteArray = ByteArray(n).also { SecureRandom().nextBytes(it) }

    /* -------------------------------------------------------------------- */
    /*  Vault 本体                                                          */
    /* -------------------------------------------------------------------- */

    /**
     * 从磁盘读入信封。损坏数据绝不抛出 —— 原始值会被隔离保存供用户下载，
     * 保险库以空状态启动。加密保险库返回锁定状态。
     */
    suspend fun init(): InitResult = withContext(Dispatchers.IO) {
        key = null
        _issues = emptyList()
        _recovered = null
        plainAccounts = emptyList()

        val raw = readRaw()
        if (raw == null) {
            envelope = null
            return@withContext InitResult("empty", emptyList(), locked = false)
        }

        val parsed: Any = try {
            if (raw.trimStart().startsWith("[")) JSONArray(raw) else JSONObject(raw)
        } catch (e: JSONException) {
            return@withContext quarantine(raw, "本地数据已损坏，无法解析")
        }

        if (parsed is JSONObject && parsed.optString("mode") == "pin") {
            val kdf = parsed.optJSONObject("kdf")
            val cipher = parsed.optJSONObject("cipher")
            val valid = kdf?.optString("salt")?.isNotEmpty() == true &&
                cipher?.optString("iv")?.isNotEmpty() == true &&
                cipher?.optString("data")?.isNotEmpty() == true &&
                !kdf.optDouble("iterations", Double.NaN).isNaN()
            if (!valid) return@withContext quarantine(raw, "加密数据缺少必要字段")
            envelope = parsed
            return@withContext InitResult("pin", emptyList(), locked = true)
        }

        // plain（或遗留的裸数组）信封。
        val rows: JSONArray = when (parsed) {
            is JSONArray -> parsed
            is JSONObject -> parsed.optJSONArray("accounts")
                ?: return@withContext quarantine(raw, "找不到账户列表")
            else -> return@withContext quarantine(raw, "本地数据格式异常")
        }

        envelope = JSONObject().apply {
            put("v", SCHEMA_VERSION)
            put("mode", "plain")
            put("accounts", JSONArray())
            put(
                "updatedAt",
                if (parsed is JSONObject && parsed.has("updatedAt") && !parsed.isNull("updatedAt"))
                    parsed.optLong("updatedAt") else JSONObject.NULL,
            )
        }

        val accounts = normalizeRows(rows)
        plainAccounts = accounts
        envelope?.put("accounts", JSONArray(accounts.map { Store.accountToPlainJson(it) }))
        InitResult("plain", accounts, locked = false, issues = _issues)
    }

    /** 逐行规整，收集单行失败而不是中止。 */
    private fun normalizeRows(rows: JSONArray): List<Account> {
        val out = mutableListOf<Account>()
        val seen = mutableSetOf<String>()
        for (index in 0 until rows.length()) {
            try {
                val obj = rows.opt(index) as? JSONObject
                    ?: throw ValidationError("account", "账户数据格式不正确")
                val account = Store.normalizeAccount(obj, lenient = true)
                var id = account.id
                if (id in seen) id = "$id-$index"
                seen.add(id)
                out += account.copy(id = id)
            } catch (e: Exception) {
                _issues = _issues + VaultIssue(index, e.message ?: "无法解析")
            }
        }
        return out
    }

    /** 把不可读数据挪到一边；保留可下载副本，然后清空存储位。 */
    private fun quarantine(raw: String, reason: String): InitResult {
        envelope = null
        _recovered = raw
        try {
            prefs.edit()
                .putString("$RECOVERY_PREFIX${System.currentTimeMillis()}", raw)
                .remove(STORAGE_KEY)
                .apply()
        } catch (e: Exception) {
            // 存储不可写；内存中的副本仍可对外提供。
        }
        return InitResult("empty", emptyList(), locked = false, recovered = raw, reason = reason)
    }

    /** 用 PIN 解锁。不匹配时抛 VaultError("PIN_WRONG")。 */
    suspend fun unlock(pin: String): UnlockResult = withContext(Dispatchers.IO) {
        if (mode != "pin") return@withContext UnlockResult(plainAccounts)
        val env = envelope!!
        val kdf = env.optJSONObject("kdf")!!
        val cipher = env.optJSONObject("cipher")!!

        val k = try {
            deriveKey(pin, Utils.base64ToBytes(kdf.optString("salt")), kdf.optInt("iterations"))
        } catch (e: Exception) {
            throw VaultError("NO_WEBCRYPTO", "密钥派生失败，当前环境不支持加密接口", e)
        }

        val plaintext = try {
            aesGcm(
                Cipher.DECRYPT_MODE, k,
                Utils.base64ToBytes(cipher.optString("iv")),
                CIPHER_AAD,
                Utils.base64ToBytes(cipher.optString("data")),
            )
        } catch (e: Exception) {
            // GCM 认证失败（AEADBadTagException）即 PIN 错误。
            throw VaultError("PIN_WRONG", "密码不正确，请重试", e)
        }

        val rows: JSONArray = try {
            val text = String(plaintext, Charsets.UTF_8)
            if (text.trimStart().startsWith("[")) {
                JSONArray(text)
            } else {
                JSONObject(text).optJSONArray("accounts")
                    ?: throw IllegalStateException("missing accounts array")
            }
        } catch (e: IllegalStateException) {
            throw VaultError("CORRUPT", "保险库内容缺少账户列表", e)
        } catch (e: Exception) {
            throw VaultError("CORRUPT", "保险库内容已损坏，无法读取", e)
        }

        key = k
        _issues = emptyList()
        val accounts = normalizeRows(rows)
        UnlockResult(accounts, _issues)
    }

    /** 丢弃内存密钥；磁盘数据不动。 */
    fun lock() {
        key = null
    }

    /** 以当前生效的模式持久化账户。 */
    suspend fun save(accounts: List<Account>): Unit = withContext(Dispatchers.IO) {
        val clean = JSONArray(accounts.map { Store.accountToPlainJson(it) })
        val now = System.currentTimeMillis()

        if (mode == "pin") {
            val k = key ?: throw VaultError("LOCKED", "保险库已锁定，无法保存")
            val iv = randomBytes(12)
            val plaintext = JSONObject().apply {
                put("v", SCHEMA_VERSION)
                put("accounts", clean)
            }.toString().toByteArray(Charsets.UTF_8)
            val ciphertext = aesGcm(Cipher.ENCRYPT_MODE, k, iv, CIPHER_AAD, plaintext)

            val env = JSONObject().apply {
                put("v", SCHEMA_VERSION)
                put("mode", "pin")
                put("kdf", envelope!!.optJSONObject("kdf"))
                put(
                    "cipher",
                    JSONObject().apply {
                        put("alg", "AES-GCM")
                        put("iv", Utils.bytesToBase64(iv))
                        put("data", Utils.bytesToBase64(ciphertext))
                    },
                )
                put("updatedAt", now)
            }
            writeRaw(env.toString())
            envelope = env
            return@withContext
        }

        val env = JSONObject().apply {
            put("v", SCHEMA_VERSION)
            put("mode", "plain")
            put("accounts", clean)
            put("updatedAt", now)
        }
        writeRaw(env.toString())
        envelope = env
    }

    /** 为当前账户开启加密。 */
    suspend fun enablePin(pin: String, accounts: List<Account>): Unit = withContext(Dispatchers.IO) {
        val salt = randomBytes(16)
        val k = deriveKey(pin, salt, KDF_ITERATIONS)

        // 提交前验证密钥可往返加解密，避免 subtly 损坏的加密环境把用户数据锁死。
        // 这里使用全新 IV —— 同一密钥绝不复用 IV。
        val probeIv = randomBytes(12)
        val probe = aesGcm(Cipher.ENCRYPT_MODE, k, probeIv, "probe", "ok".toByteArray(Charsets.UTF_8))
        aesGcm(Cipher.DECRYPT_MODE, k, probeIv, "probe", probe)

        envelope = JSONObject().apply {
            put("v", SCHEMA_VERSION)
            put("mode", "pin")
            put(
                "kdf",
                JSONObject().apply {
                    put("alg", "PBKDF2-SHA256")
                    put("iterations", KDF_ITERATIONS)
                    put("salt", Utils.bytesToBase64(salt))
                },
            )
            put(
                "cipher",
                JSONObject().apply { put("alg", "AES-GCM"); put("iv", ""); put("data", "") },
            )
            put("updatedAt", System.currentTimeMillis())
        }
        key = k
        save(accounts)
    }

    /** 只验证当前 PIN，不做任何修改。 */
    suspend fun verifyPin(pin: String): Boolean = withContext(Dispatchers.IO) {
        if (mode != "pin") return@withContext true
        val env = envelope!!
        val kdf = env.optJSONObject("kdf")!!
        val cipher = env.optJSONObject("cipher")!!
        val k = deriveKey(pin, Utils.base64ToBytes(kdf.optString("salt")), kdf.optInt("iterations"))
        try {
            aesGcm(
                Cipher.DECRYPT_MODE, k,
                Utils.base64ToBytes(cipher.optString("iv")),
                CIPHER_AAD,
                Utils.base64ToBytes(cipher.optString("data")),
            )
            true
        } catch (e: Exception) {
            throw VaultError("PIN_WRONG", "密码不正确，请重试")
        }
    }

    /** 换新 PIN 重新加密（必须先证明旧 PIN）。 */
    suspend fun changePin(currentPin: String, nextPin: String, accounts: List<Account>) {
        verifyPin(currentPin)
        enablePin(nextPin, accounts)
    }

    /** 移除加密；以明文写回账户。 */
    suspend fun disablePin(pin: String, accounts: List<Account>) {
        verifyPin(pin)
        key = null
        envelope = JSONObject().apply {
            put("v", SCHEMA_VERSION)
            put("mode", "plain")
            put("accounts", JSONArray())
            put("updatedAt", System.currentTimeMillis())
        }
        save(accounts)
    }

    /** 删除一切，包括被隔离的数据。 */
    suspend fun wipe(): Unit = withContext(Dispatchers.IO) {
        key = null
        envelope = null
        _recovered = null
        _issues = emptyList()
        plainAccounts = emptyList()
        try {
            val editor = prefs.edit()
            editor.remove(STORAGE_KEY)
            // 先收集再删除，避免遍历时修改键集。
            prefs.all.keys.filter { it.startsWith(RECOVERY_PREFIX) }.forEach(editor::remove)
            editor.apply()
        } catch (e: Exception) {
            throw VaultError("STORAGE_WRITE", "清除本地数据失败", e)
        }
    }

    /** 本应用各键占用的近似字节数。 */
    fun usage(): Double {
        var bytes = 0.0
        val keys = prefs.all.keys.filter { it == STORAGE_KEY || it.startsWith(RECOVERY_PREFIX) }
        for (k in keys) {
            bytes += (k.length + (prefs.getString(k, null)?.length ?: 0)) * 2.0
        }
        return bytes
    }

    fun recoveryCount(): Int =
        prefs.all.keys.count { it.startsWith(RECOVERY_PREFIX) }
}
