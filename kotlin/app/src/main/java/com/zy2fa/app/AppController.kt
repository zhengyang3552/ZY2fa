package com.zy2fa.app

import android.app.Activity
import android.content.SharedPreferences
import android.content.res.Configuration
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.view.isVisible
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.zy2fa.app.core.*
import com.zy2fa.app.ui.MenuItemSpec
import com.zy2fa.app.ui.ToastVariant
import com.zy2fa.app.ui.Ui
import kotlinx.coroutines.*
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * ZY2fa · 应用控制器（对应 js/app.js）
 *
 * 持有状态、渲染与事件绑定。所有持久化走 [Vault]；所有加密走 core/Totp。
 *
 * 【架构映射】
 * - DOM 渲染 → RecyclerView + ViewHolder（index.html 的标记假定已镜像为
 *   R.layout.item_account_card / dialog_account / dialog_pin，元素 id 与 JS 版一致）。
 * - hash 路由（#/codes 等） → 底部导航点击直接调 setRoute()，state.route 语义不变。
 * - setInterval(tick, 200) → 协程循环 while(isActive) { delay(200); tick() }。
 * - document.hidden / visibilitychange → Activity 生命周期回调 onAppHidden/onAppVisible。
 * - 键盘快捷键（'/'、Ctrl+K、'n'） → 触屏设备无对应物，省略。
 * - localStorage 偏好 → 独立的 prefs（THEME/AUTOLOCK），与保险库存储分离。
 */
class AppController(
    private val activity: AppCompatActivity,
    private val prefs: SharedPreferences,      // 主题/自动锁等偏好
    vaultPrefs: SharedPreferences,             // 保险库存储（对应 localStorage）
) {
    companion object {
        private const val THEME_KEY = "zy2fa.theme"
        private const val AUTOLOCK_KEY = "zy2fa.autolock"
        private const val AUTO_LOCK_MS = 5 * 60 * 1000L
        private const val TICK_MS = 200L
        private const val EXPIRING_AT = 10  // 进入警告态的剩余秒数
        private const val CRITICAL_AT = 5   // 进入危急态的剩余秒数
        private val THEME_LABELS = mapOf("light" to "浅色", "dark" to "深色", "system" to "跟随系统")
        private val ROUTES = listOf("codes", "backup", "settings")
    }

    /* ------------------------------------------------------------------ */
    /*  状态                                                              */
    /* ------------------------------------------------------------------ */

    private data class CachedCode(
        val code: String,
        val counter: Long,
        var remaining: Int,
        val error: String? = null,
    )

    private data class Notice(
        val id: String,
        val variant: String,
        val message: String,
        val action: String? = null,
        val onAction: (() -> Unit)? = null,
    )

    private class State {
        var accounts: List<Account> = emptyList()
        var query: String = ""
        var sort: String = "created"
        var theme: String = "system"
        var route: String = "codes"
        var pinMode: String = "enable"
        var editingId: String? = null
        val codes = mutableMapOf<String, CachedCode>()   // accountId → 缓存验证码
        val inFlight = mutableSetOf<String>()
        val notices = mutableListOf<Notice>()
        var booted = false
        var hiddenAt: Long? = null
        var autoLock = false
    }

    private val state = State()
    private val noticeDismissed = mutableSetOf<String>()
    private val draft = object { var algorithm = "SHA1"; var digits = 6 } // 新增/编辑表单草稿

    private val vault = Vault(vaultPrefs)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var tickJob: Job? = null

    /* ------------------------------------------------------------------ */
    /*  视图绑定（假定 XML id 与 index.html 元素一一对应）                  */
    /* ------------------------------------------------------------------ */

    private class Views(a: Activity) {
        val root: View = a.findViewById(android.R.id.content)
        val appBar: View = a.findViewById(R.id.appBar)
        val appBody: View = a.findViewById(R.id.appBody)
        val gate: View = a.findViewById(R.id.gate)
        val gatePin: EditText = a.findViewById(R.id.gatePin)
        val gateSubmit: Button = a.findViewById(R.id.gateSubmit)
        val gateError: TextView = a.findViewById(R.id.gateError)
        val gateReset: Button = a.findViewById(R.id.gateReset)
        val accountList: RecyclerView = a.findViewById(R.id.accountList)
        val emptyState: View = a.findViewById(R.id.emptyState)
        val emptyTitle: TextView = a.findViewById(R.id.emptyTitle)
        val emptyDesc: TextView = a.findViewById(R.id.emptyDesc)
        val emptyImport: Button = a.findViewById(R.id.emptyImport)
        val emptyAdd: Button = a.findViewById(R.id.emptyAdd)
        val codesSummary: TextView = a.findViewById(R.id.codesSummary)
        val countLabel: TextView = a.findViewById(R.id.countLabel)
        val searchInput: EditText = a.findViewById(R.id.searchInput)
        val searchClear: View = a.findViewById(R.id.searchClear)
        val noticeSlot: LinearLayout = a.findViewById(R.id.noticeSlot)
        val btnSort: View = a.findViewById(R.id.btnSort)
        val sortLabel: TextView = a.findViewById(R.id.sortLabel)
        val btnAdd: View = a.findViewById(R.id.btnAdd)
        val btnTheme: View = a.findViewById(R.id.btnTheme)
        val btnLockTop: View = a.findViewById(R.id.btnLockTop)
        val encBadge: View = a.findViewById(R.id.encBadge)
        val themeSegmented: ViewGroup = a.findViewById(R.id.themeSegmented)
        val themeHint: TextView = a.findViewById(R.id.themeHint)
        // 账户编辑对话框（自定义视图）
        val accountDialogView: View = a.layoutInflater.inflate(R.layout.dialog_account, null)
        val dlgAccountTitle: TextView = accountDialogView.findViewById(R.id.dlgAccountTitle)
        val uriInput: EditText = accountDialogView.findViewById(R.id.uriInput)
        val issuerInput: EditText = accountDialogView.findViewById(R.id.issuerInput)
        val labelInput: EditText = accountDialogView.findViewById(R.id.labelInput)
        val secretInput: EditText = accountDialogView.findViewById(R.id.secretInput)
        val periodInput: EditText = accountDialogView.findViewById(R.id.periodInput)
        val algoSegmented: ViewGroup = accountDialogView.findViewById(R.id.algoSegmented)
        val digitsSegmented: ViewGroup = accountDialogView.findViewById(R.id.digitsSegmented)
        val previewBox: View = accountDialogView.findViewById(R.id.previewBox)
        val previewText: TextView = accountDialogView.findViewById(R.id.previewText)
        val btnSaveAccount: Button = accountDialogView.findViewById(R.id.btnSaveAccount)
        val btnParseUri: Button = accountDialogView.findViewById(R.id.btnParseUri)
        val btnToggleSecret: View = accountDialogView.findViewById(R.id.btnToggleSecret)
        // PIN 对话框
        val pinDialogView: View = a.layoutInflater.inflate(R.layout.dialog_pin, null)
        val pinTitle: TextView = pinDialogView.findViewById(R.id.dlgPinTitle)
        val pinSubtitle: TextView = pinDialogView.findViewById(R.id.dlgPinSubtitle)
        val currentPinField: View = pinDialogView.findViewById(R.id.currentPinField)
        val currentPin: EditText = pinDialogView.findViewById(R.id.currentPin)
        val newPinField: View = pinDialogView.findViewById(R.id.newPinField)
        val newPin: EditText = pinDialogView.findViewById(R.id.newPin)
        val confirmPinField: View = pinDialogView.findViewById(R.id.confirmPinField)
        val confirmPin: EditText = pinDialogView.findViewById(R.id.confirmPin)
        val pinStrength: View = pinDialogView.findViewById(R.id.pinStrength)
        val pinWarning: View = pinDialogView.findViewById(R.id.pinWarning)
        val btnConfirmPin: Button = pinDialogView.findViewById(R.id.btnConfirmPin)
        // 备份 / 设置页
        val statAccounts: TextView = a.findViewById(R.id.statAccounts)
        val statEncrypted: TextView = a.findViewById(R.id.statEncrypted)
        val statUsage: TextView = a.findViewById(R.id.statUsage)
        val statUpdated: TextView = a.findViewById(R.id.statUpdated)
        val pinHint: TextView = a.findViewById(R.id.pinHint)
        val btnPinPrimary: Button = a.findViewById(R.id.btnPinPrimary)
        val btnLockNow: View = a.findViewById(R.id.btnLockNow)
        val autoLockToggle: android.widget.Switch = a.findViewById(R.id.autoLockToggle)
        val dataCountHint: TextView = a.findViewById(R.id.dataCountHint)
        val dataCountBadge: TextView = a.findViewById(R.id.dataCountBadge)
        val btnWipe: Button = a.findViewById(R.id.btnWipe)
        val importText: EditText = a.findViewById(R.id.importText)
        val btnImport: Button = a.findViewById(R.id.btnImport)
        val btnImportClear: View = a.findViewById(R.id.btnImportClear)
        val btnExportFile: View = a.findViewById(R.id.btnExportFile)
        val btnExportClipboard: View = a.findViewById(R.id.btnExportClipboard)
        val btnExportUris: View = a.findViewById(R.id.btnExportUris)
        val viewCodes: View = a.findViewById(R.id.viewCodes)
        val viewBackup: View = a.findViewById(R.id.viewBackup)
        val viewSettings: View = a.findViewById(R.id.viewSettings)
        val navItems: List<View> = listOf(a.findViewById(R.id.navCodes), a.findViewById(R.id.navBackup), a.findViewById(R.id.navSettings))
    }

    private val v = Views(activity)
    private val adapter = AccountAdapter()
    private var accountDialog: androidx.appcompat.app.AlertDialog? = null
    private var pinDialog: androidx.appcompat.app.AlertDialog? = null

    // 解锁失败退避（对应 gateAttempts / gateRateUntil 顶层变量）。
    private var gateAttempts = 0
    private var gateRateUntil = 0L

    /* ------------------------------------------------------------------ */
    /*  小助手                                                            */
    /* ------------------------------------------------------------------ */

    private fun findAccount(id: String?): Account? = state.accounts.firstOrNull { it.id == id }

    private fun storageGet(key: String): String? =
        try { prefs.getString(key, null) } catch (e: Exception) { null }

    private fun storageSet(key: String, value: String) {
        try { prefs.edit().putString(key, value).apply() } catch (e: Exception) { /* 偏好尽力而为 */ }
    }

    private fun nowSecondsLeft(period: Int): Int = stepAt(period).remaining

    /** 用于检测添加重复密钥的指纹。 */
    private fun describeAccount(a: Account): String =
        if (a.label.isNotEmpty()) "${a.issuer} · ${a.label}" else a.issuer

    private fun toast(message: String, variant: ToastVariant = ToastVariant.DEFAULT,
                      action: String? = null, onAction: (() -> Unit)? = null) =
        Ui.toast(v.root, message, variant, action, onAction)

    /* ------------------------------------------------------------------ */
    /*  主题                                                              */
    /* ------------------------------------------------------------------ */

    private fun applyTheme(theme: String, persist: Boolean = true) {
        val value = if (theme in THEME_LABELS) theme else "system"
        state.theme = value

        // 对应 documentElement.dataset.theme；AppCompat 以 DayNight 全局处理。
        AppCompatDelegate.setDefaultNightMode(
            when (value) {
                "light" -> AppCompatDelegate.MODE_NIGHT_NO
                "dark" -> AppCompatDelegate.MODE_NIGHT_YES
                else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
            },
        )

        if (persist) storageSet(THEME_KEY, value)

        val systemDark = (activity.resources.configuration.uiMode and
            Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        v.themeHint.text = if (value == "system") {
            "跟随系统（当前为${if (systemDark) "深色" else "浅色"}）"
        } else {
            "固定为${THEME_LABELS[value]}模式"
        }

        syncSegmented(v.themeSegmented, value)
        v.btnTheme.contentDescription = "切换外观（当前：${THEME_LABELS[value]}）"
    }

    private fun initTheme() {
        applyTheme(storageGet(THEME_KEY) ?: "system", persist = false)
        // 对应 matchMedia('(prefers-color-scheme: dark)').addEventListener('change')：
        // DayNight 模式下系统随 uiMode 配置自动切换，无需手工监听。

        v.themeSegmented.children().forEach { btn ->
            btn.setOnClickListener {
                applyTheme(btn.tag?.toString() ?: "system")
                toast("外观已切换为${THEME_LABELS[state.theme]}")
            }
        }

        v.btnTheme.setOnClickListener {
            Ui.openMenu(v.btnTheme, listOf(
                MenuItemSpec("浅色", onSelect = { applyTheme("light") }),
                MenuItemSpec("深色", onSelect = { applyTheme("dark") }),
                MenuItemSpec("跟随系统", onSelect = { applyTheme("system") }),
            ))
        }
    }

    /* ------------------------------------------------------------------ */
    /*  通知横幅（持久 banner）                                            */
    /* ------------------------------------------------------------------ */

    private fun addNotice(id: String, variant: String = "info", message: String,
                          action: String? = null, onAction: (() -> Unit)? = null) {
        if (id in noticeDismissed) return
        if (state.notices.any { it.id == id }) return
        state.notices += Notice(id, variant, message, action, onAction)
    }

    private fun renderNotices() {
        v.noticeSlot.removeAllViews()
        state.notices.forEach { n ->
            val row = activity.layoutInflater.inflate(R.layout.item_banner, v.noticeSlot, false)
            row.findViewById<TextView>(R.id.bannerText).text = n.message
            row.findViewById<View>(R.id.bannerAction)?.apply {
                isVisible = n.action != null
                (this as? Button)?.text = n.action
                setOnClickListener { n.onAction?.invoke() }
            }
            row.findViewById<View>(R.id.bannerDismiss).setOnClickListener {
                noticeDismissed.add(n.id)
                state.notices.removeAll { it.id == n.id }
                renderNotices()
            }
            v.noticeSlot.addView(row)
        }
    }

    /* ------------------------------------------------------------------ */
    /*  卡片渲染                                                          */
    /* ------------------------------------------------------------------ */

    /** 完整重绘一张卡片（从缓存的验证码状态）。 */
    private fun paintCard(account: Account) {
        val holder = adapter.holderFor(account.id) ?: return

        val cached = state.codes[account.id]
        if (cached == null || cached.code.isEmpty()) {
            holder.codeValue.text = if (cached?.error != null) "— — —" else "··· ···"
            holder.seconds.text = "--"
            holder.itemView.isActivated = false
            holder.itemView.alpha = 1f
            return
        }

        holder.codeValue.text = Utils.groupCode(cached.code)
        holder.itemView.contentDescription =
            "复制 ${describeAccount(account)} 的验证码 ${cached.code.toCharArray().joinToString(" ")}"

        // 重绘时重新推导相位：卡片可能在步长中途被重建（搜索/排序/切页），
        // JS 通过负 animation-delay 让环形动画seek到正确偏移；
        // Android 上直接以剩余秒数驱动文本与状态色（环形进度同理按剩余比例设置）。
        val remaining = stepAt(account.period).remaining
        paintCountdown(holder, account, remaining)
    }

    private fun paintCountdown(holder: AccountAdapter.CardHolder, account: Account, remaining: Int) {
        if (holder.seconds.text.toString() != remaining.toString()) {
            holder.seconds.text = remaining.toString()
            holder.itemView.contentDescription = "剩余 $remaining 秒刷新"
        }
        val critical = remaining <= CRITICAL_AT
        val expiring = !critical && remaining <= EXPIRING_AT
        // 对应 li.classList.toggle('is-critical'/'is-expiring')；以 alpha 表达紧急程度。
        holder.itemView.alpha = when {
            critical -> 0.75f
            expiring -> 0.9f
            else -> 1f
        }
    }

    private fun renderList() {
        val visible = Store.filterAndSort(state.accounts, state.query, state.sort)
        val total = state.accounts.size

        adapter.submit(visible)
        v.accountList.adapter = adapter

        // 空状态：区分「没有账户」和「没有匹配」。
        val showEmpty = visible.isEmpty()
        v.emptyState.isVisible = showEmpty
        if (showEmpty) {
            if (total == 0) {
                v.emptyTitle.text = "还没有添加任何账户"
                v.emptyDesc.text = "添加账户后，这里会显示每 30 秒刷新的动态验证码。所有密钥只保存在这台设备里。"
                v.emptyImport.isVisible = true
            } else {
                v.emptyTitle.text = "没有匹配的账户"
                v.emptyDesc.text = "没有找到包含「${state.query}」的服务或账户，换个关键词试试。"
                v.emptyImport.isVisible = false
            }
        }

        v.codesSummary.text =
            if (total == 0) "共 0 个账户"
            else "共 $total 个账户${if (state.query.isNotEmpty()) "，匹配 ${visible.size} 个" else ""}"
        v.countLabel.text = if (total > 0) "${visible.size} / $total" else ""

        // 为刚渲染的卡片预热验证码。
        visible.forEach { refreshCode(it) }
    }

    /* ------------------------------------------------------------------ */
    /*  验证码跳动                                                         */
    /* ------------------------------------------------------------------ */

    private fun refreshCode(account: Account, force: Boolean = false): Job = scope.launch {
        if (account.secretBytes == null) {
            state.codes[account.id] = CachedCode("", -1, 0, "密钥无法解码")
            paintCard(account)
            return@launch
        }
        if (account.id in state.inFlight) return@launch

        val step = stepAt(account.period)
        val cached = state.codes[account.id]

        // 缓存命中：直接从缓存重绘（DOM/列表可能刚重建），不重算 HMAC。
        if (!force && cached != null && cached.counter == step.counter && cached.code.isNotEmpty()) {
            cached.remaining = step.remaining
            paintCard(account)
            return@launch
        }

        state.inFlight.add(account.id)
        try {
            val result = generateTOTP(account)
            state.codes[account.id] = CachedCode(result.code, result.counter, result.remaining)
        } catch (err: Exception) {
            state.codes[account.id] = CachedCode("", step.counter, step.remaining, err.message)
            if (err !is TotpError) android.util.Log.e("ZY2fa", "TOTP 生成失败", err)
        } finally {
            state.inFlight.remove(account.id)
            paintCard(account)
        }
    }

    private fun tick() {
        // 仅在列表可见、应用在前台时工作。
        if (v.root.windowVisibility != View.VISIBLE || state.route != "codes") return

        for (account in state.accounts) {
            val cached = state.codes[account.id]
            val step = stepAt(account.period)

            if (cached == null || cached.counter != step.counter) {
                refreshCode(account)
                continue
            }
            if (cached.remaining != step.remaining) {
                cached.remaining = step.remaining
                adapter.holderFor(account.id)?.let { paintCountdown(it, account, step.remaining) }
            }
        }
    }

    private fun startTicking() {
        if (tickJob != null) return
        tickJob = scope.launch {
            while (isActive) {
                delay(TICK_MS)
                tick()
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /*  持久化                                                            */
    /* ------------------------------------------------------------------ */

    private suspend fun persist(silent: Boolean = false): Boolean =
        try {
            vault.save(state.accounts)
            refreshStats()
            true
        } catch (err: Exception) {
            val message = if (err is VaultError) err.message ?: "保存失败，请重试" else "保存失败，请重试"
            toast(message, ToastVariant.ERROR)
            if (err is VaultError && err.code == "LOCKED") {
                lockNow(silent = true)
            }
            false
        }

    private fun setAccounts(accounts: List<Account>) {
        state.accounts = accounts.map { Store.withSecretBytes(it) }
        state.codes.clear()
    }

    /**
     * 应用一次变更并持久化。写盘失败时回滚内存状态，
     * 保证 UI 永远不会展示一个并未实际保存的变更。
     */
    private suspend fun commit(mutate: () -> Unit): Boolean {
        val snapshot = state.accounts
        val codes = state.codes.toMutableMap()
        mutate()

        val ok = persist()
        if (!ok) {
            state.accounts = snapshot
            state.codes.clear()
            state.codes.putAll(codes)
            renderList()
            return false
        }
        return true
    }

    /* ------------------------------------------------------------------ */
    /*  视图与路由                                                         */
    /* ------------------------------------------------------------------ */

    private fun setRoute(route: String) {
        val next = if (route in ROUTES) route else "codes"
        state.route = next

        listOf(v.viewCodes to "codes", v.viewBackup to "backup", v.viewSettings to "settings")
            .forEach { (view, name) -> view.isVisible = name == next }

        v.btnAdd.isVisible = next == "codes"

        if (next == "backup") refreshStats()
        if (next == "settings") refreshSettings()
        if (next == "codes") renderList()
    }

    /** 对应 initRouter：hash 路由在 Android 上替换为底部导航项选择。 */
    private fun initRouter() {
        v.navItems.forEachIndexed { index, item ->
            item.setOnClickListener { setRoute(ROUTES[index]) }
        }
        setRoute("codes")
    }

    /* ------------------------------------------------------------------ */
    /*  统计与设置页                                                        */
    /* ------------------------------------------------------------------ */

    private fun refreshStats() {
        val encrypted = vault.isEncrypted
        v.statAccounts.text = state.accounts.size.toString()
        v.statEncrypted.text = if (encrypted) (if (vault.isLocked) "已锁定" else "已加密") else "否"
        v.statUsage.text = Utils.formatBytes(vault.usage())
        v.statUpdated.text = Utils.formatRelative(vault.updatedAt)

        v.encBadge.isVisible = encrypted
        v.btnLockTop.isVisible = encrypted
        v.btnLockNow.isVisible = encrypted

        val count = state.accounts.size
        v.dataCountHint.text = if (count > 0) "$count 个账户已保存到本机" else "尚未添加任何账户"
        v.dataCountBadge.text = count.toString()
    }

    private fun refreshSettings() {
        val encrypted = vault.isEncrypted

        v.pinHint.text = if (encrypted) {
            "已开启。密钥以 AES-256-GCM 加密保存，应用重开后需要输入密码才能解锁。"
        } else {
            "未开启。密钥以明文保存在本机存储中，拿到这台设备的人可能读取。"
        }
        v.btnPinPrimary.text = if (encrypted) "修改密码" else "开启加密"
        v.btnLockNow.isVisible = encrypted

        v.autoLockToggle.isChecked = state.autoLock
        v.autoLockToggle.isEnabled = encrypted
        v.autoLockToggle.alpha = if (encrypted) 1f else 0.5f

        v.btnWipe.isEnabled = state.accounts.isNotEmpty() || encrypted
        refreshStats()
    }

    /* ------------------------------------------------------------------ */
    /*  新增 / 编辑对话框                                                   */
    /* ------------------------------------------------------------------ */

    private fun resetAccountForm() {
        v.uriInput.setText("")
        v.issuerInput.setText("")
        v.labelInput.setText("")
        v.secretInput.setText("")
        v.secretInput.inputType = android.text.InputType.TYPE_CLASS_TEXT
        v.periodInput.setText("30")
        draft.algorithm = "SHA1"
        draft.digits = 6
        syncSegmented(v.algoSegmented, "SHA1")
        syncSegmented(v.digitsSegmented, "6")
        Ui.clearFieldErrors(v.accountDialogView.findTextInputLayouts())
        updatePreviewSoon()
    }

    /** 对应 syncSegmented：子项 tag 持有值，激活态表示选中。 */
    private fun syncSegmented(container: ViewGroup, value: String) {
        container.children().forEach { btn ->
            btn.isActivated = btn.tag?.toString() == value
        }
    }

    private fun toggleSegmented(container: ViewGroup, onSelect: (String) -> Unit) {
        container.children().forEach { btn ->
            btn.setOnClickListener {
                if (btn.isActivated) return@setOnClickListener
                val value = btn.tag?.toString() ?: return@setOnClickListener
                syncSegmented(container, value)
                onSelect(value)
            }
        }
    }

    private fun openAccountDialog(accountId: String? = null) {
        state.editingId = accountId
        resetAccountForm()

        if (accountId != null) {
            val account = findAccount(accountId)
            if (account == null) {
                toast("该账户已不存在", ToastVariant.ERROR)
                return
            }
            v.dlgAccountTitle.text = "编辑账户"
            v.btnSaveAccount.text = "保存修改"
            v.issuerInput.setText(account.issuer)
            v.labelInput.setText(account.label)
            v.secretInput.setText(account.secret)
            v.periodInput.setText(account.period.toString())
            draft.algorithm = account.algorithm
            draft.digits = account.digits
            syncSegmented(v.algoSegmented, account.algorithm)
            syncSegmented(v.digitsSegmented, account.digits.toString())
            updatePreviewSoon()
        } else {
            v.dlgAccountTitle.text = "添加账户"
            v.btnSaveAccount.text = "保存"
        }

        accountDialog = Ui.accountDialog(activity, v.accountDialogView) // 见 Ui 扩展说明
        accountDialog?.show()
        scope.launch {
            delay(60) // 对应 setTimeout(..., 60)
            v.uriInput.requestFocus()
        }
    }

    private val updatePreviewSoon: () -> Unit =
        Utils.debounce(220) { scope.launch { updatePreview() } }

    private suspend fun updatePreview() {
        val secret = v.secretInput.text.toString().trim()
        if (secret.isEmpty()) {
            v.previewText.text = "填写密钥后可实时预览"
            return
        }

        val period = Store.parseIntLike(v.periodInput.text.toString())?.let { Utils.clamp(it, 5, 300) } ?: 30
        try {
            val secretBytes = base32Decode(secret)
            val result = generateTOTP(
                Account(id = "", issuer = "", label = "", secret = secret,
                    algorithm = draft.algorithm, digits = draft.digits, period = period,
                    createdAt = 0, updatedAt = 0, secretBytes = secretBytes),
            )
            v.previewText.text =
                "预览 ${Utils.groupCode(result.code)}（${draft.algorithm} · ${draft.digits} 位 · ${period}s）"
        } catch (err: Exception) {
            v.previewText.text = err.message ?: "密钥无效"
        }
    }

    private suspend fun parseUriIntoForm() {
        val raw = v.uriInput.text.toString().trim()
        if (raw.isEmpty()) {
            toast("请先粘贴 otpauth 链接", ToastVariant.ERROR)
            v.uriInput.requestFocus()
            return
        }

        try {
            val parsed = parseOtpAuthUri(raw)
            v.issuerInput.setText(parsed.issuer)
            v.labelInput.setText(parsed.label)
            v.secretInput.setText(parsed.secret)
            v.periodInput.setText(parsed.period.toString())
            draft.algorithm = parsed.algorithm
            draft.digits = parsed.digits
            syncSegmented(v.algoSegmented, parsed.algorithm)
            syncSegmented(v.digitsSegmented, parsed.digits.toString())
            updatePreview()
            toast(
                if (parsed.warnings.isNotEmpty()) parsed.warnings[0] else "已解析链接并填入字段",
                if (parsed.warnings.isNotEmpty()) ToastVariant.ERROR else ToastVariant.SUCCESS,
            )
        } catch (err: Exception) {
            toast(err.message ?: "链接无法解析", ToastVariant.ERROR)
        }
    }

    private suspend fun saveAccount() {
        val candidate = JSONObject().apply {
            put("id", state.editingId ?: uid())
            put("issuer", v.issuerInput.text.toString().trim())
            put("label", v.labelInput.text.toString().trim())
            put("secret", v.secretInput.text.toString())
            put("algorithm", draft.algorithm)
            put("digits", draft.digits)
            put("period", Store.parseIntLike(v.periodInput.text.toString())?.let { Utils.clamp(it, 5, 300) } ?: 30)
        }

        val account = try {
            Store.normalizeAccount(candidate)
        } catch (err: Exception) {
            toast(err.message ?: "输入无效", ToastVariant.ERROR)
            return
        }

        val existing = state.editingId?.let { findAccount(it) }
        val others = state.accounts.filter { it.id != account.id }

        // 完全重复：同密钥 + 同服务 + 同标签。
        val duplicate = Store.findDuplicate(others, account)
        if (duplicate != null) {
            val proceed = Ui.confirmDialog(
                activity, "已存在相同账户",
                "「${describeAccount(duplicate)}」使用了相同的密钥，继续添加会产生两个完全一样的验证码。",
                confirmText = "仍然添加", cancelText = "取消",
            )
            if (!proceed) return
        } else {
            // 较温和的情况：同密钥不同标签 —— 通常是同一账户被导入两次。
            val clash = Store.findSecretClash(others, account)
            if (clash != null) {
                val proceed = Ui.confirmDialog(
                    activity, "密钥已被使用",
                    "「${describeAccount(clash)}」已经使用同一个密钥。若这是同一个账户，建议直接编辑原记录而不是新增。",
                    confirmText = "仍然添加", cancelText = "返回修改",
                )
                if (!proceed) return
            }
        }

        val finalAccount = if (existing != null) {
            account.copy(createdAt = existing.createdAt, updatedAt = System.currentTimeMillis())
        } else account

        val saved = commit {
            state.accounts = if (existing != null) {
                state.accounts.map { if (it.id == existing.id) Store.withSecretBytes(finalAccount) else it }
            } else {
                state.accounts + Store.withSecretBytes(finalAccount)
            }
        }
        if (!saved) return

        accountDialog?.dismiss()
        state.codes.remove(finalAccount.id)
        setRoute("codes")
        renderList()
        refreshSettings()
        toast(if (existing != null) "账户已更新" else "已添加「${finalAccount.issuer}」", ToastVariant.SUCCESS)
    }

    /* ------------------------------------------------------------------ */
    /*  卡片操作                                                          */
    /* ------------------------------------------------------------------ */

    private suspend fun copyAccountCode(accountId: String) {
        val account = findAccount(accountId)
        val cached = state.codes[accountId]
        if (account == null || cached == null || cached.code.isEmpty()) {
            toast("验证码还没生成，请稍候再试", ToastVariant.ERROR)
            return
        }

        try {
            Utils.copyText(activity, cached.code)
            val holder = adapter.holderFor(accountId)
            holder?.markCopied()
            scope.launch {
                delay(1400)
                adapter.holderFor(accountId)?.markCopied(false)
            }
            toast("已复制「${account.issuer}」的验证码")
        } catch (err: Exception) {
            toast(err.message ?: "复制失败", ToastVariant.ERROR)
        }
    }

    private suspend fun deleteAccount(accountId: String) {
        val account = findAccount(accountId) ?: return

        val ok = Ui.confirmDialog(
            activity, "删除账户？",
            "「${describeAccount(account)}」将从本机移除。如果这是唯一的验证方式，删除后将无法登录该服务。",
            confirmText = "删除", cancelText = "保留", danger = true,
        )
        if (!ok) return

        val saved = commit {
            state.accounts = state.accounts.filter { it.id != accountId }
            state.codes.remove(accountId)
        }
        if (!saved) return

        renderList()
        refreshSettings()
        toast("已删除「${describeAccount(account)}」")
    }

    private fun openAccountMenu(accountId: String, anchor: View) {
        val account = findAccount(accountId) ?: return

        Ui.openMenu(anchor, listOf(
            MenuItemSpec("复制验证码", onSelect = { scope.launch { copyAccountCode(accountId) } }),
            MenuItemSpec("复制 otpauth 链接", onSelect = {
                scope.launch {
                    try {
                        Utils.copyText(activity, buildOtpAuthUri(account))
                        toast("已复制 otpauth 链接，可导入其他验证器")
                    } catch (err: Exception) {
                        toast(err.message ?: "", ToastVariant.ERROR)
                    }
                }
            }),
            MenuItemSpec("编辑", onSelect = { openAccountDialog(accountId) }),
            MenuItemSpec("删除", danger = true, onSelect = { scope.launch { deleteAccount(accountId) } }),
        ))
    }

    /* ------------------------------------------------------------------ */
    /*  锁定门与 PIN                                                       */
    /* ------------------------------------------------------------------ */

    private fun showGate(reason: String = "") {
        v.gate.isVisible = true
        v.appBody.isVisible = false
        v.btnAdd.isVisible = false
        gateAttempts = 0
        gateRateUntil = 0
        v.gatePin.setText("")
        v.gateError.text = reason
        scope.launch {
            delay(80)
            v.gatePin.requestFocus()
        }
    }

    private fun hideGate() {
        v.gate.isVisible = false
        v.appBody.isVisible = true
        v.btnAdd.isVisible = state.route != "codes"
    }

    private fun lockNow(silent: Boolean = false, reason: String = "保险库已锁定") {
        vault.lock()
        state.accounts = emptyList()
        state.codes.clear()
        renderList()
        showGate(if (silent) "" else reason)
        if (!silent) toast("已锁定保险库")
    }

    private suspend fun handleUnlock() {
        if (!v.gateSubmit.isEnabled) return

        val pin = v.gatePin.text.toString()
        if (pin.isEmpty()) {
            v.gateError.text = "请输入密码"
            v.gatePin.requestFocus()
            return
        }

        // 简单的客户端节流：连续失败后放慢。
        if (gateRateUntil > System.currentTimeMillis()) {
            v.gateError.text = "尝试过于频繁，请稍后再试"
            return
        }

        v.gateSubmit.isEnabled = false
        v.gateSubmit.text = "解密中…"
        v.gateError.text = ""

        try {
            val result = vault.unlock(pin)
            setAccounts(result.accounts)
            hideGate()
            renderList()
            refreshStats()
            refreshSettings()
            toast("已解锁", ToastVariant.SUCCESS)
            gateAttempts = 0
        } catch (err: Exception) {
            gateAttempts += 1
            v.gatePin.setText("")
            v.gatePin.requestFocus()

            if (err is VaultError && err.code == "PIN_WRONG") {
                v.gateError.text = "密码不正确（已尝试 $gateAttempts 次）"
                if (gateAttempts >= 3) {
                    // Math.min(30_000, 2**(attempts-3)*1000)
                    val backoff = minOf(30_000L, 1000L shl (gateAttempts - 3))
                    gateRateUntil = System.currentTimeMillis() + backoff
                    v.gateError.text = "密码连续错误，请等待几秒后重试"
                }
            } else {
                v.gateError.text = err.message ?: "解锁失败"
            }
        } finally {
            v.gateSubmit.isEnabled = true
            v.gateSubmit.text = "解锁"
        }
    }

    private fun openPinDialog(mode: String) {
        state.pinMode = mode

        val config = when (mode) {
            "change" -> PinDialogConfig(
                "修改密码", "先用当前密码验证身份，再设置新密码。修改后旧密码立即失效。",
                showCurrent = true, showNew = true, confirmText = "保存",
            )
            "disable" -> PinDialogConfig(
                "关闭本地加密", "关闭后密钥将以明文写入本机存储。请确认这台设备只有你使用。",
                showCurrent = true, showNew = false, confirmText = "关闭加密",
            )
            else -> PinDialogConfig(
                "开启本地加密", "设置一个密码。密钥会用该密码派生的密钥加密后保存，忘记密码将无法恢复。",
                showCurrent = false, showNew = true, confirmText = "开启加密",
            )
        }

        v.pinTitle.text = config.title
        v.pinSubtitle.text = config.subtitle
        v.btnConfirmPin.text = config.confirmText
        v.currentPinField.isVisible = config.showCurrent
        v.newPinField.isVisible = config.showNew
        v.confirmPinField.isVisible = config.showNew
        v.pinWarning.isVisible = true

        v.currentPin.setText("")
        v.newPin.setText("")
        v.confirmPin.setText("")
        v.pinStrength.tag = "0"
        Ui.clearFieldErrors(v.pinDialogView.findTextInputLayouts())

        pinDialog = Ui.accountDialog(activity, v.pinDialogView)
        pinDialog?.show()
        scope.launch {
            delay(60)
            (if (config.showCurrent) v.currentPin else v.newPin).requestFocus()
        }
    }

    private data class PinDialogConfig(
        val title: String,
        val subtitle: String,
        val showCurrent: Boolean,
        val showNew: Boolean,
        val confirmText: String,
    )

    private suspend fun submitPin() {
        if (!v.btnConfirmPin.isEnabled) return

        val current = v.currentPin.text.toString()
        val next = v.newPin.text.toString()
        val confirm = v.confirmPin.text.toString()

        try {
            if (state.pinMode != "enable") {
                try {
                    Store.validatePin(current)
                } catch (err: Exception) {
                    toast(err.message ?: "", ToastVariant.ERROR)
                    v.currentPin.requestFocus()
                    return
                }
            }
            if (state.pinMode != "disable") {
                try {
                    Store.validatePin(next, confirm)
                } catch (err: Exception) {
                    toast(err.message ?: "", ToastVariant.ERROR)
                    (if (err is ValidationError && err.field == "confirm") v.confirmPin else v.newPin).requestFocus()
                    return
                }
            }

            v.btnConfirmPin.isEnabled = false
            val original = v.btnConfirmPin.text.toString()
            v.btnConfirmPin.text = "处理中…"

            try {
                when (state.pinMode) {
                    "enable" -> {
                        vault.enablePin(next, state.accounts)
                        toast("加密已开启，下次打开需要输入密码", ToastVariant.SUCCESS)
                    }
                    "change" -> {
                        vault.changePin(current, next, state.accounts)
                        toast("密码已更新", ToastVariant.SUCCESS)
                    }
                    else -> {
                        vault.disablePin(current, state.accounts)
                        state.autoLock = false
                        storageSet(AUTOLOCK_KEY, "false")
                        toast("加密已关闭，密钥以明文保存")
                    }
                }
                pinDialog?.dismiss()
                refreshSettings()
                refreshStats()
            } finally {
                v.btnConfirmPin.isEnabled = true
                v.btnConfirmPin.text = original
            }
        } catch (err: Exception) {
            toast(err.message ?: "操作失败", ToastVariant.ERROR)
        }
    }

    /* ------------------------------------------------------------------ */
    /*  导入 / 导出                                                        */
    /* ------------------------------------------------------------------ */

    private suspend fun exportBackup(kind: String) {
        if (state.accounts.isEmpty()) {
            toast("还没有可导出的账户", ToastVariant.ERROR)
            return
        }

        try {
            when (kind) {
                "file" -> {
                    val payload = Store.buildBackup(state.accounts).toString(2)
                    val stamp = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date())
                    Utils.downloadFile(activity, "zy2fa-backup-$stamp.json", payload)
                    toast("已导出 ${state.accounts.size} 个账户")
                }
                "clipboard" -> {
                    Utils.copyText(activity, Store.buildBackup(state.accounts).toString(2))
                    toast("备份 JSON 已复制到剪贴板")
                }
                else -> {
                    Utils.copyText(activity, state.accounts.joinToString("\n") { buildOtpAuthUri(it) })
                    toast("otpauth 列表已复制")
                }
            }
        } catch (err: Exception) {
            toast(err.message ?: "导出失败", ToastVariant.ERROR)
        }
    }

    private suspend fun runImport() {
        val raw = v.importText.text.toString().trim()
        if (raw.isEmpty()) {
            toast("请先粘贴备份内容或选择文件", ToastVariant.ERROR)
            v.importText.requestFocus()
            return
        }

        v.btnImport.isEnabled = false
        try {
            val parsedImport = Store.parseImportPayload(raw)
            val merge = Store.mergeAccounts(state.accounts, parsedImport.accounts)

            if (merge.added == 0) {
                val parts = mutableListOf<String>()
                if (merge.duplicates > 0) parts += "${merge.duplicates} 个已存在"
                if (parsedImport.skipped.isNotEmpty()) parts += "${parsedImport.skipped.size} 个无法解析"
                toast("没有新增账户（${parts.joinToString("，").ifEmpty { "内容为空" }}）", ToastVariant.ERROR)
                return
            }

            val saved = commit { setAccounts(merge.accounts) }
            if (!saved) return

            v.importText.setText("")
            renderList()
            refreshSettings()
            setRoute("codes")

            val extra = mutableListOf<String>()
            if (merge.duplicates > 0) extra += "跳过重复 ${merge.duplicates} 个"
            if (parsedImport.skipped.isNotEmpty()) extra += "忽略无效 ${parsedImport.skipped.size} 个"
            if (merge.overflow > 0) extra += "超出上限未导入 ${merge.overflow} 个"
            toast(
                "已导入 ${merge.added} 个账户${if (extra.isNotEmpty()) "，${extra.joinToString("，")}" else ""}",
                if (parsedImport.skipped.isNotEmpty()) ToastVariant.ERROR else ToastVariant.SUCCESS,
            )
        } catch (err: Exception) {
            toast(err.message ?: "导入失败", ToastVariant.ERROR)
        } finally {
            v.btnImport.isEnabled = true
        }
    }

    /** 由 Activity 的文件选择器回调（对应 <input type=file> 的 change 事件）。 */
    suspend fun readImportFile(uri: Uri?) {
        uri ?: return
        val resolver = activity.contentResolver
        val size = resolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getLong(0) else -1L
        } ?: -1L
        if (size > 5 * 1024 * 1024) {
            toast("文件超过 5 MB，请确认是否选择了正确的备份文件", ToastVariant.ERROR)
            return
        }
        try {
            v.importText.setText(resolver.openInputStream(uri)?.use { it.readBytes().toString(Charsets.UTF_8) } ?: "")
            toast("已读取备份文件")
        } catch (err: Exception) {
            toast("文件读取失败：${err.message}", ToastVariant.ERROR)
        }
    }

    /* ------------------------------------------------------------------ */
    /*  清除                                                              */
    /* ------------------------------------------------------------------ */

    private suspend fun wipeAll() {
        val first = Ui.confirmDialog(
            activity, "清除全部数据？",
            "所有账户密钥与本地设置都会被删除，且无法恢复。",
            detail = "如果还没有导出备份，请先取消并前往「备份」页面导出。",
            confirmText = "继续", cancelText = "取消", danger = true,
        )
        if (!first) return

        val second = Ui.confirmDialog(
            activity, "最后确认",
            "即将删除 ${state.accounts.size} 个账户。此操作不可撤销。",
            confirmText = "确认删除", cancelText = "取消", danger = true,
        )
        if (!second) return

        try {
            vault.wipe()
            state.accounts = emptyList()
            state.codes.clear()
            state.autoLock = false
            storageSet(AUTOLOCK_KEY, "false")
            hideGate()
            renderList()
            refreshSettings()
            refreshStats()
            toast("本地数据已清除")
        } catch (err: Exception) {
            toast(err.message ?: "清除失败", ToastVariant.ERROR)
        }
    }

    /* ------------------------------------------------------------------ */
    /*  自动锁定（visibilitychange 的生命周期等价物）                        */
    /* ------------------------------------------------------------------ */

    private fun initAutoLock() {
        state.autoLock = storageGet(AUTOLOCK_KEY) == "true"

        v.autoLockToggle.setOnCheckedChangeListener { _, checked ->
            if (!vault.isEncrypted) {
                v.autoLockToggle.isChecked = false
                toast("请先开启本地加密", ToastVariant.ERROR)
                return@setOnCheckedChangeListener
            }
            state.autoLock = checked
            storageSet(AUTOLOCK_KEY, checked.toString())
            toast(if (checked) "离开 5 分钟后自动锁定" else "已关闭自动锁定")
        }
    }

    /** Activity onStop 时调用（对应 document.hidden = true 分支）。 */
    fun onAppHidden() {
        state.hiddenAt = System.currentTimeMillis()
    }

    /** Activity onStart 时调用（对应 visibilitychange → visible 分支）。 */
    fun onAppVisible() {
        val away = state.hiddenAt?.let { System.currentTimeMillis() - it } ?: 0
        state.hiddenAt = null

        if (vault.isEncrypted && state.autoLock && !vault.isLocked && away > AUTO_LOCK_MS) {
            lockNow(silent = false, reason = "离开超过 5 分钟，已自动锁定")
            return
        }
        // 从后台返回：系统时钟可能已经前进，立即对齐验证码而不是等下一次 tick。
        if (v.appBody.isVisible) {
            if (state.route == "codes") renderList()
            tick()
        }
    }

    /* ------------------------------------------------------------------ */
    /*  事件绑定                                                          */
    /* ------------------------------------------------------------------ */

    private fun bindEvents() {
        v.accountList.layoutManager = LinearLayoutManager(activity)
        initRouter()
        initTheme()

        /* --- 搜索 --- */
        val onSearch = Utils.debounce(150) {
            state.query = v.searchInput.text.toString()
            v.searchClear.isVisible = state.query.isNotEmpty()
            renderList()
        }
        v.searchInput.addTextChangedListener(onTextChange { onSearch() })
        v.searchClear.setOnClickListener {
            v.searchInput.setText("")
            state.query = ""
            v.searchClear.isVisible = false
            renderList()
            v.searchInput.requestFocus()
        }

        /* --- 排序 --- */
        v.btnSort.setOnClickListener {
            Ui.openMenu(v.btnSort, Store.SORT_OPTIONS.map { option ->
                MenuItemSpec(option.label, onSelect = {
                    state.sort = option.value
                    v.sortLabel.text = option.label
                    renderList()
                })
            })
        }

        /* --- 账户列表（事件委托 → Adapter 回调） --- */
        adapter.onCopy = { id -> scope.launch { copyAccountCode(id) } }
        adapter.onMenu = { id, anchor -> openAccountMenu(id, anchor) }

        /* --- 新增 / 编辑 --- */
        v.btnAdd.setOnClickListener { openAccountDialog() }
        v.emptyAdd.setOnClickListener { openAccountDialog() }
        v.emptyImport.setOnClickListener { setRoute("backup") }

        v.btnParseUri.setOnClickListener { scope.launch { parseUriIntoForm() } }
        listOf(v.secretInput, v.periodInput).forEach { input ->
            input.addTextChangedListener(onTextChange { updatePreviewSoon() })
        }
        v.btnToggleSecret.setOnClickListener {
            val show = (v.secretInput.inputType and android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD) != 0
            v.secretInput.inputType = if (show) android.text.InputType.TYPE_CLASS_TEXT
            else android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        toggleSegmented(v.algoSegmented) { value ->
            draft.algorithm = value
            scope.launch { updatePreview() }
        }
        toggleSegmented(v.digitsSegmented) { value ->
            draft.digits = value.toIntOrNull() ?: 6
            scope.launch { updatePreview() }
        }
        v.btnSaveAccount.setOnClickListener { scope.launch { saveAccount() } }

        /* --- 锁定门 --- */
        v.gateSubmit.setOnClickListener { scope.launch { handleUnlock() } }
        v.gateReset.setOnClickListener {
            scope.launch {
                val ok = Ui.confirmDialog(
                    activity, "清除本地数据？",
                    "密码无法找回。继续将删除本机所有账户，之后可以重新导入备份。",
                    confirmText = "清除并重来", cancelText = "取消", danger = true,
                )
                if (!ok) return@launch
                try {
                    vault.wipe()
                    state.accounts = emptyList()
                    state.codes.clear()
                    hideGate()
                    renderList()
                    refreshSettings()
                    refreshStats()
                    toast("已清除，保险库为空")
                } catch (err: Exception) {
                    toast(err.message ?: "", ToastVariant.ERROR)
                }
            }
        }

        /* --- 设置 --- */
        v.btnPinPrimary.setOnClickListener { openPinDialog(if (vault.isEncrypted) "change" else "enable") }
        v.btnLockNow.setOnClickListener { lockNow() }
        v.btnLockTop.setOnClickListener { lockNow() }
        v.btnConfirmPin.setOnClickListener { scope.launch { submitPin() } }
        v.newPin.addTextChangedListener(onTextChange {
            v.pinStrength.tag = Utils.pinStrength(v.newPin.text.toString()).toString()
        })
        v.btnWipe.setOnClickListener { scope.launch { wipeAll() } }

        /* --- 备份 --- */
        v.btnExportFile.setOnClickListener { scope.launch { exportBackup("file") } }
        v.btnExportClipboard.setOnClickListener { scope.launch { exportBackup("clipboard") } }
        v.btnExportUris.setOnClickListener { scope.launch { exportBackup("uris") } }
        v.btnImport.setOnClickListener { scope.launch { runImport() } }
        v.btnImportClear.setOnClickListener {
            v.importText.setText("")
            v.importText.requestFocus()
        }
    }

    /* ------------------------------------------------------------------ */
    /*  启动                                                              */
    /* ------------------------------------------------------------------ */

    private fun fatal(message: String, detail: String = "") {
        v.gate.isVisible = false
        v.appBody.isVisible = false
        v.btnAdd.isVisible = false
        toast("应用无法启动：$message${if (detail.isNotEmpty()) "（$detail）" else ""}", ToastVariant.ERROR)
    }

    suspend fun boot() {
        bindEvents()
        initAutoLock()
        startTicking()

        // 环境检查 —— 降级体验而不是直接阻断。
        // Android 恒有 javax.crypto（对应 WebCrypto 缺失的提示保留为注释：
        // JS 版此处检查 globalThis.crypto?.subtle）。
        if (!isStorageAvailable()) {
            addNotice("storage", "warning",
                "本机存储不可用。本次添加的账户在关闭应用后会丢失。")
        }

        val result: Vault.InitResult = try {
            vault.init()
        } catch (err: Exception) {
            fatal("读取本地数据失败。", err.message ?: "")
            return
        }

        if (result.recovered != null) {
            addNotice(
                "recovered", "warning",
                "检测到损坏的本地数据（${result.reason ?: "格式异常"}）。原始内容已备份，可导出后手工修复。",
                action = "下载原始数据",
                onAction = {
                    Utils.downloadFile(
                        activity, "zy2fa-corrupt-${System.currentTimeMillis()}.txt",
                        result.recovered, "text/plain",
                    )
                },
            )
        }

        if (result.issues.isNotEmpty()) {
            addNotice("issues", "warning",
                "有 ${result.issues.size} 条账户记录无法读取（密钥格式异常），已跳过。")
        }

        renderNotices()
        refreshStats()
        refreshSettings()

        if (result.locked) {
            showGate()
            return
        }

        setAccounts(result.accounts)
        hideGate()
        renderList()
        state.booted = true

        if (state.accounts.isEmpty() && noticeDismissed.isEmpty()) {
            scope.launch {
                delay(900)
                if (state.accounts.isEmpty()) {
                    toast("点击右下角「添加账户」开始使用",
                        action = "了解用法", onAction = { openAccountDialog() })
                }
            }
        }
    }

    fun start() {
        scope.launch {
            try {
                boot()
            } catch (err: Exception) {
                android.util.Log.e("ZY2fa", "启动失败", err)
                fatal("启动过程中出现未预期的错误。", err.message ?: err.toString())
            }
        }
    }

    /** Activity onDestroy 时调用，避免泄漏。 */
    fun destroy() {
        scope.cancel()
    }

    /* ------------------------------------------------------------------ */
    /*  卡片 Adapter（对应 cardTemplate + DOM 查询式重绘）                  */
    /* ------------------------------------------------------------------ */

    private inner class AccountAdapter : RecyclerView.Adapter<AccountAdapter.CardHolder>() {

        private var items: List<Account> = emptyList()
        private val holders = mutableMapOf<String, CardHolder>()

        var onCopy: ((String) -> Unit)? = null
        var onMenu: ((String, View) -> Unit)? = null

        fun submit(list: List<Account>) {
            items = list
            holders.clear()
            notifyDataSetChanged()
        }

        fun holderFor(id: String): CardHolder? = holders[id]

        inner class CardHolder(view: View) : RecyclerView.ViewHolder(view) {
            val codeValue: TextView = view.findViewById(R.id.codeValue)
            val seconds: TextView = view.findViewById(R.id.seconds)
            private val copyIcon: View = view.findViewById(R.id.copyIcon)

            /** 对应 is-copied 类切换与复制图标替换。 */
            fun markCopied(copied: Boolean = true) {
                copyIcon.isActivated = copied
            }

            fun bind(account: Account) {
                holders[account.id] = this
                itemView.findViewById<TextView>(R.id.avatar).text =
                    Utils.initials(account.issuer, account.label)
                itemView.findViewById<TextView>(R.id.issuerText).text = account.issuer
                itemView.findViewById<TextView>(R.id.labelText).text =
                    account.label.ifEmpty { "未填写账户标识" }
                itemView.findViewById<View>(R.id.codeBtn).setOnClickListener {
                    onCopy?.invoke(account.id)
                }
                itemView.findViewById<View>(R.id.btnMenu).setOnClickListener {
                    onMenu?.invoke(account.id, it)
                }
                paintCard(account)
            }
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): CardHolder =
            CardHolder(activity.layoutInflater.inflate(R.layout.item_account_card, parent, false))

        override fun getItemCount(): Int = items.size

        override fun onBindViewHolder(holder: CardHolder, position: Int) = holder.bind(items[position])
    }

    /* ------------------------------------------------------------------ */
    /*  帮助扩展                                                          */
    /* ------------------------------------------------------------------ */

    private fun ViewGroup.children(): List<View> =
        (0 until childCount).map { getChildAt(it) }

    private fun onTextChange(block: () -> Unit): android.text.TextWatcher =
        object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) = block()
        }

    private fun View.findTextInputLayouts(): List<com.google.android.material.textfield.TextInputLayout> =
        (this as? ViewGroup)?.let { vg ->
            vg.children().flatMap { child ->
                if (child is com.google.android.material.textfield.TextInputLayout) listOf(child)
                else (child as? ViewGroup)?.findTextInputLayouts().orEmpty()
            }
        }.orEmpty()
}
