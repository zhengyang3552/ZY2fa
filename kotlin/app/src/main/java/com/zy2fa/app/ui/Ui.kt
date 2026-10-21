package com.zy2fa.app.ui

import android.content.Context
import android.view.Gravity
import android.view.Menu
import android.view.View
import android.widget.PopupMenu
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputLayout
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * ZY2fa · UI 原语（对应 js/ui.js）
 *
 * JS 版包装 <dialog>、DOM 事件与 innerHTML 模板；Android 版映射到等价平台组件：
 *
 * | js/ui.js                    | Android 对应物                                   |
 * |-----------------------------|--------------------------------------------------|
 * | toast()                     | Material Snackbar（支持 action）                  |
 * | confirmDialog() (Promise)   | MaterialAlertDialogBuilder + suspendCancellableCoroutine |
 * | openMenu()/closeMenu()      | PopupMenu（锚点定位、外部点击关闭由系统处理）      |
 * | setFieldError()             | TextInputLayout.error                            |
 * | icon()                      | 矢量资源 R.drawable.*，此处不再用字符串拼 SVG     |
 *
 * 行为对齐：confirmDialog 在 Esc/点外部取消时同样返回 false；
 * Snackbar 的自动消失时长对应 JS 的 2800/5200ms 分档。
 */

enum class ToastVariant { DEFAULT, ERROR, SUCCESS }

data class MenuItemSpec(
    val label: String,
    /** 可选的矢量资源 id（对应 JS 的 icon 名称）。 */
    val iconRes: Int? = null,
    val danger: Boolean = false,
    val onSelect: () -> Unit = {},
)

object Ui {

    /**
     * 显示一条会自动消失的消息。
     * 有 action 时用 LENGTH_INDEFINITE（等价 JS 悬停保持的语义），
     * 否则按 variant 分档为长/短时长。
     */
    fun toast(
        view: View,
        message: String,
        variant: ToastVariant = ToastVariant.DEFAULT,
        action: String? = null,
        onAction: (() -> Unit)? = null,
    ) {
        val duration = when {
            action != null -> Snackbar.LENGTH_INDEFINITE
            variant == ToastVariant.ERROR -> Snackbar.LENGTH_LONG   // ≈ 5200ms 档
            else -> Snackbar.LENGTH_SHORT                            // ≈ 2800ms 档
        }
        val snackbar = Snackbar.make(view, message, duration)
        if (variant != ToastVariant.DEFAULT) {
            // 轻量高亮：错误红 / 成功绿（需要主题中定义对应颜色）。
            snackbar.setTextColor(
                if (variant == ToastVariant.ERROR) 0xFFFFCDD2.toInt() else 0xFFC8E6C9.toInt(),
            )
        }
        action?.let { label ->
            snackbar.setAction(label) { onAction?.invoke() }
        }
        snackbar.show()
    }

    /**
     * 模态确认框。确认返回 true；取消、Esc、点外部返回 false —— 与 JS 版一致。
     * detail 附加为警告文案（对应 JS 的 banner--warning 区块）。
     */
    suspend fun confirmDialog(
        context: Context,
        title: String,
        message: String,
        detail: String = "",
        confirmText: String = "确定",
        cancelText: String = "取消",
        danger: Boolean = false,
    ): Boolean = suspendCancellableCoroutine { cont ->
        val fullMessage = if (detail.isNotEmpty()) "$message\n\n⚠ $detail" else message
        val dialog = MaterialAlertDialogBuilder(context)
            .setTitle(title)
            .setMessage(fullMessage)
            // Android 的按钮颜色由主题控制；danger=true 可换成错误色主题的按钮样式。
            .setPositiveButton(confirmText) { _, _ -> if (cont.isActive) cont.resume(true) }
            .setNegativeButton(cancelText) { _, _ -> if (cont.isActive) cont.resume(false) }
            .setOnCancelListener { if (cont.isActive) cont.resume(false) }
            .create()
        cont.invokeOnCancellation { dialog.dismiss() }
        dialog.show()
    }

    /** 在锚点旁打开菜单。PopupMenu 自带锚点定位与外部点击关闭。 */
    fun openMenu(anchor: View, items: List<MenuItemSpec>) {
        val popup = PopupMenu(anchor.context, anchor, Gravity.END)
        items.forEachIndexed { index, item ->
            popup.menu.add(Menu.NONE, index, Menu.NONE, item.label).apply {
                item.iconRes?.let {
                    // PopupMenu 原生不显示图标；若必须显示，可用
                    // SpannableString + ImageSpan 或换成 ListPopupWindow。
                }
            }
        }
        popup.setOnMenuItemClickListener { mi ->
            items[mi.itemId].onSelect()
            true
        }
        popup.show()
    }

    /** 等价 closeMenu()：PopupMenu 无全局单例；如需「同一时间只开一个」，在调用方保存引用并 dismiss。 */

    /** 以自定义视图创建对话框（对应 openDialog() + index.html 中的 <dialog> 模板）。 */
    fun accountDialog(context: Context, view: View): androidx.appcompat.app.AlertDialog =
        MaterialAlertDialogBuilder(context).setView(view).create()

    /** 字段级错误提示。message 为空表示清除错误。 */
    fun setFieldError(field: TextInputLayout?, message: String = "") {
        field ?: return
        field.isErrorEnabled = message.isNotEmpty()
        field.error = message.ifEmpty { null }
    }

    fun clearFieldErrors(vararg fields: TextInputLayout?) {
        fields.forEach { setFieldError(it, "") }
    }
}
