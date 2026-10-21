package com.zy.twofa

import android.os.Bundle
import android.view.WindowManager
import android.webkit.WebResourceRequest
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewClientCompat

/**
 * ZY2fa Android 壳：用 WebView 加载打包进 APK 的网页应用（assets/www/）。
 *
 * 关键决策：
 *  · 通过 androidx.webkit 的 WebViewAssetLoader 以 https://appassets.androidplatform.net
 *    域名提供内置资源——网页因此拥有正常 https origin，localStorage（账户持久化）
 *    才能可靠工作（直接用 file:// 加载时 origin 为 null，存储会出问题）。
 *  · 不申请 INTERNET 权限、WebViewClient 只放行 appassets 域名，
 *    把网页版"页面不发起任何网络请求"的设计固化到系统权限层面。
 *  · FLAG_SECURE 禁止截屏与最近任务预览，与 2FA 密钥的敏感度匹配。
 */
class MainActivity : AppCompatActivity() {

    private var webView: WebView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        val assetLoader = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()

        webView = WebView(this).also { view ->
            setContentView(view)
            view.settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true   // 应用使用 localStorage 持久化账户
                allowFileAccess = false
                allowContentAccess = false
            }
            view.webViewClient = object : WebViewClientCompat() {
                override fun shouldOverrideUrlLoading(
                    view: WebView,
                    request: WebResourceRequest
                ): Boolean {
                    // 完全离线：只允许本应用内置资源域名，其余一律不放行
                    return request.url.host != "appassets.androidplatform.net"
                }
            }
            if (savedInstanceState == null) {
                view.loadUrl("https://appassets.androidplatform.net/assets/index.html")
            }
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        // 应用有自己的浮层/页面状态，优先交给 WebView 返回，避免一按返回就退出
        val view = webView
        if (view != null && view.canGoBack()) {
            view.goBack()
        } else {
            @Suppress("DEPRECATION")
            super.onBackPressed()
        }
    }

    override fun onDestroy() {
        webView?.destroy()
        webView = null
        super.onDestroy()
    }
}
