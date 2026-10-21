# ZY2fa 发布签名说明

## 方案

三个 ZY 系列 Android 应用（ZYEmail / RemoteFileManager / ZYNotificationHistory）共用同一个**固定发布 keystore**，保证：

- 同一应用的所有版本签名一致 → 用户可以稳定地覆盖安装与升级
- 版本号 / versionCode 在 `app/build.gradle` 中固定，不随构建变化
- 签名证书 SHA-256（校验值）在每次 Release 的 Step Summary 中输出，应恒定不变：

```
52:C7:67:37:D2:2A:A3:E7:F2:BF:1A:C9:8E:9F:DB:5F:D4:77:60:34:61:22:64:E6:83:21:3C:44:D2:70:A1:B4
```

## keystore 与 Secrets 的关系

- keystore 原件由仓库所有者本地保管（**不要提交进仓库**）
- CI 通过 4 个 Actions Secrets 使用它（已配置）：
  - `KEYSTORE_BASE64` — keystore 的 base64 编码
  - `KEYSTORE_PASSWORD` / `KEY_ALIAS`（`zy_release`）/ `KEY_PASSWORD`

## 更换机器 / 丢失 Secret 时重新配置

```bash
# 1. 用本地备份的 keystore 重新生成 base64
base64 -w0 zy-release.keystore > keystore.b64

# 2. 重新写入 Secrets（gh 已登录时）
gh secret set KEYSTORE_BASE64 --repo zhengyang3552/ZY2fa < keystore.b64
gh secret set KEYSTORE_PASSWORD --repo zhengyang3552/ZY2fa --body "<密码>"
gh secret set KEY_ALIAS --repo zhengyang3552/ZY2fa --body "zy_release"
gh secret set KEY_PASSWORD --repo zhengyang3552/ZY2fa --body "<密码>"
```

## 与其他仓库的关系

Android 壳工程位于 `android/`，CI 会把网页构建产物（dist/）打进 APK 的 assets，
App 完全离线、不申请 INTERNET 权限。网页本身仍通过 GitHub Pages 分发，
无需签名；APK（`v*` 标签触发）使用本签名方案。

## 发版流程

1. 更新 `android/app/build.gradle.kts` 中的（并与 package.json 的 version 同步） `versionCode`（+1）与 `versionName`
2. 提交并打 `v*` 标签推送，CI 的 release job 自动构建签名包并发布到 GitHub Releases
3. 在 Release 的 CI Step Summary 里核对签名指纹是否仍为上面的固定值

## 本地构建

不设置 `KEYSTORE_PATH` 时本地可正常构建（release 为 unsigned，仅供验证编译）。
需要本地出签名包时：

```bash
export KEYSTORE_PATH=/path/to/zy-release.keystore
export KEYSTORE_PASSWORD="<密码>"
export KEY_ALIAS=zy_release
export KEY_PASSWORD="<密码>"
./gradlew assembleRelease   # 或 gradle :app:assembleRelease
```
