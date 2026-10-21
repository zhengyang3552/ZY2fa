# ZY2fa

纯前端 TOTP 验证器 · Material 3 设计系统 · 零运行时依赖

**[在线使用](https://zhengyang3552.github.io/ZY2fa/)** · **[CI](https://github.com/zhengyang3552/ZY2fa/actions/workflows/ci.yml)** — 密钥只留在你自己的浏览器里，页面不发起任何网络请求。

```
npm start                        # 开发预览 → http://localhost:5173（不打包，直接跑源码）
npm test                         # 67 项测试
npm run build                    # 产出 dist/（打包 + 压缩 + 内容哈希）
npm run tokens                   # 重新生成设计令牌
```

开发态不需要构建：`npm start` 直接以 ES Modules 提供源码。只有部署时才 `npm run build`。

---

## 关于仓库状态的说明

`https://github.com/zhengyang3552/ZY2fa` 在动手时是**空仓库**：`size: 0`、
`default_branch: main`，`/contents` 返回 “This repository is empty.”，
`/commits` 返回 “Git Repository is empty.”，也没有任何分支、标签或 release。
也就是说**没有既有代码可供“在保持功能可用的前提下改造”**。

因此这里的选择是：按仓库名 `ZY2fa`（2FA = two-factor authentication）所指的产品意图，
从零建立该应用，并把原任务的三条要求作为建设标准落地——Material 3 主题体系、
UI 布局与交互优化、核心功能梳理与边界处理。技术栈选用**原生 ES Modules + Web Crypto**，
不引入框架与构建链：对于这个体量的应用，它可以做到零安装、零构建、离线可用，
且加密与 TOTP 都能直接落在浏览器原生 API 上。

如果你原本有一份实现想作为基线，把它放进仓库后我可以基于真实代码重新做这次改造。

---

## 一、应用概览

| | |
|---|---|
| 功能 | 添加/编辑/删除账户，实时 TOTP 验证码，复制、搜索、排序，导入导出，本地加密 |
| 算法 | RFC 6238 TOTP / RFC 4226 HOTP，SHA-1 / SHA-256 / SHA-512，6 或 8 位，自定义周期 5–300s |
| 存储 | `localStorage`；可选 PIN 加密（PBKDF2-SHA256 210,000 次 → AES-256-GCM） |
| 网络 | 无任何请求。密钥永不出本机 |
| 依赖 | 无。运行时、构建、测试全部为零依赖 |
| 浏览器 | 支持 `<dialog>`、CSS 嵌套变量与 `color-mix()` 的现代浏览器 |

### 目录结构

```
ZY2fa/
├── index.html              应用骨架、图标 sprite、对话框
├── css/
│   ├── tokens.css          ← 生成物：三层设计令牌
│   ├── base.css            reset、排版、焦点环、无障碍工具类
│   ├── components.css      M3 组件（按钮、文本框、卡片、对话框、Snackbar…）
│   └── layout.css          外壳、导航（rail ↔ bottom bar）、响应式栅格
├── js/
│   ├── totp.js             base32、HOTP/TOTP、otpauth 解析（无 DOM 依赖）
│   ├── store.js            账户校验、归一化、导入合并、搜索排序
│   ├── vault.js            持久化 + 可选加密（纯函数式外壳）
│   ├── ui.js               Snackbar、确认框、菜单、字段错误
│   ├── utils.js            剪贴板、base64、格式化等
│   └── app.js              状态、渲染、事件编排
├── tools/
│   ├── generate-tokens.mjs      配色/令牌生成器（含对比度校验）
│   └── build.mjs                生产构建（esbuild 打包，产物落 dist/）
├── .github/workflows/ci.yml     校验 → 测试 → 构建 → Pages 部署
├── tests/
│   ├── core.test.mjs           核心逻辑测试（含 RFC 官方向量）
│   └── css.test.mjs            样式不变量（防止对话框裁切一类回归）
└── serve.mjs                   零依赖静态服务器
```

分层原则：`totp.js` 不知道 DOM，`store.js` 不知道存储实现，`vault.js` 不知道界面，
`app.js` 只做编排。因此核心逻辑可以在 Node 里直接跑测试，无需浏览器。

---

## 二、配色方案与设计依据

### 1. 为什么不是“挑一组好看的十六进制”

Material 3 的色彩体系不是一组固定色值，而是一条**由色调（tone）驱动的推导链**：

```
种子色 → 色调板（tone 0–100 的固定色相色阶） → 语义颜色角色（role ← tone）
```

角色与色调是**声明式映射**，例如浅色方案 `primary = primary-40`、`on-primary = primary-100`；
深色方案整体翻转成 `primary-80` / `on-primary-20`。手写色值会让这条链断掉：改一个品牌色
就要重新推导几十个角色，且必然出现对比度回归。所以本项目把推导过程写成生成器
`tools/generate-tokens.mjs`，`css/tokens.css` 是它的产物（文件头明确标注“请勿手改”）。

### 2. 色调模型

M3 的 tone 是 CIE L\*（0–100）。OKLab 的 L 与 L\* 有确定关系：

```
L* = 116·L_ok − 16   ⇒   L_ok = (L* + 16) / 116
```

据此把 tone 映射进 OKLCH（感知均匀的极坐标色彩空间），色相固定、彩度按调色板给定，
再**逐色调做 sRGB 色域裁剪**（二分降低彩度直到可表示）。这样高彩度色相在两端自然降饱和，
得到与 Material HCT 色阶同构的观感，而无需移植整套 CAM16。

### 3. 色相与彩度的选择依据

| 调色板 | 色相 | 彩度 | 依据 |
|---|---|---|---|
| primary | 262°（靛蓝） | 0.155 | 安全/凭证类产品的可信感；比 M3 默认紫（#6750A4）更蓝、更冷静，避免“通用模板感” |
| secondary | 300° | 0.045 | 低彩度的“同族邻色”，用于次级容器、头像、选中态。M3 的 secondary 本就是 primary 的低强调同族；这里刻意偏转 38°，因为同色相时 `secondary-container` 在 tone 90 会被色域裁剪到与 `primary-container` 完全相同的 #d4e3ff，两个容器角色就失去了区分度。偏转后为 #e7dcfd（与 M3 基线 #E8DEF8 几乎一致），既保留同族感又拉开了层次 |
| tertiary | 196°（青） | 0.105 | 与 primary 形成 66° 色相差，仅用于**状态语义**：倒计时环、“仍然有效”的肯定态。冷色不与错误红冲突 |
| neutral | 262° | 0.007 | 表面色保留极微弱的品牌色相，避免纯灰的“塑料感”，这是 M3 的 surface tint 思路 |
| neutral-variant | 262° | 0.022 | 描边与分隔线，比 neutral 略强以在表面色上可辨 |
| error | 25°（红橙） | 0.19 | M3 错误色，高彩度以确保警示优先级 |
| success / warning | 148° / 75° | 0.13 | **扩展语义角色**（M3 custom color roles 模式）：`success` 表示复制成功/已加密，`warning` 表示验证码即将过期 |

关键的语义分层是：**品牌色（primary）不承担状态**。倒计时用 tertiary → warning → error
三级递进，颜色变化本身就在传递“还剩多少时间”，不需要用户读数字。这解决了原任务里
“视觉层次”的核心问题——同一张卡片上，账户名（on-surface）、验证码（on-surface + 大字号）、
剩余时间（三级色阶）三个层级各自有独立而一致的表达手段。

### 4. 明暗模式的映射规则

完全按 M3 规范成对取值，而非“把浅色调暗”：

| 角色 | 浅色 | 深色 |
|---|---|---|
| primary / on-primary | tone 40 / 100 | tone 80 / 20 |
| primary-container / on-… | 90 / 10 | 30 / 90 |
| surface | 98 | 6 |
| surface-container-lowest → highest | 100 / 96 / 94 / 92 / 90 | 4 / 10 / 12 / 17 / 22 |
| on-surface / on-surface-variant | 10 / 30 | 90 / 80 |
| outline / outline-variant | 50 / 80 | 60 / 30 |

深色方案的表面不是纯黑：surface 取 tone 6，容器从 4 递进到 22，用**色调高度**
（tonal elevation）而非仅靠阴影表达层级——深色下阴影几乎不可见，这是 M3 明确的分层策略。

主题跟随系统时，CSS 用 `@media (prefers-color-scheme: dark)` 且加
`:root:not([data-theme='light'])` 守卫，保证显式选择永远优先；`<head>` 里的内联脚本在首屏前
写入 `data-theme`，消除主题闪烁。

### 5. 对比度是构建期校验的，不是事后抽查

生成器内置 WCAG 对比度计算，每次生成都检查 11 组关键前景/背景配对，低于 4.5:1 直接告警：

```
light  on-surface / surface                16.21
light  on-primary / primary                 6.67
light  on-primary-container / container    13.51
dark   on-surface / surface                14.33
dark   on-primary / primary                 7.95
dark   on-primary-container / container     7.49
...
最低：light outline / surface = 4.28（描边为非文本角色，要求 3:1）
```

### 6. 令牌分层

```
--md-ref-palette-*   原始色阶（tone 0–100）
--md-sys-color-*     语义颜色角色（浅/深各一套）
--md-sys-shape-*     圆角：4 / 8 / 12 / 16 / 28 / full
--md-sys-elevation-* 阴影等级 0–5
--md-sys-motion-*    M3 缓动曲线 + 时长令牌
--md-sys-typescale-* 完整字号/行高/字重/字距（display → label）
--md-sys-spacing-*   4dp 栅格
```

组件 CSS 里**没有一处裸色值**，全部引用 `var(--md-sys-color-*)`。换品牌色只需改
`tools/generate-tokens.mjs` 里的 `HUES`/`CHROMA` 再重新生成。

---

## 三、主要改动点

### 1. 主题系统（原任务要求 1）

- 三层令牌体系 + 生成器（见上）。
- 明暗双方案 + 跟随系统，三档可选；选择持久化到 `localStorage`，首屏无闪烁。
- 完整语义角色集：含 `surface-container-*` 五档、`inverse-*`、`outline-variant`、
  以及 `success`/`warning` 扩展角色。
- 浏览器 UI 同步：运行时把当前 `surface` 写入 `<meta name="theme-color">`。

### 2. 布局与交互（原任务要求 2）

**布局**
- 响应式导航：≥900px 用**导航轨（navigation rail）**，以下用**底部导航栏**，同一份 DOM
  靠 CSS Grid + `position` 切换，不重复渲染。
- 内容最大宽度 1080px 居中；账户栅格 `minmax(320px, 1fr)` 自适应；间距全部走 4dp 令牌。
- 顶栏 `sticky` + 半透明模糊，滚动后才出现分隔线（`is-stuck`）。

**视觉层次**
- 验证码是卡片的主操作：整块区域可点击复制，26px 等宽数字、`tabular-nums` + 分组排版
  （`123 456`），8 位码自动切成 `1234 5678`。
- 倒计时环 + 秒数双重编码，`is-expiring` / `is-critical` 两级状态换色。
- 空状态区分“没有账户”与“搜索无结果”，并给出不同的行动按钮。

**交互细节**
- M3 状态层：hover 8% / focus 10% / pressed 10% 的叠加层，而非直接改背景色。
- 焦点环 3px + offset，仅 `:focus-visible` 生效，指针操作不受打扰。
- 对话框用原生 `<dialog>` + `@starting-style` 过渡，天然获得焦点陷阱与 Esc 关闭；
  高度受 `max-height` 约束、内容区独立滚动，页脚永远可达；视口高度 <520px 时按 M3
  的紧凑窗口规范切换为全屏对话框。
- 内容底部预留 152px，保证最后一张卡片不会被悬浮 FAB（96px 偏移 + 56px 高）挡住。
- Snackbar 最多堆叠 3 条，悬停暂停计时。
- 键盘：`/` 或 `Ctrl/⌘+K` 聚焦搜索，`n` 新建，菜单支持上下键与 Esc。
- `prefers-reduced-motion` 全局降级；`prefers-color-scheme` 实时响应。

### 3. 核心功能与边界处理（原任务要求 3）

**功能梳理**（原来只有“输入密钥看验证码”，现在是一条完整闭环）

- 添加：粘贴 `otpauth://` 链接自动解析（`paste` 即触发）、手动录入、**保存前实时预览验证码**
- 管理：编辑、删除（二次确认并说明后果）、按添加时间/名称/账户排序、搜索
- 迁移：导出 JSON / 复制 JSON / 复制 otpauth 列表；导入支持备份 JSON、裸数组、
  多行 otpauth、纯密钥文本
- 安全：可选 PIN 加密、立即锁定、离开 5 分钟自动锁定

**异常与边界**

| 场景 | 处理 |
|---|---|
| 密钥含非法字符 / 过短 | 精确报错（指出是哪个字符），字段级内联提示，不提交 |
| `otpauth://hotp` | 明确拒绝并解释原因，而不是静默失败 |
| 未知 algorithm / digits / period | 降级到安全默认值，同时提示「已回退」 |
| 链接 issuer 与标签前缀不一致 | 采用 `issuer` 参数并告知 |
| 重复添加（同密钥同名） | 二次确认；同密钥不同名则给“密钥已被使用”的软提示 |
| 导入文件部分行损坏 | 逐行降级，报告“新增 N／跳过重复 N／忽略无效 N”，不影响其余 |
| 导入超大文件 | 5MB 上限，避免主线程卡死 |
| 账户数上限 | 300 条，超出部分不计入并提示 |
| JSON 损坏 | 隔离到 `zy2fa.recovered.*`，**可一键下载原始数据**，不静默丢弃 |
| 某行账户密钥损坏 | 跳过该行、保留其余，并汇总提示 |
| localStorage 被禁用 / 无痕模式 | 启动即警告「本次修改不会保留」 |
| 写入配额超限 | 捕获 `QuotaExceededError`，**回滚内存状态**，界面不谎报成功 |
| 剪贴板被拒 | 降级到 `execCommand`，再失败则提示手动复制 |
| 非安全上下文（无 `crypto.subtle`） | 显式横幅说明，而非出现空白验证码 |
| PIN 输错 | 计数 + 指数退避节流（3 次后逐级延长），提示剩余尝试次数 |
| PIN 密码本身不可恢复 | 开启前明确提示；锁屏页提供“清除并重来” |
| 标签页后台挂起导致时钟偏移 | `visibilitychange` 回归时强制对齐验证码与环相位 |
| 中途重渲染（搜索/排序） | 倒计时环用负 `animation-delay` 定位相位，不会回到满格 |
| 保存失败 | 快照回滚，列表与磁盘保持一致 |
| 加密库异常 | 开启加密前用一次性密钥做加解密往返自检，避免把数据锁进坏密钥 |

### 4. 可验证性

- `tests/core.test.mjs`：57 项，零依赖，含 **RFC 6238 Appendix B 全部 18 个官方向量**
  （SHA-1/256/512 × 6 个时间点）、base32 编解码、otpauth 正常与畸形输入、
  导入合并、vault 加解密往返 / 错误 PIN / 损坏数据隔离。
- 界面层另有 27 项基于 jsdom 的冒烟检查（挂载真实 `index.html`，驱动添加、复制、
  搜索、路由、主题、导入、加密、锁定、解锁），因需额外依赖故不随仓库分发。

```
$ node --test tests/core.test.mjs
# tests 57
# pass 57
# fail 0
```

---

## 四、构建与持续集成

### 构建

源码本身不需要构建就能运行，`tools/build.mjs` 只负责产出**可部署产物**：

```
dist/
├── index.html            ← 引用改写为哈希化资源，内联的主题引导脚本保留
├── app.<hash>.css        ← 4 个样式表合成 1 个并压缩（76 kB → 57 kB）
├── app.<hash>.js         ← ES Module 图打包成 1 个并压缩（≈110 kB → 57 kB）
└── .nojekyll             ← 关掉 Pages 的 Jekyll 处理
```

三点设计取舍：

- **文件名带内容哈希**：可以给 `app.*.css/js` 设置永久缓存，HTML 不缓存，改版即失效。
- **esbuild 只是 devDependency**：运行时依然零依赖；没装依赖时构建会**降级为原样拷贝**，
  而不是直接失败，所以离线也能出包。
- **构建期断言自包含**：如果产物里出现任何 `https://` 资源引用，构建直接报错——
  这个应用承诺过"不发任何网络请求"，这条约束必须由构建守住，而不是靠自觉。

### CI（.github/workflows/ci.yml）

`push main` / 每个 PR / 手动触发，四步串行：

1. **令牌对账** — 重新执行生成器，若 `css/tokens.css` 与提交内容不一致就失败。
   这个文件是生成物，手改一次就会和明暗两套角色失配，而且界面上不会报错。
2. **测试** — 67 项（核心逻辑 57 + 样式不变量 10）。
3. **构建** — `npm run build`。
4. **产物校验** — 断言 `index.html` 指向哈希化资源、无远程引用、主题引导脚本仍在。

校验通过后上传 `zy2fa-dist` 产物（保留 14 天），并在 `main` 上自动部署到 GitHub Pages。
Pages 用的就是同一份 `dist/`，不存在"CI 测的和上线的不是同一个东西"。

## 五、已知取舍

- **无 QR 扫描**：需要摄像头权限与解码库，与“零依赖”冲突。已支持粘贴链接与手动录入，
  多数服务在“无法扫描”时都会提供密钥文本。
- **无 WebAuthn / 通行密钥**：保持 TOTP 单一职责。
- **PIN 加密不防御内存取证**：解锁后密钥驻留内存以便实时生成验证码，这是所有
  同类客户端的共同取舍；因此自动锁定默认开启建议。
- **`<dialog>` 与 `color-mix()` 需要较新浏览器**；旧浏览器会退化为无动画的可用界面。
- 字体使用系统栈（Roboto → 系统无衬线），不引外链字体，保证离线可用；
  Material 3 的字号/行高/字距令牌已完整落地，替换字体无需改样式。
