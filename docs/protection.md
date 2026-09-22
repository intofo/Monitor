# 系统拦截实现进度

## 当前可运行部分

Agent 内页 → 设置提供五种模式，分别原子保存到 `~/.monitor/config.json` 的 `agent_protection[agent_id]`。未配置的 Agent 默认仅监测，不继承别的 Agent 的授权。旧 `protection` 字段只保留兼容历史配置，不自动扩大授权范围。系统组件状态保留在全局设置的辅助服务页；Jev 配置在全局设置的 Jev 模型页。

原生执行器尚未部署，规则下发、实时 AI 审批及网络强制执行仍未接通，保存规则不代表实际保护。

| 模式 | 已授权目录读取 | 未授权目录读取 | 已授权网络目标 | 未授权网络目标 |
| --- | --- | --- | --- | --- |
| 仅监测 | 观察 | 观察 | 观察 | 观察 |
| 白名单拦截 | 允许 | 拒绝 | 允许 | 拒绝 |
| 访问时询问 | 允许 | 待审批 | 允许 | 待审批 |
| 禁止联网 | 允许 | 拒绝 | 仅批准的模型 API 允许 | 拒绝 |
| AI 拦截 | 允许 | 先拒绝、待 Jev 审查 | 允许 | 先拒绝、待 Jev 审查 |

`monitor-core::protection::ProtectionEngine` 仅返回判定，不能产生 `enforced=true` 日志。Ask 是未授权状态，不等于允许，也尚未实现系统请求审批窗口。只有原生执行器确认拒绝成功后才能写入实际拦截日志。

目录规则采用路径组件边界匹配；保存时解析符号链接并确认目录存在，拒绝根目录、相对路径、父目录穿越和超量规则。网络规则精确匹配标准化域名/IP、端口及 TCP/UDP，不隐式允许子域名、解析出的 IP、回环或 QUIC。禁止联网模式忽略通用网络白名单，使用用户批准的 `model_api_allowlist`，并保留用户单独开启的公开网页连接许可。保存失败保留旧规则，不写入拦截日志。

## 原生文件执行器进展

已新增 `monitor-enforcer` 的 Endpoint Security 文件授权实现、进程实例/子进程跟踪、受保护规则快照读取，以及宿主 SystemExtensions 激活接口和未签名扩展包构建脚本。代码可编译并通过身份/判定测试，但尚未获签名授权、部署或接入桌面规则下发/审计；Network Extension 内容过滤器原型也已实现，但尚未完成部署联调。详见 [macOS 系统扩展](../native/macos/README.md)。以下仍为上线前必要工作。

## 仍需完成的系统接入

1. Endpoint Security 文件执行器：获取获批的 `com.apple.developer.endpoint-security.client` entitlement、Developer ID 签名及用户完全磁盘访问授权。以 AUTH_OPEN 等事件在访问前判定；内存映射、目录枚举、已打开句柄、FD 传递、硬链接、别名和符号链接竞态需要单独验证，不能仅凭路径规则宣称完整文件隔离。
2. Network Extension 内容过滤器：系统扩展签名和激活、用户网络过滤授权、流身份认证、TCP/UDP/IPv4/IPv6 覆盖。通过内核提供的进程 token 关联 Agent；现有 sysinfo 的名称匹配和三秒采样不能作为强制执行身份依据。
3. 可信规则下发：签名校验的 IPC、root 管理的规则快照、规则版本及应用回执。不能直接把当前用户可修改的 config.json 作为抵御同用户 Agent 篡改的安全边界。
4. 审批：绑定进程实例、请求、规则版本和目标，禁止 PID 复用审批。遇到未授权请求先拒绝，UI 审批后重试；不能让系统授权事件无限等待 UI。超时或 UI 退出维持拒绝。当前规则引擎只给出 Ask 判定。
5. 健康状态：执行器加载成功且确认当前规则版本后才能显示保护生效；断连、事件丢失、系统授权失效须撤销该状态。当前命令明确返回 `enforcement_available=false`。
6. 验收：测试越界文件内容未被读取、被禁止的网络目标没有接收到连接或字节；子进程继承、进程重用、软硬链接、现有连接、服务故障和规则变更必须覆盖。

允许连接模型 API 无法保证该加密连接没有携带源码。准确区分正常模型上下文与未授权上传，还需定义内容授权及可信内容检测路径。不能将域名白名单描述为通用源码防泄漏能力。

现有 tcpdump 辅助服务维持只读采样，不支持以上授权事件，也不会因保存拦截设置自动改变行为。不恢复之前移除的代理功能。未正式签名开发版提供 SIP 检测与临时关闭的说明，详见原生开发文档。

## Apple 依据

- Endpoint Security entitlement：https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client
- ES 客户端创建及 TCC：https://developer.apple.com/documentation/endpointsecurity/es_new_client(_:_:)
- AUTH 响应与时限：https://developer.apple.com/videos/play/wwdc2020/10159/
- Network Extension entitlement：https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension

## 每个 Agent 的模型 API 批准

支持从 Codex TOML、Claude Code / Gemini CLI / OpenCode 的已知配置位置及自动识别的项目配置文件提取显式 API 地址字段。不自动补猜默认供应商域名；环境变量引用和没有明文地址的配置不会被解析成授权。候选项不代表当前活跃模型，用户需逐项选择批准。

每份配置最多 256 KiB，禁止跟随文件自身的符号链接，只返回不含凭据、查询字符串的 origin、来源路径和 TCP host/port，不返回 Key 或完整配置。拒绝用户名密码 URL，不执行配置内容。未识别或未找到地址时，确认后保持全部禁网。

批准令牌仅存于内存，有效期 5 分钟，绑定 Agent 与配置版本，一次使用；后端从原始候选列表生成授权，拒绝前端伪造地址、跨 Agent 或过期令牌。配置变更不会自动增添网络例外。批准的是域名/IP 和端口，不是 HTTPS 中的单一路径或特定请求内容。

## Jev 接口和密钥

当前实现可配置的 OpenAI 兼容 `chat/completions` API；未内置或假定真实 Jev 模型 ID。设置填写 API 地址、实际模型名称和 Key，Key 存 macOS 登录钥匙串，配置文件只保存地址和模型。修改服务地址不会把旧地址的密钥自动转发给新地址。HTTP 仅允许本地回环服务，远端要求 HTTPS，不跟随重定向，12 秒请求超时、16 KiB 响应上限。

每个 Agent 开启 AI 模式需确认所展示的 Jev 地址；修改全局 Jev 服务/模型会撤销已有 AI 同意，必须重新确认。只发送访问类型、是否在项目内、目标是否已授权三个结构化字段，不发送源码、真实路径、命令行或 Agent 配置密钥。Jev 自身的 Key 仅通过该服务的 Authorization header 发送。

连接测试和“模拟越界读取，测试 AI”均使用合成事件；真实系统事件尚未接入。模型必须返回严格 JSON 的 allow/deny/ask 和有限长度的原因。AI 推荐是推断，不证明上传意图；不会直接解除系统拒绝或覆盖本地硬性规则。原生文件执行器遇到 Review 判定会拒绝并标记 `ai_review_required`，不在 ES 回调中等待模型。后续可信事件消费者及人工批准/重试通道还需完成。


项目目录由当前 Agent 的独立进程工作目录自动识别，不接受前端手动提供的项目目录。识别时核对 PID、启动时间和执行路径，不从继承的工具进程推断项目；用户根目录、系统目录和无法识别的 GUI 工作区不自动授权。Agent 未运行时不保留旧项目授权，页面每 3 秒更新检测结果，项目目录不写入持久配置，旧版本保存的项目目录在加载时清除。该发现数据仍不是系统执行端的可信身份或已部署规则。
模型 API 只从匹配 Agent 的已知配置位置和识别出的项目配置中发现，取消手动选择配置文件；缺失配置或不支持的 Agent 不猜测地址。白名单编辑入口位于拦截模式右侧，弹窗修改后仍需保存规则；禁止联网模式继续逐项批准发现的 API。


系统级执行的新进展见 `native/macos/README.md`：文件扩展可按 exec 实例维护独立项目，网络扩展原型通过 root-only 本机 IPC 读取进程归属。它不使用 Docker 或本机启动沙箱。新增 `allow_web` 可配置公开 HTTP/HTTPS 连接许可；这不是加密内容防泄漏检查。根规则部署、实时审批/AI 桥和可信审计回传未全部接通前，设置页继续显示未生效。
