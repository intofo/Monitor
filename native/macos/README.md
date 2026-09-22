# Monitor 用户空间系统扩展

不使用 DriverKit（没有设备驱动需求）或内核扩展。正式发行使用 Apple 授权签名；开发测试可选择临时关闭 SIP。

## 当前代码

- `crates/monitor-enforcer`：Endpoint Security 原生文件授权执行器原型；C shim 调用 Apple SDK，Rust 复用已有规则引擎。
- `src-tauri/native/system_extensions.m`：宿主通过 `OSSystemExtensionManager` 请求激活，处理批准、升级、重启及失败回调。未打包或未签名时拒绝请求；不使用 root shell 安装系统扩展。
- 设置 → 辅助服务展示文件和网络组件的准备/激活状态。每个 Agent 内页单独配置策略。**激活状态与保护生效分开**：当前没有执行器连接、规则回执的完整联调，因此应用仍显示拦截未生效。
- Endpoint Security 订阅 AUTH_OPEN、AUTH_MMAP、AUTH_READDIR、AUTH_CLONE、AUTH_COPYFILE 和 exec/fork/exit 通知。无读取标志的单纯写打开不作为读拦截。
- 按真实 UID 与显式登记的路径/CDHash 匹配根 Agent；使用内核 audit token 的 PID/pidversion 跟踪 fork/exec 子进程。代码签名失效或原路径代码被替换时拒绝读取；重名程序不自动获得保护身份。
- 非监测用户和无关进程不拦截。读取截断路径或多硬链接普通文件时保守拒绝，避免只凭路径白名单放行别名。
- Ask 模式当前拒绝未授权访问并输出 `approval_required=true`，尚无请求审批 UI/恢复机制，不能把它描述为已实现交互式审批。
- 回调不做磁盘/网络 I/O，不等待前端。拒绝响应使用正确的 flags/auth API，关闭内核决策缓存。系统接受拒绝响应后才输出 `enforced=true`。响应失败、事件序列丢失或进程容量溢出会停止客户端并报错，不能继续宣称保护完整。
- 审计为有界 JSONL stdout 队列（512 条）；出现日志缺口输出 `audit_gap`。未接入桌面 SQLite，也不自动信任普通用户提交的拒绝日志。

## 构建与无权限检查

```sh
python3 scripts/build_endpoint_extension.py
# 不请求系统授权，不建立 ES 客户端：
target/system-extensions/debug/dev.agentmonitor.endpoint.systemextension/Contents/MacOS/monitor-enforcer --check
cargo test -p monitor-enforcer
```

输出为可审阅的未签名开发包，不会安装、激活或更改系统设置。`--check` 只检查本进程声明的 entitlement 和 root 状态，不代表 profile 有效或已获 Full Disk Access。

签名时，必须同时提供真正的 Developer ID Application 身份和获批 ES provisioning profile：

```sh
python3 scripts/build_endpoint_extension.py --release \
  --identity 'Developer ID Application: YOUR ORGANIZATION (TEAMID)' \
  --profile /absolute/path/to/EndpointSecurity.provisionprofile
```

这一步仅构建和签名，不激活。Apple profile、证书和私钥不提交到仓库。

宿主发行包后续需将扩展放入 `Monitor.app/Contents/Library/SystemExtensions/`，宿主使用同一团队签名并包含 `host.entitlements.plist` 的 `system-extension.install` 权限。整个 app 需重新签名及公证，放入合适的 Applications 目录，再由用户在设置页请求激活；还需用户授予 Full Disk Access。Developer ID 签名和本地声明 entitlement 不能替代 Apple 授予的权限。

## 规则快照

扩展默认读取 `/Library/Application Support/Monitor/Enforcement/policy.json`。文件及每级父目录必须 root 所有、不可由组或其他用户写入，逐级 openat + O_NOFOLLOW 校验，限制 1 MiB，不直接读取 `~/.monitor/config.json`。

结构为 `Snapshot { revision, users: [{ uid, policy, agents: [{ agent_id, executable, cdhash }] }] }`，见 Rust 类型。`policy` 与应用规则格式一致；`executable` 应为核验后的真实路径，`cdhash` 是当前可执行文件架构的 40 位十六进制 Code Directory Hash，不是随意输入的文件摘要。禁止 root 用户规则和重复身份。签名核验后的 IPC、登记确认、root 快照发布/更新与回执还未实现；当前不会自动安装规则文件。

因此当前开发包不能直接激活使用。缺失规则时启动返回错误，不会加载任意用户文件或默默切换到“已保护”。

## 尚未覆盖，不能宣称完成防泄漏

- Network Extension 过滤器原型已加入（见下文），尚未签名激活或完成系统联调；文件执行器本身不能阻断联网。
- 激活前已有的子进程、已打开 FD、FD 传递、现有映射、注入/跨进程访问、服务代理读取、路径/文件系统竞态等，仍需补充系统集成和对抗测试。
- 系统扩展默认事件静默规则、截止时间、事件丢失及服务失效仍需签名环境验证；当前客户端停止会撤销文件保护，不是内核 fail-closed 保证。
- 名称/路径采样不能直接变成可信身份；不能把共享 node/python 解释器登记成某个 Agent 后就声称准确区分脚本。
- 允许的 HTTPS 连接可能正常携带代码上下文。网络目标授权不是加密内容防泄漏检测。

验证完成前，应用的 `enforcement_available` 保持 false。

## Apple 文档

- https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers
- https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client
- https://developer.apple.com/videos/play/wwdc2020/10159/

AgentIdentity 支持可选 `policy` 覆盖同用户旧模板，子进程沿用其归属 Agent 的策略。AI Review 在原生回调中保持拒绝并输出 `ai_review_required`，不会同步调用模型；模型服务与实时事件桥尚未连接。

## 本轮系统级执行层

已撤销容器启动方案。新增 `native/macos/network/Filter.m` 的 Network Extension 内容过滤器、对应 entitlements / Info.plist 和 `scripts/build_network_extension.py`，可先构建未签名包。补齐签名时使用与文件扩展相同团队的 Developer ID 身份，并分别提供 Apple 授权的描述文件。

```sh
python3 scripts/build_endpoint_extension.py
python3 scripts/build_network_extension.py
# 网络扩展签名示例（只构建，不激活）
python3 scripts/build_network_extension.py --release \
  --identity 'Developer ID Application: YOUR ORGANIZATION (TEAMID)' \
  --profile /absolute/path/to/NetworkExtension.provisionprofile
```

网络扩展激活后，还必须通过宿主的 `NEFilterManager` 启用过滤配置；辅助服务设置内已增加显式启用/停用按钮。宿主 entitlement 模板同时包含安装系统扩展与网络内容过滤能力。未签名的开发程序不执行这一步。

文件扩展的 `AgentIdentity.dynamic_project=true` 使用 ES EXEC 事件提供的 cwd 为每个 PID/pidversion 实例建立独立项目权限，覆盖旧模板中的项目目录；同一 Agent 同时从 `/code/a`、`/code/b` 启动不会合并授权。子进程继承所属实例项目，不因自己 chdir/exec 扩大范围。没有观察到 exec 的已有实例不猜测项目权限，应在完成部署后重新启动这些 Agent。运行库与配置目录仍需显式只读授权。

文件扩展在可信 root 目录中提供权限 0600 的 `runtime.sock`，仅允许 root 对等方读取内存中的进程归属与规则；不提供配置修改接口，不保存进程/活动历史。网络扩展在后台读取，使用 audit token 的真实 UID、PID/pidversion 匹配；模型域名放行同时要求 flow hostname、解析出的目标 IP、端口与协议一致。没有 hostname 时不会把整个 CDN IP 当作域名授权。已登记进程的身份不匹配、心跳过期、Ask/AI 未有批准均拒绝连接。显式覆盖 IPv4/IPv6 loopback 过滤规则，避免框架默认放过本地代理连接。

`allow_web` 为单独启用的连接级许可：允许公开目标的 TCP 80/443，阻止私网、loopback、QUIC/其他端口（明确白名单除外）。它不检查加密 HTTP 方法或正文，不能宣称允许网页读取就能同时禁止所有代码上传。

### 仍待完成及签名环境联调

- 桌面配置到 root 规则的签名认证部署、热更新与版本回执，ES/NE 拒绝记录到桌面 SQLite 的可信回传，以及 Jev/人工审批的实时执行桥仍需接通。当前保存设置仍不会部署系统规则。
- ES → NE 进程归属同步存在时间窗口；首次连接与子进程登记竞态、无法归属的流、事件缺口和已建立连接必须继续做对抗测试。未归属流不全局阻断，以免影响无关程序；因此不能宣称无遗漏防泄漏。
- 数据过滤器的沙箱对 root IPC 的实际可访问性、Full Disk Access、宿主与两个扩展的签名/profile、升级与重启恢复必须在正式授权环境测试。
- 未签名包的 `--check` 不激活扩展，不代表系统保护已生效。GUI 的 `enforcement_available` 继续保持 false。

### 未正式签名的开发版本

首次运行检测宿主签名与 `csrutil status`，提示开发机的恢复模式操作与恢复 SIP 方法；设置 → 辅助服务中可重新查看。普通监测不以关闭 SIP 为条件。未知或部分关闭状态不作为 SIP 已关闭处理。

SIP 完全关闭时，激活入口允许有效的 ad-hoc 签名扩展，但仍要求宿主安装 entitlement、扩展 entitlement 和正确 bundle。完全无签名的裸二进制不等于可加载的开发扩展。系统是否允许最终加载由 macOS 决定；启动提示不会安装、激活或修改系统保护，也不会改变 enforcement_available。该路径尚未在关闭 SIP 的设备上验证。

参考 Apple：[开发与测试系统扩展](https://developer.apple.com/documentation/driverkit/debugging-and-testing-system-extensions)、[关闭和恢复 SIP](https://developer.apple.com/documentation/security/disabling-and-enabling-system-integrity-protection)。
