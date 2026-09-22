# Contributing to Monitor

欢迎通过 Fork + Pull Request 参与 macOS Monitor / EDR 项目。普通贡献者无需仓库 Write 权限。

## 项目与开发环境

Monitor 是面向本机 AI 编程 Agent 的桌面监测工具，使用 Tauri 2、Rust 和 Svelte 5。系统级拦截仍是开发中的原型，规则拒绝判定不代表系统实际阻断。

推荐 Node.js 24、npm、Rust stable；macOS 原生组件需要 Xcode Command Line Tools / macOS SDK。完整安装与能力边界见 [README](README.md)、[验证说明](docs/validation.md) 和 [扩展开发说明](native/macos/README.md)。

```sh
npm ci
npm run tauri dev
```

浏览器预览使用 `npm run dev`，无法访问桌面原生采集功能。提交前按修改范围运行：

```sh
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm run check
npm run build
```

原生扩展修改还需在 macOS 上运行 `python3 scripts/build_endpoint_extension.py` 和 `python3 scripts/build_network_extension.py`。构建通过不能替代系统授权、扩展加载和真实阻断验收。跨平台 CI 范围见 [Checks](.github/workflows/check.yml)。

项目代码采用现有 [MIT License](LICENSE)，图标另有来源与许可说明。引入第三方代码或依赖时保留版权声明，说明来源与许可证，不提交未经授权的材料。

## 提交流程

1. 查看现有 Issues，避免重复；较大的功能或架构变更先开 Issue 讨论范围。
2. Fork 本仓库，在自己的 Fork 中从最新 main 创建主题分支。
3. 每个 PR 聚焦一个问题，附上修改原因和验证方式。
4. Push 到自己的 Fork，向 `intofo/Monitor` 的 `main` 提交 PR。
5. 按维护者反馈更新，最终由维护者合并。无需申请直接写入 main。

文档修正可以直接提交 PR。领取 `good first issue` 或 `help wanted` 任务时，请先留言说明计划；这些标签不会自动授予权限。

## 开发和验证

- 在可恢复的测试环境中验证监控、拦截和权限相关改动，避免影响日常使用的机器。
- 记录 macOS、硬件架构、Xcode 版本及复现步骤；未测试的内容明确标注。
- Endpoint Security、System Extension 等相关能力的签名、entitlement 和授权要求，应在引入对应模块时依据 Apple 官方文档验证并记录。
- 不提交签名证书、私钥、Provisioning Profile、访问令牌、真实用户活动日志或其他敏感数据。
- 测试数据采用合成或脱敏样本；行为修改应附有针对性测试或可复现的手工验证。
- 不要求贡献者为了参与文档或单元测试工作而关闭系统安全保护。

## PR 检查

- 解释用户可观察到的行为变化，并关联相关 Issue。
- 更新受影响的文档，注明测试结果和限制。
- 涉及日志、进程信息、文件路径、网络事件或权限时，说明数据收集范围、保存方式及权限变化。
- 漏洞按 [SECURITY.md](SECURITY.md) 私下报告，不在公开 Issue 或 PR 中披露利用细节。

## 交流

Bug 和已明确的任务使用 Issues。Discussions 开启后可用于使用问题和开放式讨论。请尊重他人，提供可复现的信息，避免发布个人或设备的敏感数据。
