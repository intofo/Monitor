# Security policy

## 项目阶段与支持范围

Monitor 当前处于开发阶段，系统拦截与部署仍有待验收的环节，详见 [能力边界](README.md) 和 [验证说明](docs/validation.md)。请在报告中注明具体版本或提交；目前未设长期支持分支、固定修复时限或版本支持周期。

## 私下报告漏洞

请勿在公开 Issue、Discussions 或 PR 中发布未修复漏洞的利用细节、访问令牌或真实用户数据。

优先访问 [Security 页面](https://github.com/intofo/Monitor/security)，使用 **Report a vulnerability** 私下报告（本仓库已启用 GitHub Private Vulnerability Reporting）。如果没有该入口，说明此渠道尚未开放；可提交不包含漏洞细节的 Issue，仅请求维护者提供私密联络方式，在确认渠道前不要发送敏感材料。

报告应包含：

- 受影响版本或提交，以及 macOS 和硬件架构。
- 预期与实际行为、影响范围和必要的前置权限。
- 最小化复现步骤及合成或脱敏样本。
- 可选的修复建议。

不要附带签名私钥、真实终端遥测、个人文件或第三方凭据。仅在自己拥有或获得授权的环境中验证问题。

维护者将评估报告、讨论修复与披露安排；目前未设固定响应 SLA 或漏洞奖励计划。
