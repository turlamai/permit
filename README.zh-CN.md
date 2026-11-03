# Permit

**给独立软件的签名产品权益：离线可验证，需要时也能在线管理。**

[![CI](https://github.com/turlamai/permit/actions/workflows/ci.yml/badge.svg)](https://github.com/turlamai/permit/actions/workflows/ci.yml) ![Racket](https://img.shields.io/badge/Racket-9F1D20?logo=racket&logoColor=white) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) ![Protocol](https://img.shields.io/badge/protocol-v1-C15F3C)

[English](README.md) · **中文**

Permit 是一套与应用框架无关的协议及 Racket 参考实现，只回答一个产品问题：

> 这个人、组织或安装实例，现在可以使用什么？

支付平台能说明钱是否到账，账号系统能说明谁已登录；Permit 则把长期产品权益变成带签名、可携带的凭证。应用只需内置公开信任库，就能在本地完成验证——不强制账号、不依赖每次联网，也不把商业授权塞进应用框架。

## 加密运行环境要求

Permit 必须具备可用的原生 **Ed25519** 实现才能验签或签发。
Racket 参考实现按固定顺序尝试 OpenSSL 3+、libsodium 和 Nettle，
它们均是上游 crypto-lib 提供的 Ed25519 实现，而不是降级签名算法。
如果所有后端均不可用，必须拒绝密码学操作；源码编译成功不代表运行环境受支持。
见[原生加密后端诊断及官方包构建证据](docs/crypto-runtime.md)。

## 使用入口

需要签名且可离线验证的权益时，在应用旁组合 Permit。从 entitlement 开始；只有产品明确需要在线租约时才增加 activation。免费产品不需要授权子系统。

[使用选择、成熟度、升级与支持](docs/USING.zh-CN.md) · [English](docs/USING.md)

## 为什么需要 Permit？

商业软件通常同时需要两种看似相反的能力：

- **离线可验证**：已安装的应用不联网也能判断功能是否应该放行。
- **在线可管理**：Commerce 或其他明确的签发服务可以续订订阅、分配席位、轮换密钥或刷新短期激活租约，而不改变客户端验证协议。

Permit 把两者拆开。长期的 **entitlement（权益凭证）** 描述商业权利；可选的 **activation lease（激活租约）** 在有限时间内把权利绑定到某个安装实例；**trial（试用凭证）** 则保持为独立类型。产品只采用自己需要的层级。

Permit 与应用框架并列组合：

```text
                         产品
                       /      \
              Rivet 或 Glaze   Permit
              运行时 / 更新     产品权益
```

Rivet 和 Glaze 都不依赖 Permit。更新制品签名与 Permit 凭证签名也始终使用不同的密钥和信任策略。长期依赖方向和职责分工见[框架集成契约](docs/framework-integration.md)。

需要在线商业能力的产品可以增加 [Commerce](https://github.com/turlamai/commerce)，负责支付渠道事件、商业状态投影、签发流程与凭证领取。Commerce 只通过显式 issuer API 使用 Permit；Permit 永不依赖 Commerce，产品仍只根据已验证的 Permit 凭证在本地授权。

## 可表达的产品模型

Protocol v1 用一套词汇覆盖常见商业模型，但不把价格或支付策略写进应用：

| 产品模型 | 使用权 | 更新 | 新发布功能 |
| --- | --- | --- | --- |
| 永久买断 | 永不过期 | 不限制或限定期限 | 不限制或限定期限 |
| 永久使用 + 更新维护期 | 永久 | 截止维护期结束 | 通常不限制 |
| 永久使用 + 新功能窗口 | 永久 | 通常不限制 | 截止功能窗口结束 |
| 订阅 | 截止订阅结束 | 按策略定义 | 按策略定义 |
| 试用 | 截止试用结束 | 按策略定义 | 按策略定义 |

授权项可以表示版本、功能、附加项、套餐和标量能力。团队所有权、实名席位、设备激活数与并发席位是彼此独立的声明，不挤进一个含义模糊的计数器。`installation_id` 由应用生成并保护隐私，不做硬件指纹。

## 快速开始

如果你第一次接触签名凭证，请先看[从零开始指南](docs/getting-started.zh-CN.md)。它会说明哪些文件必须保密、哪些文件需要随应用发布，以及“验证凭证”和“判断产品权限”为什么是两个步骤。

安装 Racket 包：

```bash
raco pkg install --auto --name permit https://github.com/turlamai/permit.git
```

生成 Ed25519 密钥对和初始信任库：

```bash
raco permit keygen \
  --private private-key.der \
  --public public-key.der \
  --trust-store trust-store.json \
  --key-id license-2026 \
  --issuer com.example \
  --purpose entitlement
```

`--purpose` 可以重复传入，用于生成最小权限签名 key；只有确实要让同一把 key 签全部 v1 凭证的小型部署才应省略。私钥不能进入源码仓库或应用包。可以先从 [`examples/`](examples/) 中选择一份已通过 schema 校验的商业模型模板，再对 payload 文件的原始字节签名：

```bash
raco permit issue \
  --key private-key.der \
  --key-id license-2026 \
  --trust-store trust-store.json \
  --payload entitlement.json \
  --output entitlement.permit.json
```

验证签名、信任密钥、签发方和 schema：

```bash
raco permit verify \
  --trust-store trust-store.json \
  --credential entitlement.permit.json
```

再执行产品策略判断：

```bash
raco permit check \
  --trust-store trust-store.json \
  --credential entitlement.permit.json \
  --product example-app \
  --feature example-feature \
  --feature-published-at 2026-10-01T00:00:00Z \
  --version 2.0.0
```

`inspect` 会明确标记输出未经验证；绝不能只看 inspect 出来的声明就放行功能。

## Protocol v1

凭证是一个很小的 JSON 信封：

```json
{
  "permit_version": 1,
  "algorithm": "Ed25519",
  "key_id": "license-2026",
  "payload": "<原始 JSON 字节的 base64>",
  "signature": "<Ed25519 签名的 base64>"
}
```

Ed25519 对解码后的 `payload` 字节做**精确签名**。验证端先验签，再解析授权声明；绝不为了验签而“解析 JSON 后重新序列化”。这条规则消除了跨语言 JSON 规范化差异。

Protocol v1 包含：

- `entitlement`、`trial`、`trial-extension`、`activation` 四种凭证
- 相互独立的 `use_expires_at`、`updates_through`、`features_through` 窗口
- 可选的产品版本范围与安装实例绑定
- 版本、显式功能、按发布时间自动解锁未来功能、附加项、套餐和标量能力授权
- 团队、实名席位、设备数和并发席位限制
- 用稳定 `entitlement_id` + 单调 `revision` 表达续费、重签和方案变更
- 使用绝对截止时间、可安全重复导入的签名试用延期
- 绑定到精确 entitlement 快照并带明确离线宽限期的短期激活租约
- 支持 `next`、`active`、`retired`、`revoked` 状态并限制每把密钥签名用途的多密钥信任库
- 确定性的跨语言测试向量

第一次使用请从[从零开始指南](docs/getting-started.zh-CN.md)开始。需要参与实现时，先阅读[架构地图](docs/architecture.md)；需要实现协议时，再阅读[规范性的 Protocol v1 文档](docs/protocol-v1.md)、[权益模型](docs/entitlement-v1.md)、[激活租约](docs/activation-v1.md)、[信任模型](docs/trust-model.md)、[生命周期](docs/lifecycle.md)、[兼容规则](docs/compatibility.md)、[威胁模型](docs/threat-model.md)、[框架集成契约](docs/framework-integration.md)和[管理边界](docs/management-boundaries.md)。

## 客户端与签发端 API

默认的 `(require permit)` 有意保持为客户端 API：只包含验签、信任库读取、策略判断、安装标识和本地 Trial runtime，不导出私钥生成、签名、原始 envelope 构造或 raw schema parser。

签发端显式使用：

```racket
(require permit/issuer)

(define envelope
  (issue-credential payload-bytes private-key "license-2026" trust-store))
```

`issue-credential` 是推荐的安全签发路径：它会检查 schema、issuer、密钥必须处于 active 状态、credential type 是否在 key purposes 中、`issued_at` 是否落在签发窗口内，以及私钥是否真的对应信任库中的公钥。CLI 的 `raco permit issue` 走同一条路径；`raco permit sign` 仅保留为明确的低层逃生口。

## Racket API

```racket
#lang racket/base

(require permit)

(define store (read-trust-store "trust-store.json"))
(define entitlement
  (verify-credential "entitlement.permit.json" store))

(when (feature-entitled? entitlement
                         "example-app"
                         "example-feature"
                         #:published-at "2026-10-01T00:00:00Z")
  (enable-pcap-export!))
```

续费或方案变化不会修改旧文件，而是签发一个 `entitlement_id` 相同、`revision` 更高、`credential_id` 全新的完整权益快照。客户端只在自己实际拿到的凭证中选择最高 revision；这不是离线撤销机制。

在线管理型产品会同时验证长期权益和短期安装租约：

```racket
(credential-usable? entitlement
                    #:installation-id installation-id
                    #:activation activation-lease)
```

纯离线产品完全可以省略 activation 层。

## 本地首次试用

应用第一次运行、尚未联系签发端时，不可能拥有一份针对这个安装实例唯一签名的 Trial。因此 Permit 不把这种状态硬塞进 Protocol v1，而提供一个很小的、与存储实现无关的本地 Trial 状态机：

```racket
(define trial
  (make-local-trial #:duration-seconds (* 14 24 60 60)))

(define result (evaluate-local-trial trial))
(save-local-state! (local-trial-evaluation-state result))
```

状态使用随机 trial id 与 `last_seen_at` 时钟高水位，也可以消费已经验签的 Protocol v1 `trial-extension`。这只是合理的防误重置能力，不声称能阻止完全控制本机的用户删除或回滚状态。

需要 activation 的产品可用 `generate-installation-id` 生成同样隐私友好的随机安装标识。详见[本地 Trial 与安装标识](docs/local-trials.md)。

## 信任与密钥轮换

应用只携带公钥。信任库可以先放入带未来签发起始时间的 `next` 密钥，再让签发端切换；用 `active` 密钥进行正常签发；`retired` 密钥保留明确的签发截止时间并继续验证截止前签出的永久凭证；`revoked` 密钥则立即失去信任。密钥时间窗约束的是凭证中已经签名的 `issued_at`，不是多年以后客户端执行验证的当前时间。

因此，一个应用版本可以提前携带明天要启用的公钥，而本地验证路径始终保持确定。

## 有意保留的边界

Permit v0.1 **不实现**支付、客户账号、邮件、定价、税务、管理后台、托管计量或完整许可证服务器。家族内从支付到权益的编排由 Commerce 负责，账号由身份/产品服务负责；这些系统可以通过显式 issuer API 签发和刷新 Permit 凭证，但不属于验证核心。

席位分配、设备回收、订阅续期和凭证交付属于 Commerce 或其他管理操作，账号恢复仍属于身份/产品服务；v0.1 只定义这些系统与产品之间交换的签名制品。

## 开发

```bash
raco pkg install --auto --no-docs --link
raco make permit/main.rkt permit/cli.rkt permit-doc/scribblings/permit.scrbl
raco test -p permit
```

[`test-vectors/v1`](test-vectors/v1) 下的确定性语料是其他语言实现的互操作契约；[`conformance/c`](conformance/c) 中的 C 运行器即以独立实现身份执行该语料。
完整变更门槛见 [CONTRIBUTING.md](CONTRIBUTING.md)，走向 1.0 所需的证据见 [ROADMAP.md](ROADMAP.md)。

## 仓库结构

```text
permit/
├── permit/                 # 公共门面、实现与 CLI
├── permit-doc/             # 随包安装的 Scribble 参考手册
├── docs/                   # 架构、规范协议与边界
├── examples/               # 已通过 schema 校验的商业模型模板
├── test-vectors/v1/        # 确定性跨语言一致性语料
├── conformance/c/          # 针对语料的独立 C 一致性运行器
├── permit-test/            # 单元、集成、文档与向量测试
└── site/                   # 双语产品主页
```

## 状态

Protocol v1 已实现 v0.1 的全部凭证类型，但仓库尚未作出稳定 1.0 的兼容承诺。安全敏感字段一律严格校验并默认拒绝；只有 `extensions` 保持开放扩展。

## 许可证

[Apache-2.0](LICENSE)
