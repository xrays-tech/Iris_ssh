# SSH 网关开发计划 M4（后端基础设施专项）

> 状态：**已过门禁（有条件通过，P0 已修订）** ｜ 版本：v1.1 ｜ 依据：`dev-docs/plan-m3.md` §10、`docs/known-limitations.md` #1/#2、`dev-docs/propose.md` §3.3
> 范围：**M4-1 后端 host key `@cert-authority` ＋ M4-2 后端 `TrustedUserCAKeys` 用户证书拨号（cert-dial）**——后置自 M3 门禁（P1-1）的后端侧子项。
> 执行顺序：**先一次性全量实现（M4-I）→ 再统一收口测试修正（M4-V）**，与 M1/M2/M3 一致。
> 评审记录：@oracle 裁决「有条件通过」——P0-1（M4-T1 host 证书四步校验链含 principals 匹配）已于本版修订，P1/P2 项并入（见 §9 修订记录）。

---

## 1. 依据与本底事实（已核实，不重复调研）

| 事实 | 出处（已确认） |
|---|---|
| russh client 原生支持证书认证：`authenticate_openssh_cert(user, key: Arc<PrivateKey>, cert)` / `authenticate_certificate_with(user, cert, hash_alg, &mut signer)`（openssh cert 用内层签名私钥；FutureCertificate 用自定义 signer） | russh client/mod.rs:482-493, 636-653 |
| **host 证书校验为 handler 全责（源码已核实）**：russh client 在 `check_server_key` 前对 host 证书**零前置校验**——KEX 签名验证后直接 `certificate.into()` 交 handler（client/mod.rs:2012-2022，证书**替换**而非叠加 key check）；Handler 文档明示「是否信任 key/证书由实现决定」（L2726-2728），默认实现拒绝一切（L2733-2735） | russh client/mod.rs（M4-P0 S1 结论） |
| OpenSSH `TrustedUserCAKeys` 原生支持 ed25519 用户证书 + principals + 有效期（5.4+ 引入、8.x 成熟） | 既有知识（S2 实连验证） |
| 网关→后端认证现走私钥：`BackendDialer` → `authenticate_publickey(&grant.target.user, pkwha)` | src/backend/mod.rs:295 |
| 后端 host key 校验现按内层指纹（pin/accept-new）：`check_server_key` + `HostKeyVerifier`；`host_key_fingerprint` 对 `Certificate` 也取内层公钥（占位，非 CA 校验） | src/backend/mod.rs:128-135, 157-177 |
| russh client Handler `check_server_key(&mut self, server_public_key: &PublicKeyOrCertificate)`——通过 `PublicKeyOrCertificate::Certificate` 分支可判 `signature_key()` ∈ 受信 CA | src/backend/mod.rs:159 已导入该类型 |
| 网关已具备 CA 能力：`CertificateAuthority`（受信 CA 集 + 签发私钥 + `issue_user_certificate_with` 短期用户证书）、`[ca]` 配置（trusted_ca_keys/signing_key/cert_lifetime） | src/ca/mod.rs:38-205；src/config.rs:[ca] |
| 门禁基线：build/clippy(-D warnings)/fmt 全绿、单元 161、集成 23 PASS/2 SKIP（真机半开/netem 实演已 PASS：提交 94ef29d） | 既成事实 |
| 测试后端真机 `root@47.109.73.53`（Linux，可 root）：可改 `sshd_config` 增 `TrustedUserCAKeys`/host 证书、`authkeys` 验证；本地 macOS sshd 亦可用于开发态 | 既有通道 |

---

## 2. 目标与范围

### 2.1 目标
1. **M4-1**：后端 host key 纳入 `@cert-authority` 信任体系——网关 client 腿对 host 证书校验 `cert.signature_key()` ∈ 受信 CA 集（而非内层指纹），host key 证书化/CA 统一签发成为可能。
2. **M4-2**：后端 `TrustedUserCAKeys` 用户证书拨号——网关用 CA 签发的短期用户证书认证后端 sshd（而非固定私钥），后端可要求用户级 CA 统一签发。

### 2.2 In Scope
- M4-1：host 证书校验（`@cert-authority` 语义：CA 集内任意 host 证书可信任）、`check_server_key` 证书分支、单测 + E2E。
- M4-2：后端用户证书签发/加载路径（复用 `CertificateAuthority.issue_user_certificate_with`）、`authenticate_openssh_cert`/`authenticate_certificate_with` 接线、按后端策略选择凭据、证书过期/CA 轮换语义、E2E。
- 配置与文档：`[ca]` 相关配置扩展（若需）、known-limitations 更新（移除 #1/#2 占位）。
- 测试：单元 + 真机/本地 sshd 集成（后端 `TrustedUserCAKeys`、host 证书两种拓扑）。

### 2.3 Out of Scope（明确不做，本轮）
- 前端（客户端→网关）证书签发的正式运维 API（M3 已有 `issue_user_certificate_with` 能力，控制面面集成另议）。
- host key 向客户端的 `@cert-authority`（`known_hosts`/client 侧）——不属于后端基础设施。
- russh 上游 feature（global_request hook 等）仍不涉及。

---

## 3. 里程碑与排期

**执行顺序（同前批次）：先一次性全量实现（M4-I）→ 再统一收口测试修正（M4-V）。**

| 阶段 | 周期（假设） | 出口门禁 |
|---|---|---|
| **M4-P0 Spike 期** | 2~3 有效日（前置技术决策；S1 结论已由门禁核实，可省 ~1 日） | MS4-P0：3 个 Spike 全闭环 |
| **M4-I 一次性全量实现** | 1~2 周 | MS4-I：M4-1/M4-2 全部代码一次性实现，`cargo build` 通过 |
| **M4-V 统一收口验证** | 2~4 日 | MS4：全量单元 + 集成统一跑通，修正至全绿 |

> 排期假设：单人即可（两项都集中在 backend/ca 模块）。两项都只动 `src/backend/`、`src/ca/`、`src/config.rs`、`tests/`、`scripts/` 后端拓扑脚本；无跨 lane 耦合。MS4 门禁一次性过。

---

## 4. 任务分解（WBS）

### 4.0 M4-P0 — Spike 期（实现前置决策）

| ID | Spike | 目标 / 方法 | 产出物 | 依赖 |
|---|---|---|---|---|
| S1 | **host 证书校验路径（确认性 Spike）** | russh 行为已由门禁源码核实为「handler 全责、零前置校验」（§1）。本 Spike 仅确认 `signature_key()`/`valid_before`/`valid_principals` API 可用性 + 与既有 `Pinned`（内层指纹）/`AcceptNew` 策略并存方式；设计「@cert-authority = CA 集内任意 host 证书按四步校验链信任」 | host 证书校验设计结论（四步链）；`HostKeyVerifier` 扩展方案 | 无 |
| S2 | **后端用户证书认证** | 在测试后端 sshd 配置 `TrustedUserCAKeys ./ca.pub` + 网关 CA 签发短期用户证书，用 russh client `authenticate_openssh_cert`（主路径）/`authenticate_certificate_with`（fallback）实连通；确认后端 `authorized_keys` 不需网关公钥（证书即可）；验证证书过期/错 principal 被后端拒 | cert-dial 可行结论 + demo 代码；后端配置模板 | 无 |
| S3 | **凭据选择策略** | 设计 `BackendClient` 何时用私钥 vs 证书：按 grant/policy 字段（新增 `backend_auth: "key"|"cert"` 或后端目标配置）路由；向后兼容（默认私钥 = 现行为不变）；cert 模式下 `backend.credential_map/private_key` 可省略，两种模式互斥/并存校验规则 | 凭据路由方案 + 配置契约 | S2 |

### 4.1 M4-I 一次性实现内容

| ID | 任务 | 说明（要点） | TDD / 验证步骤 | 验收标准（DoD） | 依赖 |
|---|---|---|---|---|---|
| M4-T1 | **`HostKeyVerifier` 支持 `@cert-authority`** | 扩展 `HostKeyVerifier`：host 证书四步校验链——① `signature_key()` ∈ 受信 CA 集 → ② `cert.verify_signature()` → ③ 有效期窗口 `valid_after < now < valid_before`（时钟注入）→ ④ `cert.valid_principals()` 含目标主机名（大小写规范化后比较）；`check_server_key` 证书分支；保留内层指纹 pin 作为既有策略不回归 | ① 单测：合法 CA+合法 principal → accept；非法 CA → reject；过期 → reject；篡改签名 → reject；**principals 不含目标主机 → reject**（host-type 证书用例）② 裸公钥按既有策略 ③ 证书 + 指纹双路径互不干扰 | M4-1 单测全绿；既有 pin/accept-new 用例不回归 | S1 |
| M4-T2 | **后端凭据路由（key vs cert）** | `BackendClient` 增加证书认证路径：按 grant/policy 选择 `authenticate_publickey`（默认，现行为）或 `authenticate_openssh_cert`（主路径）/`authenticate_certificate_with`（自定义 signer fallback）；**证书在 `BackendDialer::connect` 时由 CA 现签（principals=target.user，lifetime 沿用 `[ca].cert_lifetime`），不缓存不复用**——无状态、无过期缓存、审计天然每连一条、HA 多副本无协调；在途连接不受 CA 轮换影响（SSH 会话内无重验证，TDM 记录该语义） | ① 单测：路由决策纯函数（key/cert/缺省）② 证书签发字段正确 ③ E2E（本地 sshd + TrustedUserCAKeys）④ 过期/错 principal 后端拒 | cert-dial E2E 通；过期拒绝；CA 轮换（换 signing_key 重新签发后新连接可用） | S2, S3, M4-T1 |
| M4-T3 | **配置与契约** | `[ca]`/`[backend]` 配置扩展：后端凭据路由开关（`backend_auth` 或按 grant policy），`[ca] trusted_ca_keys` 复用于 host 证书校验；**cert 模式下 `backend.credential_map/private_key` 可省略**，两种模式（key/cert）互斥/并存校验规则写入配置验证；`config.example.toml` 更新 | ① 配置解析单测（缺省/自定义/冲突/互斥）② 文档 | 配置向后兼容（无新字段时行为不变） | M4-T2 |
| M4-T4 | **测试拓扑与集成** | 本地 sshd 双拓扑用例：① 后端 host 证书——后端 `HostCertificate ./host_cert.pub`（服务端出示证书）+ 网关 @cert-authority 校验 ② `TrustedUserCAKeys` 用户证书；真机可选（`root@47.109.73.53`） | ① 集成用例：M4-1 后端 host 证书可连、篡改/过期/错 principal 拒；M4-2 cert-dial 可连 ② 真机可选跑 ③ 全套回归 | 集成全绿；真机（可选）记录 | M4-T2/T3 |

### 4.2 M4-V 统一收口
- 全量单元（161 + 新增）+ 本地集成统一跑；修正至全绿。
- known-limitations.md #1/#2 移除占位（转「已实现」或按需修订）；plan-m3 §10 标记 M4 完成。
- 真机可选演练（后端 host 证书 + cert-dial）若环境允许则跑，输出记录入 docs/。

---

## 5. 依赖图与并行策略

```
M4-P0: S1 S2 S3  ── 全并行（独立）→ MS4-P0
M4-I:  M4-T1(赖S1) → M4-T2(赖S2,S3,T1) → T3 ∥ T1；T4(赖T2,T3) → MS4-I（一次全量实现，cargo build 过）
M4-V:  全量单元+集成统一收口 → 修正至全绿 → MS4
```

**并行提示**：单人即可（M4-T1/T4 集中在 backend/ca/config，无写面冲突）。S1~S3 独立可行。

---

## 6. 门禁与 DoD

### 6.1 MS4-P0
- [ ] S1~S3 结论明确（host cert 校验路径、cert-dial 连通、凭据路由方案）；TDM 入库
- [ ] 后端 sshd 模板（TrustedUserCAKeys / host 证书）在本地可用

### 6.2 MS4-I
- [ ] M4-1/M4-2 全部代码一次性实现落地，无演示 stub
- [ ] `cargo build` 通过；S 结论已固化进实现

### 6.3 MS4（总门禁，唯一交付门禁）
- [ ] M4-1 单测/E2E：host 证书合法 CA accept、非法/过期 reject；pin/accept-new 不回归
- [ ] M4-2 E2E：cert-dial 可连（本地 sshd + TrustedUserCAKeys）；过期/错 principal 拒；CA 轮换后新连接可用
- [ ] 配置向后兼容（缺省私钥路径行为不变）
- [ ] 全量单元（161+新增）+ 本地集成（23+新增）全绿；clippy/fmt 过
- [ ] known-limitations #1/#2 状态更新；@oracle 总门禁复核

### 6.4 通用（每次 commit）
- TDD；内部禁 Mock（纯函数 + 时钟注入），外部边界（真实 sshd/证书）允许
- src 侧：clippy -D warnings / fmt / 禁 unwrap/expect/panic/unsafe / spawn 内 map_err / lock 内禁 await
- tests/scripts 侧：set -euo pipefail、引号、禁 eval、清理（禁触碰 SSH_GW_ASSET_DIR）
- 根因治理禁 Hack；Cargo.lock 提交

---

## 7. 风险

| 风险 | 概率/影响 | 缓解 | Spike |
|---|---|---|---|
| russh `check_server_key` 对 host 证书的前置校验（是否库自校验）——**已核实为 handler 全责、零前置校验**（russh client/mod.rs:2012-2022, 2726-2733），不确定性消除 | 确定（已核实）/中 | S1 仅做确认性 Spike + API 摸底；四步校验链由 handler 实现 | S1 |
| russh `authenticate_openssh_cert` 与后端 `TrustedUserCAKeys` 的算法/格式兼容（ed25519 证书为主） | 中/中 | S2 实连通验证；必要时 fallback `authenticate_certificate_with` | S2 |
| `TrustedUserCAKeys` 在测试后端需要改 sshd_config + 重启（影响既有拓扑） | 中/低 | 本地独立 sshd 实例测试；真机可选且协调 | S2 |
| 凭据路由引入语义复杂化（key vs cert 选择） | 低/中 | 默认私钥向后兼容；路由纯函数 + 单测；cert 模式下 private_key 可省略且互斥校验 | S3 |
| cert-dial 证书过期时效运维负担 | 低/低 | 短期证书 + connect 时现签（不缓存不复用）+ 可配置 lifetime + 审计每连一条 | — |
| host 证书 principals 越权（CA 签 A 主机的证书被 B 信任） | 低/高 | **M4-T1 四步校验链含 principals 匹配（P0-1）**；补「principals 不含目标 → reject」单测 | S1 |

---

## 8. 交付物
- `src`：`HostKeyVerifier` cert-authority 扩展、后端证书认证路径、配置扩展
- `tests`：M4-1/M4-2 单元 + 本地 sshd 集成拓扑（host 证书、TrustedUserCAKeys）
- `scripts`：后端 sshd 证书模板（可选真机）
- 文档：known-limitations #1/#2 更新、plan-m3 §10 状态标记、TDM
- 每阶段测试与提交

---

## 9. 修订记录
| 版本 | 日期 | 修订者 | 变更 | 依据 |
|---|---|---|---|---|
| v1.0 | 2026-10-11 | 编排者 | 初稿（基于 plan-m3 §10 后置登记，扩展为完整计划） | — |
| v1.1 | 2026-10-11 | 编排者 | **P0-1**：M4-T1 host 证书校验链补为四步（signature_key∈CA → verify_signature → 有效期 → **valid_principals 含目标主机**）+ 补「principals 不含目标 → reject」单测；风险表加 principals 越权行。P1-1：S1 结论前移（russh handler 全责已核实，client/mod.rs:2012-2022, 2726-2733）→ §1 本底事实表 + S1 降为确认性 Spike + 风险表首行降「确定」。P1-2：M4-T2 明确证书在 connect 时**现签不缓存**（无状态/审计每连一条/HA 无协调，在途连接不受 CA 轮换影响）。P2-1：§1/T2 修正证书认证 API 签名（openssh_cert 用内层私钥，certificate_with 用自定义 signer）。P2-2：M4-T4 ① 修正术语（后端 `HostCertificate` 服务端出示，非 TrustedHostKeys）。P2-3：M4-T3 cert 模式下 private_key 可省略 + 互斥/并存校验 | @oracle M4 计划门禁（有条件通过） |

> 门禁记录：@oracle 裁决「有条件通过」——1 个 P0（M4-T1 principals 匹配）与若干 P1/P2 均已修订；修订后具备放行资格，可进入 M4-P0 Spike 期。
> 本文档待实施；实施细节随 Spike 结论与 russh 版本行为校准。
