# SSH 网关开发计划 M3（合并批次）

> 状态：**已过门禁（有条件通过，P0 已修订；v1.2 执行顺序重构）** ｜ 版本：v1.2 ｜ 依据：`dev-docs/propose.md` §八、`dev-docs/plan.md` §4.3 与 §13 遗留清单
> 范围：**批次 A（稳定收尾 5 项）＋ 批次 B（M3 功能 X1~X5）** 合并为一份 M3 计划。
> 执行顺序：**先一次性全量实现（M3-I），再统一收口测试修正（M3-V）**——与 M1/M2 执行模式一致。
> 评审记录：@oracle 裁决「有条件通过」——P0-1 已于 v1.1 修订，v1.2 按用户要求重构执行顺序（见 §9）。

---

## 1. 依据与本底事实（已核实，不重复调研）

| 事实 | 出处（已确认） |
|---|---|
| russh 0.64.1 server Handler 含 `channel_open_direct_tcpip(&mut self, channel, host_to_connect, port_to_connect, originator_address, originator_port, reply, session)`——jump 模式可行；当前 `src/server/mod.rs` **未 override**（需显式拒绝基线 + 按策略放开） | russh src/server/mod.rs; src/server/mod.rs 现状 |
| russh 0.64.1 server Handler 含 `auth_openssh_certificate(&mut self, user, certificate: &Certificate)`——用户证书 CA 认证可行；当前 `src/server/mod.rs:696` 已留 `// Certificate auth (TrustedCA) is an M3 deliverable.` 占位 | src/server/mod.rs:693-698 |
| `ssh-key` crate 已在依赖树（Cargo.lock:2219）；`src/backend/mod.rs` 已用 `PublicKeyOrCertificate`（含 Certificate 分支）做后端 host key 指纹 | Cargo.lock; src/backend/mod.rs:19,128-131 |
| russh client `Handle::channel_open_direct_tcpip`（client/mod.rs:845）存在 | russh 源码 |
| 集成基础设施齐备：本地自举 sshd + mock 控制面 + `SSH_GW_ASSET_DIR` 固定资产 + `SSH_GW_BACKEND_TARGET` 真机切换（测试真机 `root@47.109.73.53` 已部署网关后端公钥） | scripts/run_integration.sh; 真机实测 |
| **keepalive 检出语义（源码级核实）**：russh 0.64.1 client 是**间隔计数模型**（client/mod.rs:1426-1437）——每 `keepalive_interval`(默认15s) 无流量则 `alive_timeouts+=1` 并发探测，`alive_timeouts > keepalive_max(2)` 才断连；**不存在每探测 5s 超时**；`pool.keepalive_timeout`(5s) 为**死配置未接线**（src/backend/mod.rs:203-212 仅映射 interval 与 max）。⇒ 真实检出 ≈ 15s×(max+1)=**45s** | russh 源码 + src/config.rs + src/backend/mod.rs |
| **jump 基线已是 deny**：russh `channel_open_direct_tcpip` 默认 `async { Ok(()) }`，但 `ChannelOpenHandle` 未 accept/reject 即 Drop 时**自动拒绝**（russh server/mod.rs:392-394）——当前未 override 即拒绝基线（`case_port_forward_denied` refused 观测佐证） | russh 源码 + 实测 |
| 全量门禁基线：build/clippy(-D warnings)/fmt/单元 108/集成 18 PASS 全绿 | 既成事实 |

**环境限制（影响任务设计，勿忽略）**：本机为 macOS，**无 iptables / netem（tc）**；需注入链路损伤/假死时使用：① 测试真机 `47.109.73.53`（Linux Ubuntu，root 可登，iptables/tc 可用）；② Docker 容器（可选）；③ macOS 无特权替代（kill 后端进程，已实现 `case_backend_lost`）。wire 级抓包本机可装 tshark（opt-in）。

---

## 2. 范围

### 2.1 批次 A — 稳定收尾（源自 @oracle M2 门禁遗留清单，5 项）
| ID | 任务 | 出处 |
|---|---|---|
| A1 | **半开连接假死注入专项**：iptables DROP（不 RST）→ russh keepalive 检出 → `BackendLost` → DISCONNECT(11) 全链路 15s 时效 | oracle 遗留 1 |
| A2 | **wire 级抓包对拍**：补 `case_ordering_matrix` 的 cross-channel/帧序缺口 | oracle 遗留 2 |
| A3 | **netem 真实链路损伤**：替代 `case_slow_link` 的窗口替代近似法 | oracle 遗留 3 |
| A4 | **客户端兼容矩阵扩展**：PuTTY / WinSCP / Windows OpenSSH + host key 轮换降级路径演练 | oracle 遗留 4（+ propos §六 客户端兼容） |
| A5 | **长跑 soak**：RSS/泄漏趋势，M2-U5 收尾项 | oracle 遗留 5 |

### 2.2 批次 B — M3 功能（源自 plan.md §4.3 X1~X5 与 propose.md §八）
| ID | 任务 | 说明 |
|---|---|---|
| B1 | **Host/用户 CA** | 网关签发短期用户证书 + 后端 `TrustedUserCAKeys`；host key 轮换无感（`@cert-authority`） |
| B2 | **会话录制** | `SessionRecorder`（SubsystemInterceptor Tap 语义落地） |
| B3 | **SFTP 拦截器实现** | `SftpAuditInterceptor`（命令级审计/拦截，如禁 rm） |
| B4 | **jump 模式** | direct-tcpip 按策略放开并校验目标 |
| B5 | **HA 演练** | 无状态多副本 + L4 LB（least-conn）+ 排水 + 摘流演练 |

### 2.3 范围外（明确不做，本轮）
- russh 上游 feature（global_request hook / hostkeys-00 拦截 / client::Handle 跨会话 Sync）——已确认受 russh 0.64.1 限制，如需则 upstream PR（独立任务）。
- mosh（UDP）、X11、压缩协商。
- 控制面本体（仅消费 resolve 契约）。

---

## 3. 里程碑与排期

**执行顺序（本研究核心约束，与 M1/M2 一致）：先一次性全量实现，再统一收口测试修正。**

| 阶段 | 周期（假设） | 出口门禁 |
|---|---|---|
| **M3-P0 Spike 期** | 3~5 有效日（前置技术决策，并入实现 lane 内完成） | MS3-P0：6 个 Spike 全闭环，TDM 入库 |
| **M3-I 一次性全量实现** | 3~5 周 | MS3-I：A1~A5 + B1~B5 **全部代码一次性实现**（src + tests + scripts 全量生成），`cargo build` 通过 |
| **M3-V 统一收口验证** | 1~2 周 | MS3：全量单元测试 + 集成测试**统一跑通**，缺陷修正至全绿 |

> **执行顺序说明（勿偏离）**：**不做「批次 A 先交付门禁、批次 B 再交付门禁」的分段交付**；A 批（稳定收尾）与 B 批（M3 功能）的全部代码在一次实现阶段（M3-I）内**一次性生成**，先跑通编译；随后进入**统一收口（M3-V）**——全部单元测试 + 集成测试统一执行、统一修正缺陷，门禁只在最终收口后一次性过。Spike（S1~S6）作为实现前置的最小技术决策先行，但**不设独立实施交付门禁**（仅 MS3-P0 决策门禁）。
> 排期假设：单人或双人并行。A 批（scripts/tests/真机）与 B 批（src/）写面隔离可并行实现（沿用既有双 lane 模式）。B1 依赖 A4 的 host key 轮换演练结论。**M3-I 单人偏紧（B1 CA 签发+认证+后端 TrustedUserCAKeys+host key 侧改造工作量大）**：B1 单列 2 周缓冲，或明确收口时优先 B1。排期含门禁复核时间。MS3 允许 B3/B4/B5 拆审。

---

## 4. 任务分解（WBS）

> **WBS 组织说明（执行顺序见 §3）**：以下 A1~A5 / B1~B5 为**工作分解内容**（范围与 DoD），**非执行顺序**。执行时：M3-I 阶段一次性实现 A/B 全部代码（src 侧 B 批 + 测试/脚本侧 A 批并行生成），M3-V 阶段统一跑单元+集成测试并修正。

### 4.0 M3-P0 — Spike 期（批次 A/B 的前置技术决策）

| ID | Spike | 目标 / 方法 | 产出物 | 依赖 |
|---|---|---|---|---|
| S1 | **半开假死可控注入** | 在测试真机(Linux) 确认 iptables DROP 注入路径：如何只断「网关→后端」链路、不断管理链；恢复用 iptables 删除规则；记录可靠复现剧本；失败→ 回退 kill 后端（已有 case_backend_lost 语义但时效口经不同） | 半开注入剧本 + 真机可用性结论 | 无 |
| S2 | **wire 抓包方案** | 确认本机 tshark/tcpdump 可用性与抓包基线（loopback 抓 SSH 流量）：能否抓客户端↔网关、网关↔后端两段并 diff？若不可用→ 用 russh DEBUG 事件日志双端对拍替代（记录局限） | 抓包可行性结论；对拍工具脚本 | 无 |
| S3 | **PuTTY/WinSCP 认证兼容** | russh 0.64.1 对 PuTTY/WinSCP 的连接（KEX/算法/userauth）兼容性：需真实 Windows 客户端；无则用 `-o` 模拟算法集 + 文档记录 | 兼容矩阵初版 + 真实客户端可用性 | 无 |
| S4 | **证书 CA 路径可行性** | russh server `auth_openssh_certificate` 回调 + `ssh-key` crate 签发：验证 网关签发短期用户证书 → 客户端用证书走网关 认证 的端到端是否可行。**重点核查证书在 offered（probe）阶段的指纹语义**：russh 对证书 userauth 的 probe 与签名两阶段传给 handler 的是**内层公钥**（encrypted.rs `PublicKey::new(cert.public_key(), "")` 先于 is_real 分支）——即现网 `auth_publickey_offered` 控制面 resolve 拿到的是内层密钥指纹而非证书/CA 指纹，证书客户端按现有授权模型会 403。**Spike 结论必须给出**：「cert 请求 offered 阶段应放行让签名继续、最终授权在 `auth_openssh_certificate` 内按 `cert.signature_key()` 指纹∈受信 CA + `valid_before` + principals 校验」的语义设计；不可处记录降级 | CA 可行性结论；offered/最终证书授权语义设计；证书签发 demo 代码 | 无 |
| S5 | **会话录制/拦截 Tap 数据面** | `PassThroughInterceptor` → `Tap` 的转发路径开销与数据面 hook 点确认（code path 已有 trait）；录制缓冲/落盘策略（文件 vs 内存） | Tap 路径设计结论 | 无 |
| S6 | **jump 策略放开的 grant 契约** | 控制面 resolve 需返回 policy 中 tcp_forwarding/目标白名单字段的契约确认（mock 控制面扩展）；direct-tcpip 校验目标算法设计 | jump 策略契约 + 校验设计 | 无 |

> 出口 **MS3-P0**：6 个 Spike 结论明确（含不可用降级），TDM 入库。

### 4.1 批次 A — 稳定收尾

| ID | 任务 | 说明（要点） | TDD / 验证步骤 | 验收标准（DoD） | 依赖 |
|---|---|---|---|---|---|
| A1 | 半开假死专项 | 在测试真机对「网关→后端」链注入 iptables DROP；网关 keepalive（russh 间隔计数：每 `keepalive_interval`(15s) 探测计 +1，超过 `keepalive_max`(2) 断连）判定假死；`BackendLost` 路径 → 客户端 DISCONNECT(11)；**测检出时效** | ① S1 剧本可用 ② 注入→观测 `sshgw_backend_lost_total` + disconnect_reason[11] 在 **≤ `keepalive_interval × (max+1)` ≈ 45s** 内出现（**russh 无每探测 5s 超时，`pool.keepalive_timeout` 为死配置，勿按 hey 的 25s 验收**）③ 客户端收到 goodbye（非 reset）④ 注入清除后网关可重建连接 | 检出 ≤45s（默认配置）并发 DISCONNECT；指标正确；剧本可重复。（可选加速：A1 附带把 `pool.keepalive_interval` 调 5s → 检出≈20s，评估探测流量代价后写回配置样例） | S1, (M2 已落的 keepalive 基础) |
| A2 | wire 对拍 | 双段抓包（或 russh 事件日志双端对拍）diff「网关不改序」：跨 channel、帧序；补 ordering_matrix 缺口。**写面边界：若 S2 结论走「russh DEBUG 事件日志对拍」则不改 src/，隔离成立；若需在 src/ 增连接级 trace 事件，则作为独立小 PR 单独过审（勿混入 A 批 commit）** | ① 抓包脚本/对拍工具落地 ② pty→shell、裸 exec、多 channel 并行顺序 diff ③ 结论固化为 CI 用例 | 对拍用例 PASS；无「网关改序」证据 | S2 |
| A3 | netem 损伤 | 测试真机 netem 加 1Mbps+延迟抖动 → scp 大文件经网关：完整性 + RSS 平稳 + 完成 | ① 真机 tc 脚本 ② netem 前后对拍 RSS/完整性 ③ 可选并入 ci（标真机专用） | 完整性不破；RSS 平稳；与 slow_link 近似结论一致 | S1（借用真机通道） |
| A4 | 兼容矩阵 + 轮换演练 | 实测 PuTTY/WinSCP/Windows OpenSSH 经网关（真实客户端或 -o 模拟）；host key 轮换降级路径（hostkeys-00 不可用 → 管控面下发 known_hosts 演练） | ① 矩阵用例（真实/模拟）② 轮换引入→切换→下线演练（OpenSSH 无感预期；PuTTY 已知一次性提示）③ 事故检测（KEX 后断开模式）监控 | 矩阵记录与预期一致；轮换演练无感/降级路径验证 | S3 |
| A5 | 长跑 soak | 持续会话 + 频繁连接/断开 + 周期指标采样：RSS/泄漏趋势、session 计数归零、无 fd 泄漏 | ① soak 脚本（≥8h 或压缩循环）② RSS 趋势与启动点偏差 < 阈值 ③ 端指标收敛 | soak 无 OOM/泄漏；指标归零；写入报告 | A1~A4 稳定后 |

### 4.2 批次 B — M3 功能

| ID | 任务 | 说明（要点） | TDD / 验证步骤 | 验收标准（DoD） | 依赖 |
|---|---|---|---|---|---|
| B1 | Host/用户 CA | 网关持有 CA 私钥，签发短期用户证书（`ssh-key` crate，含有效期/principal）；客户端用证书经网关认证（`auth_openssh_certificate` 回调校验 CA 与 principal）；后端 `TrustedUserCAKeys` 落地；host key 侧 `@cert-authority` 支持（client 腿 `HostKeyVerifier` 从「对证书算内层指纹」改为「校验 `cert.signature_key` 对 CA」，涉及 src/backend/mod.rs:128-135 改造） | ① 证书签发单元测试（字段/有效期/principal）② 证书认证 E2E（合法/过期/篡改/错 principal 各一）③ **cert offered 语义用例：内层指纹≠授权指纹时仍能完成证书认证**（offered 阶段放行让签名继续、最终授权按 CA/principal/valid_before——S4 结论固化）④ **host key 侧 CA 校验改造单测**（@cert-authority 路径）⑤ 后端 TrustedUserCAKeys 连通 ⑥ host key 轮换无感 | B1 认证用例全绿；证书过期拒绝；后端 CA 链路通；host key @cert-authority 校验通过 | S4, A4 |
| B2 | 会话录制 | `SessionRecorder` 实现 SubsystemInterceptor Tap：录制输入输出流（含命令/字节/时间），安全落盘（权限/脱敏），停止/清理语义 | ① Tap 路径数据单测 ② 录制完整性（回放校验）③ 权限/脱敏用例 ④ 审计联动（session-id 关联） | 录制文件完整可回放；无明文密钥/密码泄漏；与审计对齐 | S5 |
| B3 | SFTP 拦截器 | `SftpAuditInterceptor`：SFTP 命令级审计/拦截（如禁 rm、限路径）；按策略返回 Deny(msg) | ① SFTP 协议解析（子集：rm/rename/put/get/open 等）+ 命令提取单测 ② 拦截规则单测 ③ E2E：禁 rm 生效 ④ 审计分类正确 | 拦截规则生效；审计分类正确；Deny 语义（客户端报错）正确 | S5, B2（复用 Tap） |
| B4 | jump 模式 | server `channel_open_direct_tcpip` override：显式拒绝基线 → 按策略（resolve policy 的 tcp_forwarding/目标白名单）放开并校验目标；客户端经 `-J` 或 `-L` 使用 | ① 拒绝基线测试（现行为固化）② 策略放开 + 目标校验单测 ③ E2E：经网关 `-J` 连通 ④ 越权目标拒绝 | 默认拒绝不回归；jump E2E 通；越权目标被拒 | S6 |
| B5 | HA 演练 | 双/三副本网关 + L4 LB（least-conn）+ 排水（已有 DISCONNECT(11)/readyz 503）+ 摘流：会话在副本间无状态迁移验证（新会话走新副本）；排水期新连接转走 | ① 多副本启动脚本 ② LB 配置 ③ 排水演练（摘流→旧会话排空→下线）④ 指标核对 | 摘流/排水演练 PASS；新会话路由新副本；无会话中断语义说明 | B1~B4 稳定后（或独立并行） |

---

## 5. 依赖图与并行策略

**执行分三段（先实现、后收口）：**

```
M3-P0: S1 S2 S3 S4 S5 S6  ── 全并行（独立决策）→ MS3-P0（仅决策门禁，无交付）

M3-I（一次性全量实现，写面隔离双 lane 并行）:
  lane src/ :  B1(赖S4, 参考A4)  B2(赖S5)  B3(赖S5,B2)  B4(赖S6) ── 全部功能代码一次性生成
  lane tests/: A1(赖S1)  A2(赖S2)  A3(赖S2/S1)  A4(赖S3) ── 测试/脚本/真机基础设施一次性生成
  完成条件：`cargo build` 通过（A/B 全部代码落地）→ MS3-I

M3-V（统一收口验证修正）:
  A5(soak，依赖 A1~A4 稳定) ＋ B5(HA 演练，依赖 B1~B4) ＋ 全量单元测试 ＋ 全量集成测试
  → 统一修正缺陷直到全绿 → MS3
```

**并行提示**：A 批（tests/scripts/真机）与 B 批（src/）写面天然不冲突，M3-I 阶段双 lane 并行一次性生成；M3-V 阶段统一收口。B4 无 A 依赖，src/ lane 内可最早实现。Spike 结论在 M3-I 启动时已就绪（S1~S6 先于实现完成）。

---

## 6. 门禁与 DoD

> 门禁按「先全量实现、后统一收口」的顺序组织：MS3-P0（决策）→ MS3-I（实现完成）→ MS3（收口总门禁，唯一交付门禁）。

### 6.1 MS3-P0（Spike 决策门禁，非交付）
- [ ] 6 个 Spike 均有结论 + 降级路径；TDM 入库
- [ ] 半开注入剧本在真机可重复（S1）；证书 offered 语义设计成稿（S4）

### 6.2 MS3-I（一次性实现完成）
- [ ] **A1~A5 与 B1~B5 全部代码一次性实现落地（src + tests + scripts），无演示版 stub**
- [ ] `cargo build` 通过；Spike 结论（S4 证书 offered 语义等）已固化进实现
- 注：本阶段**不做分项交付**，继续进入 M3-V 统一收口

### 6.3 MS3（统一收口总门禁，唯一交付门禁）
- [ ] 全量单元测试绿（含 B1 证书四类用例 + cert offered 语义、B2 录制、B3 拦截、A2 对拍补例）
- [ ] 全量集成测试绿（既有 18 + M3 新增 A2/A3/B3/B4 等，真机剧本 A1 重复 ≥2 次）
- [ ] **A 批 DoD**：A1 半开假死检出 ≤ keepalive_interval×(max+1)≈45s + DISCONNECT(11) + 指标；A2 wire 对拍无改序证据；A3 netem 完整性/RSS；A4 兼容矩阵 + 轮换降级演练；A5 soak 无泄漏
- [ ] **B 批 DoD**：B1 证书认证 E2E + host key @cert-authority + 后端 TrustedUserCAKeys；B2 录制完整可回放/无敏感泄漏；B3 SFTP 拦截规则生效/Deny 正确；B4 默认拒绝不回归 + jump E2E + 越权拒绝；B5 摘流/排水 PASS
- [ ] `cargo clippy -- -D warnings` / `cargo fmt --check` 通过
- [ ] @oracle 总门禁复核（一次；若 B 批体量过大，允许 B3/B4/B5 拆审，B1 优先）

### 6.4 通用（每次 commit）
- 实现先于测试编写的顺序不豁免 DoD——**功能代码与对应测试在同一实现阶段全部落地**，收口阶段统一修正而非补写
- 内部逻辑禁 Mock（纯函数 + 时钟注入），外部边界（控制面/真机环境）允许
- src 侧：clippy -D warnings / fmt / 禁 unwrap/expect/panic/unsafe / spawn 内 map_err / lock 内禁 await
- tests/scripts 侧：set -euo pipefail、引号、禁 eval、清理（禁触碰 SSH_GW_ASSET_DIR；残局只删自己带 stamp 的目录）
- 根因治理禁 Hack；Cargo.lock 提交

---

## 7. 风险

| 风险 | 概率/影响 | 缓解 | Spike |
|---|---|---|---|
| macOS 无 iptables/netem → A1/A3 无法本地化 | 高/中 | 真机 Linux 通道（已部署公钥）；Docker 备选 | S1 |
| wire 抓包不可行（权限/环回可见性） | 中/中 | russh DEBUG 事件日志双端对拍替代（记录局限） | S2 |
| PuTTY/WinSCP 无真实 Windows 客户端 | 中/中 | `-o` 算法集模拟 + 兼容矩阵文档 + 真实机选做 | S3 |
| russh `auth_openssh_certificate` 端到端受限（仅 server 侧？） | 中/高 | S4 先行验证；降级=用户证书经会话内二次认证或管控面签发 & 记录 | S4 |
| **证书 offered 阶段指纹错位**（probe 阶段 handler 收内层公钥指纹 ≠ CA 指纹，证书客户端按现授权模型会 403） | 确定/高 | S4 设计「offered 放行让签名继续、最终授权在 `auth_openssh_certificate` 内按 CA/principal/valid_before」；固化 TDD 用例 | S4 |
| **B1 host key 侧改造工作量**（client 腿 `HostKeyVerifier` 从内层指纹改为 `@cert-authority` CA 校验，涉及 src/backend/mod.rs:128-135） | 中/中 | 单列 B1 子任务 + 单测；风险已入 B1 TDD 步骤 | S4 |
| 会话录制数据面性能/磁盘 | 中/中 | Tap 零开销快路径已存在；录制放独立容量 + 配额 | S5 |
| B4 jump 的 dns/目标校验被绕过 | 低/高 | 目标白名单 + 端口约束 + 防 SSRF 校验（禁解析内网段等，策略面） | S6 |
| **B5 LB 会话粘性误配 → 已建会话被摘流中断**（会话有状态，已断不可迁移，仅新会话路由新副本） | 中/中 | 排水前置（readyz 503 摘流）+ 粘性/least-conn 配置核对 + 演练验证 | — |
| 上游限制（hostkeys-00/global_request/Sync） | 确定/中 | 已有降级路径；明确不阻塞本轮 | — |

---

## 8. 交付物
- 批次 A：真机半开注入剧本、wire 对拍工具+用例、netem 脚本、兼容矩阵文档、soak 报告
- 批次 B：CA 签发/认证模块、SessionRecorder、SftpAuditInterceptor、jump 策略模块、HA 演练脚本
- 每阶段 TDM/门禁记录；全量测试与提交

---

## 10. 后续批次登记（M4 — 后端基础设施专项）

> MS3 门禁（有条件通过）要求将 B1 的两个**后端侧子项**以书面落账后置，做此登记即视为 MS3 完全闭合（无需新代码）。

| ID | 项 | 判定性 DoD | 触发条件 | 落账位置 |
|---|---|---|---|---|
| M4-1 | 后端 host key `@cert-authority`（host 证书） | host cert 校验 `signature_key()` ∈ 受信 CA 集；`check_server_key` 单测；host cert E2E | 后端纳管规模化/CA 统一签发 host 证书 | docs/known-limitations.md #1；src/backend/mod.rs:128-135 M4 占位注释 |
| M4-2 | 后端 `TrustedUserCAKeys` 用户证书拨号（cert-dial） | cert-dial E2E（网关用 CA 签发的动态证书认证后端；证书过期拒绝；CA 轮换无感） | 后端安全策略要求用户级 CA 统一签发 | docs/known-limitations.md #2；backend/mod.rs:290 注释参照 |

---

## 9. 修订记录
| 版本 | 日期 | 修订者 | 变更 | 依据 |
|---|---|---|---|---|
| v1.0 | 2026-10-11 | 编排者 | 初稿（合并 oracle 遗留 + plan §4.3） | — |
| v1.1 | 2026-10-11 | 编排者 | **P0-1**：A1 检出时效改为「≤ keepalive_interval×(max+1) ≈ 45s」，§1 记录 russh 间隔计数语义 + `pool.keepalive_timeout` 为死配置；可选加速（interval 调 5s）。P1：B1 增加 cert offered 内层指纹语义设计/用例 + host key 侧 @cert-authority 改造；风险表补证书指纹错位、host key CA 改造、LB 会话粘性三项。P2：§1 修正 jump 基线已是 deny（ChannelOpenHandle Drop 自动拒绝）；A2 写面边界注明；MS3-B 增加 B3 拆审 + P0 后允许 B1 单独过审；排期补 B1 单列 2 周缓冲 / B2/B3 滑批 | @oracle M3 计划门禁（有条件通过） |
| v1.2 | 2026-10-11 | 编排者 | **执行顺序重构（用户要求）**：由「批次 A（MS3-A）→ 批次 B（MS3-B）分阶段门禁交付」改为 **M3-P0(Spike 决策) → M3-I(一次性全量实现 A+B 全部代码) → M3-V(统一收口：全量单元+集成测试统一跑通、修正至全绿) → MS3(唯一交付门禁)**。§3 里程碑、§4 WBS 序言、§5 依赖图、§6 门禁同步重排；Spike 仅设决策门禁非交付门禁。 | 用户指定（与 M1/M2 执行模式一致） |
| v1.3 | 2026-10-11 | 编排者 | **MS3 门禁落账（P1-1）**：新增 §10「后续批次登记（M4 — 后端基础设施专项）」，把 B1 两个后端侧子项（host key `@cert-authority`、后端 `TrustedUserCAKeys` cert-dial）书面落账并附判定性 DoD；配套 docs/known-limitations.md（6 项）、src/backend/mod.rs M4 占位注释、src/ca/mod.rs 文档矛盾修正（P2-2）。落账后 MS3 完全闭合。 | @oracle MS3 总门禁（有条件通过） |

> 门禁记录：@oracle 裁决「有条件通过」——1 个 P0（A1 keepalive 时效口径，源码级核实）与若干 P1/P2 均已修订；修订后具备放行资格，可进入 M3-P0 Spike 期。
> 本文档待实施；实施细节随 Spike 结论与 russh 版本行为校准。
