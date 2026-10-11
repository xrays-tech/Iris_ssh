# SSH 网关开发计划（v2 · 基于 propose.md）

> 状态：**已过门禁（有条件通过，P0 已修订）** ｜ 版本：v1.2 ｜ 依据：`dev-docs/propose.md`（SSH 网关设计方案 v2）
> 评审记录：@oracle 裁决「有条件通过」，3 个 P0 阻塞项已于本版修订（见 §13 修订记录）。

---

## 1. 目标与范围

### 1.1 目标
交付一个生产可用的 **SSH 网关**：终结客户端 SSH（russh server 侧），经「严格 FIFO + 有界背压」转发引擎管道到后端 sshd（russh client 侧），实现「用户名即路由」——客户端以 `ssh alex_host1@GW` 方式访问内网主机，网关按 `(principal, fingerprint)` 向控制面解析并授权后拨号后端。

### 1.2 范围（In Scope）
- M1：端到端 shell / exec / sftp / 新旧 scp / rsync / git over ssh 打通。
- M1：严格 FIFO 请求管线（I1~I4）+ 协议级保序验证。
- M1：双向有界内存 + Semaphore 保险丝 + 准入控制。
- M1：认证（网关验签）/ 授权（控制面策略）边界，含坏签名必拒。
- M2：连接池 + 假死检测 + 熔断；host key 多密钥 + hostkeys-00 轮换；稳定性与性能调优。
- M3（后续）：Host/用户 CA、会话录制、SFTP 拦截器、jump 模式、HA。
- 工程交付：约束合规、TDD、CI 门禁、可观测性、运维手册、测试报告。

### 1.3 范围外（Out of Scope / 明确拒绝）
- L4 纯 TCP 转发（决于 1.4）。
- 端口转发 / agent forwarding / x11 转发（网关默认拒绝；jump 模式 M3 按策略放开）。
- mosh（UDP）、X11、压缩协商非首期目标（Spike #5 评估）。
- 控制面本体（仅消费其 `/api/v1/resolve` 契约）。
- 后端私钥 **KMS 加载与热轮换**不在首期（首期假设静态密钥文件 0600，见 M1-T2；KMS 显式排入 M2-U4）。若产品决策不做 KMS，本项维持静态文件即可。
- `env` 请求白名单过滤不在 M1（M1 默认原样透传，配置占位见 §5.5/§13）。

### 1.4 定案技术路线（propose.md §一）
| 项 | 结论 |
|---|---|
| 路由方式 | **russh 双会话管道**（终结 SSH，用户名在加密通道内可见，RFC 4252） |
| 库 | `russh`（tokio，server/client 双角色，aes-gcm/chacha20、curve25519、ed25519、OpenSSH 私钥加载） |
| 语言/工具链 | Rust + tokio；`cargo clippy -D warnings` + `cargo fmt` 必过；Cargo.lock 提交 |
| 方法 | **TDD**（先写测试）；验证闭环：改后必测，禁假设正确；根因治理禁 Hack |

---

## 2. 关键决策与约束回顾（实施时不得偏离）

| 编号 | 决策 | 出处 |
|---|---|---|
| D1 | 请求路径严格串行 FIFO，**禁止 spawn 转发任务/批处理聚合**，并发优化只作用于数据路径 | §3.5 I1~I3 |
| D2 | 失败一律用协议原生机制（open failure / request failure / DISCONNECT），不伪造 exec 输出与 exit code | §3.5 I4 |
| D3 | 认证=网关验签；授权=控制面纯策略；**offered 回调绝不最终 Accept** | §3.2 |
| D4 | 认证结果按 `(principal, fingerprint)` 键控缓存，offered/最终两阶段复用，避免两次 RTT | §3.2 |
| D5 | 上行/下行有界内存 + per-channel `Semaphore` 保险丝（默认开启，Spike #2 后可调） | §3.6 |
| D6 | `auth-agent-req@openssh.com` / `x11-req` / `direct-tcpip` / `forwarded-tcpip` 默认本地拒绝，不转发后端 | §3.4 |
| D7 | `hostkeys-00@openssh.com` 由网关应答本侧全部 host 公钥，不转发后端；`keepalive@openssh.com`（客户端→网关）默认本地 success，M2 可配端到端 | §3.4 |
| D8 | 后端主机密钥策略：生产 `pinned`；`accept-new` + 告警仅限非生产 | §3.3 |
| D9 | 默认每会话独连；连接池 opt-in（`pool.enabled=false`），池化连接 ≤8 channel、禁 agent forwarding | §3.8 |
| D10 | 优雅退出：DISCONNECT(11) 协议级告别 + 两阶段排水；**禁止向 subsystem(sftp) channel 写提示文本** | §5.4 |
| D11 | 生产代码禁 `unwrap()`/`expect()`/裸 `panic!`/`unsafe`（无详注）；tokio spawn 内 `map_err`；lock 内禁 await | 工程规约 |

---

## 3. 里程碑总览

| 里程碑 | 周期 | 主题 | 出口门禁 |
|---|---|---|---|
| **M0 Spike 期** | ≈3–5 个有效日（含在 M1 前三周排期内，先行） | 5 个 Spike 出技术结论 + M1 可编译骨架 | MS0：Spike 全部闭环，产出 TDM |
| **M1** | 3 周 | 端到端核心链路 + 保序 + 背压 + 认证授权边界 + 审计/优雅退出/集成测试 | MS1：M1 DoD 全绿 |
| **M2** | 2–3 周 | 连接池/假死检测/熔断 + host key 轮换 + 稳定性 + 性能调优 | MS2：M2 DoD 全绿 |
| **M3** | 视产品排期（不估） | Host/用户 CA、会话录制、SFTP 拦截器、jump、HA 演练 | MS3：按需求拆分 |

> 排期假设：单人或双人并行（同仓库需拉分支隔离写面，见 §8）。若单人，M0+M1 连续约 4 周；**关键路径（T5/T6/T10）另加 ≥20% 缓冲，建议 T5（转发引擎）独占整周**；绝对禁止把回旋余地压缩到无，否则门禁会被迫打折。

---

## 4. 任务工作分解（WBS）

### 4.0 M0 — Spike 验证（先于 M1 实施，且是 M1 若干任务的入径）

| ID | 任务 | 验证目标 / 方法 | 产出物 | 依赖 |
|---|---|---|---|---|
| M0-S1 | **Spike #1：russh server 侧 API 完整性** | 逐项验证：① exit-status 发送；② global_request 应答 `hostkeys-00@openssh.com`；③ DISCONNECT 发送；④ 多 host key offer；⑤ 未知 channel request catch-all | 结论表：可用/缺失（缺失→小补丁或 fork 备选）；TDM 文档 | 无 |
| M0-S2 | **Spike #2：russh 窗口语义** | 验证 ① 出站 `Channel::data()` 窗口耗尽是否阻塞；② `WindowAdjusted` 是否在 `wait()` 暴露；③ 入站 WINDOW_ADJUST 是否自动发送 | 决定 §5.1「保险丝是否常开」；TDM | 无（可与 S1 并跑） |
| M0-S3 | **Spike #3：验签时序** | 验证 `auth_publickey_offered`/`auth_publickey` 回调语义与「先验签后回调」；**手工构造坏签名用例**，固化 CI | 坏签名用例测试；TDM | M0-T（需最小 server harness 才能触发回调） |
| M0-S4 | **Spike #4：同算法 host key 轮换** | 验证 hostkeys-00 通道可用性（依赖 S1 的②）；不可用→降级=管控面下发 known_hosts | 轮换可行性结论；TDM | M0-S1 |
| M0-S5 | **Spike #5：遗留项** | OpenSSH 证书支持度、老客户端算法兼容矩阵、压缩协商、控制面 fail-open/closed 行为 | 兼容矩阵初版；TDM | 无 |
| M0-T | **骨架 + 工程基座** | 仓库骨架（§5.1 结构）、CI（clippy -D warnings + fmt + test）、`git init`、集成测试框架占位 | 可编译骨架 + CI 绿 | 无（与 Spikes 并行） |

> M0 出口门禁 **MS0**：5 个 Spike 均有明确结论（含不可用的备选路径），TDM 已评审并随代码入库；骨架通过 `cargo clippy -D warnings`。

### 4.1 M1 — 核心链路（3 周，任务依依赖序）

| ID | 任务 | 说明（要点） | TDD 步骤 | 验收标准（DoD） | 依赖 |
|---|---|---|---|---|---|
| M1-T1 | 项目与配置基座 | workspace 结构（`server/ backend/ resolve/ policy/ relay/ audit/ pool/`）、`toml` 配置加载（§5.2 全字段）、`thiserror` 错误类型、JSON tracing | ① 配置解析单测（缺失/非法字段→清晰错误）② 错误枚举映射单测 | clippy/fmt 绿；Cargo.lock 提交 | M0-T |
| M1-T2 | 监听 + 握手 + **host key 与后端凭据加载** | 启动监听、KEX、host key 加载（多算法 offer 先行，轮换 M2）；**后端凭据加载（§3.3）**：解析 `credential_map {"root"="/keys/root_ed25519"}` → 私钥加载、`AuthorizedKeys` 校验网关公钥、文件权限 0600 | ① 集成：客户端握手成功并校验 host key 指纹 ② credential_map 解析单测 ③ 私钥文件缺失/权限≠0600 → 拒绝启动（fail-closed） ④ 网关公钥不在后端 authorized_keys → 启动告警/失败 | 任意 SSH 客户端可完成 KEX+userauth 探针；凭据故障禁启（禁带病启动） | M0-T |
| M1-T3 | 用户名解析 Resolver | `moka` 缓存（TTL 30s+jitter、负缓存 5s）、`get_with` 单飞、governor 熔断、控制面 client（reqwest+rustls）、fail-closed（默认）/fail-open 可配 | ① 缓存命中/未命中 ② 负缓存 ③ 控制面 5xx→fail-closed 拒绝 ④ 熔断打开后快速失败 | §3.1 契约全用例过；指标 `resolve_latency/hit_rate` | M1-T1 |
| M1-T4 | 认证/授权边界 | offered 回调=预检/早期拒绝（403 快败），final 回调=授权决策；`(principal, fingerprint)` 双阶段缓存复用；审计含 指纹+签名算法+认证结果 | ① **坏签名必拒**（Spike #3 用例）② 未授权 key→403 ③ bob 的 key 冒用 alex_host1→403 ④ offered 绝不 Accept | §3.2 全用例绿；审计字段完整 | M0-S3, M1-T3 |
| M1-T5 | 转发引擎 ChannelRelay（核心） | 懒拨号（channel_open 内同步 connect，失败→open_failure CONNECT_FAILED）；请求路径回调内同步 await 透传 pty/shell/exec/subsystem/env/signal/window-change；want_reply FIFO 路由；agent/x11 本地拒绝；下行 pump（Data/ExtendedData/Success/Failure/WindowAdjusted/ExitStatus/ExitSignal/Eof/Close）；**全局请求处理：客户端 `keepalive@openssh.com` → 网关本地应答 success（D7，防 ServerAlive 客户端误判失活），`hostkeys-00@openssh.com` 应答归 M2-U3**；**未知 channel request 默认策略：本地 request_failure + 日志（I4），待 M0-S1⑤ 结论固化** | ① 单测：pending_replies FIFO 弹栈正确性 ② 集成：`ssh gw true` ③ `ssh gw 'exit 42'; echo $?`→42 ④ stderr 分离 ⑤ 时序矩阵对拍（见 §7） ⑥ **ServerAliveInterval=15 客户端长连 ≥5 分钟存活** | 全请求类型透传绿；**不动序**对拍通过；I1~I4 成立；keepalive 本地应答用例绿 | M1-T4 |
| M1-T6 | 流量控制与背压 | 双向有界：下行 await 直写不二缓冲；上行 data() await 转发写；Semaphore 保险丝（per-channel, permits=后端初始窗口, WindowAdjusted 增量补充）；准入控制 max_sessions 按内存公式动态计算 | ① 单测：保险丝许可发放/归还 ② 反例：`cat 2GB \| 慢读`、`yes` 洪泛、netem 1Mbps 下 scp → RSS 平稳无 OOM、吞吐损失<15% | 反例全过；指标 `relay_inflight_bytes/window_exhausted_total` | M0-S2, M1-T5 |
| M1-T7 | SFTP 拦截预留 + 审计分类 | `SubsystemInterceptor` trait（Pass\|Deny∥Tap）+ `PassThroughInterceptor`（零开销 None 快路径）；执行型请求分类规则表（scp 传统/SFTP/rsync/其他 exec） | ① trait 快路径**可判定基准**：criterion bench「PassThrough 路径 vs 直写」相对开销 <5%，且 None 快路径无锁、无堆分配（代码审查+bench 双重断言）② 分类判定表单测 | 分类规则全过；M1 透传基准达标 | M1-T5 |
| M1-T8 | 审计与可观测性 | 审计日志（who/when/target/bytes/duration/exit-code/命令分类）、session-id UUIDv7 串联两侧、指标集（§5.5）、`/healthz` `/readyz` | ① 审计字段完整性单测 ② 会话串联单测 | 指标/日志字段与 §5.5 对齐；readyz 初始即 true | M1-T5, M1-T6（bytes/duration/exit-code 来自 relay 事件流） |
| M1-T9 | 优雅退出（基础版） | SIGTERM→Draining：停 accept、readyz→503、drain 阶段注入 stderr 提示（**禁写 sftp channel**）、DISCONNECT(11)、flush 超时强关、hard_deadline SIGKILL | ① 集成：活跃会话收 TERM→客户端干净退出并显示消息 ② scp 中途→非零退出码 ③ sftp channel 无污染文本断言 | 用例全绿；断开原因码直方图入指标 | M1-T8 |
| M1-T10 | 集成测试与协议对拍 | 抓包 diff 方案（客户端/后端各一份报文序列 diff，「网关不改序」固化）；时序矩阵：`pty→shell`、`env→pty→shell`、裸 `exec`、`-tt`、subsystem、罕见顺序 | 时序矩阵全部 diff 通过 | CI 常驻；对拍失败=门禁失败 | M1-T5, M1-T6 |
| M1-T11 | 性能基线 | `sshbench`：握手→退出延迟、scp/rsync 吞吐 vs 直连基线 | 基线报告入库 | 吞吐损失 记录在案（≤15% 目标，超则入 M2 调优排队） | M1-T10 |
| M1-T12 | M1 门禁收口 | 全量回归 + DoD 清单核对（见 §6.1） | 门禁清单全勾 | **MS1 通过** | 全部 M1 |

### 4.2 M2 — 池 / 轮换 / 稳定性（2–3 周）

| ID | 任务 | 说明（要点） | TDD 步骤 | 验收标准（DoD） | 依赖 |
|---|---|---|---|---|---|
| M2-U1 | 连接池 | opt-in；每连接 ≤8 channel（sshd MaxSessions 约束）；复用摊薄 3~4 RTT；池化连接禁 agent forwarding | ① 单测：**第 9 条 channel → 拒绝**（上限边界）② 集成：scp/rsync 多 channel 复用同一后端连接 | 复用同一连接；上限拒绝单测绿 | M1-T5 |
| M2-U2 | 健康检查 + 销毁语义 | L4 keepalive；L7 每 15s `keepalive@openssh.com`(want_reply=true) 5s 超时、连续 2 次失败→假死判定；空闲>30s 复用前 ping；销毁=对全部挂连客户端发 DISCONNECT(11) 并清 Relay；熔断（连续 N 次失败→open circuit T 秒） | ① **前置断言脚本**：iptables DROP 注入 → 15s 内检出 ② 熔断单元测试（连续失败计数/开合闸） ③ 销毁后客户端可重连 | 故障注入：假死 15s 内检出并收敛爆炸半径；熔断生效；客户端可立即重连 | M2-U1 |
| M2-U3 | host key 多密钥 + 轮换 | 多密钥 offer（ed25519+rsa-sha2+ecdsa）；`hostkeys-00@openssh.com` 全量应答；轮换三阶段（引入/切换/下线）演练；不支持 UpdateHostKeys 客户端（PuTTY/WinSCP）→ 管控面下发 known_hosts | ① 轮换演练剧本即验收脚本（引入→切换→下线逐步断言）② hostkeys-00 应答字段单测 | OpenSSH UpdateHostKeys 轮换**无感**通过；演练记录；轮换失败率指标；事故检测（KEX 后立即断开） | M0-S4, M1-T5 |
| M2-U4 | 稳定性 + 凭据运维 | 客户端 keepalive 转发（M2 可配端到端）、rekey 中途、per-IP 限流（governor, `max_sessions_per_ip=20`）、auth_timeout；**后端私钥 KMS 加载与热轮换（§3.3，M1 为静态文件假设）** | ① 用例：keepalive 长连存活 ② rekey 中途数据不丢 ③ 限流生效 ④ KMS 密钥变更后新连接使用新凭据（热轮换） | 全部用例绿；KMS 加载/热轮换可行 | M1-T5 |
| M2-U5 | 稳定性回归 + 故障演练 | 后端宕机、控制面超时/熔断、并发上限、rekey 中途、长跑 soak | 全部场景无 OOM/无泄漏（RSS 平稳）；指标佐证 | M2-U2..U4 |
| M2-U6 | 性能调优 | flamegraph + tokio-console 定位热点；对比 M1 基线 | 相对直连吞吐损失 ≤15% 目标达成或记录差距 | M1-T11, M2-U2 |
| M2-U7 | M2 门禁收口 | 全量回归 + DoD（§6.2） | **MS2 通过** | 全部 M2 |

### 4.3 M3 — 扩展（按需求拆分，不估期）

| ID | 任务 | 说明 |
|---|---|---|
| M3-X1 | Host/用户 CA | 网关签发短期用户证书 + 后端 `TrustedUserCAKeys`；host key 轮换完全无感（`@cert-authority`） |
| M3-X2 | 会话录制 | `SessionRecorder`（Tap 语义落地） |
| M3-X3 | SFTP 拦截器实现 | `SftpAuditInterceptor`（命令级审计/拦截，如禁 rm） |
| M3-X4 | jump 模式 | direct-tcpip 按策略放开并校验目标 |
| M3-X5 | HA 演练 | 无状态多副本 + L4 LB（least-conn）+ 排水 + 摘流演练 |

---

## 5. 关键技术落点（约束实施细节）

### 5.1 保险丝决策
- **默认常开**（outbound_guard=true）。Spike #2 若证明 russh client 侧 `data()` 在窗口耗尽时可靠阻塞，允许在**性能基准后**评估关闭，但仍保留 per-channel Semaphore 作为能力。
- 实现要点：permits=后端初始 window_size；每个下行 `WindowAdjusted` 增量 `add_permits`；超窗写入前 `acquire`（`data()` 回调内 await 即可见源码级保底）。

### 5.2 会话状态机
`Handshake → Auth → Authorized → ChannelOpen(懒拨号) → RequestRelaying(执行型请求前) → DataFlow(执行型请求后) → Closed`
- 任意一侧断开联动关闭另一侧；审计落盘；session-id 用 UUIDv7 串联网关 session 与后端 channel。

### 5.3 请求转发矩阵遵守
按 propose.md §3.4 全表实现；**I2 want_reply 原样透传 + FIFO 回执路由**是 `pending_replies: VecDeque<Option<oneshot::Sender<bool>>>` 的实现语义，禁止旁路。

### 5.4 认证时序红线
- **禁止**在 `auth_publickey_offered` 中返回最终 Accept（跳签风险）；该回调仅预检/缓存预热/早期拒绝。
- 坏签名用例必须为 CI 常驻测试，防止 russh 升级回归。

### 5.5 配置契约
配置文件字段与 propose.md §5.2 表一致，未配置项走默认值；新增字段需 TDD 先行。
- 配置占位（本版起预留，M1/M2 启用）：`[relay] env_allowlist = []`——M1 默认全透传，白名单过滤启用时校验 `env` 变量名（propose §3.4）。
- 后端凭据：`[backend] private_key`（静态文件）+ `credential_map` 解析即 M1-T2 范围；KMS 加载/热轮换在 M2-U4。

---

## 6. 门禁与定义完成（DoD）

### 6.1 M1 门禁（MS1）清单
- [ ] `cargo clippy -- -D warnings` + `cargo fmt --check` 通过（CI 常驻）
- [ ] 全单元/集成测试绿（含坏签名、冒用 principal、时序矩阵对拍、反例 3 例）
- [ ] `ssh gw true`、`ssh gw 'exit 42'`→42、stderr 分离、交互 shell（resize/Ctrl+C/vim/tmux）通过
- [ ] sftp / 新旧 scp / rsync / git over ssh 通过；端口转发/agent/x11 默认拒绝
- [ ] 反例（2GB 慢读 / yes 洪泛 / netem 限速 scp）：RSS 平稳无 OOM、吞吐损失 <15%【**反例场景硬门禁**；sshbench 基线（T11）为记录性差距，非硬门禁，超 15% 入 M2-U6 调优排队】
- [ ] `auth_publickey_offered` 语义固化测试绿；认证审计字段完整
- [ ] 优雅退出用例绿（TERM 干净退出 + sftp channel 无污染）
- [ ] 指标/日志与 §5.5 字段清单对齐；基线报告入库

### 6.2 M2 门禁（MS2）清单
- [ ] 池健康检：iptables DROP 假死 15s 内检出，爆炸半径收敛（客户端 DISCONNECT 可重连）
- [ ] 熔断生效（连续失败→circuit open→快速失败）
- [ ] host key 轮换三阶段演练通过（OpenSSH 无感；PuTTY/WinSCP 走管控面下发）
- [ ] 稳定性长跑 soak 无 OOM/泄漏；rekey 中途不丢数据
- [ ] 吞吐损失 ≤15% 目标达成（或差距记录在案）
- [ ] 全量回归绿

### 6.3 通用门禁（每次 commit 强制）
- TDD：先有失败测试→实现→测试绿；内部逻辑禁 Mock（重构为纯函数），外部边界（控制面 API）允许 Mock
- 根因治理：禁止 Hack/补丁式绕过；禁空 catch/吞异常
- 安全：禁字符串拼接 SQL（本项目无 DB，控制面请求用严格类型序列化）；敏感信息走环境变量/密钥文件（0600）；外部输入必验
- 依赖：Cargo.lock 提交；新增依赖评审

---

## 7. 验证策略（分层）

### 7.0 测试环境（实际使用）
- 后端测试目标服务器：**`root@47.109.73.53`**（ssh root@47.109.73.53，端口默认 22）。
- 用途：M1-T5 起全部端到端集成测试、M1-T6 反例（含 netem 限速）、M1-T10 协议对拍、M1-T11 性能基线、M2 池/健康检查/故障注入（iptables DROP 演练需在目标机或网络侧执行）。
- 前提（由实施阶段准备）：`root@47.109.73.53` 的 `authorized_keys` 需加入网关后端公钥（§3.3 凭据），首次联通后按 `pinned` 固化其 host key 指纹。
- 周期性故障演练（假死/宕机）会把该目标临时置为不可用，需与维护窗口协调，避免影响其他联调。

| 层 | 内容 | 工具 |
|---|---|---|
| 单元 | 配置/错误类型、resolver 缓存/熔断、FIFO 回执路由、保险丝许可、审计字段、拦截分类 | cargo test |
| 协议对拍 | 时序矩阵双端报文 diff（网关不改序固化） | 自研抓包 diff 脚本（ssh-keyscan/pcap 或 russh 事件日志对拍） |
| 反例 | 2GB 慢读、yes 洪泛、netem 限速 scp | 脚本 + RSS 断言 |
| 认证负例 | 坏签名、未授权 key、冒用 principal | cargo test + 集成 |
| 故障注入 | 后端假死（iptables DROP）、后端宕机、控制面超时/熔断、rekey 中途 | 脚本 + 容器 |
| 生命周期演练 | TERM/SIGKILL/轮换三阶段/LB 摘流 | 剧本演练 |
| 客户端兼容 | OpenSSH 8/9、PuTTY、WinSCP、Windows OpenSSH | 兼容矩阵用例 |
| 性能 | sshbench 基线/对比、flamegraph、tokio-console | 报告入库 |
| **任何 Web/交互面修改后** | Playwright 验证（本网关为 SSH 服务，UI 面仅告警页/指标页等可视面，如存在才适用） | playwright |

---

## 8. 依赖图与并行策略

```
M0:  S1 ─┐
     S2 ─┤──（并行，独立）→ M0-T 骨架（并行）→ MS0 门禁
     S3 ─┤（依赖 M0-T，但可与 M0-T 并行启动编写用例）
     S4 ─┤(依赖 S1 ②)
     S5 ─┘
M1:  关键链：T1 → T3 → T4 → T5 → T6 → T7 → T11 → MS1
     并行支：T2 ∥（T3→T4→T5）【即 T2 与 T3 起头并行】；T8/T9 在 T5/T6 齐后 ∥；T10 在 T5/T6 齐后即启（对拍框架是其验证工具，越早越好，与 T7~T9 并行）；T11 赖 T10
     依赖约束：T4 赖 M0-S3 结论+M1-T3；T6 赖 M0-S2；T7 赖 T5；T8 赖 T5+T6
M2:  U1→U2；U3 ∥ U2（U3 赖 M0-S4/M1-T5，不赖 U2）；U4 ∥ U1..U3；U5→U6→MS2
```

**并行写面隔离**：若双人并行，按下划线领域拆分分支（如 `feat/resolver`、`feat/relay`），relay 由单一写者独占（改动最密集且保序红线敏感）；合并走 PR + 门禁。

---

## 9. 风险管理

| 风险 | 概率/影响 | 缓解 | 出处 |
|---|---|---|---|
| russh server 侧缺 exit-status/DISCONNECT/hostkeys-00 等 API | 中/高 | M0-S1 首发验证；缺失→小补丁或上游 PR，预留 fork 备选 | §7-1 |
| russh client 侧 `data()` 窗口耗尽不阻塞（内部缓冲增长） | 中/高 | Semaphore 保险丝常开兜底 | §7-2 |
| 验签时序被误用（offered 提前 Accept） | 低/极高 | 红线固化 + 坏签名 CI 用例 | §7-3 |
| 同算法 host key 轮换不可用 | 中/中 | hostkeys-00 通道；降级=管控面下发 known_hosts | §7-4 |
| sshd 未开 `MaxSessions` 放宽致池化受限 | 低/中 | 每连接 ≤8 channel 保守值 | §3.8 |
| 控制面不可用 | 中/中 | fail-closed 默认 + fail-open 可配 + 旧缓存 | §3.1 |
| 性能不达标（内存/吞吐） | 中/中 | M1 基线先行、M2 调优预算、准入控制 | §四 |
| 老客户端算法不兼容 | 中/中 | M0-S5 兼容矩阵 + 多算法 offer | §7-5 |

---

## 10. 工程规范与工具链

- **Git**：项目始即 `git init`；**每任务完成即 `git commit`**（WBS 粒度）；PR 门禁。
- **TDD + 验证闭环**：先测试后实现；改后必测；任何需编译项目改后必编译验证。
- **约束**：遵守 `constraints/rust.md` 与 AGENTS.md 红线（禁 `var`/裸 `except` 等在本项目为禁 `unwrap`/`expect`/裸 `panic`/`unsafe`；tokio spawn 内 `map_err`；lock 内禁 await）。
- **CI**：cargo clippy -D warnings、cargo fmt --check、cargo test、协议对拍/反例脚本（M1 后常驻）、坏签名用例。

---

## 11. 交付物清单

| 类别 | 交付物 |
|---|---|
| 代码 | Cargo workspace（§5.1 目录）+ 全部模块 |
| 测试 | 单元/集成/对拍/反例/故障注入/兼容矩阵脚本 + 报告 |
| 文档 | TDM（Spike 结论）、抓包对拍方案、运维手册（含轮换/排水/熔断 runbook）、性能基准报告、验收报告 |
| 产物 | 编译通过的网关二进制 + 配置样例 + systemd/K8s 部署样例（含 /readyz 探针） |

---

## 12. 下一步执行建议

1. 若门禁通过 → 启动 M0（5 个 Spike + 骨架，3–5 个有效日），先 TDD 固化 M0-S3 坏签名用例。
2. 每任务完成后由实施者按 §6.3 通用门禁自检并 commit。
3. MS0 通过后进入 M1-T1/T2/T3 并行实施；M1-T5（转发引擎）为关键路径，建议独占写者。

---

## 13. 修订记录

| 版本 | 日期 | 修订者 | 变更 | 依据 |
|---|---|---|---|---|
| v1.0 | 2026-10-10 | 编排者 | 初稿 | — |
| v1.1 | 2026-10-10 | 编排者 | **P0-1**：M1-T2 扩为「host key + 后端凭据加载」（TDD：凭据解析/缺失/权限≠0600 → 拒绝启动）；KMS 加载与热轮换显式排入 M2-U4；§1.3 标注首期静态文件假设。**P0-2**：M1-T5 增加全局请求处理（keepalive → 本地 success），DoD 增 ServerAlive 长连用例。**P0-3**：§8 依赖图修正（T2 ∥ (T3→T4→T5)；T10 与 T7~T9 并行）。P1：M2-U1~U4 补 TDD 步骤列。P2：吞吐口径统一（反例 <15% 为 MS1 硬门禁，T11 基线记录性差距）；M0-S3 依赖改 M0-T；M1-T8 补 T5 依赖；env 白名单配置占位；M1-T7 性能断言改为可判定基准；单人排期加缓冲；未知 channel request 策略固化 | @oracle 门禁审核（有条件通过） |
| v1.3 | 2026-10-12 | 编排者 | **M2-U6 关闭决议**：单连接 scp 吞吐 ≤15% 判定为**架构限制**（双隧道「终结+重建」双重加解密 + russh 逐包开销）；数据路径调度重构（mpsc+sender task）实测零收益且破坏红线（I1 保序/D11 锁纪律/§3.6 有界内存）→ @oracle 裁决**回退**（提交 d6c4eb5），保留 tap 枚举化与 perf-report。外部调研（lib-1）指出低成本机会：双腿 `nodelay=true`（当前 Nagle 开）、腿 A/B 隔离诊断、cipher A/B（aes-gcm vs chacha20）、写路径流水化（仿 bssh 6.2x）——列入后续待实测项。KPI 改口径为**连接级**（ControlMaster 复用、每连接建立成本、并发会话容量）；架构级选项（ProxyJump 直通 / 可信后端裸 TCP）需产品与威胁建模决策，记录于 known-limitations #7 与 perf-report | 外部调研 + @oracle 门禁裁决 |
| v1.2 | 2026-10-10 | 编排者 | §7.0 新增「测试环境（实际使用）」：后端测试目标服务器 `root@47.109.73.53`，含用途、凭据准备前提、故障演练协调说明 | 用户指定 |

> 门禁记录：@oracle 裁决「有条件通过」——3 个 P0 均为文档级修改，不触及架构决策；经上述修订后具备放行实施资格，可直接进入 M0。

> 本文档为计划层；实施细节随 Spike 结论与 russh 实际版本行为校准更新（版本化记录）。
