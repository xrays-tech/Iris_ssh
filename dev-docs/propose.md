# SSH 网关设计方案 v2（Rust）

**结论先行：维持「russh 双会话管道」方案**，v2 重点修正转发引擎的时序保序、流量控制背压、认证/授权边界、SFTP 拦截预留四个关键设计，并补充 Host Key 轮换、连接池健康检查、SSH 协议级优雅退出三项工程化设计。

---

## v2 变更摘要（审核意见 → 落点）

| 审核意见 | 落点章节 | 修正要点 |
|---|---|---|
| 1. exec/pty-req 时序问题 | 4.5 转发引擎 | 严格 FIFO 请求管线，四条不变量，禁止 spawn 转发任务 |
| 2. 窗口与背压 | 4.6 流量控制 | 双向有界内存模型 + Semaphore 保险丝，内存公式与准入控制 |
| 3. 签名验证 vs 指纹校验 | 4.2 认证授权边界 | 网关做认证、控制面做授权，russh 验签时序明确化 + spike 用例 |
| 4. SFTP/审计预留 | 4.7 | SubsystemInterceptor trait + scp 新旧模式审计判定表 |
| 5. Host Key 轮换 | 6.3 | 多密钥加载 + hostkeys-00@openssh.com + 同算法轮换的协议限制说明 |
| 6. 连接池爆炸半径 | 4.8 | keepalive 假死检测、销毁语义、熔断 |
| 7. 优雅退出 | 6.4 | SSH_MSG_DISCONNECT(11) 协议级告别 + 两阶段排水 |

---

## 一、结论与技术路线

核心协议事实（不变）：**用户名在加密通道建立后才出现**（RFC 4252，USERAUTH_REQUEST 在 NEWKEYS 之后），纯 L4 转发在路由决策点看不到 `alex_host1`，故网关必须终结 SSH。路线调研结论与 v1 一致：

| 路线 | 用户名改写 | 结论 |
|---|---|---|
| L4 纯 TCP 转发 | ❌ | 否决 |
| OpenSSH ForceCommand | ✅（shell 层） | 过渡备选 |
| **russh 双会话管道** | ✅ | **✅ 采用** |
| Jump 模式（direct-tcpip） | ❌ 需 `-J` | M3 可选模式 |
| libssh 绑定 / 自研协议栈 | ✅ | 备选 / 否决 |

选型：`russh`（纯 Rust + tokio，server/client 双角色，aes-gcm/chacha20、curve25519、ed25519、OpenSSH 私钥加载）。

---

## 二、总体架构

```
                    ┌──────────────────────────────────────────────────┐
 ssh alex_host1@GW  │                SSH Gateway (russh)               │
        │           │                                                  │       ┌──────────────┐
        ├── SSH ───▶│ ServerLeg ──▶ ChannelRelay(严格FIFO+窗口有界) ────├──────▶│ root@10.1.2.3:22
        │           │ (认证/解析)        │           │                 │       │ (russh client leg)
        │           │                  ▼           ▼                 │       └──────────────┘
        │           │        Resolver(缓存/熔断)  Auditor(审计)        │
        │           │        SubsystemInterceptor(预留)   Pool+健康检查 │
        └───────────└──────────────────────────────────────────────────┘
```

会话生命周期：`TCP → KEX(网关host key) → userauth(alex_host1, pubkey) → resolve+authorize → Accept → channel_open(懒拨号后端) → 请求/数据双向中继 → 关闭联动`。

---

## 三、关键设计

### 3.1 用户名解析与控制面契约

与 v1 一致，要点保留：

- 用户名整体作为不透明 token 查控制面；正则校验 `^[a-z0-9][a-z0-9_-]{0,62}$`。
- **缓存 + 单飞 + 熔断**：`moka`（TTL 30s + jitter，负缓存 5s，`get_with` 合并并发查询），控制面故障时 fail-closed（默认）/ fail-open（用旧缓存，可配）。

```json
POST /api/v1/resolve  {"principal":"alex_host1","client_ip":"..","key_fp":"SHA256:.."}
→ 200 {"target":{"host":"10.1.2.3","port":22,"user":"root"},
       "policy":{"agent_forwarding":false,"tcp_forwarding":false,"recording":false,"ttl":60}}
→ 404 / 403 / 429
```

### 3.2 认证与授权的边界（⚠️ 修正 #3：签名验证 vs 指纹校验）

**职责三分，绝不可混淆：**

| 职责 | 承担方 | 机制 |
|---|---|---|
| **认证 Authentication**：证明客户端持有私钥 | 网关（russh 协议层） | 验证 USERAUTH_REQUEST 中对 session ID 的签名，伪造签名一律拒绝 |
| **授权 Authorization**：principal + 指纹能否访问目标 | 控制面 | resolve+authorize API，纯策略决策，**不做任何密码学验证** |
| 后端认证 | 后端 sshd | 校验网关密钥 / 网关签发的用户证书 |

**russh 回调时序（以引入版本行为为准，Spike #3 固化）：**

```
1. 客户端 probe（无签名）──────▶ russh 回调 auth_publickey_offered
   网关动作：仅预检/缓存预热/早期拒绝（403 快速失败）
   ⚠️ 绝不能在该回调做出最终 Accept 并跳过签名流程

2. 客户端重发（带签名）───────▶ russh 库内完成签名验证（绑定 session ID）
   验签失败 → 直接拒绝，不进入回调
   验签成功 → 回调 auth_publickey → 网关查控制面授权 → Accept
```

- 授权结果按 `(principal, fingerprint)` 键控，同一连接的 offered/最终两个阶段复用缓存，避免两次控制面 RTT。
- **Spike 用例**：手工构造坏签名报文，验证无论 handler 返回什么都被拒——把「russh 先验签后回调」固化为 CI 测试。
- 审计记录必须同时含：指纹（授权依据）+ 签名算法 + 认证结果，事后可追溯「谁用什么钥认证了什么」。

### 3.3 网关 → 后端认证

与 v1 一致：网关密钥环 `credential_map = {"root" = "/keys/root_ed25519"}`，文件 0600，支持 KMS 加载与热轮换；后端 `authorized_keys` 放网关公钥（长期：网关签发短期用户证书 + `TrustedUserCAKeys`）；后端主机密钥策略 `pinned`（生产）/ `accept-new` + 告警。

### 3.4 Channel 请求转发矩阵（含 want_reply 语义）

| 客户端请求 | 转发 | want_reply / 回执处理 |
|---|---|---|
| `pty-req` / `shell` / `exec` / `subsystem` | **原样透传，保序** | 标志原样透传；后端 Success/Failure 按 FIFO 路由回客户端 |
| `env` | 原样（可配白名单过滤） | 多数客户端 want_reply=0，仍按 FIFO 透传 |
| `window-change` / `signal` / `break@openssh.com` | 原样 | 无回执语义 |
| `auth-agent-req@openssh.com` | **默认拒绝**：本地 request_failure | 不转发后端 |
| `x11-req` / `direct-tcpip` / `forwarded-tcpip` | **默认拒绝** | jump 模式（M3）下按策略放开并校验目标 |
| 后端 → `exit-status` / `exit-signal` / `eof` / `close` | 回传客户端 | `ssh gw 'exit 42'` 必须拿到 42 |
| 全局请求 `keepalive@openssh.com`（客户端→网关） | 网关本地应答 success | M2 可配端到端转发到后端做活链路检测 |
| 全局请求 `hostkeys-00@openssh.com` | **网关应答本侧全部 host 公钥** | 支撑 host key 轮换（见 6.3），不转发后端 |

### 3.5 转发引擎 v2：严格 FIFO 请求管线（⚠️ 修正 #1）

**问题回顾**：客户端 channel request 顺序不固定（`pty-req→shell`、裸 `exec`、`env→pty-req→exec` 等都合法），且 `exec` 一旦发出后端即开始执行，其后到达的 `pty-req` 会被 sshd 拒绝。任何重排/合并/注入都是事故源。

**网关强制不变量：**

- **I1** 同一 channel 上，客户端→后端的所有 CHANNEL_REQUEST / DATA / EOF / CLOSE **按到达序转发**，不合并、不重排、不注入网关自有请求。
- **I2** `want_reply` 标志原样透传；后端回执（SUCCESS/FAILURE）按 FIFO 与已转发请求一一对应地路由回客户端。
- **I3** `shell`/`exec`/`subsystem` 为「执行型」请求：发出后该 channel 进入 DataFlow 态，网关此后只透传 data/eof/signal/exit/close，**不得再补发任何请求**。
- **I4** 失败/拒绝一律使用协议原生机制（channel open failure / request failure / DISCONNECT），**不伪造 exec 输出或 exit code**。

**实现映射（关键）：**

- russh 在单连接内**按报文到达顺序串行 await 调用** server Handler 回调（以引入版本行为为准，用乱序用例在 CI 固化）。因此「在回调内同步 await 转发」即天然保序。
- **禁止**在请求类回调中 `spawn` 任务后异步转发（破坏顺序）；**禁止**为性能做批处理聚合。
- 并发优化只允许作用于**数据路径**（见 4.6），永不作用于**请求路径**。

```rust
// 伪代码，API 以实际引入的 russh 版本为准（Spike #1 校准）
struct ChannelRelay {
    backend_ch: client::Channel<client::Msg>,
    pending_replies: VecDeque<Option<oneshot::Sender<bool>>>, // I2：want_reply FIFO 路由表
    outbound_budget: Arc<Semaphore>,                          // 4.6 背压保险丝
}

impl server::Handler for ClientConn {
    // 懒拨号在 channel_open 内同步完成：失败 → open_failure(CONNECT_FAILED)
    // （遵守 I4：不伪造 exec 结果，且天然规避 exec 时序问题）
    async fn channel_open_session(&mut self, ch: Channel<Msg>) -> Result<bool> {
        match self.dialer.connect(&self.grant).await {
            Ok(be) => { let bch = be.open_session_channel().await?;
                        self.relays.insert(ch.id(), ChannelRelay::new(bch));
                        spawn(pump_backend_to_client(...)); Ok(true) }
            Err(e) => { self.send_open_failure(ch.id(), CONNECT_FAILED, e.user_msg()).await?; Ok(false) }
        }
    }
    // 请求路径：回调内同步 await，串行保序（I1）；回执经 FIFO 路由（I2）
    async fn pty_request(&mut self, id, want, term, w, h, pw, ph, modes) -> Result<bool> {
        let rx = self.forward_request(id, want, |c| c.request_pty(term, w, h, pw, ph, modes)).await?;
        Ok(rx.await.unwrap_or(false))            // 后端 Success/Failure 原样回客户端
    }
    async fn exec_request(&mut self, id, want, cmd) -> Result<bool> { /* 同上，cmd 原文透传 */ }
    async fn shell_request / subsystem_request / env_request / signal_request / window_change_request
    /* 同模式；agent/x11 请求在此本地拒绝（I4） */

    // 数据路径：await 转发写 → 天然背压（4.6）
    async fn data(&mut self, id, data) -> Result<()> {
        let _p = self.relay(id).outbound_budget.acquire(data.len()).await?;
        self.relay(id).backend_ch.data(data).await?; Ok(())
    }
    async fn extended_data(&mut self, id, ext, data) -> Result<()> { /* 同上，ext 类型保留 */ }
}

// 下行泵：独立 task，只负责 后端→客户端 方向 + 回执投递
async fn pump_backend_to_client(mut bch: Channel<client::Msg>, up: ServerUpstream, id: ChannelId) {
    while let Some(msg) = bch.wait().await {
        match msg {
            ChannelMsg::Data { data }              => { audit.tap(&data); up.data(id, data).await; }
            ChannelMsg::ExtendedData { data, ext } => up.extended_data(id, ext, data).await,
            ChannelMsg::Success | ChannelMsg::Failure => relay.deliver_reply(msg), // 弹 pending FIFO → oneshot
            ChannelMsg::WindowAdjusted { .. }      => relay.outbound_budget.add_permits(..),
            ChannelMsg::ExitStatus { exit_status } => up.exit_status(id, exit_status).await,
            ChannelMsg::ExitSignal { .. }          => up.exit_signal(id, ..).await,
            ChannelMsg::Eof                        => up.eof(id).await,
            ChannelMsg::Close                      => { up.close(id).await; break; }
            _ => tracing::debug!(?msg, "unhandled"), // catch-all + 日志（Spike #1 覆盖面）
        }
    }
}
```

- 一条客户端连接 lazily 建立一条后端连接，多 channel 复用（scp/rsync 走 ControlMaster 复用连接时天然受益）。
- 会话状态机：`Handshake → Auth → Authorized → ChannelOpen(懒拨号) → RequestRelaying(执行型请求前) → DataFlow(执行型请求后) → Closed`；任意一侧断开联动关闭另一侧，审计落盘（session-id 用 UUIDv7 串联两侧日志）。

### 3.5.1 单顺序消费者例外（agent 穿透模式，红线 11）

**动机。** §3.5 的设计前提是「handler 侧同步处理，不做跨会话异步等待」。agent 穿透打破了这个前提：网关必须作为 SSH 客户端，向用户端发起 `channel_open_agent()`、建立 `AgentClient`、`request_identities()` 并在需要签名时调用 `sign_request()` —— 这些都是 **await**，且必须发生在用户端连接的 session 事件循环之上。若在 `agent_request()`/handler 回调里直接 await，会阻塞 russh 的单线程串行事件循环，导致后端/用户端后续消息无法推进，形成**自锁死锁**（D11 违例）。

**例外条款。** agent 模式下，允许把「agent 通道生命周期 + 后端拨号 + 队列消费」整体搬进一个 **per-session supervisor task**，handler 侧只做非阻塞入队。该例外受以下四条限定词约束，任一违反即视为越过红线 11：

1. **作用域仅限 agent 模式。** supervisor 只在 `backend_auth = "agent"` 且 `allow_agent_backend_auth = true` 时存在；非 agent 路径（key/cert）**字节级不变**，不引入任何新的 task、channel 或 await 点。
2. **每会话单一顺序消费者。** 每条用户端连接至多一个 supervisor task、一个 FIFO 队列。禁止 per-request spawn、禁止多消费者合并、禁止乱序消费、禁止注入请求。FIFO 串行消费保证 I1（channel ↔ 后端 1:1 绑定）不被破坏 —— 签名请求与后续 pty/shell/env/data 的因果顺序由串行消费天然保证。
3. **handler 侧永不阻塞、内存有界（C5/D11）。** handler 回调内只做 `try_send`（Dialing 状态下队列满 → 该 channel 原生失败并计数，**绝不 await**）；Ready 状态下的 `send().await` 等价于今天的内联背压，不新增缓冲。队列容量 = `ceil(relay.window_size / max_packet)` 槽位，保证入队数据总量 ≤ `relay.window_size`（I2/I3 记忆体上界继续成立）。锁内不 await（D11）：就绪信号用 oneshot/watch，不用 `Mutex` 保护的条件变量。
4. **失败走协议原生、不回退凭证（I4/红线 3）。** supervisor 任一环节失败（grant 超时、agent 通道被拒、无匹配指纹身份、`connect_agent` 认证失败、后端通道建立失败）→ 排空队列并对 pending 请求回 `Handle::channel_failure`、再 `Handle::close`，**绝不**回退到 `backend_auth = "key"`/`"cert"`，也绝不静默降级。签名面最小化（红线 4）：只对 resolve 出的目标拨号签名，且只用与 `grant.fingerprint` 匹配的 agent 身份。

**可观测性。** 上述失败均需可观测：`auth_kind="agent"` 进入审计与指标，`sshgw_agent_signatures_total`、`sshgw_agent_channel_denied_total` 与 `agent_identity`（指纹）随审计记录落盘。

### 3.6 流量控制与背压（⚠️ 修正 #2）

**目标：网关内存占用必须有协议级上界，禁止无限缓冲。**

**方向 A（后端→客户端，下行泵）：**
- pump 在 `bch.wait()` 取数后 **await** 写入客户端侧（`up.data(...)`），不在网关内二次缓冲。
- 后端发送速率受其后端声明的 channel window 约束；russh 消费 `wait()` 后按需自动补 WINDOW_ADJUST（Spike #2 验证）。
- ⇒ 下行在网关驻留量 ≈ 后端声明的窗口大小，天然有界。

**方向 B（客户端→后端，上行）：**
- `data()` 回调内 await 转发写；后端窗口耗尽时写路径挂起 → russh 停读客户端 socket → 客户端窗口耗尽 → 停发。链式背压成立。
- **保险丝（默认开启）**：若 Spike #2 发现 russh client 侧 `Channel::data()` 在窗口耗尽时不阻塞（内部缓冲增长），则启用 per-channel `Semaphore`（permits = 后端初始窗口），`WindowAdjusted` 到达时增量补充 permits——保证即使库行为变化，网关内存依然有界。

**参数与准入：**

| 项 | 默认 | 说明 |
|---|---|---|
| 初始 window_size | 1MB（可调 256KB~8MB） | 过小伤吞吐，过大伤内存 |
| max packet size | 32KB（SFTP 大读取场景可调至 256KB） | 两侧配置一致 |
| 内存公式（最坏） | ≈ 活跃会话 × (上行窗口 + 下行窗口) | 10k 会话全满载 ≈ 20GB → 按实例内存预算做**准入控制**（max_sessions 动态计算） |
| 监控 | `relay_inflight_bytes`、`window_exhausted_total`、RSS/活跃会话比 | 超阈值告警 |

**反例测试（必须进 CI）：** `cat 2GB 文件 | 慢消费者`、`yes` 洪泛、tc/netem 限速 1Mbps 下 scp 大文件——RSS 必须平稳、无 OOM。

### 3.7 SFTP / Subsystem 拦截预留 + 审计判定（⚠️ 修正 #4）

M1 透传，但架构上在 Relay 层预留拦截接口，默认实现必须零开销（`None` 快路径，无锁无拆包）：

```rust
#[async_trait]
pub trait SubsystemInterceptor: Send + Sync {
    async fn on_subsystem_request(&self, name: &str, grant: &Grant) -> Verdict;   // Pass | Deny(msg) | Tap
    async fn on_data(&self, ctx: &ChannelCtx, dir: Dir, buf: &Bytes) -> DataVerdict; // 仅 Tap 模式被调用
}
// M1 唯一实现：PassThroughInterceptor —— 透传路径零额外成本
// M3 实现：SftpAuditInterceptor（命令级审计/拦截，如禁 rm）、SessionRecorder
```

**审计分类规则**（scp 协议在 OpenSSH 9.0+ 默认走 SFTP，必须区分）：

| 特征 | 判定 | 说明 |
|---|---|---|
| `exec` 且命令前缀 `scp ` | scp 传统模式 | 文本协议走 stdout/stderr |
| `subsystem == "sftp"` | SFTP | 新版 scp、WinSCP、FileZilla |
| `exec` 且命令含 `rsync` | rsync | 记录模块路径参数 |
| 其他 `exec` | 命令审计 | 记录原文（注意敏感信息脱敏） |

### 3.8 连接池与健康检查（M2，⚠️ 修正：爆炸半径）

复用一条后端连接承载 ≤8 条 channel（受 sshd `MaxSessions` 默认 10 约束），把 TCP+KEX+认证 3~4 RTT 摊薄为 1 RTT。**池化连接必须解决「后端假死」问题：**

```
健康检查（每条池化连接）：
 - L4：TCP keepalive
 - L7：每 15s 发 global request keepalive@openssh.com (want_reply=true)，5s 超时
        连续 2 次失败 → 判定假死，立即销毁该连接
Checkout 防护：
 - 空闲超过 30s 的连接，复用前先做一次 ping 验证
销毁语义（爆炸半径收敛）：
 - 向该连接上所有 channel 对应的客户端发
   SSH_MSG_DISCONNECT{reason=11 BY_APPLICATION, "backend connection lost, please retry"}
 - 清理全部 Relay 状态，指标记录，客户端可立即重连（新连接新拨号）
熔断：
 - 同一目标连续 N 次拨号失败/假死 → open circuit T 秒，channel open 直接快速失败
限制：
 - 池化连接上禁用 agent forwarding（channel 路由歧义）；每连接 ≤8 channel
 - 默认模式仍是每会话独连，池化 opt-in
```

---

## 四、性能设计

| 项目 | 设计/预算 |
|---|---|
| 加密 | 每会话 2 层，强制 aes256-gcm / chacha20-poly1305 + curve25519；AES-NI 下非瓶颈 |
| 数据路径 | 上行：1 次解密 + await 转发写；下行：泵直通写，无额外拷贝/缓冲 |
| 请求路径 | 严格串行 FIFO（安全第一），交互延迟影响可忽略（请求数量少） |
| 内存 | 见 4.6 公式与准入控制 |
| 水平扩展 | 无状态多副本 + L4 LB（least-conn）+ 排水（见 6.4） |
| 基准 | `sshbench`：握手→退出延迟、scp/rsync 吞吐 vs 直连基线；flamegraph + tokio-console |

---

## 五、工程化

### 5.1 项目结构与依赖

与 v1 一致：`server/ backend/ resolve/ policy/ relay/ audit/ pool/`；依赖 `tokio`、`russh`、`moka`、`reqwest`(rustls)、`tracing`、`metrics`、`governor`、`semaphore`（tokio 自带）、`uuid`、`thiserror`。

### 5.2 配置

```toml
[listen]        addr = "0.0.0.0:22"
[host_keys]     keys = [ { path = "/etc/ssh-gw/host_ed25519", state = "active" },
                         { path = "/etc/ssh-gw/host_rsa",     state = "active" } ]
[relay]         window_size = "1MB"   max_packet = "32KB"   outbound_guard = true
[backend]       private_key = "/etc/ssh-gw/backend_root_ed25519"
                host_key_policy = "pinned"
[pool]          enabled = false        channels_per_conn = 8
                keepalive_interval = "15s"  keepalive_timeout = "5s"  keepalive_max_miss = 2
[control_plane] url = "https://cp.internal"  cache_ttl = "30s"  timeout = "2s"
[limits]        max_sessions = 10000   max_sessions_per_ip = 20   auth_timeout = "30s"
[shutdown]      drain_wait = "60s"     disconnect_flush = "3s"    hard_deadline = "30s"
```

### 5.3 Host Key 管理与无缝轮换（⚠️ 新增 #5）

**能力矩阵：**

- **多密钥同时加载**：`ed25519 + rsa-sha2 + ecdsa` 各一把同时 offer（russh `Config.keys: Vec<PrivateKey>` 支持），覆盖不同客户端的算法偏好，也支撑跨算法轮换。
- **`hostkeys-00@openssh.com` 支持**：客户端认证通过后 OpenSSH（≥6.8，`UpdateHostKeys`）会主动询问服务器全部 host 公钥并更新本地 known_hosts——网关应答全部 host key。**这是同算法轮换无感化的关键通道。**

**轮换流程（ed25519 → 新 ed25519）：**

```
协议限制须知：KEXINIT 按"算法名"协商，同算法一条连接只能签一把 K_S，
因此同算法新老密钥无法靠"算法列表"并存，必须走以下路径：

1) 引入期：正常用老 key 签名；hostkeys-00 应答中同时列出 老 key + 新 key
   → 客户端（OpenSSH + UpdateHostKeys）把新 key 写入 known_hosts
2) 切换期：签名切换到新 key（老 key 保留在 hostkeys-00 应答中）
   → 老客户端（已学到新 key）无感；配置 UpdateHostKeys 的新装客户端也 OK
3) 下线期：观察指标确认无客户端再用老 key（或超时窗口结束）→ 移除老 key
不支持 UpdateHostKeys 的客户端（PuTTY/WinSCP）：依赖管控面下发 known_hosts，
或接受一次性提示；这是轮换窗口期的已知成本，写入运维手册。
```

- **长期方案（M3）：Host CA**——客户端只 pin `@cert-authority` 一条，网关 host key 轮换完全无感。
- **事故检测**：轮换窗口期监控「KEX 后立即断开」模式与连接失败率激增，自动回滚告警。
- 用户入口统一为单一网关域名/IP ⇒ known_hosts 只有这一条需管理，轮换影响面收敛。

### 5.4 优雅退出的 SSH 特殊性（⚠️ 新增 #6）

直接断 TCP 会让用户看到 `Connection reset by peer`。v2 采用**协议级告别 + 两阶段排水**：

```
SIGTERM → Draining
 t0     停止 accept、关闭 listener；/readyz → 503（LB 摘流；K8s preStop 配合）
 t0     可选 drain_wait（默认 60s，可配 0）：给短任务自然收尾
        - 向交互/exec channel 注入 stderr 提示 "gateway draining, please wrap up"
        - ⚠️ 禁止向 subsystem(sftp) channel 写任何提示文本——会污染二进制协议
 t1     对每个活跃会话发送
        SSH_MSG_DISCONNECT{reason=11 SSH_DISCONNECT_BY_APPLICATION,
                           description="Gateway is shutting down, please reconnect"}
        客户端干净退出并显示该消息，而非 broken pipe
 t1+3s  flush 超时 → 强制关 TCP
 t0+hard_deadline（30s）→ SIGKILL 兜底
```

- 断开原因码直方图入指标（区分：by_application / timeout / backend lost / auth failed）。
- 验证用例：活跃 `ssh gw` 会话收 TERM → 客户端干净退出并显示消息；scp 中途 → 非零退出码。

### 5.5 可观测性

JSON 日志 + Prometheus 指标：active sessions、auth 成败（含 offered/最终两阶段）、resolve 延迟/命中率、`relay_inflight_bytes`、`window_exhausted_total`、后端拨号延迟、池健康（假死检出数/熔断状态）、disconnect 原因码直方图、轮换失败率；`/healthz` `/readyz`；审计日志（who/when/target/bytes/duration/exit-code/命令分类）。

---

## 六、测试矩阵（v2 扩充）

**功能/协议**
- 交互 shell（resize、Ctrl+C、vim、tmux）；`ssh gw true`；`ssh gw 'exit 42'; echo $?` 透传；stderr 分离
- **时序矩阵**：`pty→shell`、`env→pty→shell`、裸 `exec`、`-tt` 强制 pty+exec、subsystem、罕见顺序——网关前后各抓一份报文序列做 diff，固化「网关不改序」
- sftp / 新旧 scp / rsync / git over ssh；端口转发默认拒绝

**流量控制（4.6 反例必须进 CI）**
- `cat 2GB | 慢读`、`yes` 洪泛、netem 限速下 scp，RSS 平稳无 OOM，吞吐损失 <15%

**认证（4.2）**
- 好签名 / **坏签名（必须拒）** / 未授权 key / **冒用 principal（bob 的 key 访问 alex_host1 → 403）**
- `auth_publickey_offered` 与最终回调语义固化测试

**生命周期**
- TERM 优雅退出（客户端干净退出 + 显示消息）、SIGKILL 兜底、LB 摘流演练
- host key 轮换三阶段演练（OpenSSH UpdateHostKeys 无感 / PuTTY 已知成本）
- 后端假死（iptables DROP 不 RST）→ 池健康检查 15s 内检出并收敛爆炸半径
- rekey 中途、客户端 keepalive、后端宕机、控制面超时/熔断、并发上限

**客户端兼容性**：OpenSSH 8/9、PuTTY、WinSCP、Windows OpenSSH；明确不支持 mosh（UDP）、X11。

---

## 七、风险与 Spike 清单（M1 前完成）

1. **russh server 侧 API 完整性**：exit-status 发送、global_request（`hostkeys-00@openssh.com` 应答）、DISCONNECT 发送、多 host key offer、未知 channel request catch-all——逐项验证，缺失则小补丁/上游 PR。
2. **russh 窗口语义**：出站 `data()` 窗口耗尽是否阻塞、`WindowAdjusted` 是否在 `wait()` 暴露、入站 WINDOW_ADJUST 是否自动发送——决定 4.6 保险丝是否常开。
3. **验签时序**：`auth_publickey_offered` / `auth_publickey` 回调语义与「先验签后回调」固化（坏签名用例）。
4. **同算法 host key 轮换**：hostkeys-00 通道可用性（依赖 Spike #1）；不可用时的降级 = 管控面下发 known_hosts。
5. 遗留自 v1：OpenSSH 证书支持度、老客户端算法兼容矩阵、压缩协商、控制面 fail-open/closed 行为。

---

## 八、里程碑

- **M1（3 周）**：端到端 shell/exec/sftp 打通；**严格 FIFO 管线 + 保序测试**；**背压保险丝 + 内存准入**；外部解析/授权 + 认证授权边界（含坏签名测试）；审计分类；优雅退出基础版；集成测试框架。
- **M2（2~3 周）**：连接池 + **keepalive 假死检测 + 熔断**；**host key 多密钥 + 轮换流程与 hostkeys-00**；稳定性（keepalive、rekey、限流）；性能基准调优。
- **M3**：Host/用户 CA、会话录制、SFTP 拦截器实现、jump 模式（direct-tcpip）、HA 演练。

---

需要的话，下一步我可以输出：① M1 可编译的 russh server/client 骨架（含 FIFO Relay 与 Semaphore 保险丝）；② Spike #1~#4 的具体验证代码清单；③ 保序对拍测试的抓包 diff 方案。
