# SSH 网关运维手册（Ops Runbook）

> 适用：本 SSH 网关（russh 双会话中继，用户名即路由）。所有命令以本仓库 `config.example.toml`、`docs/known-limitations.md` 与 `src/` 实际行为为准。
> 配套：`docs/perf-report.md`（性能基线）、`docs/known-limitations.md`（已知限制）。

---

## 1. 架构速览

```
  客户端 ssh alex_host1@GW
        │  SSH(终结在网关)
        ▼
  网关 Server(认证/解析) → 授权 → 双会话中继 Relay → 后端 sshd(目标)
        │        │
        │        └─ Resolver → 控制面 POST /api/v1/resolve（策略决策）
        └── 审计 / 指标 / 拦截器（SFTP/录制）
```

- **会话生命周期**：`TCP → KEX(网关 host key) → userauth(alex_host1, 公钥/证书) → resolve+authorize → channel_open(懒拨号后端) → 数据双向中继 → 关闭联动`。
- **角色**：网关终结客户端 SSH（在加密通道内才可见用户名），再用 russh client 腿连后端，**纯转发不落盘**（录制功能显式开启才写盘）。
- **关键目录/端口**：`[listen] addr` 服务 SSH；`[metrics] addr` 暴露 `/healthz /readyz /metrics`；`[recording] dir` 录制目录（若启用）。

---

## 2. 部署

### 2.1 产物
```bash
cargo build --release            # 产物在 ${CARGO_TARGET_DIR:-target}/release/ssh-gw
install -m 0755 "${CARGO_TARGET_DIR:-target}/release/ssh-gw" /usr/local/bin/ssh-gw
```
实际构建产物路径受环境 `CARGO_TARGET_DIR` 影响（本机为全局 target 目录），部署时以 `cargo metadata` 输出或实际产物为准。

### 2.2 配置文件
- 按 `config.example.toml` 复制为生产配置（如 `/etc/ssh-gw/gateway.toml`）。
- 加载顺序：`$SSHGW_CONFIG` → 首个 CLI 参数 → `/etc/ssh-gateway/config.toml`。
- 启动：`ssh-gw --config /etc/ssh-gw/gateway.toml`。
- systemd 参考：本仓库 `deploy/ssh-gw.service`（ExecStart 指向 `--config`；`TimeoutStopSec=70s` 配合优雅排水）。

### 2.3 Host key 生成（首次部署）
```bash
mkdir -p /etc/ssh-gw && chmod 700 /etc/ssh-gw
ssh-keygen -t ed25519 -N "" -f /etc/ssh-gw/host_ed25519     # user "active"
ssh-keygen -t rsa     -b 3072 -N "" -f /etc/ssh-gw/host_rsa # 可选兼容
chmod 600 /etc/ssh-gw/host_*    # 权限不符 → 拒绝启动（fail-closed）
```
`[host_keys] keys` 可多算法同时 offer（`state=active` 签名 / `passive` 仅通告学习）。

### 2.4 后端授权（唯一模式：agent 穿透）
- 网关 → 后端的凭证**只有一种**：终端用户自己的 ssh-agent，即 `ssh -A` / `-o ForwardAgent=yes` 语义的 agent 穿透。后端 `authorized_keys` 放**用户公钥**；网关不持有、也不代管任何后端私钥（`[backend] private_key` / `credential_map` 已删除，`backend_auth` / `cert` 模式已删除）。详见 §5.7。
- 是否放行由控制面逐 grant 决定：resolve 返回 `policy.agent_forwarding`，`true` 才建立后端会话；`false` 则拒绝（**不降级**、无凭据可降级）。
- **客户端必须转发 agent**：`ssh -A` 或 `-o ForwardAgent=yes`。没带 agent 的会话在后端握手阶段失败，网关不会代签任何东西。
- 后端 host key 信任：生产用 `host_key_policy="pinned"`（首次 await 后固化指纹）；初次联调可 `accept-new` 并尽快 pin。
- `direct-tcpip` / jump（跳板）已删除：一律拒绝并计数 `sshgw_direct_tcpip_denied_total`，无任何配置可放开。

---

## 3. 配置速查（字段 / 默认 / 必填 / 互斥）

| 段 | 字段 | 默认 | 说明 / 约束 |
|---|---|---|---|
| `[listen]` | `addr` | `0.0.0.0:2222` | 网关 SSH 监听 |
| `[host_keys]` | `keys` | — | host key 文件+state；**缺失/权限≠0600 → 拒绝启动** |
| `[relay]` | `window_size` | `1MB` | 初始通道窗口（256KB~8MB） |
| | `max_packet` | `32KB` | 最大单包（≤65535） |
| | `outbound_guard` | `true` | per-channel Semaphore 背压保险丝 |
| | `env_allowlist` | `[]` | 空=env 原样透传；非空=过滤变量名 |
| `[backend]` | `host_key_policy` | `pinned` | `pinned` / `accept-new`；后端主机密钥信任策略 |
| | `private_key` / `credential_map` / `backend_auth` / `allow_agent_backend_auth` | — | **已删除**（agent-only 改造）。未知键按 TOML 解析为忽略，不会报错；写旧键的配置仍能启动，但**不再有任何效果** |
| `[pool]` | `enabled` | `false` | **必须为 `false`**：`enabled = true` 是无条件的配置错误（启动即报错）。agent 穿透下每会话一个后端连接，没有可复用的东西；熔断/channel 上限与 `enabled` 无关，始终生效 |
| | `channels_per_conn` | `8` | 每连接 ≤8（sshd MaxSessions 安全界） |
| | `keepalive_interval` / `keepalive_max_miss` | `15s` / `2` | 假死检测（`keepalive_timeout` 为保留字段，实际语义见 §5.3） |
| | `circuit_failure_threshold` / `circuit_reset_timeout` | `5` / `30s` | 拨号熔断 |
| `[control_plane]` | `url` | — | 控制面 resolve 地址（POST /api/v1/resolve）。**`routing="openstack_only"` 时整节可省略**（此时网关不向它发任何请求）；其余路由下必填 |
| | `cache_ttl` | `30s` | 授权缓存 |
| | `timeout` | `2s` | 控制面请求超时 |
| | `fail_open` | `false`（注释） | 控制面故障时用旧缓存放行 |
| `[openstack]` | `enabled` | `false` | **默认关**：缺本节或 `enabled=false` 时行为与旧版完全一致（路由谓词对所有 principal 都答"控制面"） |
| | `routing` | `hybrid` | `hybrid`：UUID→Nova，其余→控制面；`openstack_only`：只认规范 UUID，**无控制面回退**，非 UUID 直接拒绝。**启用态（`enabled=true`）目前只接受 `openstack_only`**——`hybrid` 会以 `openstack.routing` 配置错误拒绝启动，等方案 A（控制面授权）落地 |
| | `authorization` | `control_plane` | `control_plane`：授权权威仍在控制面（默认值，但**启用态下不可用**：`routing`/`authorization` 任一为可启用的组合都必须两者同时为 `openstack_only`，方案 A 未实现）；`openstack_only`：**实验室模式**，必须同时 `allow_any_authenticated_key = true`，语义是"任意通过前腿验签的密钥 + 已知 UUID ⇒ 可达该实例"（见 §5.8 / `known-limitations.md` §9） |
| | `auth_url` / `application_credential_*` / `project_id` | — | Keystone v3；`project_id` 是 token scope，也是可见实例范围的爆炸半径闸门；secret 支持 `_file` 与环境变量注入 |
| | `nova_endpoint` | 空 | 显式 Nova base URL（跳过 catalog 发现；测试/内网云用） |
| | `timeout` / `cache_ttl` / `fail_open` | `3s` / `30s` / `false` | 独立于 `[control_plane]` 的缓存与超时；`fail_open=true` 才允许在 TTL 过期后用旧地址（且须配合 `host_key_policy="pinned"`） |
| | `network` / `address_family` / `prefer` / `on_ambiguous` | `""` / `ipv4` / `floating` / `reject` | 地址选择；多网络实例不配 `network` 且候选 >1 → 拒绝（`on_ambiguous="reject"`） |
| | `address_kind` | `any` | `any`（默认，= 现状零回归）\| `floating`\| `fixed`：**硬过滤**（在 `prefer` 排序前按地址种类过滤候选）。`floating` 只取浮动 IP、实例无浮动 → 拒绝 `reason="no_floating"`（**绝不回退 fixed**）；`fixed` 镜像（`no_fixed`）。公网可达部署用 `floating`，避免网关拨到不可达的 VXLAN 私网地址 |
| | `default_backend_user` / `backend_user_metadata_key` | — / `""` | 后端登录用户：metadata 命中 → 映射规则 → `default_backend_user`（enabled 时必填） |
| | `ssh_port` | `22` | 所有实例的 SSH 端口（实例文档里不带端口） |
| `[limits]` | `max_sessions` / `max_sessions_per_ip` | `10000` / `20` | 准入 |
| | `auth_timeout` | `30s` | 首个 "none" 认证探测的 backoff 上限（实际延迟 = `min(auth_timeout, auth_rejection_pad)`；`0s` 关闭每连接 initial backoff，**保留每次拒绝的持续 pad**，公钥/证书为主的生产可用；非整个认证期预算） |
| | `auth_rejection_pad` | `1s` | 每次认证拒绝的恒时填充（防时间泄露） |
| | `inactivity_timeout` | `600s` | 空闲回收 + 认证停滞 deadline |
| | `max_auth_attempts` | `10` | 防爆破尝试上限（`0`=不限） |
| `[shutdown]` | `drain_wait` / `disconnect_flush` / `hard_deadline` | `60s` / `3s` / `30s` | 排水阶段各时限 |
| `[metrics]` | `addr` | `127.0.0.1:9090` | 健康/指标端口 |
| `[ca]` | `trusted_ca_keys` | 注释 | 证书 CA（**verify-only**，见 §5.4）。`signing_key` / `cert_lifetime` 已删除：网关不再签发任何证书 |
| `[recording]` | `dir` / `max_bytes_per_session` | `/var/lib/ssh-gateway/recordings` / `64MiB` | 会话录制（`0` 关闭） |
| `[intercept.sftp]` | `enabled` / `deny_commands` / 路径前缀 | `false` | SFTP 命令级拦截 |

---

## 4. 认证

- **客户端 → 网关**：公钥（`auth_publickey`）或用户证书（`auth_openssh_certificate`，按 CA / 有效期 / principals 校验）。`auth_publickey_offered` 仅为预热/形状预检，**不**在该阶段做最终 accept。恶意签名一律被 russh 库拒。
- **网关 → 后端**：agent 穿透（§2.4 / §5.7）。网关以用户转发来的 ssh-agent 签名认证，且**只签控制面已授权的那个指纹**；网关自身不提供任何 key/cert 凭据。
- **目标来自哪里**：用户名只是一条**路由线索**，不是目标地址。启用 `[openstack]` 后规范形式的实例 UUID 走 Nova，其余源照旧走控制面（`routing="openstack_only"` 时非 UUID 直接拒绝、不回退）。目标 host 始终由 Nova 返回的地址决定，用户名里出现 host/IP 是不可能的（SSRF 红线）。预认证的 publickey 探测（`auth_publickey_offered`）在 OpenStack 路由上**只跑纯路由谓词、零网络调用**，真正的 Nova 查询发生在客户端完成签名校验之后（plan-openstack MUST1，用例 `case_openstack_preauth_no_lookup`）。

---

## 5. 运维操作 runbook

### 5.1 Host key 轮换（同算法）
受 russh 无 `hostkeys-00@openssh.com` hook 限制，**同算法无感轮换需走 known_hosts 下发降级**：
1. **引入期**：生成新 key，加入 `[host_keys] keys`（`active` 用于签名），经管控面把新公钥下发给管理端 known_hosts；观察 `hostkeys-00` 不应答属预期（客户端只认已 pin 指纹）。
2. **切换期**：签名切到新 key（旧 key 可保留 `passive` 通告）。
3. **下线期**：确认无客户端再用旧 key（或超时窗口结束）后移除旧 key。
- **事故检测**：轮换期监控「KEX 后立即断开」与连接失败率激增 → 自动回滚告警。
- **跨算法轮换**：多算法 offer（ed25519+rsa）天然并存，可无感。

### 5.2 优雅停机 / 排水
```bash
kill -TERM <ssh-gw-pid>        # 或 systemctl stop
```
- `SIGTERM` → 停止 accept、`/readyz → 503`（LB/K8s 摘流）、进入 `drain_wait` 排水。
- 排水期：对交互/exec channel 注射 stderr 提示「gateway is shutting down, please wrap up」；**禁止向 SFTP/录制 channel 写提示文本**（不污染二进制协议）。
- 排水结束 → 对活跃会话发 `SSH_MSG_DISCONNECT(11)`「Gateway is shutting down, please reconnect」→ `disconnect_flush` 后强关 TCP → `hard_deadline` 兜底 SIGKILL。
- 验证：`ssh` 活跃会话收 TERM 后客户端显示该消息而非 `Connection reset by peer`。

### 5.3 后端宕机 / 假死处理
- **检测语义**：russh keepalive 为**间隔计数**——每 `keepalive_interval`(15s) 无流量则 `alive_timeouts+1` 并发探测，超过 `keepalive_max`(2) 判定假死。**检出 ≈ `keepalive_interval × (max_miss+1)` ≈ 45s**（`keepalive_timeout` 为保留字段，不受 5s 限制）。
- **处置**：判定后向挂连客户端发 `SSH_MSG_DISCONNECT(11)`「backend connection lost, please retry」；客户端可立即重连（新连接新拨号）。
- **熔断**：同一目标连续 `circuit_failure_threshold` 次拨号失败 → open circuit `circuit_reset_timeout`，期间 channel open 快速失败。
- **排查命令**：
  ```bash
  curl -s localhost:<metrics>/metrics | grep -E 'backend_lost|disconnect_reason|backend_dial'
  # 日志：见 5.6
  ```

### 5.4 证书信任轮换（`[ca] trusted_ca_keys`）
- **CA 是 verify-only 的**：`[ca]` 只放 CA 公钥，网关不签发任何证书，因此没有 `signing_key` 轮换这一说。用户证书由运维侧工具（如 `ssh-keygen -s <ca> -n <principal> <userkey.pub>`）签发，轮换 CA = 换 `trusted_ca_keys` 指向的新公钥并重启网关。
- **在途连接**：SSH 会话内不再认证，**不**受影响；撤销已建会话是运维侧职责。
- **host 证书信任**：后端若出示 host 证书，网关按四步校验（signing key ∈ `[ca] trusted_ca_keys` → 验签 → 有效期 → principals 含目标主机名）；签发参考 `ssh-keygen -s <ca> -h -n <host> <hostkey.pub>` 或仓库 `scripts/cert_topo.sh`。

### 5.5 指标与告警建议
| 指标 | 含义 | 建议告警 |
|---|---|---|
| `sshgw_active_sessions` | 活跃会话数 | 与 `max_sessions` 对比，>80% 预警 |
| `sshgw_auth_accept_total` / `reject_total` / `offered_total` | 认证结果（offered/最终两阶段） | reject 突增 / offered 幻增（爆破） |
| `sshgw_resolve_ok_total` / `err_total` | 控制面解析 | err 率突增 |
| ~~`sshgw_resolve_cache_hit_total` / `miss_total` / `circuit_open_total`~~ | **已导出但从未累加**（解析器尚未接线），恒为 0 | 勿据此告警 |
| `sshgw_backend_dial_ok_total` / `fail_total` / `latency_seconds` | 后端拨号 | fail 上升 / P95 上升 |
| `sshgw_backend_lost_total` | 后端假死检出 | >0 即查 |
| `sshgw_disconnect_reason_total` | 断开原因直方图（含 `reason="11"` 排水） | 异常原因激增 |
| **`sshgw_relay_window_budget_bytes`** | **预留窗预算**（`active_sessions×window×2`，非实时在途） | 按内存预算容量规划；**勿当实时缓冲** |
| `sshgw_window_exhausted_total` | 背压熔断触发 | 持续增加=慢消费者或窗口过小 |
| `sshgw_sftp_requests_seen_total` / `denied_total` | SFTP 拦截 | denied 突增=策略命中 |
| `sshgw_direct_tcpip_denied_total` | 端口转发拒绝（恒拒绝） | 突增=客户端在探测转发能力 |
| ~~`sshgw_pool_dead_detected_total` / `tracked_conns`~~ | 池已不可启用（`enabled=true` 即配置错误），且从未接线，恒为 0 | 勿据此告警；拨号健康看上面的 `backend_dial_*` 与 `backend_lost` |
| `sshgw_recorded_sessions_total` / `bytes_total` | 录制 | 磁盘配额预警（`sessions_total` 已接线；**`bytes_total` 目前恒为 0**，配额看磁盘用量） |
| `sshgw_cert_auth_accept_total` / `reject_total` | 证书认证 | reject 突增=证书问题 |
| `sshgw_agent_backend_auth_ok_total` / `fail_total` | agent 模式后端认证结果 | fail>0 且 ok 不动=用户 agent 未转发/缺 key |
| `sshgw_agent_signatures_total` | 经网关中继的 agent 签名次数 | 与 `ok_total` 长期偏离=会话复用异常 |
| `sshgw_agent_channel_denied_total` | 因**并发**通道数达到 `channels_per_conn`（≤8，等价 sshd `MaxSessions`）而被拒的通道 | 持续出现=同一连接并发开太多通道（如 ControlMaster 大量复用）；它是并发上限，不是连接一生的配额 |

吞吐回归门：`make bench`（= `scripts/bench.sh`）的 **Tier B** —— 复用连接上的数据面中位数相对基线 **±20%** 越界即非零退出；Tier A（每连接 ~1s 固定成本）只告警、Tier C（新建连接 scp）只记录，两者都不判定回归（定义与基线见 `docs/perf-report.md`「基准定义 v2」）。

动态采样脚本参考：`scripts/run_soak.sh`（RSS/drift 模式）、`scripts/ha_drain.sh`（排水断言模式）。

### 5.6 常见故障排查
| 症状 | 定位 | 处置 |
|---|---|---|
| 连接卡 ~1s 才认证 | `auth_rejection_pad`（默认 1s，防爆破） | 属正常；测试/内网可调小 |
| 连接卡 ~45s 后断开 | 后端假死（keepalive 检出） | 查后端存活与恢复策略 |
| 客户端收到 `backend connection lost` | 后端宕机/熔断 | 恢复后端；熔断 `circuit_reset_timeout` 后自愈 |
| 连不上 / 超时 | `/healthz`、`/readyz`、后端拨号日志 | 检查控制面与后端 reachability |
| RSS 持续上涨 | `relay_window_budget_bytes` / 慢消费者 | 调 `window_size` / `max_packet`、排查背压 |
| SFTP 操作被拒绝 | `sftp_requests_denied_total` + 拦截配置 | 检查 `[intercept.sftp] deny_commands/路径` |
| 认证总失败 | `auth_*` 指标 + 审计（指纹/签名算法/principal） | 核对 key/证书与授权策略 |
| 端口转发不通 | 设计如此 | `direct-tcpip` **恒拒绝**，无任何配置可放开；网关不是出站跳板 |
| `-A` 会话立刻失败 | `agent_backend_auth_fail_total` + 网关日志中的 reason | 见 §5.7 排障表 |
| `-A` 会话成功但客户端挂住不退出 | 网关未关闭转发的 agent 通道 | 属缺陷；升级到含 C2 修复的版本 |

### 5.7 Agent 穿透（后端认证的唯一方式）

以终端用户的 ssh-agent 作为后端凭据。语义等同 `ssh -A`：**网关只做签名中继，不持有也不代管任何私钥**。这不是可选模式，而是网关到后端的唯一数据通路（plan-agent-only，propose §3.5.1）。

**启用（两道门，缺一不可）**
1. 客户端带 agent：`ssh -A` 或 `-o ForwardAgent=yes`；
2. 控制面 resolve 返回 `policy.agent_forwarding: true`（按 grant 授权）。

没有其他开关：`[backend] backend_auth` 与 `[backend] allow_agent_backend_auth`（旧的全局 kill-switch）都已删除。`policy.agent_forwarding: false` 的 grant **整体拒绝**，既没有、也不会回落成 key/cert——网关手里没有第二套凭证。

**约束**
- 每会话只开**一个**后端通道；`direct-tcpip`（跳板）一律拒绝并计数 `sshgw_direct_tcpip_denied_total`。
- `[pool] enabled` 必须为 `false`（否则启动即报错）：池化连接无法携带 per-session 的 agent 身份。
- 只有**控制面已授权指纹**对应的 agent 身份会被提供给后端；agent 里即便有别的可用 key 也不会用（最小签名面）。
- 后端 `authorized_keys` 应**只放用户公钥**，不要放任何网关 key——没有网关 key 就没有降级路径，一旦转发链断开会话必然失败而不是"悄悄成功"。

**排障**
| 症状 / 日志关键字 | 含义 | 处置 |
|---|---|---|
| `client never requested agent forwarding` | 客户端没带 `-A` | 让用户用 `ssh -A`；网关不做降级 |
| `agent forwarding denied by policy` | 控制面 `agent_forwarding` 未开 | 在 resolve 响应中为该 grant 打开 |
| `no agent identity matches the authorized fingerprint` | 用户 agent 里没有被授权的那个 key | `ssh-add -l` 核对；补加正确 key |
| `backend rejected the agent signature` | 后端 `authorized_keys` 不含该用户 key | 核对后端 authorized_keys |
| `client refused the agent channel` | 客户端拒绝打开 agent 通道 | 检查客户端 `-A`/`ForwardAgent` 配置 |
| 会话成功但客户端不退出 | 网关未关闭转发通道 | 升级；C2 已修复 |

**可观测**：审计记录带 `auth_kind="agent"`、`agent_identity`（签名身份指纹）与 `agent_signatures`（签名次数）；指标见 §5.5 agent 三行。

### 5.8 OpenStack 实验室模式（方案 B，`routing=openstack_only`）

**定位**：这是**显式实验室/内网 PoC 模式**，不是生产路由方案。它去掉控制面这条依赖，让"OpenStack 实例 UUID 本身就是路由"：客户端用 `<instance-uuid>@gw` 登录，网关查 Nova 拿地址与后端用户，再用转发来的 agent 签名拨进实例。默认关闭；不写 `[openstack]` 节时行为与旧版完全一致。

**启用条件（缺一不可；配置层只接受这一种组合，其余组合启动即报 `openstack.routing` / `openstack.authorization` 错误——`routing="hybrid"` 或"控制面授权"都属于方案 A，尚未实现）**
```toml
[openstack]
enabled = true
routing = "openstack_only"          # 只认规范 UUID，非 UUID 直接拒绝、不回退控制面
authorization = "openstack_only"    # 危险：授权权威就是 Nova 的回答
allow_any_authenticated_key = true  # 必须显式置 true，接受其语义
auth_url = "https://keystone.../v3"
application_credential_id = "..."
application_credential_secret_file = "/etc/ssh-gw/os-appcred.secret"
project_id = "..."                  # scope = 爆炸半径闸门，给最小 project
nova_endpoint = "https://nova.../v2.1"
default_backend_user = "cloud-user"
ssh_port = 22
# route_by = ["uuid", "name"]  # 可选：追加 "name" 启用实例名路由（见下）
```
此时 `[control_plane]` 整节可以不写。**启动日志会打两条 WARN**（`allow_any_authenticated_key = true: ... Lab mode only.` 与 `talking to OpenStack over plain http`），看到它们才说明模式确实打开了。

**安全语义（写进变更单）**
- 任意通过前腿验签的密钥，只要知道（或猜到）实例 UUID，就能登进该实例，**范围仅受 application credential 的 project 限制**。UUID 不是秘密（日志、对象存储、API 都会泄露），且 Nova 的 404/200 差异构成存在性预言机——所有失败对客户端同构 `Auth::reject()`，缓解靠 `max_auth_attempts` + 负缓存限速，不是靠 UUID 难猜。
- 目标 host **只能**来自 Nova；`network` 过滤、`on_ambiguous="reject"`（默认）保证不会拨到歧义地址。
- `fail_open` 默认 `false`：TTL 过期后 Nova 不可达即拒绝，不回落控制面。缓存**在 TTL 之内**是权威的（与控制面路由一致），这不是 fail-open。

**实例名路由（appendix A，默认关）**：`route_by` 默认 `["uuid"]`，现有部署行为不变。写成 `route_by = ["uuid", "name"]` 后，非 UUID principal 在满足实例名边界（非空、≤255、无控制字符）时经 `GET /servers?name=<值>` 解析：名字只作百分号编码的 query 值、绝不进路径；Nova 的 `name` 是**子串**搜索，网关本地做**全等**过滤，0 个或多个全等命中对客户端都等于 404（`ambiguous_name` 只进日志，不猜机器）。UUID 形态永远优先走 UUID 路由、从不视为名字。路由选择的可观测性是 `sshgw_openstack_resolve_by_uuid_total` / `sshgw_openstack_resolve_by_name_total` 两个计数器——**审计记录格式不变**。

**跨项目模式（appendix C，`scope="cross_project"`，默认关）**：`scope` 默认 `single_project`（零回归）；`cross_project` 让网关以 `all_tenants=1` 解析**任意项目**的实例——UUID（全局唯一）可直接直达；名字要求全云**唯一全等**，跨项目重名 → `ambiguous_name_cross_project` 拒绝，绝不猜。**必须 `auth_method="password"`**（app-credential 被 Keystone 锁死在单项目，无法跨项目），此时 `project_id` 是**认证 scope**（决定 token 带哪种角色），不是可见性边界。⚠ **这是最重的实验室开关**：网关持有的凭据能看/能拨其 admin 角色覆盖的所有项目实例，且依赖平台 Nova 策略允许 project-scoped admin 用 `all_tenants`（严格云会是 404）；**禁止公网/共享网关**。启动会出现专属 WARN（`scope = "cross_project": this is a LAB mode …`）。真机已验证：单项目 admin token 跨项目解析并 root 登录另一项目的实例（`case_openstack_cross_project_*` / T_3741 实录）。

**排障**
| 症状 / 日志关键字 | 含义 | 处置 |
|---|---|---|
| `reason="unrouted"`（`target=resolve` WARN） | principal 不是规范 UUID，`openstack_only` 直接拒绝 | 用户名必须是小写规范 v4 UUID |
| `reason="not_found"` | Nova 404 / 实例无可用地址（两者客户端表现相同） | 核对 UUID 与 application credential 的 project 可见性 |
| `reason="ambiguous"`（`target=openstack` WARN） | 多网络多地址且未配 `network` | 配 `network = "<name>"`，或确认 `on_ambiguous` |
| `reason="unavailable"` / `reason="circuit_open"` | Keystone/Nova 不可达或熔断 | 看该源自己的熔断与 `sshgw_openstack_resolve_err_total`；**不会**影响控制面熔断 |
| 实例达但登录失败 | 后端 `authorized_keys` / 用户不匹配 | 看映射链：metadata 键 → `backend_user_map` → `default_backend_user` |
| `reason="unparseable"`（`target=openstack` WARN） | 200 body 里 `addresses` 结构读不出（如成了字符串）——**响亮**拒绝，不是 `no_network` | 看同一条日志的 `summary=`（只含 keys/类型/网络数/长度，不含 body）；核对云或前置代理返回的 API 形态 |
| `reason="decode"`（`target=openstack` WARN） | 200 body 不是 JSON / 不是 server 文档 / 列表里有读不出 `addresses` 的元素 | 同上，`summary=` 给出结构摘要；通常是代理层或 compat 层改写了响应 |
| `ambiguous_name`（name 路由 WARN） | 多个实例共用同一个名字（全等命中 >1） | 改实例名或改用 UUID 登录；网关按设计不猜机器 |
| `sshgw_openstack_resolve_by_{uuid,name}_total` | 名字路由的命中分布（appendix A.4） | name 计数在未启用时恒 0；意外增长说明有人在用名字登录 |
| 探测阶段有 `sshgw_auth_offered_total`、零 Nova 请求 | 预认证探测按设计不联网 | 属预期（MUST1），不是"解析没生效" |

**可观测**：`sshgw_openstack_resolve_{ok,err}_total`、`sshgw_openstack_resolve_latency_seconds`（与既有 `sshgw_resolve_*` 分开，两条源的健康度不可混淆）；审计记录带 `resolve_source="openstack"`；pre-auth 失败没有会话也没有审计记录，只有一条 `target=resolve` 的结构化 WARN（含 principal / client_ip / source / reason）。

---

## 6. 健康检查
- `/healthz`：进程存活（200=live）。
- `/readyz`：可服务（200=ready；排水期/不可服务=503）。
- `/metrics`：Prometheus 文本。

K8s 探针建议：
```yaml
livenessProbe:  { httpGet: { path: /healthz, port: metrics }, periodSeconds: 10 }
readinessProbe: { httpGet: { path: /readyz,  port: metrics }, periodSeconds: 5 }
```
排水对外编排配合 `preStop: sleep 若干` 等待 readyz→503 摘流。

---

## 7. 已知限制导航
- `docs/known-limitations.md`（本机维护，含各项触发条件与处置）：
  - `#1/#2`：后端 host 证书 / TrustedUserCAKeys cert-dial —— **M4 已实现**（`11d42cb`，E2E 实跑）。
  - `#3`：真机半开假死 / netem 演练脚本已交付并在测试真机实跑 PASS（检出口径 `~45s`）。
  - `#4`：8h soak 未跑（`SOAK_DURATION=28800` 参数化，运维排窗）。
  - `#5`：HA 演练为 client-side readyz 近似；PuTTY/WinSCP 为算法集模拟。
  - `#9`：**OpenStack 实验室模式（方案 B）的边界** —— 授权语义、`match_image` 未实现、domain 字段已移除、缓存与 fail-open 的分工。
  - `#6`：offered 探测触发控制面 resolve（预热 miss，量级可接受）。
- russh 上游限制（同算法 host key 轮换需 known_hosts 下发降级、`client::Handle` 非 Sync 限制跨会话池化）——按 §5.1/§5.3 与 known-limitations 处理。
