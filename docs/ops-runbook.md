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
        └── 审计 / 指标 / 拦截器（SFTP/录制/jump）
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

### 2.4 后端授权（三种模式）
- **key 模式（默认）**：网关后端私钥 `[backend] private_key`（或 `credential_map`），对应公钥加入后端 `authorized_keys`。
- **cert 模式（可选）**：后端 sshd 配 `TrustedUserCAKeys <网关CA公钥>`，网关 `[backend] backend_auth="cert"` + `[ca] signing_key`，拨号时现签短期用户证书（后端不再需要网关公钥）。
- **agent 模式（可选，C2）**：以**终端用户自己的 ssh-agent** 作为后端凭据，即 `ssh -A` 语义的 agent 穿透。后端 `authorized_keys` 放用户公钥；网关既不需要也不使用自己的 key/CA（`private_key` 与 `[ca]` 均可省略）。详见 §5.7。
- 后端 host key 信任：生产用 `host_key_policy="pinned"`（首次 await 后固化指纹）；初次联调可 `accept-new` 并尽快 pin。

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
| `[backend]` | `private_key` / `credential_map` | — | **key 模式必须其一**（该模式无 key 拒绝启动） |
| | `host_key_policy` | `pinned` | `pinned` / `accept-new` |
| | `backend_auth` | `key` | `key` / `cert` / `agent`；**cert 模式要求 `[ca] signing_key`**；`signing_key` 又要求至少一个 `trusted_ca_keys`；**agent 模式要求 `allow_agent_backend_auth=true`，且与 `[pool] enabled=true` 互斥** |
| | `allow_agent_backend_auth` | `false` | agent 模式的**全局 kill-switch**；为 false 时 agent 授权被整体拒绝（不降级为 key） |
| `[pool]` | `enabled` | `false` | opt-in 池化；**熔断/channel 上限与 enabled 无关（始终生效）**；**与 `backend_auth="agent"` 互斥（启动即报错）** |
| | `channels_per_conn` | `8` | 每连接 ≤8（sshd MaxSessions 安全界） |
| | `keepalive_interval` / `keepalive_max_miss` | `15s` / `2` | 假死检测（`keepalive_timeout` 为保留字段，实际语义见 §5.3） |
| | `circuit_failure_threshold` / `circuit_reset_timeout` | `5` / `30s` | 拨号熔断 |
| `[control_plane]` | `url` | — | 控制面 resolve 地址（POST /api/v1/resolve） |
| | `cache_ttl` | `30s` | 授权缓存 |
| | `timeout` | `2s` | 控制面请求超时 |
| | `fail_open` | `false`（注释） | 控制面故障时用旧缓存放行 |
| `[limits]` | `max_sessions` / `max_sessions_per_ip` | `10000` / `20` | 准入 |
| | `auth_timeout` | `30s` | 首个 "none" 认证探测的 backoff 上限（实际延迟 = `min(auth_timeout, auth_rejection_pad)`；`0s` 关闭每连接 initial backoff，**保留每次拒绝的持续 pad**，公钥/证书为主的生产可用；非整个认证期预算） |
| | `auth_rejection_pad` | `1s` | 每次认证拒绝的恒时填充（防时间泄露） |
| | `inactivity_timeout` | `600s` | 空闲回收 + 认证停滞 deadline |
| | `max_auth_attempts` | `10` | 防爆破尝试上限（`0`=不限） |
| `[shutdown]` | `drain_wait` / `disconnect_flush` / `hard_deadline` | `60s` / `3s` / `30s` | 排水阶段各时限 |
| `[metrics]` | `addr` | `127.0.0.1:9090` | 健康/指标端口 |
| `[ca]` | `trusted_ca_keys` / `signing_key` / `cert_lifetime` | 注释 | 证书 CA（见 §5.4） |
| `[recording]` | `dir` / `max_bytes_per_session` | `/var/lib/ssh-gateway/recordings` / `64MiB` | 会话录制（`0` 关闭） |
| `[intercept.sftp]` | `enabled` / `deny_commands` / 路径前缀 | `false` | SFTP 命令级拦截 |
| `[jump]` | `enabled` / `allow_private_networks` / `allowed_targets` | `false` | direct-tcpip 跳板（默认拒绝） |

---

## 4. 认证

- **客户端 → 网关**：公钥（`auth_publickey`）或用户证书（`auth_openssh_certificate`，按 CA / 有效期 / principals 校验）。`auth_publickey_offered` 仅为预热/形状预检，**不**在该阶段做最终 accept。恶意签名一律被 russh 库拒。
- **网关 → 后端**：见 §2.4 三种模式；cert 模式在 `connect` 时现签短期证书（不缓存）；agent 模式以用户 agent 的签名认证，且**只签控制面已授权的那个指纹**（见 §5.7）。

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

### 5.4 证书轮换（CA signing_key）
- **新连接**：换 `signing_key` 后，下一拨号即签发新 CA 证书（现签不缓存）。
- **在途连接**：SSH 会话内不再认证，**不**受轮换影响；撤销已建会话是运维侧职责。
- **host 证书信任**：后端若出示 host 证书，网关按四步校验（signing key ∈ `[ca] trusted_ca_keys` → 验签 → 有效期 → principals 含目标主机名）；签发参考 `ssh-keygen -s <ca> -h -n <host> <hostkey.pub>` 或仓库 `scripts/cert_topo.sh`。

### 5.5 指标与告警建议
| 指标 | 含义 | 建议告警 |
|---|---|---|
| `sshgw_active_sessions` | 活跃会话数 | 与 `max_sessions` 对比，>80% 预警 |
| `sshgw_auth_accept_total` / `reject_total` / `offered_total` | 认证结果（offered/最终两阶段） | reject 突增 / offered 幻增（爆破） |
| `sshgw_resolve_ok_total` / `err_total` / `cache_hit_total` / `miss_total` / `circuit_open_total` | 控制面解析 | err 率突增 / circuit_open>0 |
| `sshgw_backend_dial_ok_total` / `fail_total` / `latency_seconds` | 后端拨号 | fail 上升 / P95 上升 |
| `sshgw_backend_lost_total` | 后端假死检出 | >0 即查 |
| `sshgw_disconnect_reason_total` | 断开原因直方图（含 `reason="11"` 排水） | 异常原因激增 |
| **`sshgw_relay_window_budget_bytes`** | **预留窗预算**（`active_sessions×window×2`，非实时在途） | 按内存预算容量规划；**勿当实时缓冲** |
| `sshgw_window_exhausted_total` | 背压熔断触发 | 持续增加=慢消费者或窗口过小 |
| `sshgw_sftp_requests_seen_total` / `denied_total` | SFTP 拦截 | denied 突增=策略命中 |
| `sshgw_jump_open_total` / `denied_total` / `forbidden_address_total` | jump 模式 | forbidden 突增=扫描 |
| `sshgw_pool_dead_detected_total` / `tracked_conns` | 池健康 | 池化场景启用 |
| `sshgw_recorded_sessions_total` / `bytes_total` | 录制 | 磁盘配额预警 |
| `sshgw_cert_auth_accept_total` / `reject_total` | 证书认证 | reject 突增=证书问题 |
| `sshgw_agent_backend_auth_ok_total` / `fail_total` | agent 模式后端认证结果 | fail>0 且 ok 不动=用户 agent 未转发/缺 key |
| `sshgw_agent_signatures_total` | 经网关中继的 agent 签名次数 | 与 `ok_total` 长期偏离=会话复用异常 |
| `sshgw_agent_channel_denied_total` | agent 会话中被拒的额外通道（如 direct-tcpip） | 突增=客户端在尝试跳板 |

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
| 端口转发不通 | jump 默认拒绝 | 需 `[jump] enabled` + 白名单 + 地址类护栏；**agent 会话永远拒绝跳板**（见 §5.7） |
| `-A` 会话立刻失败 | `agent_backend_auth_fail_total` + 网关日志中的 reason | 见 §5.7 排障表 |
| `-A` 会话成功但客户端挂住不退出 | 网关未关闭转发的 agent 通道 | 属缺陷；升级到含 C2 修复的版本 |

### 5.7 Agent 穿透（`backend_auth = "agent"`）

以终端用户的 ssh-agent 作为后端凭据。语义等同 `ssh -A`：**网关只做签名中继，不持有也不代管任何私钥**。

**启用（三道门，缺一不可）**
1. 配置 `[backend] backend_auth = "agent"`；
2. 配置 `[backend] allow_agent_backend_auth = true`（全局 kill-switch，默认 `false`）；
3. 控制面 resolve 返回 `policy.agent_forwarding: true`（按 grant 授权）。

`agent` 与 `cert` 一样支持逐 resolve 覆盖（`policy.backend_auth`），但任何 agent 授权都会先过 kill-switch；kill-switch 关闭时**整体拒绝**，绝不回落为 key/cert。

**约束**
- 与 `[pool] enabled = true` **互斥**（池化连接无法携带 per-session 的 agent 身份），启动即报错。
- 每会话只开**一个**后端通道；`direct-tcpip`（跳板）在 agent 会话中一律拒绝并计数 `sshgw_agent_channel_denied_total`。
- 只有**控制面已授权指纹**对应的 agent 身份会被提供给后端；agent 里即便有别的可用 key 也不会用（最小签名面）。
- 后端 `authorized_keys` 应只放用户公钥，不要放网关 key——这样一旦网关偷偷降级，会话必然失败而不是"悄悄成功"。

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
  - `#6`：offered 探测触发控制面 resolve（预热 miss，量级可接受）。
- russh 上游限制（同算法 host key 轮换需 known_hosts 下发降级、`client::Handle` 非 Sync 限制跨会话池化）——按 §5.1/§5.3 与 known-limitations 处理。
