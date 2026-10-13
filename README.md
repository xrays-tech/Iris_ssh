# ssh-gateway（Iris_ssh）

一个 SSH 网关，用 Rust 和 [russh](https://github.com/Eugeny/russh) 写的。

它做的事：你在外面用 SSH 连机器时，先连到网关，网关验证你的身份、决定你"应该"连到哪台后端机器，然后帮你把连接转发过去。客户端这边的用法不变——`ssh 用户名@网关地址`，差别只在"用户名"在这里是路由信息：网关拿这个用户名去问控制面，查到你实际要登录的后端地址和账号，再替你拨过去。

```
ssh alex_host1@gw.example.com
     │
     ▼
  网关（终结客户端 SSH，认证 + 授权，双会话中继）
     │
     ▼
  后端 sshd（目标机器）
```

数据是纯转发的，网关不落盘（除非你显式开启会话录制）。认证、审计、访问控制都发生在网关这一侧，后端机器不需要为网关做任何特殊配置（用普通 SSH 账号即可）。

## 功能

- **用户名即路由**：控制面接口 `POST /api/v1/resolve` 根据用户名返回目标后端 `{host, port, user}` 和策略；拒绝返回 403，未知返回 404。
- **双会话中继**：终结客户端 SSH（server 腿）+ 拨号后端（client 腿），双向转发。上行有窗口熔断（`outbound_guard`）防止缓冲无限增长。
- **认证**：公钥 / CA 签发的用户证书；后端拨号支持固定私钥或现签短期证书（`backend_auth="cert"`）。
- **防爆破 / 防时序**：每次认证拒绝有恒定时间填充（`auth_rejection_pad`），尝试次数上限（`max_auth_attempts`），每 IP 并发上限。
- **会话语义完整**：exec / shell / scp / sftp / stderr（extended data）/ exit status / rekey / 信号全部按 SSH 协议原样透传；不伪造成功、不注入协议行为（I4）。
- **审计与录制**：按通道录制抓包（`.srec`，默认关闭）；字节计数与操作事件写审计。
- **SFTP 命令级拦截**（默认关）：可拒绝特定命令（如 `REMOVE`/`RENAME`）并按路径前缀控制。
- **可观测**：`/healthz`、`/readyz`、`/metrics`（Prometheus 文本格式）。
- **优雅停机**：SIGTERM 排水后向客户端发协议级 `DISCONNECT[BY_APPLICATION]`。

## 部署

### 构建

需要 Rust 工具链。

```bash
cargo build --release
# 产物：target/release/ssh-gw（受 CARGO_TARGET_DIR 影响）
install -m 0755 target/release/ssh-gw /usr/local/bin/ssh-gw
```

### 配置文件

按 `config.example.toml` 复制成生产配置（例如 `/etc/ssh-gw/gateway.toml`），改里面指向你机器的路径。加载顺序：`$SSHGW_CONFIG` 环境变量 → 第一个命令行参数 → `/etc/ssh-gateway/config.toml`。

```bash
/usr/local/bin/ssh-gw --config /etc/ssh-gw/gateway.toml
```

systemd 参考单元在 `deploy/ssh-gw.service`（已配好优雅排水和基本加固）。

### 首次部署步骤

1. **生成 host key**（网关对外提供身份）：
   ```bash
   mkdir -p /etc/ssh-gw && chmod 700 /etc/ssh-gw
   ssh-keygen -t ed25519 -N "" -f /etc/ssh-gw/host_ed25519
   chmod 600 /etc/ssh-gw/host_ed25519
   ```
   权限不对会拒绝启动（fail-closed）。
2. **准备后端拨号身份**（二选一）：
   - **key 模式（默认）**：另生成一对密钥，私钥写进 `[backend] private_key`（或用 `credential_map` 按用户名指定），公钥加进各后端机器的 `authorized_keys`。
   - **cert 模式**：后端 sshd 配 `TrustedUserCAKeys` 指向你的 CA 公钥，网关配 `[ca] signing_key` + `backend_auth="cert"`，拨号时现签短期用户证书。
3. **配置控制面**：网关自己不存"用户名→目标"映射，必须有一个控制面服务响应 `POST /api/v1/resolve`。请求体示例：

   ```json
   {"principal": "alex_host1", "client_ip": "203.0.113.7", "key_fp": "SHA256:..."}
   ```

   响应示例：

   ```json
   {"target": {"host": "db.internal", "port": 22, "user": "alex"}, "policy": {"ttl": 60}}
   ```
   拒绝返回 `{"status":403,...}`，未知 `{"status":404,...}`。不想搭真实服务的话，仓库里有 [scripts/mock_control_plane.py](scripts/mock_control_plane.py)（按一条 JSON 规则表应答，用于本地联调）。
4. **后端 host key 信任**：生产用 `host_key_policy="pinned"`（首次固化指纹）；初次联调可先 `accept-new` 再尽快 pin。

## 使用

客户端不用装任何东西，普通 OpenSSH 即可。用户名按控制面的规则填。

```bash
# 登录（用户名即路由）
ssh -p 2222 alex_host1@gw.example.com

# 执行单条命令
ssh -p 2222 alex_host1@gw.example.com 'uptime'

# 复制文件（scp 走 sftp/exec 语义，按 SSH 协议转发）
scp -P 2222 build.tar alex_host1@gw.example.com:/tmp/

# 交互式 sftp
sftp -P 2222 alex_host1@gw.example.com
```

被连载的会话行为和直连后端基本一致；端口转发（`direct-tcpip`）一律拒绝——网关不是出站跳板。

观察运行状态：

```bash
curl http://127.0.0.1:9090/healthz   # 存活
curl http://127.0.0.1:9090/readyz    # 就绪（后端/控制面健康）
curl http://127.0.0.1:9090/metrics    # 指标
```

## 性能指标

以下均为**本机 loopback、64 MiB、字节校验过**的实测（Fedora 44，OpenSSH 10.2 / russh 0.64.1，chacha20-poly1305 默认加密）。别的机器、网络、算法下数字会不同，只作参考。

| 场景 | 数值 |
|---|---|
| 数据面单向持续吞吐（单连接，trace transfer phase） | 上行 **356–486 MB/s**，下行 **356–438 MB/s** |
| 复用连接（OpenSSH ControlMaster）端到端 | **386–602 MB/s** |
| 新建连接（默认配置） | 握手→认证结束约 **1.17 s** |

两个需要知道的点：

1. **数据面没有额外瓶颈**。网关本身的转发、拷贝、调度在实测里都不是限制（这个结论是经过多轮 A/B 验证的：零拷贝、调度解耦、窗口、加密算法、nodelay 单独调都动不了这个数）。要达到上面的吞吐，用连接复用（ControlMaster / 长连接多通道）。
2. **每个新连接有一笔约 1 s 的固定认证开销**，这是**故意**的（防爆破/防时序：每次认证拒绝都有恒定时间填充）。它的意思是：短小传输（几十 MB 级别，每次新建连接）的端到端速度会被这 1 s 摊得很低——`make bench` 里经网关 scp 的 ~45 MB/s 就是这个原因，不是数据面上限。对延迟敏感、以公钥/证书认证为主的部署，可以把 `[limits] auth_timeout` 设为 `"0s"`（保留 `auth_rejection_pad="1s"`，被拒的用户仍每次付约 1 s，防爆破不丢），新连接降到约 **0.17 s**。

完整测量与推理见 [docs/perf-investigation.md](docs/perf-investigation.md)。

## 开发 / 测试

```bash
make lint          # fmt + clippy
make test          # 单元测试
make integration   # 黑盒集成套件（本地 sshd + mock 控制面，全自动）
make bench         # 网关 vs 直连 性能对比
```

集成套件自包含：起一个本地 sshd 当后端 + 一个 mock 控制面，不需要外网。全部落盘细节、已知限制分别见 [docs/ops-runbook.md](docs/ops-runbook.md) 和 [docs/known-limitations.md](docs/known-limitations.md)。

## 许可

Apache-2.0。
