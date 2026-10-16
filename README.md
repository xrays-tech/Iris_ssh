# ssh-gateway（Iris_ssh）

一个 SSH 网关，用 Rust 和 [russh](https://github.com/Eugeny/russh) 写的。

它做的事：你在外面用 SSH 连机器时，先连到网关，网关验证你的身份、决定你"应该"连到哪台后端机器，然后帮你把连接转发过去。客户端这边的用法不变——`ssh 用户名@网关地址`，差别只在"用户名"在这里是路由信息：网关拿这个用户名去问控制面（或按 OpenStack 解析），查出你实际要登录的后端地址和账号，再替你拨过去。

```
ssh alex_host1@gw.example.com
     │
     ▼
  网关（终结客户端 SSH，认证 + 授权，双会话中继）
     │
     ▼
  后端 sshd（目标机器）
```

数据是纯转发的，网关默认不落盘（会话录制由控制面按 grant 开启）。认证、审计、访问控制都发生在网关这一侧；后端机器唯一的配置是把**终端用户的公钥**放进 `authorized_keys`——网关不持有任何后端私钥，它是靠转发用户的 ssh-agent 去拨号的。

## 功能

- **用户名即路由（控制面 / OpenStack / 简单映射 三选一）**
  - 控制面：`POST /api/v1/resolve` 按用户名返回目标后端 `{host, port, user}` 和策略；拒绝 403，未知 404。
  - **OpenStack（默认关，见下）**：规范形式的实例 UUID（或实例名）由 Nova 解析成目标地址和登录用户。
  - **简单映射（默认关）**：本地 `mappings.toml` 表把登录用户名直接映射到目标后端 `{host, port, user}`，无需控制面或 OpenStack。
- **OpenStack 路由（实验室模式）**：开启 `[openstack]` 后（当前唯一可启用组合是 `routing="openstack_only"` + `authorization="openstack_only"` + `allow_any_authenticated_key=true`）——
  - `route_by = ["uuid"]`（默认）按实例 UUID 解析；加 `"name"` 可再按**实例名**（小写）解析，重名实例拒绝不猜；
  - `scope = "single_project"`（默认）只解析本项目的实例；`"cross_project"` 用 `all_tenants=1` 解析**任意项目**的实例（不指定 Project，凭条件见部署）；
  - `address_kind = "any"（默认）| "floating" | "fixed"`：`"floating"` 只取浮动 IP（公网可达前提），无浮动地址即拒绝、绝不回退 fixed；
  - 后端登录用户按 实例 metadata → `[[openstack.backend_user_map]]` 规则 → `default_backend_user` 解析。
- **简单映射模式（实验室模式，默认关）**：开启 `[mapping]` 后——
  - 路由唯一依据是本地 `mappings.toml`：`[[entries]]` 每行把一个 `username` 映射到 `host` / `port`（默认 22）/ `user`（默认同 `username`）；表内用户名命中即用该行，**表外一律拒绝**；
  - 与 `[control_plane]`、`[openstack]` **互斥**（三者只可同时启用其一），无控制面、无 OpenStack 回退；
  - 授权仍是 `allow_any_authenticated_key=true`：任何通过前腿验签的 key 都可到达其 principal 映射的后端，仅用于实验室/内网；
  - 表在启动时一次性加载并常驻内存，**改文件需重启才生效**；`recording` 默认 false（映射会话默认不录，需显式 `recording = true`）。
- **双会话中继**：终结客户端 SSH（server 腿）+ 拨号后端（client 腿），双向转发；上行有窗口熔断（`outbound_guard`）防止缓冲无限增长。
- **认证**：客户端 → 网关支持公钥 / CA 签发的用户证书；网关 → 后端只有一种方式——转发客户端的 ssh-agent（`ssh -A` 语义）。签名算法对齐当前 SSH 生态：**后端 RSA 拨号走 `rsa-sha2-512`（默认，可配 `[backend] rsa_signature_hash="sha256"`）**，ed25519 / ecdsa 原生支持；**前腿与后端 host-key 协商都不再包含 `ssh-rsa`（SHA-1）**。
- **防爆破 / 防时序**：每次认证拒绝有恒定时间填充（`auth_rejection_pad`），尝试次数上限（`max_auth_attempts`），每 IP 并发上限。
- **会话语义完整**：exec / shell / scp / sftp / stderr（extended data）/ exit status / rekey / 信号全部按 SSH 协议原样透传；不伪造成功、不注入协议行为。
- **审计与录制**：字节计数与操作事件写审计；按通道录制抓包（`.srec`），由控制面每个 grant 的 `policy.recording` 按会话开启，`[recording] max_bytes_per_session` 只是预算上限（默认 64 MiB，设 0 整体禁用）。
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

按 `config.example.toml` 复制成生产配置（例如 `/etc/ssh-gw/gateway.toml`），改里面指向你机器的路径。加载顺序：`--config`/`-c` 旗标或第一个命令行参数 → `$SSHGW_CONFIG` 环境变量 → `/etc/ssh-gateway/config.toml`。

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
2. **准备后端授权**：把**终端用户自己的公钥**加进各后端机器的 `authorized_keys`。网关没有自己的后端私钥，也不需要——它拿用户转发来的 ssh-agent 去拨号（`ssh -A` / `-o ForwardAgent=yes`）。
3. **配置路由来源（默认控制面，共三种模式）**：默认方式下网关把用户名发给控制面服务，由它响应 `POST /api/v1/resolve` 返回目标；不想搭控制面可用下方"可选：简单映射表即路由"或"可选：OpenStack 实例即路由"。控制面请求体示例：

   ```json
   {"principal": "alex_host1", "client_ip": "203.0.113.7", "key_fp": "SHA256:..."}
   ```

   响应示例：

   ```json
   {"target": {"host": "db.internal", "port": 22, "user": "alex"}, "policy": {"agent_forwarding": true, "recording": false, "ttl": 60}}
   ```
   拒绝返回 `{"status":403,...}`，未知 `{"status":404,...}`。`policy.agent_forwarding` 为 `true` 才会建立后端会话；缺省或 `false` 一律拒绝（网关没有可回落的凭据）。不想搭真实服务的话，仓库里有 [scripts/mock_control_plane.py](scripts/mock_control_plane.py)（按一条 JSON 规则表应答，用于本地联调）。
4. **后端 host key 信任**：生产用 `host_key_policy="pinned"`（首次固化指纹）；初次联调可先 `accept-new` 再尽快 pin。

### 可选：OpenStack 实例即路由

不启用 `[openstack]` 时网关行为与上述控制面模式完全一致。启用后，规范形式的实例 UUID（以及可选的名字）由 Nova 解析成目标实例。

**当前唯一可启用组合就是实验室/内网 PoC 模式**：`routing="openstack_only"` + `authorization="openstack_only"` + `allow_any_authenticated_key=true`——没有控制面回退，任意通过前腿验签的密钥 + 已知 UUID 即可达该实例（名字路由同样）。`routing="hybrid"` 与"控制面授权"（方案 A）解析通过但启用即被配置校验拒绝（尚未实现）。

最小配置（截取自 `config.example.toml`，字段全注释）：

```toml
[openstack]
enabled = true
routing = "openstack_only"
authorization = "openstack_only"
allow_any_authenticated_key = true

route_by = ["uuid"]           # 加 "name" 启用实例名路由；UUID 形态永远优先
scope = "single_project"       # 默认；"cross_project" = 不指定 Project（见下）
address_kind = "any"           # any | floating（只取浮动 IP）| fixed

# Keystone v3 认证：application_credential（推荐）| password（仅 cross_project）| token（仅测试）
auth_url = "https://keystone.example.internal:5000/v3"
application_credential_id = "..."
application_credential_secret = "..."   # 或 _file / $SSHGW_OPENSTACK_APPLICATION_CREDENTIAL_SECRET
project_id = "..."              # single_project：可见性边界；cross_project：认证 scope
region = "RegionOne"
interface = "public"
# nova_endpoint = "https://nova:8774/v2.1"   # 跳过 catalog 发现（测试/内网云）

# 地址与登录用户
# network = "私有网络名"         # 多网络时必填
# prefer = "floating"            # floating | fixed | any
# on_ambiguous = "reject"        # reject（默认）| first
default_backend_user = "ubuntu"  # 或靠实例 metadata / backend_user_map
```

**两个需先想清楚的开关**：

- **`scope = "cross_project"`（不指定 Project，实验）**：让网关以 `all_tenants=1` 解析任意项目的实例（UUID 全局唯一可直接命中；名字要求全云唯一）。**必须 `auth_method="password"`**（app-credential 被 Keystone 锁死在单项目），且该 `project_id` 是**认证 scope**（决定 token 带哪些角色）。⚠ 网关将持有能看/能拨其角色覆盖的一切实例的凭据——**仅限内网/实验云且 Nova 策略宽松（允许项目级 admin 用 `all_tenants`），严禁公网/共享**。启动会有 `scope = "cross_project": this is a LAB mode` WARN。
- **`address_kind = "floating"`（只取浮动 IP）**：当实例只在公网侧可达（fixed/VXLAN 需要手工打通网络）时用。**前置条件：实例已关联浮动 IP**（Neutron 操作）；否则一律 `no_floating` 拒绝。无浮动地址一律拒绝、绝不回退到 fixed。

完整说明、安全边界与已知限制见 `docs/ops-runbook.md` §5.8 / §5.9 与 `docs/known-limitations.md` §9 / §11。

### 可选：简单映射表即路由

不想搭控制面、也没有 OpenStack 时，可以把登录用户名直接映射到目标后端。启用后它成为**唯一路由权威**：表内用户名命中即用该行拨号，表外一律拒绝（无回退、无控制面）。

**与 `[control_plane]`、`[openstack]` 互斥**（三者只可同时启用其一）。开启需显式确认 `allow_any_authenticated_key=true`——任何通过前腿验签的 key 都可到达其 principal 映射的后端，仅用于实验室/内网。

```toml
[mapping]
enabled = true
mapping_file = "/etc/ssh-gw/mappings.toml"
allow_any_authenticated_key = true   # 实验室授权语义，启用时必填
# recording = false                  # 默认不录；映射会话需显式 recording = true 才录
```

映射文件（`mappings.toml`）每行一个 `[[entries]]`：

```toml
[[entries]]
username = "alex"        # 登录用户名（须满足 principal 语法、表内唯一）
host = "10.0.0.7"        # 目标后端 host（IP 或可解析名）
port = 22                # 可选，默认 22
user = "alex"            # 可选，默认同 username（后端登录用户）
```

表在启动时一次性加载并常驻内存，**改文件需重启才生效**；文件不可读/损坏/超 4 MiB / 非符号链接/group-other 可写也拒绝启动（fail-closed）。

## 使用

客户端不用装任何东西，普通 OpenSSH 即可。**必须转发 ssh-agent**（`-A` 或 `-o ForwardAgent=yes`）——网关没有自己的后端私钥，会拿你 agent 里的 key 去拨号。用户名按控制面规则 / OpenStack 实例路由 / 简单映射表填。

```bash
# 控制面：用户名即路由
ssh -A -p 2222 alex_host1@gw.example.com
ssh -A -p 2222 alex_host1@gw.example.com 'uptime'
scp -o ForwardAgent=yes -P 2222 build.tar alex_host1@gw.example.com:/tmp/
sftp -o ForwardAgent=yes -P 2222 alex_host1@gw.example.com

# OpenStack：实例 UUID 即用户名
ssh -A -p 2222 550e8400-e29b-41d4-a716-446655440000@gw.example.com
# OpenStack：实例名（小写）即用户名（需 route_by=["uuid","name"]）
ssh -A -p 2222 web-1@gw.example.com

# 简单映射：映射表里的用户名即路由（需 [mapping] enabled）
ssh -A -p 2222 mapped_alex@gw.example.com
```

被连载的会话行为和直连后端基本一致；端口转发（`direct-tcpip`）一律拒绝——网关不是出站跳板，也没有任何配置能放开它。

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
make integration   # 黑盒集成套件（本地 sshd + mock 控制面/OpenStack，全自动）
make bench         # 吞吐基准（benchmark v2：A 每连接成本 / B 复用连接数据面 / C 记录）
```

集成套件自包含：起一个本地 sshd 当后端 + mock 控制面/OpenStack，不需要外网。全部落盘细节、已知限制分别见 [docs/ops-runbook.md](docs/ops-runbook.md) 和 [docs/known-limitations.md](docs/known-limitations.md)。

## 许可

Apache-2.0。
