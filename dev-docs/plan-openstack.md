# Plan — OpenStack 实例 UUID 即路由（instance_uuid as SSH username）

> **决策（2026-10-14）：采用方案 B** —— `routing="openstack_only"` +
> `authorization="openstack_only"` + `allow_any_authenticated_key=true`
> （显式实验室模式，默认关闭；无需控制面，`[control_plane]` 可整体省略）。
> 后果：该网关注定只服务 UUID 用户名，非 UUID 用户名一律拒绝（无 CP 回退）；
> 任何通过前腿验签的密钥 + 已知 project 内 UUID → 可达该实例（受 application
> credential 的 project scope 限制）。方案 A（控制面授权）不再实施，仅保留对比说明。

Status: 设计提案（analysis/design only，不写代码）。基线 HEAD `62c3945`
（agent-only：后端只用客户端 `ssh -A` 转发的 agent 签名认证；用户名即路由，
经控制面 `POST /api/v1/resolve` 解析目标）。待 @oracle 复审 O2/O3 的 diff。

---

## 0. 摘要与关键结论

**目标语义**：`ssh -A <instance_uuid>@<网关>` → 网关把用户名识别为 OpenStack
实例 UUID → 用网关服务凭据查 OpenStack 得到实例 IP → 直接连到该实例
（后端登录用户由配置映射）。

**关键结论（先看这几条）**：

1. **UUID 用户名今天就能通过前腿校验**。`Principal` 正则
   `^[a-z0-9][a-z0-9_-]{0,62}$`（`src/types.rs:15-16,28-62`）接受
   `550e8400-e29b-41d4-a716-446655440000`（36 字符、首字符为数字、含 `-`）。
   因此 **前腿 parser 无需改动**，判别点在"这个 principal 是否按 OpenStack 路由"
   （新增纯函数 `is_instance_uuid`）。
2. **解析器是唯一可插拔缝**。`Resolver` 只依赖 `ControlPlaneClient` trait
   （`src/resolve/mod.rs:170-181`），缓存/单飞/熔断/fail-open/负缓存全部位于
   `Resolver` 内（`src/resolve/mod.rs:242-304,373-472`）。让
   `OpenStackClient` **实现 `ControlPlaneClient`**（返回合成的 `ResolveResponse`）
   即可零成本复用整套机制，`fetch` 逐字不变。
3. **失败域隔离**：不应把 OpenStack 和现有控制面塞进**同一个** `Resolver`
   （共享熔断/缓存）。方案为**两个独立 `Resolver`**（CP 一个、OpenStack 一个），
   由一个 `ResolveRouter` 按 principal 形态派发。选路谓词是纯函数、可单测。
4. **安全第一结论（最高风险）**：若"任何通过前腿验签的用户 → 查 OpenStack →
   连任意实例"，则**任何持有任意 SSH 私钥的人都能 SSH 到任意 UUID 实例**——
   现有"控制面 = 授权唯一权威"的边界（plan-agent-passthrough.md:66 红线 1）
   被击穿。**默认必须保留控制面授权**（CP 先授权 `(principal, key_fp)`，网关
   再查 OpenStack 换 IP）；"纯 OpenStack、无 CP"必须是**显式、命名刺眼、默认关闭**
   的实验室模式。见 §3.5。
5. **`auth_publickey_offered` 会预热缓存**（`src/server/mod.rs:1151`），它是
   **未验签的 probe**。若此处直接查 Nova，则未认证者可触发 Nova 查询/枚举
   （UUID→IP 预言机）。必须让 offered 回调在 OpenStack 路由上**只做形态检查、不联网**，
   真正的 Nova 查询放到验签后的 `auth_publickey`/`auth_openssh_certificate`。见 §3.5。
6. **`policy.agent_forwarding` 必须为 `true`**：agent-only 下网关无自有凭据，
   `false` 等于"这个 grant 拨不通后端"（`src/policy/mod.rs:194-210`，
   `src/server/mod.rs:1594-1640`）。OpenStack 分支合成策略时硬编码
   `agent_forwarding = true`，否则整个功能无意义。
7. **`[control_plane]` 当前是必填**（`RawControlPlane` 无 `#[serde(default)]`，
   `src/config.rs:214-215,367-378`，url 非空校验 `src/config.rs:703-708`）。
   支持"纯 OpenStack 模式"必须把 `control_plane` 改为可选并按模式校验。见 §3.6。

---

## 1. 现状精读（作为全部结论的引用基础）

### 1.1 前腿认证与 resolve 调用链

- `Principal::parse`：`src/types.rs:28-62`。任何通过此校验的用户名进入后续流程。
- `GatewaySession::resolve_grant`：`src/server/mod.rs:763-781`——唯一调用
  `Resolver::authorize(principal, fingerprint, client_ip)` 的地方，并记
  `resolve_ok/err/latency` 指标。
- 三处调用点：
  - `auth_publickey_offered`（预检，未验签）：`src/server/mod.rs:1134-1154`，
    第 1151 行 `let _ = self.resolve_grant(...)` **预热缓存**，恒 `Accept`（形态通过即可）。
  - `auth_publickey`（验签后，权威）：`src/server/mod.rs:1160-1202`，
    1177 行 resolve 成功才 `Auth::Accept`，否则 `reject_all()`。
  - `auth_openssh_certificate` → `authorize_certificate`：
    `src/server/mod.rs:1213-1223,792-853`，以 CA 指纹为 resolve key，
    `grant.agent_fingerprint` 覆盖为证书 subject key。
- 未授权/未知/限速一律 `Auth::reject()`（协议原生），无差异化报错（`src/error.rs:37-63`）。

### 1.2 Resolver 机制（可复用点）

- `ControlPlaneClient` trait：`src/resolve/mod.rs:170-181`，输入 `&ResolveRequest`，
  输出 `Result<ResolveResponse, ControlError>`。
- `ControlError` 分类：`src/resolve/mod.rs:150-164`（NotFound/Forbidden/RateLimited/
  ServerError/Decode/Transport）。
- `HttpControlPlane`：`src/resolve/mod.rs:184-234`，reqwest + rustls，2xx→decode，
  403/404/429 分类，其余 ServerError。
- `Resolver::authorize`：`src/resolve/mod.rs:373-400`（缓存命中→熔断 fast-fail→
  `get_with` 单飞）；`fetch`：`src/resolve/mod.rs:404-443`（映射为 CacheEntry，
  记熔断与 last_good）；`interpret_cached`：445-460（fail-open 供旧 grant）。
- TTL 策略：`src/resolve/mod.rs:272-304`（正 30s(+jitter)/负 5s/瞬态 1s，实际由构造参数决定）。
- `GatewayContext::build_with_client` 构造 `Resolver`：`src/server/mod.rs:464-474`
  （负缓存 5s、瞬态 1s、熔断阈值 5、reset=`timeout*3`）。
- `GatewayContext` 结构：`src/server/mod.rs:200-210`（`resolver: Arc<Resolver>`）。

### 1.3 后端拨号如何使用 Grant

- `BackendDialer::connect`：`src/backend/mod.rs:433-454`；
  `authenticate_publickey_with(&grant.target.user, ...)`（447 行）——**后端登录用户
  完全来自 `grant.target.user`**。
- 主机名：`grant.target.host` 既用于 `(host, port)` dial（`src/backend/mod.rs:360`），
  也作为 host 证书的 `expected_host`（`src/backend/mod.rs:365-368`）。
- 拨号熔断按 `host:port`：`src/backend/mod.rs:339-354`。
- session 拨号由 `relay::agent` supervisor 完成，日志含
  `backend_user/backend_host/backend_port`（`src/relay/agent.rs:853-856`）。

### 1.4 策略与审计

- `agent_request` 决策：`src/server/mod.rs:1594-1640`，唯一规则
  `agent_passthrough_allowed`（`src/policy/mod.rs:202-210`）——只看
  `grant.policy.agent_forwarding`。默认拒绝即协议原生 CHANNEL_FAILURE。
- `AuditRecord` 字段：`src/audit/mod.rs:293-323`（session_id/principal/fingerprint/
  client_ip/target_host/target_port/target_user/auth_kind/agent_identity/...）；
  `set_auth_kind` `src/audit/mod.rs:206-209`。**目前无"解析来源"字段**。
- 审计仅在会话进入 relayed 态后落盘（`src/server/mod.rs:1703-1719` 的 Drop）。

### 1.5 配置

- `GatewayConfig` / `RawConfig`：`src/config.rs:20-38,206-228`。
- `ControlPlaneConfig`：`src/config.rs:107-117`；`RawControlPlane`：367-378；
  校验：703-718。
- `BackendConfig` 只剩 `host_key_policy`：`src/config.rs:80-90`。
- 时长/字节解析助手：`parse_duration`/`parse_bytes`：`src/config.rs:495-554`。
- `config.example.toml` 的 `[control_plane]`：`config.example.toml:65-70`；
  `[backend]` agent-only 说明 29-47。

### 1.6 测试与 harness

- 单测内 fake client：`src/resolve/mod.rs:502-579`；server 内 `FixControlPlane`：
  `src/server/mod.rs:1754-1762`。
- Mock 控制面契约：`scripts/mock_control_plane.py:4-25,118-138`（按规则 JSON 应答）。
- 子拓扑：`tests/integration/subtopo.sh:100-173`（拉 backend sshd + mock CP + gw，
  渲染 `gw.toml` 于 141-156，起 mock CP 于 162-165）。
- agent 拓扑：`tests/integration/agent_topo.sh`；用例 `case_agent_auth.sh`。
- 用例注册：`scripts/run_integration.sh:488-519`。
- 依赖：`reqwest`(rustls)/`uuid`（v7 features，可解析任意版本）已在
  `Cargo.toml:33,36`。

---

## 2. 需求分析

### 2.1 功能需求

**F1. 用户名 = UUID 的识别**
- 判别谓词 `is_instance_uuid(&str) -> bool`：用 `uuid::Uuid::parse_str` 解析为规范
  8-4-4-4-12 十六进制形态；**不强制 version==4**（OpenStack 主流为 UUID4，但历史
  实例存在 UUID1/随机；强制 v4 会让老实例无法路由）。
- 规范化：由于 `Principal` 拒绝大写（`src/types.rs:44-60`），用户名中的 UUID 必须是
  小写。大写 UUID 会在前腿被 `InvalidPrincipal` 拒绝——这属于"客户端配置问题"，
  文档需明确"用 `uuidgen | tr A-Z a-z` 或 OpenStack 返回的原样小写"。
- 判别是**纯函数**，与配置无关；它只回答"这个 token 长得像 UUID 吗"。

**F2. 混合模式 vs 纯 OpenStack 模式**（配置 `[openstack] routing`）
- `routing = "hybrid"`（默认）：UUID 形态 → OpenStack 源；其余 → 现有控制面源。
  向后兼容：`enabled=false` 时行为完全不变。
- `routing = "openstack_only"`：所有用户名必须为 UUID；非 UUID 一律协议原生拒绝，
  不再回退控制面。此模式要求 `[control_plane]` 可缺省（见 §3.6）。
- 语义告警：`hybrid` 下"UUID 形态的名字一律走 OpenStack"，因此**当 OpenStack 启用时，
  运营者不得再在 CP 里使用 UUID 形态的 principal**（否则被本分支截获）。写入文档与
  config 注释。

**F3. 后端登录用户映射**
- `ssh -A <uuid>@gw` 的 UUID 是**路由键**，不是后端登录名。
- 实例上的实际登录用户（`cloud-user`/`ubuntu`/`centos`/`fedora`/自定义）来自配置，
  优先级见 §3.4。**没有普适默认值**（`cloud-user` 只对 RHEL 系 cloud image 成立），
  因此 `default_backend_user` 在 `enabled=true` 时**必填**（校验期拒绝空值），或显式
  提供 metadata 键/映射规则覆盖。

**F4. 目标端口**
- 默认 22；提供 `[openstack] ssh_port`（默认 22）。

### 2.2 非功能需求

**N1. IP 解析延迟与缓存**
- Nova 查询必须受**独立** TTL 与超时约束，且不污染 CP 的熔断/缓存（§0-3、§3.1）。
- `cache_ttl` 建议较短（默认 30–60s）：实例重建/迁移后 IP 可能变化，且 UUID 复用为 0
  （实例删了 UUID 不复用），但 IP 会被别的实例复用——**stale IP 可能连到"另一个"实例**，
  因此 fail_open 默认关闭（见 N3）。

**N2. 控制面/OpenStack 不可用时的行为**
- 沿用 `Resolver` 的 fail-closed 默认（`ResolveError::Unavailable` → 协议原生拒绝）。
- fail-open 对 OpenStack **语义不同**：它会把旧 IP 当目标继续拨号。**默认 false**；
  若开启，安全性依赖后端 host-key pinning（`[backend] host_key_policy=pinned`）在 KEX
  阶段拒掉错误实例（`src/backend/mod.rs:177-225`）。文档强制联结这两项。

**N3. 多 IP 选择**（固定 vs 浮动、多网络、地址族）
- Nova `addresses` 结构：`{ "<net-name>": [ {addr, version, "OS-EXT-IPS:type": fixed|floating} ] }`。
- 选择规则见 §3.3；歧义时**默认拒绝**（fail loud），避免静默跨网络安全域。

---

## 3. 技术方案

### 3.1 总体架构与集成点

```
GatewaySession::resolve_grant
        │
        ▼
   ResolveRouter                ← 新：按 principal 形态派发（纯谓词）
   ├── routing=hybrid: is_instance_uuid(p) ? openstack : control_plane
   └── routing=openstack_only: is_instance_uuid(p) ? openstack : reject(UUID 形态错误)
        │
        ├── cp_resolver:      Arc<Resolver>  (现有，src/server/mod.rs:464-474)
        └── os_resolver:      Arc<Resolver>  (新，独立 cache/breaker/fail_open)
                    client: Arc<dyn ControlPlaneClient> = OpenStackClient
```

- **`OpenStackClient` 实现 `ControlPlaneClient`**（`src/resolve/mod.rs:170-181`）：
  输入 `ResolveRequest{principal(=uuid), client_ip, key_fp}`，输出
  `ResolveResponse{target, policy}`：
  - `target.host` = 选定 IP（字符串，可为 IPv6 字面量），`target.port = ssh_port`，
    `target.user` = 映射出的后端用户；
  - `policy.agent_forwarding = true`（硬编码，见 §0-6），
    `policy.recording = [openstack] recording`，`policy.ttl` = `cache_ttl`（透传，供审计；
    实际缓存 TTL 由 `os_resolver` 构造参数决定）。
  - `key_fp`/`client_ip` **不参与** OpenStack 查询（无此概念），仅用于日志/审计。
- **失败映射**（复用 `ControlError`，`src/resolve/mod.rs:150-164`）：
  - Nova 404 / 实例已删 → `NotFound`（→ `ResolveError::NotFound` → `Auth::reject`）。
  - Keystone 401/403 / Nova 403 → `Forbidden`。
  - 无可用地址 / 多地址歧义 → 归一为 `NotFound`（对客户端同构，防枚举差异）。
  - DNS/TCP/TLS/超时 → `Transport`；5xx → `ServerError`；JSON 解析失败 → `Decode`。
- **前腿改动**：
  - `resolve_grant` 改为调用 `router.authorize(...)`。
  - `auth_publickey_offered`（`src/server/mod.rs:1151`）：**OpenStack 路由上不联网**，
    只做 `is_instance_uuid` 形态检查后返回 `Accept`，把 Nova 查询留给验签后的回调。
    CP 路由保持现有"预热缓存"行为（字节级不变）。
  - `GatewayContext`：把 `resolver: Arc<Resolver>` 换成
    `router: Arc<ResolveRouter>`（或保留 `resolver` 加 `openstack: Option<...>` +
    `routing` 字段，改动更小）。
- **不引入新的数据面路径**：Grant/Policy/Target 类型不变，`BackendDialer`
  (`src/backend/mod.rs:433-454`)、`relay::agent`、`agent_request`、审计全部沿用。

### 3.2 OpenStack 接入

**认证（Keystone v3）**——推荐 **application credential**：
- `POST {auth_url}/v3/auth/tokens`，body：
  ```json
  {"auth":{"identity":{"methods":["application_credential"],
    "application_credential":{"id":"<id>","secret":"<secret>"}},
    "scope":{"project":{"id":"<project_id>"}}}}
  ```
  响应 201，头 `X-Subject-Token` 为 token，body `token.expires_at` + `token.catalog`。
- 为什么不用 password：需要长期保存某用户的密码，且隐式获得该用户的全部权限。
  application credential 可撤销、可限定 role/scope，是服务账号的正确形态。
- 为什么不用静态 token：Keystone token 默认 ~1h 过期，长跑网关无法依赖静态 token；
  刷新 token 仍需用户凭据（或 app cred），所以 app cred 是正解。
- **token 缓存 + 过期刷新**：缓存 `X-Subject-Token` 至 `expires_at - skew`（如 60s）；
  Nova 返回 401 时失效并重取一次。token 获取本身也要熔断/超时（在 `os_resolver`
  的 `Transport/ServerError` 路径上体现）。

**服务目录与版本协商**：
- 优先从 token catalog 选 `service.type == "compute"`、匹配
  `region`(config) 与 `interface`(public|internal|admin, 默认 public) 的 endpoint。
- 允许 `nova_endpoint` 直接覆盖（跳过 catalog，便于内网/测试）。
- Nova microversion：请求头 `X-OpenStack-Nova-API-Version: <microversion>`
  （默认 `2.1`，`GET /v2.1/servers/{id}` 基线可用）。
- region 必填（多 region 部署），默认取 catalog 第一个但记 warn。

**查询实例**：`GET {nova}/v2.1/servers/{uuid}?`（带 `X-Auth-Token`）。
响应 `server.addresses`、`server.metadata`、`server.name`、`server.image.id`、
`server.flavor`、`server.accessIPv4/6`。
- v1 用 Nova `addresses` 足够；**按需 Neutron 精确取 IP**（`GET /v2.0/ports?device_id={uuid}`
  → `fixed_ips`）作为可选增强（当 Nova 地址不足以消歧时）。

**超时/重试/TLS**：
- reqwest client 每个请求 `timeout = [openstack] timeout`（默认 3s）；
  connect 错误**至多重试 1 次**（不做无界重试，避免放大攻击；反复失败由熔断兜底）。
- TLS：reqwest rustls（`Cargo.toml:33`）。提供 `ca_bundle`（私有 CA）；
  `insecure_skip_verify=true` 只作逃生口，默认 false 且启动告警。
- **最小权限**：application credential **scope 到最窄的 project**，把网关可见的实例
  限制在该 project 内——这是"爆炸半径"的第一道闸，但**不是**用户级授权（见 §3.5）。

### 3.3 IPv6 / IP 类型与选择

给定 `addresses` 与配置 `network`、`address_family`(ipv4|ipv6|any)、
`prefer`(floating|fixed|any)：

1. 展开所有 `{netname, addr, version, type}` 候选。
2. 若 `network` 非空 → 仅保留 `netname == network`。
3. 若 `address_family != any` → 仅保留 `version == 4|6`。
4. 按 `prefer` 排序（floating 优先或 fixed 优先；`any` 时优先 floating，因跨网络可达性）。
5. 结果：
   - 恰 1 个 → 采用；
   - 0 个 → `NotFound`（协议原生拒绝，审计 `reason=no_address`）；
   - >1 个 → **配置歧义**：默认拒绝（fail loud）。若运营者显式设置
     `network` + `prefer` 仍多值，则按稳定序（netname→addr）取第一个并
     `warn!`（可配 `on_ambiguous = "reject" | "first"`，默认 `reject`）。
- **IPv6 字面量**：`Target.host` 是 `String`，拨号用 `(host.as_str(), port)`
  （`src/backend/mod.rs:360`）。tokio `ToSocketAddrs` 的 `(&str,u16)` 形态可解析
  `"2001:db8::1"`，无需加方括号。**列为集成测试项**（含 v6 后端）。
- **accessIPv4/6**：仅当 `addresses` 无候选时作为兜底（常为空）。
- **host 证书注意**：`expected_host` 将是 IP 字面量（`src/backend/mod.rs:365-368`）。
  用 `@cert-authority` 的 host 证书需把该 IP 列入 principals，否则被拒
  （`src/policy/mod.rs:102-129`）。生产更推荐 `pinned` 指纹而非按 IP 的 host 证书。

### 3.4 后端登录用户映射

优先级（高→低，第一个命中即用）：
1. **实例 metadata**：`[openstack] backend_user_metadata_key = "iris_ssh_user"`
   （可空）。读取 Nova `server.metadata[key]`。运营者建实例时打标即可，零配置重复。
2. **映射规则**：`[[openstack.backend_user_map]]`，按声明序匹配，命中即停：
   ```toml
   [[openstack.backend_user_map]]
   match_name = "^web-"            # 实例名正则（可选）
   match_metadata = { role = "web" } # 元数据子集匹配（可选）
   match_image = "<glance-image-id>" # 镜像 id（可选；Nova server.image.id）
   user = "ubuntu"
   ```
   多条件为 AND；全空的规则非法（校验期拒绝）。用 `regex` crate（新增依赖）或
   简化 glob——建议 v1 先支持精确/前缀匹配，regex 作为可选。
3. **`default_backend_user`**（required 兜底）。

- 结果校验：非空、无空白/控制字符；否则 `Decode`/配置错误（fail loud）。
- 说明：Nova `GET /servers/{id}` 默认只给 `image.id`（非镜像名）；按镜像名匹配需
  额外查 Glance（v1 不做，仅按 image id 或 suggestion：实例 metadata）。

### 3.5 授权边界（安全关键）

**问题**：前腿认证（russh 验签，`src/server/mod.rs:1160-1202`）只证明"持有某私钥"；
真正的"能否访问目标"决策当前**唯一**由控制面给出（plan-agent-passthrough.md:66 红线 1）。
若 OpenStack 分支绕过 CP，则任意有效密钥持有者只要猜到 UUID 就能连任意实例——
**横向移动漏洞**。UUID 可被枚举（公网对象存储、日志、API），且 Nova 的
404/200 差异构成存在性预言机。

**方案 A（默认，推荐）：控制面仍做授权**
- 网关先 `cp_resolver.authorize(principal=uuid, key_fp, client_ip)`。
  CP 返回两种形态之一：
  (a) 完整 `target`（现状，直接拨号）；或
  (b) 一个"路由标记"（`policy.route = "openstack"`，或新增
      `target.openstack_instance = "<uuid>"` 字段；`ResolveResponse` 已容忍未知字段，
      `src/types.rs:160-165`）→ 网关再用 OpenStack 换 IP。
- 好处：**授权权威不变**，CP 仍可表达"用户 A 只能到实例 X"；OpenStack 仅承担
  "UUID→IP + 后端用户映射"这一纯解析职责；红线 1 保持。
- 代价：CP 需理解 `route=openstack`，并保持在线；不满足"完全去 CP"的目标语义。

**方案 B（显式实验室模式，默认关闭）：纯 OpenStack 路由**
- `[openstack] authorization = "openstack_only"` 且必须有
  `allow_any_authenticated_key = true`（命名刺眼、默认 false、启动 `warn!`、写入
  known-limitations）。
- 语义：任意通过前腿验签的密钥 + 已知 UUID → 可达该实例（受 application credential
  的 project scope 限制）。
- 缓解纵深：service cred 限定最小 project；负缓存 + `max_auth_attempts`
  （`src/config.rs:421-423`）限速枚举；所有失败对客户端同构拒绝；审计记录每次
  OpenStack 解析（UUID、结果、IP）。
- **绝不**允许用户名里携带 host/IP；目标 host 只能来自 Nova 返回，杜绝 SSRF 到
  任意主机。UUID 本身不构成"用户可控的 host"。

**结论**：`routing`（走哪条源）与 `authorization`（谁授权）**解耦**：
- `routing=hybrid` + `authorization=control_plane`：安全默认。
- `routing=openstack_only` + `authorization=openstack_only` + 危险开关：实验室。
- 不提供 `routing=hybrid` + `authorization=openstack_only`（同一网关两套授权语义，
  静默降级风险，拒绝）。

**报错语义**：实例不存在/无权限/无地址一律 `Auth::reject()`（协议原生），
不向客户端泄露 UUID 是否存在、IP 是多少。审计侧保留细节。

**offered 回调**：OpenStack 路由上不在 offered 阶段联网（见 §0-5 / §3.1）。

### 3.6 配置 schema（`[openstack]` 草案，风格对齐 config.example.toml）

```toml
# OpenStack 实例 UUID 即路由。默认关闭：不写本节时行为与现状完全一致。
[openstack]
enabled = false

# 走哪条解析源：hybrid（UUID→OS，其余→控制面）| openstack_only（仅 UUID，无 CP 回退）
routing = "hybrid"

# 谁做授权：control_plane（CP 先授权，OS 仅换 IP——推荐）| openstack_only（实验室）
authorization = "control_plane"
# authorization="openstack_only" 时必须显式置 true，并接受"任意已认证密钥可达任意
# 已知 UUID 实例"的后果。
# allow_any_authenticated_key = false

# --- Keystone v3 ---
auth_url = "https://keystone.example.internal:5000/v3"
auth_method = "application_credential"   # application_credential | token
application_credential_id = "..."
application_credential_secret = "..."     # 用文件/环境变量注入更好，见注释
# token = "..."                           # auth_method="token" 时的逃生口（仅测试）
project_id = "..."                         # scope；强烈建议最小 project
user_domain_name = "Default"
project_domain_name = "Default"
region = "RegionOne"
interface = "public"                       # public | internal | admin
# nova_endpoint = "https://nova.example.internal:8774/v2.1"  # 跳过 catalog
microversion = "2.1"

timeout = "3s"
cache_ttl = "30s"          # 实例 IP 的解析缓存（独立于 control_plane.cache_ttl）
fail_open = false          # 开启则须配合 [backend] host_key_policy="pinned"
verify_tls = true
# ca_bundle = "/etc/ssl/private/openstack-ca.pem"

# --- 可达性 / IP 选择（§3.3）---
network = ""               # 实例多网络时必填（按 network 名过滤）
address_family = "ipv4"    # ipv4 | ipv6 | any
prefer = "floating"        # floating | fixed | any
on_ambiguous = "reject"    # reject（默认） | first

# --- 后端登录用户映射（§3.4）---
default_backend_user = "cloud-user"       # enabled=true 时必填（无普适默认）
backend_user_metadata_key = ""            # 如 "iris_ssh_user"
# [[openstack.backend_user_map]]
#   match_name = "^web-"
#   match_metadata = { role = "web" }
#   user = "ubuntu"

ssh_port = 22
recording = false
```

**配置层改动**：
- `RawConfig.control_plane` 由必填改 **`Option`**（`src/config.rs:214-215`）。
  校验：`routing != openstack_only`（或 OpenStack 未启用）时必填且 url 非空；
  `openstack_only` 时可缺省。这是对 `src/config.rs:703-718` 的重构。
- 新增 `RawOpenStack` + `OpenStackConfig`，逐字段校验（枚举值、正则合法性、
  `authorization`/`routing` 组合合法性、`default_backend_user` 在 enabled 时非空、
  `openstack_only` 必须 `allow_any_authenticated_key=true`）。
- **敏感凭据注入**：`application_credential_secret` 支持环境变量/
  `*_file` 形式（避免明文入 config）；对齐现有"config 非可信输入"的 parse-don't-validate 风格。
- 复用 `parse_duration`（`src/config.rs:526`）。
- 新增依赖：`regex`（映射规则，v1 可省）。

### 3.7 错误处理与审计

| 情形 | 客户端 | 审计/指标 |
|---|---|---|
| Nova 404 / 实例不存在 | `Auth::reject()`（协议原生） | `resolve_err{source=openstack}`；日志 `reason=not_found`，UUID |
| Nova 403 / Keystone 401 | 同上（同构，不区分） | `reason=forbidden` |
| 无可用地址 / 歧义 | 同上 | `reason=no_address` / `ambiguous` |
| Nova/Keystone 不可用 | fail-closed 拒绝（默认） | 熔断开；`reason=unavailable` |
| 后端登录用户映射失败 | 同上 | `reason=user_map`；配置错误则启动期拒绝 |
| 解析成功 | 正常拨号 | `resolve_ok{source=openstack}`；审计 target_host=IP、target_user=映射用户 |

- **审计扩展**：`AuditRecord` 增加 `resolve_source`（`"openstack"`/`"control_plane"`），
  可选 `instance_uuid`（=`principal`）。`Auditor` 构造时由 `Grant` 携带来源
  （`Grant` 或 `Policy` 增字段，或 `ResolveRouter` 在授权成功时告知）。改动
  `src/audit/mod.rs:293-323`、`src/types.rs`。
- **指标**：为 OpenStack 源提供独立计数器（`sshgw_openstack_resolve_ok_total` /
  `_err_total` / `_latency_seconds` / `_upstream_5xx_total`），或给现有
  `resolve_ok/err` 加 `source` label。避免混淆两条源的健康度。
- **resolve 失败的会话**：现有审计只在 relayed 态落盘（`src/server/mod.rs:1703-1719`），
  resolve 失败没有审计记录。建议增加一条 pre-auth 的 resolve-failure 结构化日志
  （含 client_ip、principal、source、reason），但不落完整 AuditRecord。

---

## 4. 测试方案

### 4.1 单元测试（Rust）

- `is_instance_uuid`：规范小写 v4 通过；大写/非 UUID/错误长度/非法十六进制拒绝。
- Nova 响应解析（mock JSON 字符串）：单网络单 IP；多网络 fixed+floating；v4+v6；
  `addresses` 为空；缺 `addresses` 字段；metadata；image id。
- IP 选择（§3.3）：network 过滤、family 过滤、prefer 排序、0 候选、多候选 reject/first。
- 后端用户映射（§3.4）：metadata 键命中；规则 name/metadata/image 各条件与 AND；
  声明序优先；`default` 兜底；全空规则被校验拒绝。
- Keystone 解析：token 头/expires_at/catalog 选取；过期刷新；401 重取一次。
- 路由谓词：hybrid（UUID→OS，非 UUID→CP）；openstack_only（非 UUID→拒绝）。
- `ControlError` 映射：4xx/5xx/超时/decode → 正确分类。
- 配置校验：enabled 时 `default_backend_user` 非空；`openstack_only` 需危险开关；
  `control_plane` 在 pure 模式可缺省、在 hybrid 模式必填；未知枚举值报字段名。
- 失败域隔离：OS 熔断打开不影响 CP resolver（反之亦然）。

### 4.2 集成测试（黑盒，复用 agent 拓扑）

**新增 `scripts/mock_openstack.py`**（对齐 `scripts/mock_control_plane.py` 模式）：
- `POST /v3/auth/tokens` → 201 + `X-Subject-Token` + body catalog 指向自身
  （含 compute endpoint）。
- `GET /v2.1/servers/{uuid}` → 按规则 JSON（`{uuid: {addresses, metadata, name, image, ...}}`）
  返回 200；未知 UUID → 404。
- `GET /healthz`、`GET /__log`（记录请求，供断言"未认证时未查 Nova"）。
- `--port/--rules/--pidfile/--bind/--access-log`，SIGTERM 优雅退出。

**harness 扩展**：`subtopo.sh` 增加 `SUBTOP_OPENSTACK_ENABLED/RULES/PORT` 等，
在 `gw.toml` 渲染 `[openstack]`（nova_endpoint 指向 mock，backend 地址用
`127.0.0.1:$ST_SSHD_PORT` 写入 rules），并在 162 行旁起 `mock_openstack.py`。

**新用例**（注册进 `scripts/run_integration.sh:488-519`）：
- `case_openstack_uuid_route.sh` — `ssh -A <uuid>@gw` 命中 Nova → 连入本地 sshd 模拟的
  实例；断言命令执行成功、审计 `resolve_source=openstack`、`target_user` 为映射值。
- `case_openstack_unknown_uuid.sh` — 未知 UUID → 404 → 协议原生拒绝（无会话）。
- `case_openstack_no_address.sh` — 实例存在但 addresses 空 → 拒绝。
- `case_openstack_multi_network.sh` — 两网络：配 `network` 命中其一；不配 → reject。
- `case_openstack_ambiguous.sh` — 多候选且 `on_ambiguous=reject` → 拒绝；
  `first` → 稳定选择 + warn。
- `case_openstack_user_map.sh` — metadata/规则/default 三条优先级各一断言。
- `case_openstack_preauth_no_lookup.sh` — 未验签 probe（仅 offered）不得产生 Nova 请求
  （断言 mock `__log` 为空），验签后才出现。
- `case_openstack_hybrid_fallback.sh` — 非 UUID 用户名仍走 CP（原用例语义不变）。
- `case_openstack_only_rejects_nonuuid.sh` — pure 模式拒绝非 UUID。
- `case_openstack_cp_authorized.sh`（方案 A）— CP 拒绝时不查 Nova（`__log` 空）且拒绝；
  CP 允许时才查 Nova。
- `case_openstack_upstream_down.sh` — mock OpenStack 停掉 → fail-closed 拒绝；
  `fail_open` + pinned host key 时旧 IP 仍可连（可选）。
- `case_openstack_ipv6.sh` — 后端监听 `::1`，Nova 返回 v6 字面量（可选，视 CI 能力）。

**回归**：现有 31 个用例（`scripts/run_integration.sh:488-519`）必须全绿——关键是
`enabled=false` 时行为字节级不变。

---

## 5. DoD / 风险 / 分层提交

### 5.1 分层提交（沿用仓库 D1.. 分层与"红线 12 复审"惯例）

- **O1（纯新增，默认关闭，零回归）**：配置 schema（`RawOpenStack`/`OpenStackConfig`、
  `control_plane` 可选化与组合校验）、类型（`resolve_source`）、纯谓词
  `is_instance_uuid`、路由谓词 `ResolveRoute`；单测。
- **O2（OpenStack 客户端，安全审查点）**：`OpenStackClient: ControlPlaneClient`
  （Keystone token 缓存、Nova 查询、IP 选择、后端用户映射、错误映射）；可注入 HTTP
  便于单测；单测 + mock JSON。
- **O3（接线，安全审查点）**：`ResolveRouter` + `GatewayContext` 改造；
  `resolve_grant` 派发；**offered 回调 OpenStack 路由不联网**；`policy.agent_forwarding=true`；
  指标与审计 `resolve_source`。
- **O4（harness/用例）**：`scripts/mock_openstack.py`、`subtopo.sh` 扩展、新用例、
  `run_integration.sh` 注册。
- **O5（文档）**：`config.example.toml`、README、`propose.md §3.1` 修订、
  `known-limitations.md`（授权边界与纯模式风险）、`ops-runbook.md`。

### 5.2 红线（Do not violate）

1. 解析器/路由仍是**唯一准入决策点**；OpenStack 分支不绕过授权（方案 A 默认）。
   红线 1（plan-agent-passthrough.md:66）不破。
2. **无凭据回退**：OpenStack 路由失败一律协议原生拒绝（`Auth::reject`），不降级到
   其他源或网关自有凭据（红线 3 / I4）。
3. 后端 host **只能**来自 Nova 返回；用户名绝不携带 host/IP（防 SSRF）。
4. `policy.agent_forwarding` 在 OpenStack grant 上恒 `true`；否则等于无会话。
5. `fail_open=true` 必须与 `[backend] host_key_policy="pinned"` 联结，否则拒绝启动。
6. offered 回调在 OpenStack 路由上**不联网**（防未认证枚举/DoS）。
7. D11：锁内禁 await；OpenStack 查询在 resolver 的 async fetch 内，不持锁跨 await。
8. `enabled=false` 时行为字节级不变（向后兼容红线）。
9. **红线 12**：O2、O3 的 diff 合并前必须经 @oracle 复审（安全关键：授权边界与
   pre-auth 行为）。

### 5.3 风险登记

| # | 风险 | 严重度 | 缓解 |
|---|---|---|---|
| R1 | 任意已认证密钥 → 任意实例（授权洞） | 极高 | 默认 `authorization=control_plane`；pure 模式需危险开关 + 文档 + @oracle 复审 |
| R2 | 未认证枚举（offered 触发 Nova） | 高 | offered 不联网；负缓存；`max_auth_attempts` 限速 |
| R3 | stale IP 连到错误实例（fail_open/重建） | 高 | fail_open 默认 false；pinned host key；短 cache_ttl |
| R4 | 多 IP 歧义跨网络安全域 | 中 | 默认 reject；强制 `network`+`prefer` |
| R5 | service cred 权限过大 | 高 | 强制/建议 scope 最小 project；最窄 role |
| R6 | 后端用户映射错 → 登录失败 | 中 | metadata 优先 + 明确日志；启动期校验规则 |
| R7 | Keystone/Nova 不可用 | 中 | 独立熔断 + 超时 + fail-closed；token 缓存 |
| R8 | `control_plane` 可选化改坏现有校验 | 中 | O1 单测覆盖两种模式的必填/可缺省 |
| R9 | IPv6 字面量解析/主机证书 | 低 | 集成 v6 用例；文档推荐 pinned |
| R10 | UUID 版本过严漏掉老实例 | 低 | 不强制 v4，仅校验规范 UUID 形态 |

### 5.4 DoD

- O1–O5 落地；§4.1 单测全绿；§4.2 新用例 + 现有 31 用例全绿；
  `cargo fmt --check`、`clippy --all-targets -D warnings`、`cargo test`、
  `cargo build --release`、`scripts/run_integration.sh` 全绿；
  `enabled=false` 回归字节级不变；docs 更新；O2/O3 diff 经 @oracle 复审。

---

## 6. 工作量与建议实施顺序

| 阶段 | 内容 | 估时 |
|---|---|---|
| O1 | 配置/类型/谓词 + 单测 | 0.5–1 天 |
| O2 | OpenStack 客户端（Keystone/Nova/IP/用户映射）+ 单测 | 2–3 天 |
| O3 | Router 接线 + offered 抑制 + 指标/审计 | 1 天 |
| O4 | mock_openstack.py + subtopo + 11 用例 | 1.5–2 天 |
| O5 | 文档 | 0.5 天 |
| **合计** | | **~6–8 人日 + 复审** |

**顺序**：O1 → O2（@oracle 复审客户端与安全边界）→ O3（@oracle 复审接线与 pre-auth）
→ O4 → O5。若时间受限，最小可用切片 = O1+O2+O3（hybrid + control_plane 授权）+
`case_openstack_uuid_route`；pure 模式与 IPv6 可后置。

---

## 附：与 `propose.md` 的关系

- `propose.md §3.1`（用户名解析与控制面契约，`dev-docs/propose.md:60-79`）需增补
  "解析源可为控制面或 OpenStack 直连（UUID 路由）"的契约分支。
- `propose.md §3.3`（agent-only，`dev-docs/propose.md:100-`）不变：OpenStack 分支同样
  只走 agent 穿透。
- 若采纳方案 A，`ResolveResponse` 可新增可选 `route`/`openstack_instance` 字段；
  现有 serde 默认容忍未知字段（`src/types.rs:157-165`），向前兼容。
