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
   > **【已实施，O2】**：`[[openstack.backend_user_map]]` 已落地，条件为
   > `match_name`（`^` 前缀匹配，否则全等）+ `match_metadata`（子集全等），**未引入
   > `regex` 依赖**；`match_image` **未实现**（plan 自身标注可选，且按镜像名匹配需
   > 额外查 Glance）。映射链 = 实例 metadata 键 → 规则（声明序首个命中）→
   > `default_backend_user`。
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

> **【已实施，O1】**：四个组合里只有两个在配置层合法，其中**启用态只接受纯模式**。
> `routing="hybrid"` 与 `authorization="control_plane"` 的组合（方案 A）**尚未实现**，
> 因此 `enabled=true` 时它们被 `openstack.routing` / `openstack.authorization`
> 组合规则拒绝（config.rs:1205-1259），错误信息直说"hybrid would authorize outside
> the control plane"。`enabled=false` 短路在这些规则之前，永远可接受。

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
# user_domain_name / project_domain_name —— 【已移除，O2】草案里的这两个字段是
# 死配置：application-credential 与静态 token 请求体都不发送它们，解析出来只是
# 摆设，故从 RawConfig/OpenStackConfig 删除，避免运维误以为改了就生效。
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

**harness 扩展【已实施，O4】**：`subtopo.sh` 增加 `SUBTOP_OPENSTACK[_RULES/_PURE/_UUID]`
与 `SUBTOP_OS_{METADATA_KEY,METADATA_USER,DEFAULT_USER,ON_AMBIGUOUS,CACHE_TTL,TIMEOUT,FAIL_OPEN,EXTRA}`
及 `openstack_topo_start` / `subtopo_kill_os` / `subtopo_os_count` /
`subtopo_os_statuses` / `subtopo_os_log`；在 `gw.toml` 渲染 `[openstack]`
（`nova_endpoint`/`auth_url` 指向 mock，`ssh_port = $ST_SSHD_PORT`），并与
`mock_control_plane.py` 并排起 `mock_openstack.py`。默认 `SUBTOP_OPENSTACK_PURE=1`
→ **不渲染 `[control_plane]`**，因此每个 OpenStack 用例都顺带证明纯模式可启动。
实例文档只带地址（端口来自 `[openstack] ssh_port`），所以 rules JSON 是静态的，
用例可在拓扑起来之前就写好。

**新用例**（注册进 `scripts/run_integration.sh` 的 `ALL_CASES`；**【已实施，O4】**
下表标 ✅ 的已落地，标 ➖ 的有意裁剪，标 ⏳ 的留给后续批次）：
- `case_openstack_uuid_route.sh` ✅ — `ssh -A <uuid>@gw` 命中 Nova → 连入本地 sshd 模拟的
  实例；断言命令执行成功、审计 `resolve_source=openstack`、`target_user` 为映射值。
- `case_openstack_unknown_uuid.sh` ✅ — 未知 UUID → 404 → 协议原生拒绝（无会话）。
- `case_openstack_no_address.sh` ✅ — 实例存在但 addresses 空 → 拒绝。
- `case_openstack_multi_network.sh` ➖ — 两网络：配 `network` 命中其一；不配 → reject。
- `case_openstack_ambiguous.sh` ✅ — 多候选且 `on_ambiguous=reject` → 拒绝；
  `first` → 稳定选择 + warn。
- `case_openstack_user_map.sh` ✅ — metadata/规则/default 三条优先级各一断言。
- `case_openstack_preauth_no_lookup.sh` ✅ — 未验签 probe（仅 offered）不得产生 Nova 请求
  （断言 mock `__log` 为空），验签后才出现。
- `case_openstack_hybrid_fallback.sh` ⏳ — 非 UUID 用户名仍走 CP（原用例语义不变）。
  依赖方案 A：`hybrid` 当前**启用即被拒绝**，该用例与 `cp_authorized` 一起等方案 A。
- `case_openstack_only_rejects_nonuuid.sh` ✅（实际名 `case_openstack_non_uuid.sh`） — pure 模式拒绝非 UUID。
- `case_openstack_cp_authorized.sh` ⏳（方案 A）— CP 拒绝时不查 Nova（`__log` 空）且拒绝；
  CP 允许时才查 Nova。
- `case_openstack_upstream_down.sh` ✅ — mock OpenStack 停掉 → fail-closed 拒绝；
  `fail_open` + pinned host key 时旧 IP 仍可连（可选）。
- `case_openstack_ipv6.sh` ⏳ — 后端监听 `::1`，Nova 返回 v6 字面量（可选，视 CI 能力）。

**回归**：现有用例必须全绿——关键是 `enabled=false` 时行为字节级不变。
> **【实测，O4/O5】**：全量 `scripts/run_integration.sh` = **38 pass / 0 fail /
> 2 skip**，计 40 项 = infra prelude 1 + 既有用例 31 + 新增 OpenStack 用例 8；
> 2 个 skip 是既有的真机 capability-gated 项（halfopen / netem）。另：`case_openstack_multi_network` 未单列，其两个分支由
> `case_openstack_ambiguous`（不配 `network` → reject）与 `case_openstack_uuid_route`
> （单网络正常命中）覆盖；`hybrid_fallback` / `cp_authorized`（方案 A）/ `ipv6` 留待
> 方案 A 落地或需要真机能力时补。

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

---

# 附录 A/B — Instance-Name 路由 + 解析鲁棒性（O6 / O7）

> 状态：设计附录，可实施。基线 `c0eb19a`。三项 real-env 抓包教训直接驱动本附录：
> v2 信封（`2963e76`）、application-credential scope（`9df7766`/`e68572e`）、
> `image: ""` untagged 回退（`0f30b01`）。本附录**只做** `src/openstack/*` +
> `src/config.rs` + `src/resolve/*` + harness/文档；**不改** Keystone 认证语义
> （含 app-cred scope）、agent 拨号路径、`AuditRecord` 字段格式。

## 附录 0 — 现状锚点（本附录引用的实现点）

- `OpenStackClient::resolve_inner`（`src/openstack/mod.rs:502-611`）：
  `is_instance_uuid` 守卫 → `get_server` → `select_address` → `map_backend_user`。
- `OpenStackClient::get_server`（`src/openstack/mod.rs:361-452`）：`GET {nova}/servers/{uuid}`
  + 401 单次刷新重试，解码用 `ServerResponse`。
- `ServerResponse`/`NovaServer`/`NovaImage`/`image_or_none`/`candidates`/`select_address`
  （`src/openstack/nova.rs:15-330`）。
- 路由：`route_for`（`src/resolve/router.rs:39-64`）、`ResolveRouter::route/authorize`
  （`src/resolve/router.rs:165-259`）、`ResolveRoute{ControlPlane,OpenStack,Reject}`。
- 前腿门禁：`auth_publickey_offered` 只在 `route()==ControlPlane` 时联网
  （`src/server/mod.rs:1249-1251`）。
- 配置：`OpenStackConfig`（`src/config.rs:230-281`）、`RawOpenStack`（`src/config.rs:597-672`）、
  `validate_openstack`（`src/config.rs:1189-1492`）、`parse_*`（`src/config.rs:1593-1678`）。
- 观测量：`resolve_source` + `sshgw_openstack_resolve_{ok,err}_total`（O3）。
- `Principal` 语法 `^[a-z0-9][a-z0-9_-]{0,62}$`（`src/types.rs:28-62`）——**名字路由的硬边界**（见 A.1）。

---

## A. Instance-Name 路由（O6）

### A.1 路由谓词与配置

**硬约束先说**：SSH 用户名在前腿已由 `Principal::parse` 收敛为
`^[a-z0-9][a-z0-9_-]{0,62}$`（`src/types.rs:28-62`）。因此**可被路由的"实例名"
只能是这个文法内的名字**（如真机 T_3741 的 `yunqing_dev` 合法；含大写/点/空格的
名字在前腿就被 `InvalidPrincipal` 拒绝，根本到不了路由）。OpenSSH 客户端侧同样不
接受空格用户名。结论：**"名字可含空格"不影响本网关**——名字一律经前腿文法过滤，
Nova `?name=` 只用 URL 编码作为查询参数值（见 A.3）。不为此放宽 `Principal`。

**新谓词**（`src/types.rs`，与 `is_instance_uuid` 并列）：
```rust
/// A guard for the name route: non-empty, ≤255 bytes (Nova's name limit),
/// no ASCII control characters. It is *not* a grammar — the Principal grammar
/// already ran — only a defence-in-depth bound before the string becomes a
/// query parameter value.
pub fn is_instance_name(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 255
        && !raw.chars().any(char::is_control)
}
```
注意：`is_instance_uuid` 优先。`route_by=["uuid","name"]` 时，UUID 形态的 principal
永远走 show-by-id，绝不当名字（避免"名字恰好像 UUID"的歧义）。

**配置**（`src/config.rs`）：
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind { Uuid, Name }
```
- `RawOpenStack` 增 `#[serde(default = "default_route_by")] route_by: Vec<String>`
  （`default_route_by = ["uuid"]`）。
- `OpenStackConfig` 增 `pub route_by: Vec<RouteKind>`（`Debug` 同步）。
- 新 `parse_route_by(&[String]) -> Result<Vec<RouteKind>, ConfigError>`：
  `"uuid"`/`"name"` 合法；未知值报 `openstack.route_by`；去重；空数组报错。
- 组合校验：若 `route_by` 含 `Name`，其余约束不变（仍受 `enabled`/`routing`/
  `authorization`/危险开关管辖）。
- **默认保守**：默认 `["uuid"]` ⇒ 与现状**字节级不变**（红线 1）。要名字路由必须显式
  `route_by = ["uuid", "name"]`。备选（默认两者皆可）被否：会改变 `enabled=true` 时
  非 UUID 的行为，违反仓库"默认关/不回归"惯例；且 name 路由的枚举面更大，应显式开启。

**接线**（`src/resolve/router.rs`）：
- `route_for(principal, routing, openstack_enabled, route_by)` 增参：
  - `routing=openstack_only`：`is_uuid && has(Uuid)` → `OpenStack`；
    `is_name(principal) && has(Name) && !is_uuid` → `OpenStack`；否则 `Reject`。
  - `routing=hybrid`（当前不可启用，仍实现）：非 UUID 且 `has(Name)` → `OpenStack`，
    否则 `ControlPlane`。
- `ResolveRouter` 增 `route_by: Vec<RouteKind>`；`route()` 透传。`ResolveRoute`
  **不新增变体**（UUID 与 name 都归 `OpenStack`；具体走 show 还是 list 由
  `OpenStackClient` 按形状决定，与今天的"defence-in-depth 形状守卫"一致）。
- `GatewayContext::build_with_clients`（`src/server/mod.rs:434-565`）把
  `os_cfg.route_by` 传给 `ResolveRouter::new`。
- `auth_publickey_offered` 门禁**无需改动**：`route()` 覆盖两种 OpenStack 形态，
  名字 principal 仍 `!= ControlPlane` ⇒ 不联网（MUST1 保持）。

### A.2 按名字解析（Nova list）

`src/openstack/nova.rs`：
```rust
/// `GET /v2.1/servers?name=<name>` body. Real clouds wrap in `{"servers":[…]}`;
/// accept a bare array too. Elements are bare server documents (not enveloped).
pub struct ServerList { pub servers: Vec<NovaServer> }

/// Exact-match filter. Nova's `?name=` is a *substring/RE search*, so this MUST
/// re-filter to equality; 0 → NotFound, >1 (names are not unique in OpenStack)
/// → AmbiguousName. Never guess.
pub enum NameLookupError { NotFound, AmbiguousName, Decode }
pub fn exact_name_match(servers: Vec<NovaServer>, name: &str)
    -> Result<NovaServer, NameLookupError>;
```

`src/openstack/mod.rs` — `OpenStackClient::find_server_by_name(token, name)`：
- URL：`GET {nova_base}/servers`，查询用 **reqwest 编码**：
  `.query(&[("name", name)])`（绝不手工拼 path/query；见 SA）。
- 401 单次刷新重试语义与 `get_server` 相同——**把这段重试抽成共享助手**（见 A.4）。
- 解码 `ServerList`（同样经 B 的宽容解码，见 B.3）。
- `exact_name_match` → 0/多/唯一；多 → `reason=ambiguous_name` → `ControlError::NotFound`。
- 拿到唯一 server 后，**复用** 现有 `select_address` + `map_backend_user` + policy 组装
  （把 `resolve_inner` 尾部抽成 `fn build_response(&self, server) -> Result<ResolveResponse, ControlError>`，
  uuid/name 两条路径共用）。

**Nova `?name=` 语义核实方式**：官方 API-ref 记 `name` 为过滤参数；实现为**正则
搜索**（`GET /servers?name=^foo$` 可用）。因此：真机验证两条——(1)
`GET /servers?name=yunqing_dev` 的返回是否含子串命中；(2) 同名多实例是否都返回。
无论哪种，网关**都在本地做全等过滤**并拒绝多命中，所以 Nova 语义是"搜索"还是
"精确"都不改变网关行为，只影响网络返回量。

### A.3 SSRF / 存在性

- name **只**作为查询参数值经 reqwest 编码；架构上无法进入 host/path。仍加
  `is_instance_name` 守卫（非空/≤255/无控制字符）作为纵深。
- 单测断言：名字含 `&`/`=`/`/`/`..`/空格 时，请求路径恒为 `/servers`，注入串只
  出现在 `name=` 的值里且被百分号编码（用 B 的 mock/`Request` 记录断言）。
- 存在性预言机：name 的 0/多/唯一、404、不可达**一律**对客户端 `Auth::reject`（同构），
  细节只进 `target=openstack` 日志（`reason=not_found|ambiguous_name|unparseable|...`）。
  与 UUID 同等，不新增泄露面（保留既有 timing 残余）。

### A.4 缓存 / 指标 / 日志

- **缓存键不变**：`Resolver` 以 `(principal, fingerprint)` 为键（`src/resolve/*`）；
  name 与 uuid 都以 principal 字符串为键，天然覆盖，无需改动。
- **抽共享 Nova 请求助手**：`async fn nova_get(&self, path: &str, query: Option<&str>)
  -> Result<Bytes, ControlError>`，内含 401 单次刷新 + `send()` 的连接重试；`get_server`
  与 `find_server_by_name` 都调它，避免复制重试循环（也避免两处语义漂移）。
- **日志**：在 `resolve_inner`/`get_server`/`find_server_by_name` 的
  `target=openstack` 行加 `route_by = "uuid" | "name"`（与 `uuid`/`reason` 并列）。
- **指标**：可选新增 `sshgw_openstack_resolve_by_uuid_total` /
  `sshgw_openstack_resolve_by_name_total`（低基数），或复用现有 `ok/err` 不细分。
  建议加，便于真机按名字路由的命中率观测。**审计格式不变**（`AuditRecord` 不加字段；
  需要区分时看 `resolve_source="openstack"` + `target_host`）。
- 后台拨号与 agent 流程**零改动**：`Target` 结构与 `policy.agent_forwarding=true` 不变。

### A.5 真机衔接

- T_3741 实例名 `yunqing_dev`（`src/openstack/nova.rs:991` 的真实抓包）可作
  `ssh -A yunqing_dev@<gw>` 的真机验证目标；真机脚本记录在
  `dev-docs/openstack-test-env.md`。

---

## B. 解析鲁棒性（O7，核心）

### B.1 分层架构

```
GET /servers[/{id}]  →  reqwest  →  serde_json::Value
        │
        ├─(1) 形态判定：value.get("server") 存在？  → envelope | flat
        │         （0f30b01 已改为按形状分派，保持；不再用 untagged 试错）
        │
        ├─(2) 字段级容错：decode_server() 逐字段独立提取，任一非关键字段
        │         null/缺失/空串/类型漂移都不拖垮整个文档
        │
        ├─(3) 灰度回退：类型化提取失败或 addresses 结构可疑时，
        │         用结构化宽松提取 walk 出 addresses（多形态/IPv6/type 缺失）
        │
        └─(4) 失败响亮：仍不可用 → reason="unparseable" + 结构摘要（非全文）
```

### B.2 字段级容错（逐字段梳理）

`NovaServer` 关键字段 vs 非关键字段（`src/openstack/nova.rs:15-80`）：

| 字段 | 角色 | 真实变体 | 处理 |
|---|---|---|---|
| `addresses` | **关键** | map / `null` / 缺失 / 非 map（串/数组）/ 空 map / 多网络 / IPv6 / entry 缺 `OS-EXT-IPS:type` | 宽松提取（B.3），产出 `usable` 标志；不可用→unparseable，空→no_address |
| `name` | 关键 | 缺失 / `null` / 非串 | 缺失→`""`（仅用于 map 规则）；非串→宽容丢弃 |
| `id` | 关键 | 缺失 | 缺失不影响拨号；仅日志 |
| `image` | 非关键 | object / `null` / `""` / bare string / 数字 / 数组 | 已由 `image_or_none`（`nova.rs:46-57`）宽容；保持 |
| `metadata` | 非关键 | `{}` / `null` / 值含非字符串（数字/布尔） | 宽松：null→空；标量→字符串化；非标量→丢弃 |
| `accessIPv4`/`accessIPv6` | 非关键 | `""` / `null` / 数字 | 宽松：非串→None |
| `flavor`/`links`/`security_groups`/... | 忽略 | 任意 | 不解析 |

实现：**弃用运行时 `#[derive(Deserialize)]` 对 `NovaServer` 的整文档解码**，改为
从 `serde_json::Value` 手写提取，逐字段独立、绝不因单字段失败而整体失败：

```rust
pub struct ServerView {
    pub id: Option<String>,
    pub name: Option<String>,
    pub addresses: BTreeMap<String, Vec<NovaAddress>>,
    pub metadata: BTreeMap<String, String>,
    pub image_id: Option<String>,
    pub access_ips: Vec<IpAddr>,
}

pub struct DecodeOutcome {
    pub view: ServerView,
    /// 结构可疑（addresses 存在但不可解析）——调用方据此判 unparseable。
    pub addresses_present_but_unusable: bool,
    /// 非致命畸形，供 warn 日志（如 image 是串）。
    pub notes: Vec<&'static str>,
}

pub enum DecodeError { NotAnObject, /* 极少见：根不是对象 */ }

pub fn decode_server(value: &serde_json::Value) -> Result<DecodeOutcome, DecodeError>;
```

`decode_server` 内部：`value.get("server").unwrap_or(value)` 取有效对象；逐字段调
`string_from_value` / `u8_from_value` / `metadata_from_value` / `image_id_from_value`
/ `access_ips_from_value` / `addr_map_from_value`。每个助手对"意外的类型"返回默认值
并记 `notes`，**不返回 Err**（仅根非对象才 Err）。`ServerResponse`（envelope/flat
分派）保留为"形态判定"的单一入口，但委托 `decode_server` 完成字段提取。

### B.3 灰度回退（lenient extraction）

`addr_map_from_value`——按形状探测，兼容真实多形态：
- `null` / 缺失 → `{}`，`present=false`。
- 空 map `{}` → `{}`，`present=true`，`unusable=false`（合法无机地址 → no_address）。
- map（正常 `{net: [ {addr,version,type}, … ]}`）：
  - 每个 entry：优先对象取 `addr`/`version`/`OS-EXT-IPS:type`；**兼容** entry 是
    `{"addr": …}` 无 type/version、或 entry 本身是裸字符串 IP（极端防御）。
  - map 有 ≥1 entry 但解析后 0 个可用 IP → `present=true, unusable=true`（不静默清空）。
- 非 map（串/数组/数字/布尔）→ `present=true, unusable=true`。
- （可选）单对象形式 `{net: {addr:…}}` 当作单元素列表。
- 地址字面量交给 `candidates` 现有的 `IpAddr::parse` 过滤（`nova.rs:223-248`），
  **信字面量不信 `version` 字段**（IPv6 自动成立）。

`resolve_inner` 决策：
```
decode_server → Err | addresses_present_but_unusable
        → reason="unparseable"，ControlError::NotFound（同构）
        → select_address 照常（genuinely empty → reason="no_address"）
```

### B.4 失败响亮（不泄 body）

`src/openstack/nova.rs`：
```rust
/// A structural summary safe to log: top-level keys, whether a `server` key is
/// present, the JSON type of `addresses`, the number of networks, byte length,
/// and a short digest. Never the body (may carry tenant/secret-adjacent data).
pub fn summarize_body(value: &serde_json::Value, raw_len: usize) -> String;
```
输出形如
`keys=[id,name,addresses,image,...] has_server=true addresses=object networks=0 len=412 sha256=ab12cd34ef56`。
`sha256` 用 `ring`（已有依赖）或 std 无 hash 时退化为 `raw_len` + 前若干 key；
**不引新依赖**（如需 sha 用 `ring::digest`，russh 已带 `ring`）。
调用点：`get_server`/`find_server_by_name` 解码失败的 `reason="decode"` 与地址不可用的
`reason="unparseable"` 两条 warn，附 `summary`。**客户端恒同构拒绝**。

### B.5 独立解码（架构级）

- `addresses`/`name`/`metadata`/`image`/`accessIP*` **各自独立提取**，任一畸形不再
  连坐（对 `0f30b01` 那类问题的架构级解决：不是再补一个特例字段，而是消除"一个字段
  拖垮整个 decode"的可能）。
- 关键字段 `addresses` 的"空"与"不可用"**显式区分**：空 → `no_address`（合法），
  不可用（结构存在但提取不出）→ `unparseable`（响亮）。这是 2963e76/0f30b01 两个
  "静默变空、误报 no_network"事故的直接对治。

### B.6 真实 body 语料与回归夹具

**组织方式**：新建 `tests/fixtures/openstack/servers/`，每个抓包一份**逐字 JSON**文件，
测试用 `include_str!("../../tests/fixtures/openstack/servers/<f>.json")` 载入（编译期、
无需运行时 IO），由一个**表驱动测试**遍历：
```rust
struct Fixture { name: &'static str, body: &'static str,
                 expect: Expect,   // Resolve(ip) | NoAddress | Unparseable
                 route_by: &'static [RouteKind] }
const FIXTURES: &[Fixture] = &[ … ];
```
现有三个 inline const（`nova.rs:836` `REAL_ENVELOPE`、`:991` `REAL_ENVELOPE_T3741`、
mock flat）迁入该目录；**逐字保留**（含 `image: ""`）。

固化语料：
- `d702cf44_envelope.json`（T_3746 信封）→ `Resolve(172.16.46.25)`。
- `e52bce4c_envelope_image_empty.json`（T_3741 信封 + `image:""`）→
  `Resolve(172.16.41.62)`，`image_id=None`。
- `flat_variant.json`（v2.1 扁平）→ `Resolve`。
- 新增变体：`addresses` 缺失 / `null` / 非 map（串）/ 空 map / 双网络 / IPv6 /
  entry 缺 `type` / `metadata:null` / `metadata` 值非串 / `image` 裸串 / 根非对象。
- 每个变体在 `Fixture.expect` 里写明**预期结果**，让"响亮 vs 静默"成为可回归的断言。

### B.7 红线段（B）

1. **不回归**：默认配置（`route_by=["uuid"]`, `enabled=false`）路径行为不变。
2. **不掩盖上游故障**：`transport`/`5xx`/`401` 映射照旧（`mod.rs:410-449`）；宽松解析
   只作用于 **200 的 body 形状**，绝不对网络错误做"重试/兜底"。
3. **失败对客户端恒同构**：`unparseable`/`um` 全部 `ControlError::NotFound`。
4. **`target.host` 只来自解析结果**；name 只作查询参数值；SSRF 面不放松。
5. **日志不泄 body 全文**：只记 `summarize_body`。
6. **无无限重试**：只保留既有"连接失败单次重试 + 401 单次刷新"。
7. **不改** Keystone 认证（app-cred scope 行为）、agent 拨号、`AuditRecord` 格式。

---

## C. 测试方案（O6+O7）

### C.1 单元（Rust）
- **A**：`is_instance_name`（空/超长/控制字符/正常）；`parse_route_by`（合法/未知/重复/
  空）；`route_for` 四象限（uuid×name × routing）× `route_by` 组合；`exact_name_match`
  （0/1/多，含 Nova 子串命中被本地过滤掉）；`find_server_by_name` URL 编码注入用例
  （名字含 `&`/`=`/`/`/`..`/空格 → path 恒 `/servers`）。
- **B**：`decode_server` 字段矩阵（B.2 表）；`addr_map_from_value` 各形态；`summarize_body`
  产出不含 body；`ServerList` 解码（信封数组 / 裸数组 / 元素含 `image:""`）。
- 表驱动 fixtures（B.6）。

### C.2 集成（黑盒，复用 agent/OpenStack 拓扑）
- `scripts/mock_openstack.py`：`do_GET` 增 `GET /v2.1/servers?name=<name>` 分支——
  `urllib.parse` 解析 query，返回 `{"servers":[…]}`；**按 Nova 语义做子串匹配**（便于
  测"本地全等过滤"与"多命中"）；rules 支持多实例按名索引；非 UUID list 请求 404 归
  既有行为。
- `tests/integration/subtopo.sh`：增 `SUBTOP_OS_ROUTE_BY`（渲染 `route_by = [...]`），
  rules 支持 `name` 字段（已支持）。
- 新用例：
  - `case_openstack_name_route` — `ssh -A <name>@gw` 命中 list → 会话成功；审计
    `resolve_source=openstack`；日志 `route_by=name`。
  - `case_openstack_name_ambiguous` — list 返回多个同名（含子串）→ 本地全等后仍 >1
    → 拒绝，`reason=ambiguous_name`，无审计。
  - `case_openstack_name_disabled` — `route_by=["uuid"]`（默认）下非 UUID 名字 →
    `reason=unrouted`、0 Nova 请求（回归红线 1）。
  - `case_openstack_envelope_variants` — mock 返回信封 + `image:""` 实例 → 会话成功
    （把 2963e76/0f30b01 变成黑盒回归）。
  - `case_openstack_unparseable_loud` — mock 返回 `addresses="not-a-map"` → 客户端同构
    拒绝，网关日志 `reason=unparseable` + summary；不泄 body。
- 回归：现有 38 case 全绿（默认 `route_by=["uuid"]` 且 mock list 分支不影响旧路径）。

### C.3 真机
- T_3741 `yunqing_dev`：`ssh -A yunqing_dev@<gw>` 端到端；记录到
  `dev-docs/openstack-test-env.md`。

---

## D. DoD / 分层提交 / 工作量

### D.1 分层提交（沿用 O 系列，@oracle 复审）
- **O6**（Instance-Name 路由）
  - **O6a**（纯新增，默认关）：`is_instance_name`、`RouteKind`、`route_by` 配置 +
  校验、`route_for` 增参、`ResolveRouter` 透传、server 接线；单测。默认 `["uuid"]`，
  零行为变化。
  - **O6b**（安全审查点）：`ServerList`/`exact_name_match`、`find_server_by_name`、
  共享 `nova_get` 401 助手、`build_response` 抽取；单测（含编码注入）。
  - **O6c**：mock list 分支 + subtopo `route_by` + 4 个 name 用例 + 真机 T_3741。
  - **O6d**：docs（config.example `route_by`、ops-runbook §5.8、known-limitations §9、
  propose §3.1、plan 标注）。
- **O7**（解析鲁棒性）
  - **O7a**（安全/正确性审查点）：`decode_server`/`ServerView`/字段助手 + 独立解码。
  - **O7b**：`addr_map_from_value` 灰度回退 + `unparseable` 响亮 + `summarize_body`。
  - **O7c**：fixtures 目录 + 表驱动测试（三个真机抓包迁入 + 新增变体）。
  - **O7d**：mock 变体 + `case_openstack_envelope_variants` / `case_openstack_unparseable_loud` + docs。
- **红线 12（复审门禁）**：O6a/O6b 与 O7a/O7b 的 diff 合并前必须经 @oracle 复审
  （安全面：SSRF/编码/歧义/同构失败；正确性面：独立解码/响亮失败）。

### D.2 DoD
- O6+O7 落地；C.1 单测全绿；C.2 新用例 + 现有 38 case 全绿；`fmt`/`clippy -D warnings`/
  `test`/`build --release`/`run_integration.sh` 全绿；`enabled=false` 与默认
  `route_by=["uuid"]` 行为不变；真机 T_3741 name 路由通过；docs 更新；O6a/b、O7a/b
  经 @oracle 复审。

### D.3 本次**不改**
- Keystone 认证（app-cred scope 行为，`9df7766`）；agent 拨号与签名面；
  `AuditRecord` 字段格式（仅加日志字段/可选指标）；`direct-tcpip`/policy 语义。

### D.4 工作量
| 阶段 | 内容 | 估时 |
|---|---|---|
| O6a | 谓词/配置/路由接线 + 单测 | 0.5–1 天 |
| O6b | name list 解码 + 共享 Nova 助手 + 单测 | 1–1.5 天 |
| O6c | mock/subtopo + 4 用例 + 真机 | 1–1.5 天 |
| O6d | docs | 0.5 天 |
| O7a/b | decode_server + 灰度回退 + 响亮失败 + 单测 | 1.5–2 天 |
| O7c/d | fixtures + 变体用例 + docs | 1–1.5 天 |
| **合计** | | **~5.5–8 人日 + 复审** |

### D.5 风险
| # | 风险 | 严重度 | 缓解 |
|---|---|---|---|
| R11 | name 路由扩大枚举面 | 中 | 默认关（`route_by=["uuid"]`）、同构失败、负缓存、`max_auth_attempts` |
| R12 | 同名多实例误连 | 高 | 本地全等过滤 + >1 → `ambiguous_name` 拒绝，绝不猜 |
| R13 | 宽松解析掩盖真故障 | 中 | 只对 200 body；关键字段显式 `usable`；`unparseable` 响亮；红线段 B.7 |
| R14 | 编码注入 | 高 | reqwest `.query()` + `is_instance_name` 守卫 + 注入单测 |
| R15 | 日志泄 body | 中 | 只记 `summarize_body` |
| R16 | fixtures 与实现漂移 | 低 | 逐字抓包 + 表驱动 expect 断言 |

---

## E. 给 fixer 的分层实施清单

1. **O6a** `types.rs:is_instance_name` + `config.rs:RouteKind/route_by/parse_route_by/校验/Debug`
   + `router.rs:route_for(+route_by)/ResolveRouter` + `server/mod.rs` 传参；单测。
2. **O6b** `nova.rs:ServerList/exact_name_match` + `mod.rs:find_server_by_name/nova_get/
   build_response`；单测（含编码注入、多命中）。
3. **O6c** `mock_openstack.py` list 分支 + `subtopo.sh:SUBTOP_OS_ROUTE_BY` +
   `case_openstack_name_{route,ambiguous,disabled}` + 真机 T_3741。
4. **O6d** docs（config.example / ops-runbook §5.8 / known-limitations §9 / propose §3.1 / 本文件标注）。
5. **O7a** `nova.rs:ServerView/DecodeOutcome/decode_server` + 字段助手 + `ServerResponse` 委托；单测字段矩阵。
6. **O7b** `addr_map_from_value` 灰度回退 + `unparseable` + `summarize_body`；单测。
7. **O7c** `tests/fixtures/openstack/servers/*`（迁入 3 抓包 + 新变体）+ 表驱动测试。
8. **O7d** mock 变体 + `case_openstack_envelope_variants` / `case_openstack_unparseable_loud` + docs。
9. **提交前门禁**：`fmt`/`clippy`/`test`/`release`/`run_integration.sh`；O6a/O6b/O7a/O7b 经 @oracle 复审。

---

# 附录 C — cross_project（不指定 Project）可选实验室模式（X 系列）

> 状态：设计附录，可实施。基线 `3391d73`（O1..O7 已落地，红线 12 层已复审放行）。
> 目标：只给 **instance name 或 instance id**、**不指定 Project** 就能解析并连接实例
> （实验/运维简化）。这是**显式刺眼的实验室模式**，默认关闭，且**依赖平台宽松的
> Nova 策略**——标准/严格云不适用。

## C.0 现状锚点与已实测的硬约束

- Keystone 认证：`acquire`/`fetch_token`/`auth_body`（`src/openstack/mod.rs:223-358`）；
  目前仅 `auth_method=application_credential`（默认）与 `token`（静态逃生口）。
  application credential **不接受请求期 scope**（`mod.rs:351-357`，真机 v3.14 实测 401），
  因此它对单项目之外天生无能为力。
- 可见性：Nova `GET /servers/{id}` / `GET /servers?name=` 的可见性由 **token 作用域**限定
  （`nova_get`，`src/openstack/mod.rs:532-`；`get_server`/`find_server_by_name`）。
- `OpenStackConfig`（`src/config.rs:262-305`）、`RawOpenStack`（`src/config.rs:633-703`）、
  `validate_openstack` 认证段（`src/config.rs:1338-1393`）、`parse_auth_method`
  （`src/config.rs:1644-1652`）。
- `NovaServer` 字段（`src/openstack/nova.rs`）现无 `tenant_id`；`decode_server` 逐字段提取。
- 名字全等过滤 + 歧义拒绝：`exact_name_match`（`src/openstack/nova.rs`）；refinement
  （`src/openstack/mod.rs:481-508`）。
- **实测（只读，采信勿复探）**：
  - T_3746 作用域 **admin token** + `GET /v2.1/servers/{e52bce4c…}?all_tenants=1`（该实例属
    T_3741）→ **200**，body 含 `tenant_id=6bdb5cae…`（＝T_3741）。
  - `GET /servers?all_tenants=1&name=yunqing_dev` → **200 命中 1 台**。
  - `alex` 取 **domain/system 作用域 token → 401**（平台不允许非项目作用域）。
  - application credential **创建即锁单项目**，无法跨项目。

**结论**：cross_project 的唯一可行路径是"**具备 admin 角色的项目作用域 token**" +
Nova `all_tenants=1`，且该 token 只能通过 **password 认证**取得（app-cred 不行，静态
token 会过期不适合常驻配置）。

---

## C.1 配置与模式

**新增一个显式模式开关**（不是 auth_method 的副作用，便于审计与校验）：

```toml
[openstack]
scope = "single_project"   # 默认，现状零回归 | "cross_project"（实验室）
```

- `RawOpenStack.scope: String`（`#[serde(default = "default_scope")]` → `"single_project"`）；
  `OpenStackConfig.scope: OpenStackScope{ SingleProject, CrossProject }`；`Debug` 增字段。
- `parse_scope`（`src/config.rs`，风格同 `parse_routing`）：`"single_project"` / `"cross_project"`，
  未知值报 `openstack.scope`；**在 `enabled=false` 短路之前解析**（拼写错误照旧 fail boot）。
- **`project_id` 在 cross_project 下仍保留**，但语义改变：它是**认证作用域**（admin 角色
  所在项目），**不是**可见性边界；用于日志上下文。为兼容，`project_id` 继续可空
  （`*.env` 注入的 password 场景可由 `project_name` 指定 scope）。
- **组合校验**（`validate_openstack`，新增一段 `match scope`）：
  - `single_project`：现状完全不变（app-cred / token 二选一，规则照旧）。
  - `cross_project`：`auth_method` **必须** `"password"`（app-credential / token **显式拒绝**，
    报 `openstack.auth_method`，reason 直说"application credentials are project-fixed;
    cross_project needs a project-scoped admin token, which only password auth yields"）。
- **兼容改动**：`OpenStackScope` 默认值使现有配置**逐字不变**；`Debug` 只增一个字段；
  校验只在 `cross_project` 分支新增，不动 `single_project` 路径（红线 1）。

---

## C.2 认证：password 回引入（跨项目唯一路径）

### C.2.1 配置字段

```toml
auth_method = "password"                 # cross_project 必须
username = "alex"                        # 认证用户名
password = "…"                           # 或 password_file / $SSHGW_OPENSTACK_PASSWORD
user_domain_name = "Default"             # user 的 domain（name 形态）
project_id = "…"                         # admin 角色所在项目 id（scope）
# project_name = "…"                     # 或 name 形态 + project_domain_name
project_domain_name = "Default"
```

- `RawOpenStack` 增 `username`、`password`、`password_file`、`project_name`、
  `project_domain_name`；`user_domain_name` **此前 O3 作为死配置删除，此处按需回引入**
  （password 身份/作用域需要它，`single_project` 下不解析、不要求）。
- secret 注入沿用 `resolve_secret`：`password_file` → 字面量 → `$SSHGW_OPENSTACK_PASSWORD`
  （`src/config.rs:1494-1533`）；`OpenStackConfig` 手写 `Debug` 把 `password` 渲染为
  `<redacted>`（与 app-cred secret/token 同规格）。
- **`single_project` 下 `auth_method=password` 是否允许** → 见 §C.6 待拍板点①。

### C.2.2 auth body（`auth_body` 改 match）

```json
{"auth":{
  "identity":{"methods":["password"],
    "password":{"user":{"name":"<username>",
                        "domain":{"name":"<user_domain_name>"},
                        "password":"<password>"}}},
  "scope":{"project":{"id":"<project_id>"}}      // 或 {"name":…,"domain":{"name":…}}
}}
```
- `project_id` 非空 → 用 id scope；否则用 `project_name` + `project_domain_name`。
- `user_domain_name` 为空时回退 `"Default"`（Keystone 惯例），但建议必填。

### C.2.3 token 生命周期

- `acquire`（`src/openstack/mod.rs:223-247`）：`Token` 静态分支不变；把
  `ApplicationCredential` 分支泛化为 **`ApplicationCredential | Password` → 缓存/单飞/`fetch_token`**。
- `fetch_token`（`mod.rs:250-330`）：**逻辑不变**（`X-Subject-Token`、`expires_at`、
  catalog、401/403/5xx/429 分类、单飞、401 单次刷新）——password 只是换 body。
- 401 刷新路径（`nova_get`，`mod.rs:560-573`）对 password 完全复用。
- 失败日志规范：把 `fetch_token` 里的 "Keystone refused the application credential"
  文案改为按 `auth_method` 取词（"password" / "application credential"），**不打印凭据**。

### C.2.4 安全评审：为何可接受回引入 password

| 维度 | password（cross_project） | application credential（single_project） |
|---|---|---|
| 触发条件 | **仅** `scope="cross_project"` 显式开启，默认关 | 默认，单项目 |
| 凭据注入 | env / `*_file`，Debug 红act，绝不入日志 | 同 |
| 用途 | **只用于换一枚项目作用域 admin token**，凭据不经手客户端数据 | 同 |
| 生命周期 | token 缓存至 `expires_at-skew`；401 单刷 | 同 |
| 爆炸半径 | **整个 token 可见范围**（由角色 + Nova 策略决定）——比 app-cred 大 | 单一 project |
| 与 app-cred 取舍 | app-cred 无法跨项目，是**唯一**跨项目路径，非"更方便" | 更安全，单项目首选 |

- **可接受的边界**：password 仅存在于"显式刺眼"的 cross_project 模式；启动打
  `WARN`（见 §C.4）；文档要求 operator 把凭据 scope 到**藏 admin 角色的那个项目**，
  并理解"该 admin 能看全云"；凭据只用于解析，网关仍是 agent-only 后端认证、不经手
  客户端私钥/数据。
- **不可接受的方向**：把 password 变成默认/单项目推荐路径（app-cred 更安全）；或在
  cross_project 之外隐式使用。校验层强制"password ⇔ cross_project"（待拍板点①定严格度）。

---

## C.3 Nova 接线

### C.3.1 `all_tenants=1`

- `nova_get`（`src/openstack/mod.rs:532-`）的 `query: Option<(&str,&str)>` 改为
  `query: &[(&str,&str)]`（list 路由要同时带 `name` 与 `all_tenants`）。
- 新增 `fn nova_query<'a>(&'a self, extra: &[(&'a str,&'a str)]) -> Vec<(&'a str,&'a str)>`：
  `cross_project` 时追加 `("all_tenants","1")`，`single_project` 时原样——**只在查询参数层
  追加**，仍走 `request.query(...)`（reqwest 百分号编码），**SSRF 面不变**（path 仍由本模块
  构造，客户端串只作 query 值；`all_tenants` 是常量）。
- `get_server` 调 `nova_get(token, &format!("/servers/{uuid}"), &nova_query(&[]), …)`；
  `find_server_by_name` 调 `nova_get(…, "/servers", &nova_query(&[("name", name)]), …)`。
- 平台前置条件：`all_tenants` 是 Nova 扩展，**标准/严格云对非 admin token 会 403/忽略**。
  文档化；`cross_project` 不得默认开启。

### C.3.2 `tenant_id` 上下文

- `NovaServer` 增 `tenant_id: Option<String>`，`decode_server` 用
  `string_from_value(doc.get("tenant_id"), "tenant_id", &mut notes)` 提取（宽容，同其它非关键字段）。
- `build_response` 的 debug/warn 行加 `tenant_id = <…>`（仅日志上下文，**不改 AuditRecord**）。
- 可选：`resolve` 的 `target=openstack` 结构化日志加 `tenant_id`。

### C.3.3 路由语义

- **UUID 路由**：`decode_server` → 唯一实例 → 直接解析（cross_project 下 `all_tenants` 让
  非本 scope 项目的实例也可见）。`target.host` 仍只来自 `select_address`。
- **名字路由**：`find_server_by_name` 的全等过滤现在跨项目。**全云全等 >1 → 拒绝**，
  reason token 按 scope 区分：
  - `single_project`：`ambiguous_name`（现状）；
  - `cross_project`：`ambiguous_name_cross_project`（新增，仅日志，客户端仍是同构 `NotFound`）。
  - 实现：`exact_name_match` 仍返回 `AmbiguousName`；在 `find_server_by_name` 选 reason 时按
    `cfg.scope` 映射（不新增 enum 变体，降低 churn）。
- 解析后 `select_address` + `map_backend_user` + policy 组装**完全复用** `build_response`。

---

## C.4 安全红线（附录 C）

1. **默认 `single_project` 零回归**：`scope` 默认值使现有配置逐字不变；`enabled=false` 不变。
2. **cross_project = 显式刺眼实验室模式**：启动 `WARN`（对照
   `allow_any_authenticated_key` 的醒目度），文档化"依赖平台宽松 Nova 策略，标准/严格云
   不适用，禁止默认开启"。
3. **失败对客户端恒同构**：cross_project 的所有失败仍是 `Auth::reject`（`NotFound`/`Decode`
   → reject）；`ambiguous_name_cross_project` 只进日志。
4. **`target.host` 只来自解析结果**（Nova `addresses`），username/name 绝不携带 host/IP。
5. **日志只摘要不泄 body**（`summarize_body`，附录 B.4）；password/凭据永不入日志，
   `Debug` 红act。
6. **凭据最小化**：admin 凭据只用于换取解析用 token；不参与后端拨号（agent-only 不变）、
   不经手客户端数据。
7. **不改** app-credential 语义（`single_project` 路径）、agent 拨号、`AuditRecord` 格式。
8. 红线 12：X 系列的安全关键层（X1/X2/X3）合并前经 @oracle 复审。

---

## C.5 测试

### C.5.1 mock_openstack.py 多 tenant + all_tenants

- rules 的每个 server 增 `tenant_id`；`State` 记录当前 token 的作用域项目。
- `POST /v3/auth/tokens`：解析请求 body 的 `scope.project.id`（或 `name`）→ mint token =
  `mock-subject-token:<project>`；返回 catalog（同现状）。
- `GET /v2.1/servers/{id}` 与 `?name=`：从 `X-Auth-Token` 解出 token 的项目；**若
  `all_tenants` 缺失/非 1 → 仅返回 `tenant_id == 本项目` 的实例；若 `all_tenants=1` → 全部**。
  记录是否带 `all_tenants` 供断言（`/__log` 已记 path，query 也在 path 中）。
- password 认证：mock 接受 `methods:["password"]`，返回成功（无需真校验密码）。
- `--pidfile`/SIGTERM 等不变。

### C.5.2 subtopo

- 增 `SUBTOP_OS_SCOPE`（`single_project` 默认；`cross_project` 渲染 `scope` + password 字段）。
- 增 `SUBTOP_OS_PROJECT_ID` / `SUBTOP_OS_PROJECT_NAME` / `SUBTOP_OS_USERNAME` /
  `SUBTOP_OS_PASSWORD`（默认从 env 读，测试用固定值），渲染进 `[openstack]`；现有
  `SUBTOP_OS_ROUTE_BY` 等保持不变。
- rules 里给实例分配不同 `tenant_id`（如主实例 T_a、跨项目实例 T_b）。

### C.5.3 用例

- `case_openstack_cross_project_uuid`（正例）：cross_project 下登录**他项目**实例 UUID →
  会话成功；断言 mock 收到 `all_tenants=1`；审计 `resolve_source=openstack`。
- `case_openstack_cross_project_name`（正例）：跨项目名字唯一 → 解析成功。
- `case_openstack_cross_project_name_ambiguous`（拒绝）：两项目同名 → 拒绝，
  日志 `reason=ambiguous_name_cross_project`，无审计，客户端同构。
- `case_openstack_single_project_default`（回归）：默认 scope 下不追加 `all_tenants`；
  他项目 UUID 不可见（404 → 拒绝）——证明默认仍是单项目。
- `case_openstack_cross_project_appcred_rejected`（组合校验）：`scope=cross_project` +
  `auth_method=application_credential` → 启动期 `openstack.auth_method` 错误。
- `case_openstack_cross_project_password_env`（注入）：password 经
  `SSHGW_OPENSTACK_PASSWORD` 注入，配置无明文 → 解析成功。
- fixtures 补 `tenant_id` 变体（`tenant_id` 缺失/null/非串）到表驱动语料（附录 B.6）。

### C.5.4 真机

- T_3746 admin 凭据 → `scope=cross_project` + password → `all_tenants=1` 解析 T_3741
  `e52bce4c…`（lookup 已验证）→ 走到 root 登录（登录应通）；记录
  `dev-docs/openstack-test-env.md`。负例：单项目 scope 下同 UUID 不可见。

---

## C.6 DoD / 分层提交（X 系列）/ 工作量 / 红线 12

### D.6.1 分层提交

- **X1**（默认关，纯新增）：`OpenStackScope` + `scope` 配置/解析/校验骨架 +
  `single_project` 分支零改动；单测（含 `enabled=false` 短路、未知值、组合骨架）。
- **X2**（安全审查点）：`auth_method="password"`（配置字段/env 注入/Debug 红act）、
  `auth_body` 改 match、`acquire` 泛化、fetch 文案按 method；
  **cross_project ⇔ password 组合校验**；单测（含 401 刷新复用）。
- **X3**（安全审查点）：`nova_get` query 切片化 + `nova_query`（`all_tenants`）+
  `NovaServer.tenant_id` + `ambiguous_name_cross_project`；单测（query 断言、tenant 日志）。
- **X4**：mock 多 tenant + all_tenants + subtopo `SUBTOP_OS_SCOPE`/password 字段 + 6 用例
  + 真机 T_3746→T_3741。
- **X5**：文档（config.example `scope`/password 块、ops-runbook §5.8、known-limitations §9、
  propose §3.1/§3.2 授权例外、本文件标注）。
- **红线 12**：X2、X3 合并前经 @oracle 复审。

### D.6.2 DoD

- X1–X5 落地；C.5 单测全绿；新用例 + 现有 44 用例全绿；`fmt`/`clippy -D warnings`/`test`/
  `release`/`run_integration.sh` 全绿；`scope=single_project`（默认）与 `enabled=false`
  行为不变；真机 cross_project 解析通过；docs 更新；X2/X3 经 @oracle 复审。

### D.6.3 工作量

| 阶段 | 内容 | 估时 |
|---|---|---|
| X1 | scope 配置/枚举/校验骨架 + 单测 | 0.5 天 |
| X2 | password 认证 + 组合校验 + 单测 | 1.5–2 天 |
| X3 | all_tenants 接线 + tenant_id + 跨项目歧义 + 单测 | 1–1.5 天 |
| X4 | mock/subtopo + 6 用例 + 真机 | 1.5–2 天 |
| X5 | docs | 0.5 天 |
| **合计** | | **~5–6.5 人日 + 复审** |

### D.6.4 风险

| # | 风险 | 严重度 | 缓解 |
|---|---|---|---|
| R17 | password 回引入扩大凭据面 | 高 | 仅 cross_project、env 注入、Debug 红act、启动 WARN、@oracle 复审 |
| R18 | admin token 爆炸半径=全项目 | 高 | 文档要求 scope 到"藏 admin 的项目"；凭据只用于解析 |
| R19 | 依赖平台宽松 Nova 策略（非标准） | 中 | 文档化硬前置；不得默认开启；单项目默认不受影响 |
| R20 | 跨项目同名 >1 误连 | 高 | 全等 >1 → `ambiguous_name_cross_project` 拒绝，绝不猜 |
| R21 | single_project 回归 | 中 | scope 默认值 + 双模式单测 |
| R22 | password 泄露进日志 | 高 | Debug 红act + 不打印 body/凭据（既有 `summarize_body`） |

---

## C.7 给 fixer 的分层清单

1. **X1** `config.rs:OpenStackScope/default_scope/parse_scope` + `RawOpenStack.scope` +
   `OpenStackConfig.scope` + `Debug`；`single_project` 路径不变；单测。
2. **X2** `config.rs`：`RawOpenStack.{username,password,password_file,project_name,project_domain_name,user_domain_name}`
   + `resolve_secret(password)` + `Debug` 红act + `parse_auth_method` 增 `"password"` +
   cross_project⇔password 组合校验；`openstack/mod.rs:auth_body` 改 match、`acquire` 泛化、
   fetch 文案按 method；单测。
3. **X3** `openstack/mod.rs:nova_query` + `nova_get(query: &[(&str,&str)])` + `get_server`/
   `find_server_by_name` 调用点 + `ambiguous_name_cross_project`；`nova.rs:NovaServer.tenant_id`
   + `decode_server` 提取 + `build_response` tenant 日志；单测。
4. **X4** `scripts/mock_openstack.py` 多 tenant/all_tenants/password + `subtopo.sh`
   `SUBTOP_OS_SCOPE`/password 字段 + `case_openstack_cross_project_{uuid,name,name_ambiguous,
   appcred_rejected,password_env}` + `case_openstack_single_project_default` + fixtures
   `tenant_id` 变体 + 真机 T_3746→T_3741。
5. **X5** docs（config.example/ops-runbook §5.8/known-limitations §9/propose/本文件）。
6. **提交前门禁**：`fmt`/`clippy`/`test`/`release`/`run_integration.sh`；X2/X3 经 @oracle 复审。

---

## C.8 待拍板点与建议

1. **`auth_method="password"` 是否也允许在 `single_project` 下使用？**
   - 建议：**只允许在 `cross_project`**（校验强制 password⇔cross_project）。理由：password
     是"跨项目唯一路径"的专用机制，callback 只在实验室模式下存在，红线段最干净；单项目继续
     用更安全的 app-credential 或静态 token。若确有单项目 password 需求，可另开一张票放宽，
     但需单独安全评审。
2. **`project_id` 在 cross_project 的语义与命名。**
   - 建议：保留字段名 `project_id`（兼容），但在文档与启动 WARN 中明确它是**认证 scope**
     而非可见性边界；可选新增别名 `scope_project_id`（不推荐，徒增歧义）。若采纳别名，需
     config 校验二选一。
3. （次要）**`ambiguous_name_cross_project` 的粒度**：建议按 scope 区分 reason token（本条
   设计）；若认为两 token 冗余，可合并为 `ambiguous_name` + 附加 `scope=` 字段。建议保留独立
   token，排障更直接。

---

# 附录 D — 只取浮动 IP（floating-only address selection）

> 状态：**已实施（2026-10-16），待 oracle 红线 12 复审。** 默认 `any` 零回归；`floating` 需实例先关联浮动 IP（Neutron 操作），未关联前开启会让该实例解析失败为 `no_floating`。
>
> 实施落点：`AddressKind` 枚举 + `AddressSelection.kind` 硬过滤 + `SelectionError::NoKind` → `no_floating`/`no_fixed` reason token（`mod.rs` 按 `cfg.address_kind` 映射，客户端恒同构 `NotFound`）+ `config` 解析/Default/Debug + 7 个单元测试 + `case_openstack_floating_only` /
`case_openstack_no_floating_rejected` / `case_openstack_address_kind_default` 三个集成用例。
真机 FLT-TEST-01 验证见 `dev-docs/openstack-test-env.md`。

## D.0 需求与现状（已真机验证）

- **运维前提**：仅浮动 IP 可从公网到达实例；fixed（VXLAN 租户网）地址需手工设置网络，不利于网关按需拨号。因此解析实例 IP 时**只能取浮动 IP**。
- **现状**：现有 `prefer`（默认）是"类型排序 + **无浮动时回退 fixed**"——不满足"只能取浮动 IP"。
- **真机验证（2026-10-15，只读）**：
  - T_3741：Nova `addresses` 全 fixed；Neutron `floatingips` **0 个**。
  - T_3746：4 个浮动 IP，其中 **3 个 `status=DOWN` 未绑定实例端口**；1 个 ACTIVE 绑定到 `192.168.2.123`（非本批 GPU 实例网段）。
  - ⇒ 当前**所有可路由实例均无关联浮动 IP**；在云侧关联浮动 IP 之前开启 floating-only 会令全部实例 `no_floating` 拒绝。

## D.1 设计：新增"地址种类硬过滤"（默认关=现状零回归）

**配置**：`[openstack] address_kind = "any"（默认）| "floating" | "fixed"`

- `"any"`：与现状**字节等价**（`prefer` 排序 + 现有回退语义，零回归，包括现有 fixed-IP 端到端）。
- `"floating"`：**只接受 `AddrKind::Floating` 候选**；实例无任何 floating 地址 → 拒绝（独立 reason `no_floating`；客户端恒同构 `NotFound`），**绝不回退 fixed**；多候选仍按 `on_ambiguous` 裁决。
- `"fixed"`：镜像（只接受 fixed，无 → `no_fixed`；对称实现，成本≈0）。

**正交性**：`address_kind` 是**硬过滤**（进入 `prefer` 排序前按类型过滤）；`prefer` 保留为**同类型内排序**。两者组合语义明确（如 floating-only + prefer=floating 等价；floating-only + prefer=fixed 仍是只取 floating 但 fixed 优先排序无意义——文档说明）。

**实现落点**（`src/openstack/nova.rs` / `src/config.rs` / `src/openstack/mod.rs`）：
- `AddressSelection` 增 `kind: AddressKind`（`any|floating|fixed`，与现有 `AddrKind` 候选区分开）；
- `select_address`：在 `network`/family 过滤后、`prefer` 排序前，先按 `kind` 过滤候选；过滤后为空 →
  - `floating` → `reason="no_floating"`、`fixed` → `reason="no_fixed"`、`any` → 现行为；
  - 沿用 O7 的"合法空 vs 不可用"判别：无对应类型是**合法空**（响亮 reason），不是 `unparseable`；
- `OpenStackConfig` + TOML + 枚举校验 + Debug 同步；`config.example.toml` 注释。

## D.2 交互

- `network` / `address_family` / `on_ambiguous` / `scope=cross_project` **全部正交**：floating 过滤后再按这些筛选。
- ⚠ **`network` 过滤器注意**：浮动 IP 的归属网络是"浮动端口所在网络"（Neutron 关联），通常**与实例 fixed 网络不同名**；若同时配 `network`（如按 fixed 网名 `NET3741`），可能把 floating 候选过滤光 → `no_floating`。文档需提示：floating-only 模式下 `network` 应指向浮动网络名或留空。
- 日志/审计：`reason` token 进 `target=openstack` 日志；`target.host` 只来自解析；`AuditRecord` 格式不变。

## D.3 测试

- 单元（`nova.rs` 表驱动）：同实例 fixed+floating → floating-only 选 floating；仅 fixed → 拒绝 `no_floating`；floating-only + 多 floating → `on_ambiguous` 生效；`any`（默认）字节不变回归；`fixed` 镜像。
- 集成：`case_openstack_floating_only`（mock 实例带 floating，拨 floating）、`case_openstack_no_floating_rejected`（仅 fixed → 拒绝、reason=no_floating、0 拨号）、`case_openstack_address_kind_default`（any=现状回归）。
- 真机（2026-10-16，FLT-TEST-01 `bb45a399…`，同网同时携带 fixed `192.168.3.219` +
  floating `172.16.31.27`）：`address_kind="floating"` + `scope="cross_project"` 下解析
  选中 **floating**，审计 `target_host=172.16.31.27`；仅 fixed 的拒绝路径见集成用例。
  记录见 `dev-docs/openstack-test-env.md` §6。

## D.4 红线 / DoD

- 默认 `any` = 现状**零回归**（不打断现有 fixed e2e）；
- `floating` 仅取 floating、无则拒绝、**绝不回落 fixed**；失败对客户端恒同构；
- `target.host` 只来自解析；日志只摘要不泄 body；不改 audit/agent/app-cred 语义；
- DoD：配置 + 选择器过滤 + reason token + 3 测试 + docs；实施后经 oracle 红线 12 复审。

## D.5 工作量

S（约 0.5–1 人日 + 复审）：配置枚举/校验、`select_address` 加 kind 过滤、reason token、单测×3、集成×2~3、docs。

---

# 附录 E — 后端认证的 SSH 签名算法集支持

> 状态：设计（2026-10-16），待实施，**ORSOLid 后续交 fixer**。默认行为对 ed25519/ecdsa 零回归；本附录只补齐 **RSA 端用户密钥**用现代签名算法（rsa-sha2-*）经网关登录后端的能力。目标语义：**"支持全算法集" = 全现代集**（绝不含 SHA-1 的 `ssh-rsa`）。

## E.0 现状锚点与已钉死的事实

- 后端拨号唯一入口 `BackendDialer::connect`（`src/backend/mod.rs:441-462`），在
  `authenticate_publickey_with(&grant.target.user, public_key, None, signer)` 里传
  **`hash_alg = None`**（第 455 行）；其上方的注释（451-453）"让 russh 走默认"是
  **本附录要改掉的错误前提**。
- `authenticate_publickey_with`（russh 0.64.1 `src/client/mod.rs:503`）：`hash_alg` 流入
  `Signer::auth_sign(key, hash_alg, data)`——RSA 私钥据此产出 `rsa-sha2-512`/`rsa-sha2-256`；
  非 RSA 密钥忽略该值（算法由密钥类型决定）。
- `HashAlg`（ssh-key 0.7.0-rc.11）= `Sha256（default）| Sha512`。
- 调用点：`src/relay/agent.rs:1174-1178` —— `public_key = identities[index].public_key().into_owned()`，
  再 `dialer.connect(grant, public_key, &mut agent)`。**`public_key` 是 `russh::keys::PublicKey`
  （= ssh_key::PublicKey），有 `.algorithm() -> ssh_key::Algorithm`。**
- 类型可用：`russh::keys::{Algorithm, EcdsaCurve, HashAlg, PublicKey}` 均已 re-export
  （`russh/src/keys/mod.rs:78`）；`Algorithm::Rsa { hash: Option<HashAlg> }`
  （ssh-key `algorithm.rs:92`），RSA 公钥走 `Algorithm::Rsa { .. }`。
- **KEX 层无缺口**：russh client/server 默认 `Preferred.key`
  （`russh/src/negotiation.rs:210`）已列
  `Ed25519, Ecdsa(P256/P384/P521), Rsa{Sha512}, Rsa{Sha256}, Rsa{None}`。
  前腿（server）与后端腿（client）**协商层本身已通告现代集**；缺口仅在 `connect` 的签名 hash。
- 失败现象（已采信）：RSA 端用户密钥 → `hash_alg=None` → 旧式 `ssh-rsa`（SHA-1）→
  Ubuntu 24.04 sshd（OpenSSH ≥8.8 默认 `PubkeyAcceptedAlgorithms` 无 `ssh-rsa`）拒绝 →
  审计 `signature_algorithm="ssh-rsa"`、后端 `"as root" failed`。ed25519 经网关成功。

## E.1 算法选择矩阵（后端 agent 认证）

**纯函数**（`src/backend/mod.rs`）：
```rust
/// The RSA signature hash this gateway uses when the end-user's forwarded agent
/// signs for the backend. Non-RSA keys get `None` (their scheme is fixed by the
/// key type). RSA gets a modern rsa-sha2 hash — never SHA-1 (see E.2).
pub fn signature_hash_alg(key: &russh::keys::PublicKey, rsa_hash: HashAlg) -> Option<HashAlg> {
    match key.algorithm() {
        russh::keys::Algorithm::Rsa { .. } => Some(rsa_hash),
        _ => None,
    }
}
```

| 端用户公钥类型 | `hash_alg` | 结果签名算法 |
|---|---|---|
| RSA | `Some(rsa_hash)`，默认 `HashAlg::Sha512` | `rsa-sha2-512`（可配 `sha256`） |
| Ed25519 | `None` | `ssh-ed25519` |
| ECDSA P-256/384/521 | `None` | `ecdsa-sha2-nistp{256,384,521}` |
| sk-ecdsa / sk-ed25519 | `None` | `sk-...`（走 russh 默认；失败即报，不承诺） |
| DSA / ed448 / 其它 | `None` | 交给 russh；不支持即协议层失败，不做特判 |

**RSA 默认 = Sha512，理由**：
1. 与 OpenSSH 客户端自身的 RSA 偏好一致（`PubkeyAcceptedAlgorithms` 首推
   `rsa-sha2-512`，其次 `rsa-sha2-256`）；
2. 更强（SHA-512 > SHA-256）；
3. "只支持 256 不支持 512"的服务器仅存在于 OpenSSH 7.2/7.3（2016 年），2026 年可忽略。

**每次尝试只签一个 hash**：russh 不做逐请求的算法回退。因此**默认选一个**，不自动重试、
不降级（红线段 E.6）。为覆盖极少数只接受 `rsa-sha2-256` 的老服务器，**建议**提供可选
配置（见 E.8 待拍板点①）：`[backend] rsa_signature_hash = "sha512"（默认）| "sha256"`。

**实现落点**：
- `BackendDialer` 增字段 `rsa_signature_hash: HashAlg`（`BackendDialer::new` 从
  `config.backend.rsa_signature_hash` 取；无配置时 `HashAlg::Sha512`）。
- `connect`（`src/backend/mod.rs:441`）：
  ```rust
  let hash_alg = signature_hash_alg(&public_key, self.rsa_signature_hash);
  tracing::debug!(target: "backend", user = %grant.target.user,
      key_type = %public_key.algorithm(), ?hash_alg, "backend publickey auth");
  let outcome = handle
      .authenticate_publickey_with(&grant.target.user, public_key, hash_alg, signer)
      .await
      ...
  ```
  失败时把 `hash_alg` 拼进 `BackendError::Auth` 的 `user` 上下文（便于排障："RSA + sha512 被拒"）。
- **不改** `relay/agent.rs` 的身份匹配/单签名面（红线 4 不变）。

## E.2 旧式 `ssh-rsa`（SHA-1）

**裁决：默认不支持，且不提供开关——永不回溯。**
- 语义约束："支持全算法集 = 全现代集"。SHA-1 已被 OpenSSH ≥8.8 默认移除、属已知破哈希；
  提供 `allow_legacy_ssh_rsa` 会**把不安全默认正常化**并扩大降级面（攻击者可诱导降级）。
- `hash_alg=None` 对 RSA 在 russh 里即产 `ssh-rsa`；E.1 的映射保证 RSA **永远**拿到
  `Some(...)`，因此 **SHA-1 在这条路径上不可达**。
- 若未来确需连接"博物馆级"老服务器，那是**另一个安全评审过的独立票**，不在 E 的语义内。
  （附录 D 的 `allow_any_authenticated_key` 那种"刺眼开关"也不适用于此：那是可见性放大，
  这是密码学降级——性质不同。）

## E.3 服务器腿（client → gateway）"全算法集"确认

- **已支持现代集**：前腿用 `ServerConfig::default().preferred`
  （`src/server/mod.rs:build_with_clients`，当前仅按配置覆盖 `cipher`），其 `key` 已含
  ed25519/ecdsa/rsa-sha2-512/rsa-sha2-256/ssh-rsa。**协商层无缺口**，仅文档说明。
- **前腿 SHA-1 姿态（建议收紧，待拍板点②）**：当前 `Preferred.key` 末项 `Rsa { hash: None }`
  意味着**前腿接受 SHA-1 的 `ssh-rsa` 用户签名**。建议在 `build_with_clients` 里把该项从
  server 侧 `preferred.key` 过滤掉：
  ```rust
  server_pref.key = std::borrow::Cow::Owned(
      server_pref.key.iter()
          .filter(|a| !matches!(a, Algorithm::Rsa { hash: None }))
          .cloned().collect());
  ```
  这样前腿也只认现代集（与后端腿语义对称）。**这是行为变更**（拒绝仅会用 ssh-rsa 的老客户端），
  故列为待拍板；若采纳，须配一个负例断言 `ssh -o PubkeyAcceptedAlgorithms=ssh-rsa` 被拒。
- **client 腿 host-key 侧**（后端 sshd 呈现的 host key 算法）：`BackendDialer::new` 的
  `client::Config.preferred.key` 同样可去掉 `Rsa{hash:None}`（host key 认证靠 fingerprint/CA，
  非签名方案；去掉纯属卫生）。低优先。

## E.4 直连私钥路径（备注）

本仓后端认证**只用 agent**（`connect_agent` 是唯一形态，plan-agent-only D3），无直连私钥路径。
若未来重新引入，同样必须在构造 `PrivateKeyWithHashAlg::new(key, signature_hash_alg(key, rsa))`
时按算法选 hash——**复用一个 `signature_hash_alg`，不得各处各写**。本条仅备注，不在本次实现。

## E.5 测试

### E.5.1 单元（`src/backend/mod.rs`）
- `signature_hash_alg` 纯函数表驱动：
  - `Algorithm::Rsa { hash: None }` 公钥（`ssh-keygen -t rsa` 产出的公钥其 `algorithm()`
    即此形态）→ `Some(Sha512)`（默认）、`Some(Sha256)`（配置为 sha256 时）；
  - Ed25519 → `None`；
  - Ecdsa P-256/384/521 → `None`；
  - （可选）`SkEd25519`/`SkEcdsaSha2NistP256` → `None`。
- 配置解析（若采纳 E.8①）：`rsa_signature_hash` 默认 `sha512`、`"sha256"` 可解析、未知值报
  `backend.rsa_signature_hash`、`Debug` 呈现。

### E.5.2 集成
- **新用例 `case_backend_rsa_signer`**：端用户持有 **RSA** 密钥（用例内 `ssh-keygen -t rsa -b 3072`），
  其 `.pub` 写入后端 `authorized_keys`；`ssh -A` 以该 RSA 密钥做前腿登录，断言会话成功。
  - 后端 sshd **必须在默认 `PubkeyAcceptedAlgorithms` 下拒绝 `ssh-rsa`**：`subtopo.sh` 的手写
    `sshd.cfg` 不设该指令，故沿用 OpenSSH 编译默认（Fedora 44 含 `rsa-sha2-512,rsa-sha2-256`、
    不含 `ssh-rsa`）。用例启动时可 `sshd -T -f <cfg> | grep -i pubkeyaccepted` 断言含
    `rsa-sha2-`、不含 `ssh-rsa`，作为前提证明。
  - 断言：会话跑通（若网关仍签 SHA-1 则 sshd 必拒——用例本身即证明）；网关 debug 日志含
    `hash_alg=Sha512`；可选 grep 后端 `sshd.log`（`-e` 记 INFO；如需算法证据把该用例 sshd 配
    `LogLevel DEBUG` 后 grep `rsa-sha2-512`）。
  - 回归：现有 ed25519 agent 用例（`case_agent_auth` 等）不变。
- 环境既有 53P/0F/2S 基线不得回归。

### E.5.3 真机（验收）
- `FLT-TEST-01`（`bb45a399…`）：用 `~/test-key.pem`（RSA）经网关
  `ssh -A bb45a399…@127.0.0.1`（`address_kind="floating"` + `scope="cross_project"`，root）。
  **直连已 OK、网关解析/浮动选择（附录 D）已 OK**，本附录的验收目标是**后端认证成功**：会话
  跑通、`resolve_ok=1`、后端 `Accepted publickey`（RSA）、无 `"as root" failed`。
  记录追加到 `dev-docs/openstack-test-env.md`（含 `hash_alg=Sha512` 证据）。

## E.6 红线 / DoD / 分层（E 系列）/ 工作量

### E.6.1 红线
1. **RSA 恒用现代 rsa-sha2，绝不放 SHA-1**；不自动重试、不降级（无 SHA-1 兜底路径）。
2. **非 RSA 密钥 `hash_alg=None`**，行为与改动前字节一致。
3. `signature_hash_alg` 是**纯函数**、表驱动单测；任何密钥材料/签名不进日志。
4. **签名面不扩大**：仍只对唯一匹配的 agent 身份签一次（红线 4 不变）。
5. **失败协议原生**：后端拒绝即 `BackendError::Auth` 硬失败，绝不换更弱算法再试。
6. 默认零回归：ed25519/ecdsa 路径、既有审计/指标格式不变。
7. 前腿 SHA-1 收紧（若采纳）是**独立、可回退**的行为变更，需自己的负例测试与文档。
8. **红线 12**：E1、E2 的 diff 合并前经 @oracle 复审。

### E.6.2 分层提交
- **E1**（安全审查点）：`signature_hash_alg` + `connect` 接线（默认 Sha512）+ 单测 + debug 日志。
- **E2**：`[backend] rsa_signature_hash` 配置（若采纳）+ 解析/校验/Debug + 单测。
- **E3**：前腿 SHA-1 收紧（若采纳）+ 负例测试。
- **E4**：`case_backend_rsa_signer` 集成用例 + 真机 FLT-TEST-01 验收 + `openstack-test-env.md`。
- **E5**：docs（config.example/ops-runbook/known-limitations/本文件标注）。

### E.6.3 DoD
- E1–E5（E2/E3 视待拍板）落地；E.5.1 单测全绿；`case_backend_rsa_signer` + 现有 53 用例全绿；
  `fmt`/`clippy -D warnings`/`test`/`release`/`run_integration.sh` 全绿；真机 RSA 登录通过；
  docs 更新；E1/E2 经 @oracle 复审。

### E.6.4 工作量
| 阶段 | 内容 | 估时 |
|---|---|---|
| E1 | `signature_hash_alg` + 接线 + 单测 | 0.25 天 |
| E2 | 可选配置 + 单测 | 0.25 天 |
| E3 | 前腿 SHA-1 收紧 + 负例 | 0.25 天 |
| E4 | 集成用例 + 真机 + 记录 | 0.5–0.75 天 |
| E5 | docs | 0.25 天 |
| **合计** | | **~1.5–1.75 人日 + 复审** |

### E.6.5 风险
| # | 风险 | 严重度 | 缓解 |
|---|---|---|---|
| R23 | 默认选错 RSA hash（512 vs 256）致个别服务器拒绝 | 低 | 默认 512 + 可选 `sha256` 开关；不自动重试 |
| R24 | 误引入 SHA-1 兜底 | 高 | 映射保证 RSA 恒 `Some`；红线 E.6.1；E2 只允许 sha256/512 |
| R25 | 非 RSA 键被误传 `Some(hash)` 致失败 | 中 | 表驱动单测覆盖 ed25519/ecdsa→None |
| R26 | 前腿收紧拒绝老客户端 | 中 | 列为待拍板 + 负例 + 文档；可回退单 commit |
| R27 | 测试 sshd 默认恰好接受 ssh-rsa 使用例空转 | 低 | 用例先 `sshd -T` 断言默认不含 ssh-rsa |

## E.7 给 fixer 的分层清单

1. **E1** `src/backend/mod.rs`：`pub fn signature_hash_alg(&PublicKey, HashAlg)->Option<HashAlg>`；
   `BackendDialer` 增 `rsa_signature_hash`（默认 `Sha512`）；`connect` 用其结果替换 `None` +
   debug 日志 + 失败上下文；改掉 451-453 的过时注释；单测（RSA→Some(Sha512)、ed25519/ecdsa→None）。
2. **E2**（若采纳）`src/config.rs`：`RawBackend.rsa_signature_hash`（默认 `"sha512"`）+
   `BackendConfig.rsa_signature_hash: HashAlg` + 解析/校验/`Debug`；单测。
3. **E3**（若采纳）`src/server/mod.rs:build_with_clients`：过滤 server `preferred.key` 的
   `Rsa{hash:None}`；负例集成用例。
4. **E4** `tests/integration/case_backend_rsa_signer.sh`（RSA 密钥 + 断言 sshd 默认不含 ssh-rsa +
   会话成功 + `hash_alg=Sha512`）；`run_integration.sh` 注册；真机 FLT-TEST-01；
   `dev-docs/openstack-test-env.md` 记录。
5. **E5** docs（config.example `[backend]` 段、ops-runbook、known-limitations、本附录标注）。
6. **门禁**：`fmt`/`clippy`/`test`/`release`/`run_integration.sh`；E1/E2 经 @oracle 复审。

## E.8 待拍板点与建议

1. **RSA 默认 hash（512 vs 256）与是否加配置开关。**
   - 建议：**默认 `Sha512`**（对齐 OpenSSH、更强），**并加 `[backend] rsa_signature_hash =
     "sha512"|"sha256"`**。理由：RSA 服务器粒度差异（极老的 7.2/7.3 只认 256）无法在编译期消除，
     一个低成本开关避免"换个服务器要重新部署"；不自动重试，保持签名面最小。
2. **前腿是否默认禁 SHA-1（`ssh-rsa`）。**
   - 建议：**是**（E3）——让"全现代集"语义前后对称，SHA-1 用户签名是明确的降级面。以独立 commit
     提交、附负例测试与 known-limitations 说明，可单独回退；若维护者担心拒绝老客户端，则**本附录
     只文档说明、把收紧留独立票**。
3. **后端是否保留任何 SHA-1 逃生口。**
   - 建议：**否**（E.2）——永不回溯；确需连博物馆服务器属独立安全评审票。

> 一句话验收：RSA 端用户密钥（`~/test-key.pem`）经网关 `ssh -A <uuid>` 在现代 sshd 上登录成功，
> 且网关从不签 SHA-1。
