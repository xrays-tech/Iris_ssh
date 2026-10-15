# Known Limitations

本文件记录 SSH 网关已知的限制与遗留项，供运维与后续批次参考。每项均含「触发条件」与「处置」。

## 1. 后端 host key `@cert-authority`（CA 签发 host 证书）——M4 已实现（`11d42cb`）

- **状态**：**M4 已实现并实跑 PASS**。`HostKeyVerifier` 证书分支已接线（src/backend/mod.rs:249-276）：host 证书经**五步校验链**——第 0 步 `WrongCertType`（普通 user 证书不能顶替 host 证书，封死 KEX 冒充）→ ① `signature_key()` ∈ 受信 CA 集 → ② `verify_signature()` → ③ 有效期窗口（时钟注入，`now_unix` 读不出时 `u64::MAX` 全部判 Expired，**fail-closed**）→ ④ `valid_principals()` 含目标主机名（大小写/尾点/空白规范化匹配，严格不放大信任）。`expected_host` 锚定本次拨号目标（backend/mod.rs:413-415）。无 CA 配置时回落内层指纹 legacy（pinned/accept-new）路径，向后兼容。
- **已落测试**：`tests/integration/case_host_cert_authority`（正例 PASS：host-cert 后端 KEX 消费 + exec）；负例用例（非受信 CA/过期/错 principals）随链生效翻转——见 P1-2 的 once-live 断言设计。单元层负例硬断言：ca/mod.rs:504/529/548（篡改/过期/错 principal）。
- **影响**：后端 host 证书化/CA 统一签发的信任收敛可用。
- **触发条件**（运维说明）：后端纳管规模化、需要 host key 证书化（CA 统一签发 host 证书）时，配合测试 CA 生成 host 证书并纳入网关 `[ca] trusted_ca_keys`。
- **备注**：网关第 0 步 `WrongCertType` 比 OpenSSH known_hosts 的 `@cert-authority` 传统实现更严（其不区分 cert type）——此为有意的安全护栏，勿当冗余删除。

## 2. 后端 `TrustedUserCAKeys`（用户证书拨号 / cert-dial）——已随 agent-only 改造删除

- **状态**：**cert-dial 已在 plan-agent-only D3 中删除**，不再是能力项。原先 `[backend] backend_auth="cert"` 在每次 `connect` 现签短期用户证书的路径（`authenticate_with_certificate`）连同 `[ca] signing_key` / `[ca] cert_lifetime` / `[backend] backend_auth` / `[backend] private_key` / `credential_map` 一并移除；`case_cert_dial` 用例随之下线。
- **影响**：后端不再支持"只信 `TrustedUserCAKeys`、不放用户公钥"的接入方式。后端要接受网关会话，`authorized_keys` 必须放**终端用户自己的公钥**，由转发来的 ssh-agent 签名（这是唯一的后端认证方式）。
- **触发条件**（运维说明）：若某后端策略只允许 `TrustedUserCAKeys`，当前版本无法满足——需要 agent 穿透，或等后续批次重新引入"网关签发短期用户证书"作为第二身份。旧配置里残留的 `backend_auth` / `private_key` / `signing_key` 等键按未知键**忽略**，不会报错也不会生效。
- **备注**：`[ca] trusted_ca_keys` **仍保留且是 verify-only 的**——用于（a）前端用户证书认证、（b）后端 host 证书（`@cert-authority`）校验，见第 1 节。变的只是"网关不再签发"。

## 3. 半开假死（iptables DROP）与 netem 真机演练未在本机实跑

- **状态**：`scripts/halfopen_inject.sh` + `case_halfopen_lost.sh`、`scripts/netem_ctl.sh` + `case_netem_slow.sh` 已交付（真机专用，Linux + iptables/tc；本机 macOS 无此能力 → 集成套件 capability-gated SKIP，检出口径为 `keepalive_interval × (max_miss+1)` ≈ 45s，非旧稿 25s）。
- **触发条件**：下一维护窗口在测试真机 `root@47.109.73.53`（Linux，可 root，iptables/tc 可用）各跑 ≥1 次并归档输出到 `docs/`。
- **处置**：计划中的维护演练项；执行命令见脚本头注释。

## 4. 长跑 soak（8h）未跑

- **状态**：`scripts/run_soak.sh` 短程自证 PASS（45s、127 ops、RSS 漂移 1733KB ≤ 阈值、active=0、backend_lost=0）；长程泄漏趋势证据弱（短窗对慢泄漏不敏感）。
- **触发条件**：排一个 `SOAK_DURATION=28800`（8h）夜间窗口，报告入 `docs/soak-report.md`。
- **处置**：脚本已参数化，零开发量；运维排程即可。

## 5. B5 HA 演练为 client-side readyz 近似、PuTTY/WinSCP 为算法集模拟

- **状态**：`scripts/ha_drain.sh` 用「client-side least-readyz chooser」近似 L4 LB（本机无 haproxy/socat），演练断言链完整（双副本 → SIGTERM 摘流 → 新会话转 B → 存量收 DISCONNECT(11) → 重纳回流）；`case_client_matrix` 以 `-o` 算法集模拟 PuTTY/WinSCP 协商。
- **触发条件**：具备真实 L4 LB（haproxy/keepalived least-conn）或真实 Windows 客户端的维护环境。
- **处置**：文档标注为近似；有环境时补测真实 LB 路径与真实客户端，断言不变。

## 6. offerred 阶段无条件 Accept 的控制面预热代价

- **状态**：M3 为满足证书授权语义，`auth_publickey_offered` 不再早期拒绝未授权裸钥，改为「无条件 Accept + 预热」、最终授权推迟到签名后回调（有 `max_auth_attempts=10` + `auth_rejection_pad` + resolver 熔断兜底）。
- **影响**：每个未授权 probe 也会触发一次控制面 resolve 预热 miss，量级可控。
- **处置**：建议在 /metrics 观察 probe 期 resolve QPS 占比，必要时优化预热策略。

## 7. 单连接 scp 吞吐为架构限制（M2-U6 关闭决议）

- **状态**：`docs/perf-report.md`（M2-U6 结论）+ 外部调研（lib-1）。经网关单连接 scp 吞吐 ~26-27 MB/s，相对直连 ~186-216 MB/s **损耗 ~85%**，目标 ≤15% **判定为当前架构不可达成**（双隧道「终结+重建」双重加解密 + russh 逐包开销）。
- **已试验**：数据路径调度重构（mpsc+sender task）→ 零收益，经 @oracle 裁决回退（提交 `d6c4eb5`）；`max_packet`/`window_size` 扫描影响 <1%。
- **调研提示的关键机会（未落地，需实测）**：russh 单跳回环可达 400~580 MB/s；同构双会话中继（warpgate）rsync≈直连；**两份被忽视的低成本项第一是双腿 `nodelay=true`（当前 Nagle 开）**，其次是腿 A/B 隔离诊断、cipher A/B（aes-gcm vs chacha20）、写路径流水化（仿 bssh 6.2x 经验）。
- **影响**：粗略说「经网关 scp 比直连慢 ~6 倍」属预期特性，非故障；容量规划按此基准（连接级 KPI：ControlMaster 复用、每连接建立成本、并发会话容量）而非单连接吞吐。
- **触发条件 / 处置**：若单连接吞吐成为业务硬需求 → 架构级选项：ProxyJump 直通引导（客户端 `-J`，内层 SSH 密文透传省一跳加密，UX/审计需产品决策）或可信后端裸 TCP 直通（需威胁建模评审）。注意这两条都依赖 `direct-tcpip`，而它在 agent-only 改造中已是**无条件恒拒绝**——要重开属于产品决策，不是配置项。参照基线见 perf-report 末尾。

## 8. 控制面契约变更：`policy.backend_auth` / `tcp_forwarding*` 已废弃，jump 已删除

- **状态**：agent-only 改造（plan-agent-only D1..D5，`1f00dd7`..`8152126`）删掉了后端侧凭证与跳板能力，控制面上与之对应的三个策略字段随之**失效**：`policy.backend_auth`、`policy.tcp_forwarding`、`policy.tcp_forwarding_targets` **网关一律忽略**。serde 忽略未知字段，所以旧控制面下发的记录仍然可用——不会报错，但也不会产生任何效果。
- **唯一门**：后端认证的唯一开关是 `policy.agent_forwarding`。为 `false` 的 grant **整体拒绝**，既没有、也不会回落成 key/cert（网关手里没有第二套凭证）；`tcp_forwarding = true` 不改变任何行为，`direct-tcpip` 恒拒绝（jump 模式已随 D1 删除，网关不是出站跳板）。
- **触发条件**（运维说明）：控制面若仍在下发这三个字段，需要在下一次策略迭代中删除，以免运维或审计从策略里读出"这个会话开了转发/用了 key"的错觉。
- **处置**：无需数据迁移。审计侧判断"是否 agent 会话"看审计记录的 `auth_kind="agent"`（见 `docs/ops-runbook.md` §5.7），指标看 `sshgw_agent_backend_auth_*`；上线前确认告警与看板没有基于 `tcp_forwarding` 或 `backend_auth` 的规则。

## 9. OpenStack 实例 UUID 即路由（方案 B）——已实现，但**只授权实验室/内网 PoC**

- **状态**：plan-openstack 方案 B 已按分层 O1..O5 落地（`routing=openstack_only` + `authorization=openstack_only` + `allow_any_authenticated_key=true`），**默认关闭**：不写 `[openstack]` 节或 `enabled=false` 时，路由谓词对所有 principal 都答"控制面"，行为与旧版一致。其后 O6（实例名路由，默认关）与 O7（解析鲁棒性）按 appendix A/B 落地。用例覆盖 `case_openstack_*` 共 13 个（含 MUST1 预认证零联网 `case_openstack_preauth_no_lookup`、名字路由三例、wire-shape 两例）。
- **授权语义（最重要的一条）**：`authorization="openstack_only"` 意味着**没有控制面这道授权**——任何通过前腿验签的密钥，只要知道/猜到实例 UUID，就能登进该实例，范围仅受 application credential 的 project scope 限制。`allow_any_authenticated_key=true` 是刻意刺眼的开关名，启动打 WARN；**禁止**用在共享或公网可达的网关上。缓解手段只有纵深：最小 project scope、`max_auth_attempts` + 负缓存限速枚举、所有失败对客户端同构拒绝、审计记录每次解析。
- **当前只有纯模式可启用（方案 A 未实现）**：`routing="hybrid"` 与
  `authorization="control_plane"`（控制面授权、Nova 只换地址）都解析得动，但在
  `enabled=true` 时**被配置校验拒绝**——否则会出现"UUID 经 Nova 解析、却从未被控制面
  授权"的静默越权。因此今天可开启的组合唯一：`routing=openstack_only` +
  `authorization=openstack_only` + `allow_any_authenticated_key=true`。
  `enabled=false`（默认）永远可接受，且是唯一安全的生产取值。
- **`routing="openstack_only"` 没有控制面回退**：非 UUID principal 在任何网络调用之前就被拒绝（`reason=unrouted`），`[control_plane]` 节可整节省略。这不是降级路径，而是路由表本身决定的。
- **预认证零联网**：`auth_publickey_offered` 只跑纯路由谓词，Nova/Keystone 查询发生在签名校验之后。改动这条等于把探测阶段变成未认证的查询放大器（MUST1，有黑盒用例看守）。
- **目标地址只来自 Nova**：用户名里不允许携带 host/IP（SSRF 红线），多网络且未配 `network` 的实例按 `on_ambiguous="reject"` 拒绝。**代价**：这类实例在配置补上 `network` 之前是不可达的，属预期失败而非故障。
- **缓存 vs fail-open 的分工**：`[openstack] cache_ttl` 之内缓存是权威的（与控制面路由一致，这不叫 fail-open）；TTL 过期后 Nova 不可达即拒绝，因为 `fail_open=false`（要放开必须显式 `fail_open=true` **且** `[backend] host_key_policy="pinned"`）。集成用例 `case_openstack_upstream_down` 用 1s TTL 把"过期后必须拒绝"钉死。
- **本批次未实现/已裁决的偏离**（对着 plan-openstack 的差异说明，供复审）：
  - `backend_user_map` 的 `match_image` **未实现**（plan §3.4 标为可选；按镜像名匹配还要额外查 Glance，v1 不做），且 `match_name` 只做**精确/前缀**匹配、不引入 `regex` 依赖（正是 plan 建议的 v1 取舍）。已实现的映射链：实例 metadata 键 → `[[openstack.backend_user_map]]` 规则（`match_name` + `match_metadata` AND、声明序首个命中）→ `default_backend_user`。
  - `user_domain_name` / `project_domain_name` **已从配置删除**：application-credential/token 请求体都不发送它们，属于死配置（plan §3.6 草案里的字段）。
  - metadata 命中但值非法（空/含空白或控制字符）按 `reason=user_map` **告警后跳过并回落默认用户**，而不是当作 `Decode` 硬失败——避免一个脏标签把整批实例锁在门外。
  - `enabled=false` 的短路放在组合规则之前：关掉特性时不必先复位 `routing`/`authorization`；枚举拼写错误仍在校验期报错（拼错不能静默变成"关闭"）。
  - `auth_method="token"` 分支的 `auth_body` 已删除（该枚举值仍可解析，走 token 逃生口）；Keystone token 刷新单飞，401 只失效触发失败的那一个 token。
- **实例名路由（O6，appendix A，默认关）**：`route_by` 默认 `["uuid"]`，零回归；`route_by = ["uuid","name"]` 才启用。已裁决的边界：UUID 形态永远优先、从不视为名字；名字只作百分号编码的 query 值、绝不进路径（SSRF 面不放松）；Nova 的 `name` 是子串搜索，网关本地全等过滤，0/多全等命中对客户端都等于 404（不猜机器）；名字边界只到"非空、≤255、无控制字符"（是 bound 不是 grammar）。观测靠 `sshgw_openstack_resolve_by_{uuid,name}_total`，**审计记录格式不变、不加字段**。已知代价：实例名不是唯一资源，改名/重名是运维现实，名字路由天然带"重名即拒绝"的可用性成本。
- **解析鲁棒性（O7，appendix B）**：Nova body 逐字段独立解码（`decode_server`），任一非关键字段的类型漂移（如 T_3741 的 `image: ""`）不再拖垮 `addresses`；`addresses` 的"缺失/空 map（合法 no_address）"与"结构在但读不出（`unparseable`，响亮）"显式区分；解码失败/不可用的 warn 只带 `summarize_body` 结构摘要（keys/类型/网络数/长度），**绝不带 body**；语料固化在 `tests/fixtures/openstack/servers/`（两份真机逐字捕获 + 12 个构造变体，表驱动）。已裁决的偏离：不新增 `SelectionError::Unparseable` 变体（unusable 标志在地址选择之前就地判定并拒绝，加变体是死代码）；`summarize_body` 用 appendix 允许的回退形态（无 sha256——`ring` 非直接依赖，不引新依赖）。
- **触发条件**（运维说明）：需要在无控制面的内网实验环境里按实例 UUID 直连时启用；生产一律保持 `[openstack]` **默认关（不启用）**，待方案 A（`authorization="control_plane"` 控制面授权）落地后再考虑启用。
- **处置 / 复审**：启用前逐条确认上面的授权语义；上线看板加 `sshgw_openstack_resolve_err_total`、`sshgw_openstack_resolve_by_{uuid,name}_total` 与 `target=resolve` 的 reason 分布。复审重点：**方案 A（`authorization="control_plane"`）缺位是否可接受——它决定 hybrid 是否该被保留为"解析通过但不可启用"**、方案 B 的授权边界、`match_image` 的去留、"缓存 TTL 内不联网"是否与运维预期一致，以及 O6a/O6b/O7a/O7b 四层（名字路由配置与实现、逐字段解码、响亮摘要）——它们按红线停在本地待 oracle 复审后才推送。
