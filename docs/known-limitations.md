# Known Limitations

本文件记录 SSH 网关已知的限制与遗留项，供运维与后续批次参考。每项均含「触发条件」与「处置」。

## 1. 后端 host key `@cert-authority`（CA 签发 host 证书）——M4 已实现（`11d42cb`）

- **状态**：**M4 已实现并实跑 PASS**。`HostKeyVerifier` 证书分支已接线（src/backend/mod.rs:249-276）：host 证书经**五步校验链**——第 0 步 `WrongCertType`（普通 user 证书不能顶替 host 证书，封死 KEX 冒充）→ ① `signature_key()` ∈ 受信 CA 集 → ② `verify_signature()` → ③ 有效期窗口（时钟注入，`now_unix` 读不出时 `u64::MAX` 全部判 Expired，**fail-closed**）→ ④ `valid_principals()` 含目标主机名（大小写/尾点/空白规范化匹配，严格不放大信任）。`expected_host` 锚定本次拨号目标（backend/mod.rs:413-415）。无 CA 配置时回落内层指纹 legacy（pinned/accept-new）路径，向后兼容。
- **已落测试**：`tests/integration/case_host_cert_authority`（正例 PASS：host-cert 后端 KEX 消费 + exec）；负例用例（非受信 CA/过期/错 principals）随链生效翻转——见 P1-2 的 once-live 断言设计。单元层负例硬断言：ca/mod.rs:504/529/548（篡改/过期/错 principal）。
- **影响**：后端 host 证书化/CA 统一签发的信任收敛可用。
- **触发条件**（运维说明）：后端纳管规模化、需要 host key 证书化（CA 统一签发 host 证书）时，配合测试 CA 生成 host 证书并纳入网关 `[ca] trusted_ca_keys`。
- **备注**：网关第 0 步 `WrongCertType` 比 OpenSSH known_hosts 的 `@cert-authority` 传统实现更严（其不区分 cert type）——此为有意的安全护栏，勿当冗余删除。

## 2. 后端 `TrustedUserCAKeys`（用户证书拨号 / cert-dial）——M4 已实现（`11d42cb`）

- **状态**：**M4 已实现并实跑 PASS**。后端证书拨号已落地（src/backend/mod.rs:516-548 `authenticate_with_certificate`）：`[backend] backend_auth="cert"` 时，每次 `connect` **现签一短期用户证书**（principals=`target.user`、lifetime=`[ca].cert_lifetime`、key_id 含审计标识），**不缓存不复用**；内层身份密钥优先用运维配置，否则一次性 ephemeral Ed25519 密钥对（cert 模式可省 `private_key` 的依据，后端信任的是 CA 而非特定网关密钥）；无 CA → fail-fast。`case_cert_dial` 实跑 PASS（cert-only 后端、authorized_keys 明确为空 → 网关会话成功即真证书认证证明，且先经 direct cert login 自证后端信任链）。
- **影响**：后端配置 `TrustedUserCAKeys` 要求用户证书认证时，网关以短期证书登录可用；`backend_auth` 缺省 `"key"` 走原私钥路径，零回归。
- **触发条件**（运维说明）：后端安全策略要求用户级 CA 统一签发（网关短期用户证书；后端 `TrustedUserCAKeys` 校验）时；真机 `root@47.109.73.53` 可选加跑（改其后端 sshd_config，需协调维护窗口）。
- **备注**：cert 模式若提供 `[ca] signing_key` 必须以 `trusted_ca_keys` 同配（互斥校验 config.rs:865-868）；规模化可考虑进程级复用一次性身份密钥（证书仍现签），纯优化项。

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
- **触发条件 / 处置**：若单连接吞吐成为业务硬需求 → 架构级选项：ProxyJump 直通引导（客户端 `-J`，内层 SSH 密文透传省一跳加密，UX/审计需产品决策）或可信后端裸 TCP 直通（需威胁建模评审）。参照基线见 perf-report 末尾。
