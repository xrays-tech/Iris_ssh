# Known Limitations

本文件记录 SSH 网关已知的限制与遗留项，供运维与后续批次参考。每项均含「触发条件」与「处置」。

## 1. 后端 host key `@cert-authority`（CA 签发 host 证书）未接线

- **状态**：M3 交付时未实现（backend/mod.rs:128-135 的 `host_key_fingerprint` 对证书仍按「内层公钥」算指纹）。
- **影响**：网关 client 腿的 `HostKeyVerifier` 只支持 `pinned`（固定内层指纹）与 `accept-new` 两种策略；后端 sshd 若签发 host 证书（`@cert-authority` 体系），网关无法按「证书签名键 ∈ 受信 CA」来信任，需改用感知已知的 host 证书内层指纹或降级为 accept-new。
- **触发条件**：后端纳管规模化、需要 host key 证书化（CA 统一签发 host 证书）运维时。
- **处置**：列为 M4（后端基础设施专项）①；M4 判定性 DoD：host cert 校验 `signature_key()` ∈ 受信 CA 集 + `check_server_key` 单测 + E2E。
- **代码占位**：`src/backend/mod.rs:128-135` 处已标注 `// M4: @cert-authority — current inner-key fingerprint is a placeholder`。

## 2. 后端 `TrustedUserCAKeys`（用户证书拨号）未实现

- **状态**：M3 交付时网关→后端认证仍走私钥路径（backend/mod.rs:290 `authenticate_publickey`），无证书拨号代码/用例。
- **影响**：后端若配置 `TrustedUserCAKeys` 期望用户证书认证，网关还不能直接以短期证书登录后端（当前用网关后端私钥 + 后端 `authorized_keys` 网关公钥方案，为 propose §3.3 的默认路径，功能不受损）。
- **触发条件**：后端安全策略要求用户级 CA 统一签发（gateway 短期用户证书；后端 `TrustedUserCAKeys` 校验）。
- **处置**：列为 M4（后端基础设施专项）②；M4 判定性 DoD：cert-dial E2E（网关用 CA 签发的动态证书认证后端，证书过期拒绝、CA 轮换无感）。

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
