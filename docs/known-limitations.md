# Known Limitations

本文件记录 SSH 网关已知的限制与遗留项，供运维与后续批次参考。每项均含「触发条件」与「处置」。

## 1. 后端 host key `@cert-authority`（CA 签发 host 证书）——测试拓扑已就绪，E2E 拒绝链待 src M4-T1

- **状态**：M4-I tests 已交付证书拓扑——`scripts/cert_topo.sh`（ssh-keygen 签发 host/user 证书 + CA）、`subtopo.sh` 的 `SUBTOP_SSHD_HOST_KEY/CERT` + `[ca] trusted_ca_keys`、`tests/integration/case_host_cert_authority`。**已验证**：后端出示 host 证书时网关 client 腿能消费证书并连通（`case_host_cert_authority` PASS，real E2E exec）。
- **仍受限**：`@cert-authority` 四步校验链（`signature_key() ∈ 受信 CA` → 验签 → 有效期 → principals 含目标主机）尚未在 src `backend/mod.rs:129-135` 接线（仍按内层公钥指纹 accept-new/pin 信任）。故**非受信 CA / 过期 / principals 不含目标主机** 的 host 证书仍会被网关接受（负例用例已备好并在检测到链生效后启用）。
- **影响**：后端 host 证书化/CA 统一签发的信任收敛暂不可用；当前以 accept-new 或感知内层指纹降级。
- **触发条件**：后端纳管规模化、需要 host key 证书化（CA 统一签发）时。
- **处置**：src M4-T1 落地 `HostKeyVerifier` 证书分支 + `host_key_policy=cert-authority` 后，`case_host_cert_authority` 的负例自动由「pending」翻转为真实断言，无需改测试。

## 2. 后端 `TrustedUserCAKeys`（用户证书拨号 / cert-dial）——拓扑已自证，网关拨号 E2E 待 src M4-T2

- **状态**：M4-I tests 已交付拓扑与自证——`case_cert_dial` 起 cert-only 后端（`TrustedUserCAKeys` + 空 authorized_keys），**已验证**：由测试 CA（`userca`）签发、principals=后端用户的用户证书经 direct `-o CertificateFile` 登录后端成功（后端信任链 + 我方签发自证 PASS）。
- **仍受限**：网关→后端的 cert-dial（`backend_auth=cert`，connect 时现签短期用户证书走 `authenticate_openssh_cert`）尚未在 src `backend/mod.rs`（现仅 `authenticate_publickey` key-dial，mod.rs:295）落地。故 `[backend] backend_auth="cert"` 被当前网关忽略；cert-only 后端下网关拨号被拒，`case_cert_dial` 网关部分 SKIP（capability-gated，非假 PASS）。
- **影响**：后端若配置 `TrustedUserCAKeys` 要求用户证书认证，网关暂不能以短期证书登录（当前仍走网关后端私钥 + 后端 authorized_keys 默认路径，功能不受损）。
- **触发条件**：后端安全策略要求用户级 CA 统一签发（网关短期用户证书；后端 `TrustedUserCAKeys` 校验）时。
- **处置**：src M4-T2 落地 backend 证书认证 + `backend_auth` 后，`case_cert_dial` 由 SKIP 翻转为 PASS；真机 `root@47.109.73.53` 可选加跑（改其后端 sshd_config）。

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
