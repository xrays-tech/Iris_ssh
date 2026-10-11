# 客户端兼容矩阵 + Host Key 轮换降级演练（M3 A4）

> 状态：**初版（M3-I）**｜维护：tests lane｜配套用例：`tests/integration/case_client_matrix.sh`、
> `tests/integration/case_hostkey_rotation.sh`
> 背景见 `dev-docs/plan-m3.md` §4.1 A4、`dev-docs/propose.md` §六（客户端兼容）。

## 1. 客户端兼容矩阵

**真实 Windows 客户端（PuTTY / WinSCP / Windows OpenSSH）在本 CI 主机不可用**，因此用 OpenSSH
`-o` 强制该客户端常见的**算法集**来模拟其**最受限组合**，经网关完成 connect+exec。成功即证明
网关的 russh 腿可协商该组合。（本地 `make integration` 中由 `case_client_matrix` 实跑。）

| 档位（代表） | 强制算法集（KEX / HostKey / Cipher / MAC） | 本地结果 |
|---|---|---|
| OpenSSH 8.x | `curve25519-sha256` / (默认 ed25519) / `aes256-ctr` / `hmac-sha2-256` | PASS |
| OpenSSH 9.x | `sntrup761x25519-sha512,curve25519-sha256` / 默认 / `chacha20-poly1305@openssh.com` / `hmac-sha2-256-etm@openssh.com` | PASS |
| PuTTY | `ecdh-sha2-nistp256,curve25519-sha256` / `ssh-ed25519,rsa-sha2-512` / `aes128-ctr,aes256-ctr` / `hmac-sha2-256` | PASS |
| WinSCP | `ecdh-sha2-nistp256,curve25519-sha256` / (默认) / `aes256-ctr` / `hmac-sha2-256` | PASS |

每个档位在 KEX 列表都含 `curve25519-sha256`（客户端与网关共有）作为可协商回退，因此失败=真正的
协商缺口，而非算法集无交集。

**局限**：这验证的是**网关的算法接受面**，不是真实客户端的完整栈（认证 UI、私钥格式、banner、
known_hosts 交互）。真实 Windows/PuTTY/WinSCP 端到端留作真机/选做（plan 风险表）。

## 2. Host Key 轮换降级演练

**结论（`case_hostkey_rotation` 实测）**：russh 0.64.1 **无 hostkeys-00 钩子**，网关换 host key
**无法做到无感轮换**——同一 `host:port` 上已 pin 旧 key 的客户端在轮换后重连会被拒（host key
mismatch）。**降级路径**：管控面**下发新的 `known_hosts`**；客户端用新 `known_hosts` 重连即通。

演练步骤（固定网关端口，`case_hostkey_rotation` 落地）：
1. 网关用 host key **A** 起服务 → 客户端 accept-new 固定 A 并重连成功；
2. **轮换**：同端口网关改用 host key **B**；
   - 持旧 `known_hosts`(A) 的客户端重连 → **被拒**（验证无感轮换不可用）；
   - **管控面下发新 `known_hosts`(B)** → 客户端重连 → **成功**（降级路径验证）。

**事故检测**：轮换导致「KEX 后以 host key mismatch/拒绝断开」的模式，客户端侧表现为硬失败
（非静默），便于监控告警。

## 3. 与其它 A/B 项的边界
- 证书（B1）走 `auth_openssh_certificate` + `@cert-authority`，是独立路径，不在本文件。
- `[ca]` 现为网关必填段（tests harness 已在生成配置中置 `trusted_ca_keys=[无害公钥]` 满足校验，
  cert 认证默认不启用）。
