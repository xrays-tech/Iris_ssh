# OpenStack 测试环境（真实后端接入记录）

> 用途：`plan-openstack.md` 方案 B（instance_uuid 即路由）的**真实环境验证**后端。
> 状态：**已连通只读验证（2026-10-14）**；可测目标已列出；尚差"认证方式/实例登录用户/网络可达"三项确认后才可端到端。
> **凭据安全**：密码等敏感值只存在**本机 `.openstack-test.env`（0600，已在 .gitignore，绝不提交）**；下文仅记录非敏感字段。

## 1. 连接信息（非敏感）

| 字段 | 值 | 备注 |
|---|---|---|
| Keystone auth_url | `http://172.16.29.18:5000/v3` | v3.14，可达（HTTP 200 发现 / 201 token） |
| 账号 | `alex` | domain `Default`；角色 `member/manager/admin/reader`（可建 app credential、可读 Nova） |
| 项目 | `T_3746` | project_id `a070dab7800e4eff88ad72e11f864471` |
| region（用户提供） | `GPU_4090_Renting` | ⚠️ **catalog 里 compute 端点的 region 是 `RegionOne`** —— 见 §3 |
| interface | `public` | |
| Nova compute（catalog，public，RegionOne） | `http://172.16.29.18:8774/v2.1` | 只读可访问 |
| 密码 | （不落文档） | `.openstack-test.env`：`OPENSTACK_PASSWORD` |

## 2. 可测实例（project T_3746，Nova 只读实测，2026-10-14）

| UUID | 名称 | 状态 | 固定 IPv4（NET3746） |
|---|---|---|---|
| `d702cf44-7c17-4410-8ac0-6bd3727fe081` | gpu-f3a3f738… | ACTIVE | 172.16.46.25 |
| `b743fddb-f10d-417f-93d2-a8c681412107` | gpu-92a4112a… | ACTIVE | 172.16.46.28 |
| `58e05289-e193-4e80-86f4-d0e4ec588e3c` | gpu-b1a9be08… | ACTIVE | 172.16.46.35 |
| `53ecfbfc-8d03-4aee-a9c9-97e1448e52bc` | gpu-97c765dc… | ACTIVE | 172.16.46.21 |
| `4abbbb21-e591-4f90-8ed0-cf2517260bed` | gpu-9e7b0d37… | SHUTOFF | 172.16.46.20 |

实例无 metadata（`{}`）→ 后端登录用户只能走 `[openstack] default_backend_user`（无 metadata 键/规则可用）。

## 3. 已确认的差异 / 坑（接入前必须处理）

1. **region 名不一致（必处理）**：用户提供 `GPU_4090_Renting`，但 Keystone catalog 的 compute 端点 region 为 `RegionOne`。网关 `[openstack] region` 若填 `GPU_4090_Renting` 会找不到 catalog 端点。两种解法：
   - `region = "RegionOne"`（对齐 catalog）；
   - 或显式 `nova_endpoint = "http://172.16.29.18:8774/v2.1"`（跳过 catalog region 匹配）。
   ⚠️ 待用户确认 `GPU_4090_Renting` 是否只是平台/计费层命名（OpenStack 层实际 region = RegionOne）。
2. **认证方式**：网关 OpenStackClient 支持 `application_credential`（默认）或 `token`（仅测试逃生口），**不支持用户名/密码**。真实接入需要：
   - 生成一个 scoped 到 `T_3746` 的 **application credential**（`id` + `secret`，secret 只在创建时可见一次，写入 gitignored env）；或
   - 给客户端加 `auth_method="password"`（违背设计安全偏好，不推荐）。
3. **实例登录用户与公钥**：实例无 metadata；需确认 GPU 实例上可 SSH 的 OS 用户（root / cloud-user / ubuntu / 平台自定义），并把测试公钥放进其 `authorized_keys`（或平台已预置）。
4. **网络可达性**：网关机需能连到实例内网 `172.16.46.x:22`（待探测）。
5. **无浮动 IP**：实例均为 fixed → 网关 `prefer` 配 `fixed`。

## 4. 网关配置映射（真实环境，草案，值来自上方）

```toml
[openstack]
enabled = true
routing = "openstack_only"
authorization = "openstack_only"
allow_any_authenticated_key = true        # 实验室模式，仅内网验证用
auth_url = "http://172.16.29.18:5000/v3"
auth_method = "application_credential"    # 或用生成的 app-credential
application_credential_id = "<从 env 注入>"
application_credential_secret = "<从 env/*_file 注入，勿写死>"
project_id = "a070dab7800e4eff88ad72e11f864471"
region = "RegionOne"                      # 或显式 nova_endpoint
# nova_endpoint = "http://172.16.29.18:8774/v2.1"
microversion = "2.1"
timeout = "3s"
cache_ttl = "30s"
fail_open = false
network = "NET3746"
address_family = "ipv4"
prefer = "fixed"
on_ambiguous = "reject"
default_backend_user = "<实例可 SSH 用户，如 root/cloud-user/ubuntu>"  # 待确认
ssh_port = 22
```

## 5. 端到端验证前置清单（缺口，需用户确认后才能跑）

- [ ] 生成 application credential 到 T_3746（或确认可给网关加 password 认证）
- [ ] 确认 region 用 `RegionOne` 还是 `nova_endpoint`
- [ ] 确认测试实例（如 `d702cf44…`）的 SSH 用户 + 放公钥（authorized_keys）
- [ ] 探测网关机 → `172.16.46.x:22` 可达
- [ ] 用 `ssh -A <uuid>@<gw>` 直连 + 审计断言 `resolve_source:"openstack"`、后端 sees 用户

## 6. 验证记录

```
2026-10-14  Keystone 发现 HTTP 200（v3.14）；password token HTTP 201；
           project T_3746 = a070dab7800e4eff88ad72e11f864471；roles=member,manager,admin,reader；
           catalog compute public RegionOne = http://172.16.29.18:8774/v2.1；
           Nova detail 列出 5 实例（4 ACTIVE）。
2026-10-15  真实冒烟（本地网关 → 真实 Keystone/Nova，静态 token，openstack_only）：
           - 抓到并修复真实 bug：本 Nova 返回经典 v2 信封 `{"server":{...}}`，旧代码只认
             扁平文档 → "成功"解码成空 addresses → `no_network`（commit 2963e76，
             `ServerResponse` 双形态解码 + 真实 body 回归测试）。
           - 修复后：UUID d702cf44… 解析成功（审计 resolve_source="openstack"、
             target_host=172.16.46.25 / user=ubuntu）；后端拨号尝试 172.16.46.25:22
             **超时＝已知网络限制**（本机到 172.16.46.x:22 不通，非 bug）；
             未知 UUID 仍拒绝。指标 resolve_ok=1/err=1。
2026-10-15  application-credential 模式（用户已开启该 API，凭据在 gitignored
           dev-docs/clouds.yaml，id/secret 已导入 .openstack-test.env）：
           - 再抓到真实 bug：Keystone 对 app-credential 认证**携带 scope 返回 401**
             （"Application credentials cannot request a scope"）；客户端 `auth_body`
             带了 scope → 统一 401。修复：app-cred 认证不再发送 scope（凭据创建时已
             锁项目；该段是创建时定死的 blast radius）。commit 见下。
           - 修复后：app-cred + **catalog 发现**（无 nova_endpoint、region=RegionOne，
             生产推荐形态）解析成功 resolve_source="openstack"→172.16.46.25；
             后端拨号仍因网络不可达超时。指标 resolve_ok=1/err=1。全量 test 255+4、
             集成 38P/0F/2S 通过。
```

## 6b. 剩余缺口（真机端到端验证`ssh -A <uuid>`成功登录实例前）

- [ ] 网络：网关所在机器需能到达 `172.16.46.x:22`（当前机器不可达）
- [ ] 实例登录用户确认 + 测试公钥放入实例 `authorized_keys`（默认按 `ubuntu` 配置）
- [ ] 实例选定（5 台 ACTIVE 任挑）后做完整登录断言（audit `resolve_source=openstack` + 会话成功）
