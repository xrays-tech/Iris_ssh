# SSH 网关性能基准报告

> 来源：`scripts/bench.sh`（自包含本地拓扑：自举 sshd + mock 控制面 + 网关，随机端口）
> 目的：plan M1-T11「网关 vs 直连」基线；吞吐损耗 ≤15% 为目标，**超过 15% 为记录项而非门禁失败**（供 M2-U6/调优排队）。
> 环境：macOS（darwin arm64），OpenSSH 10.3 客户端，`/usr/sbin/sshd` 本地后端，release 构建（LTO）。

## 测量方法
- 拓扑：客户端 → (直连 | 经网关) → 本地 sshd 后端（127.0.0.1 随机端口）。
- 延迟：`ssh '<cmd>'` 计时，取 **中位数**（BENCH_ITERS=5 默认）。
- 吞吐：内存生成文件 `scp` 上传，**校验远端字节数 == 本地字节数** 才计数，取 best-of-N。
- 参数：`BENCH_FILE_MB`（默认 64）、`BENCH_ITERS`（默认 5）。

## 实测结果（2026-10-11，本机）

| 指标 | 直连 | 经网关 | 备注 |
|---|---|---|---|
| 握手→退出延迟（`ssh 'true'`） | ~60 ms | **~1090 ms** | via 含认证初始 backoff，见下 |
| exec 延迟（`ssh 'echo ok'`） | ~60 ms | ~1090 ms | 同上 |
| scp 吞吐（32MB，best of 3） | ~216 MB/s | **~26 MB/s** | 损耗 ~88%（记录项） |

> 注：本机直连延迟 ~60ms 是**新建 SSH 会话 + 本机 sshd 全链路**的真实值（含 KEX/认证/执行/财报），非纯握手包往返；此为本地回环环境，绝对值仅作同机对比。

## 经网关延迟 ~1.09s 的构成（重要，非缺陷）
- 直接为主：**认证初始 backoff** —— russh server 对每个新连接在首个 none probe 前施加 ~1s 的抗爆破延迟（`auth_rejection_time_initial` 语义；本网关 `auth_timeout="1s"` 下的初始下限）。这是**设计意图**（防爆破/时间攻击），每次新会话固定成本，直连无此代价。
- 归属：`auth` 阶段（russh 服务器侧），非中继数据路径。
- 影响与缓解：**每次新连接**多 ~1s；复用连接（多 channel / 连接池）不受影响。若产品对「新连接首包延迟」敏感，可在 `[limits] auth_rejection_pad`/`auth_timeout` 上权衡（调小会削弱防爆破时间混淆）。

## scp 吞吐损耗 ~88% 的归因（更正：测量伪影，2026-10-12）
- **更正**：此前把 ~88% 损耗归因于数据路径双加密 / `max_packet`。T3 实测（连接复用 `ControlMaster`，同主机）显示**数据面单向持续 356–486 MB/s（trace transfer phase），复用连接端到端 386–602 MB/s** —— 数据面**不存在 ~50MB/s 上限**。
- 真正原因：每次**新建连接**的 ~1s initial auth-backoff（上节设计意图项）被摊到 32-64MiB 小文件上，掩盖了真实数据面速度。`max_packet`/`window_size`/nodelay/解耦等 A/B 在 pre-existing 固定成本下**欠功效**（<10% 的数据面变化被 1s 淹没，不可检出）。
- 正确测法：连接复用（ControlMaster/多 channel）、或 `auth_timeout="0s"`、或用 trace 的 transfer-phase。详阅 `docs/perf-investigation.md` §16 / §18。

## M2-U6 调优结论（2026-10-12，含外部调研 + 门禁裁决）
**目标测判**：单连接 scp 吞吐损耗 ≤15% **判定为当前架构限制（双隧道 + russh），非可调参达成**。

### 实测与试验摘要
- cod-5 尝试数据路径调度重构（mpsc + sender task + `Arc<Mutex<BackendWriter>>`）：**损耗 85.6% vs 基线 ~82-85%，收益 ≈ 0**（wire 噪声内）。
- `max_packet`（32KB→128KB）、`window_size`（1MB→8MB）、`outbound_guard` 扫描：影响 **<1%**。
- **@oracle 门禁裁决：回退该调度重构**（破坏 I1 保序 / D11 锁纪律 / §3.6 有界内存，且实测零收益），保留 tap 枚举化语义与本文档。回退提交 `d6c4eb5`。

### A/B 实测（2026-10-12，新增 nodelay + cipher 开关接线后）
| 配置 | direct scp | via-gw scp | 损耗 |
|---|---|---|---|
| 基线（Nagle 开，chacha20 默认） | 167.2 MB/s | 25.8 MB/s | 84.6% |
| `nodelay=true`（双腿 TCP_NODELAY） | 220.9 MB/s | 26.7 MB/s | 87.9% |
| `ciphers=["aes256-gcm","aes128-gcm"]` | 168.7 MB/s | 25.9 MB/s | 84.6% |
| `lto="fat"`（构建优化 a） | 163.0 MB/s | 25.6 MB/s | 84.3% |
| `target-cpu=native`（RUSTFLAGS，构建优化 a） | 167.8 MB/s | 25.6 MB/s | 84.7% |

**结论**：`nodelay=true`、`ciphers` 调整、构建优化（lto=fat / target-cpu=native）对经网关吞吐**均无实质影响**（25.6-26.7 MB/s 区间，run 间噪声内；direct 的提升源于 OpenSSH 直连本腿，不经网关）。→ 逐包加解密/协议栈/构建**不是该损耗的主因**；瓶颈更可能在**中继结构**（每包 await 串行链、双腿 round-trip 耦合）。
- 选项仍保留在 config 与 example 注释（低成本、无害），但**不作为吞吐解**。
- 剩余候选（需实测/架构评审）：腿 A/B 隔离诊断、写路径流水化（仿 bssh 6.2x）、或架构级 ProxyJump 直通 / 可信后端裸 TCP（见 known-limitations #7）。

### 腿 A/B 隔离诊断（2026-10-12，候选 1）——瓶颈定位
| 流量形态（经网关，64MB，best-of-3，远端字节校验通过） | 吞吐 |
|---|---|
| C. scp 上传（SFTP 双向乒乓） | **49.3 MB/s** |
| A. 纯上行流（dd \| `cat >/dev/null`，无 SFTP 层） | **52.4 MB/s** |
| B. 纯下行流（`cat` \| /dev/null） | **53.3 MB/s** |

**判定**：
1. **SFTP 乒乓 ≈ 非主因**：纯数据流 52-53 vs scp 49，仅 ~6% 差异 → SFTP 请求-响应往返排除了延迟敏感性。
2. **瓶颈 = 每包转发路径本身**：三种形态殊途同归 ~50 MB/s，即「1MB 窗口 + 32KB 包 + 每包 await 串行」下数据路径上界。
3. **与同构的 warpgate（≈直连）差距在实现层，非协议层**：russh 单腿 400-580 MB/s（官方基准/外部调研），本双跳仅 ~50 → 差距在 relay 每包中继循环的调度/拷贝/await 开销。

> **注意**：本诊断用 `scripts/bench.sh` 之外的临时 64MB 脚本测得 ~50 MB/s；`bench.sh` 32MB 基线为 ~26 MB/s，二者差异源于负载大小/采样，趋势一致（纯流 ≈ scp，主因在每包中继）。本表为准（更严格：无 eval、真参数数组、远端字节校验）。

**推论**：此前的「~85% 损耗 = 双加密架构必然」结论需修正——**部分架构性（双隧道翻倍 CPU）、部分每包中继实现层开销（可寻址）**。但合法优化空间受红线约束：b/c 形态（合流/read-ahead）被 I1/D1 禁止（@oracle 边界裁决）；唯一合法微优化是「单写者 Pass 快路径的拷贝/分配消除」（不合并、不改序、不 spawn），预期收益有限（IRL 50→60-70 MB/s？需实测）。架构级（ProxyJump 直通 / 可信后端裸 TCP）是唯一能显著超越的方案，需产品+威胁建模决策（known-limitations #7）。

### 外部调研关键发现（lib-1，2026-10-12）
| 发现 | 依据 |
|---|---|
| **27 MB/s 大概率不是「双重加密」必然结果**——russh 单跳回环可达 400~580 MB/s | russh PR #653 基准表 |
| **同构双会话终结中继 can 吞吐≈直连**：russh 作者自己的 warpgate，rsync 经网关≈直连≈ProxyJump | warpgate issue #479 |
| **最被忽视开关：russh 两腿 `nodelay` 默认 false（Nagle 开）**，本项目未设置 | russh server/client `Config` 源码（成本 2 行，免费试） |
| bssh（基于 russh 的 SFTP server）同机调优后 71→437 MiB/s（6.2x），钥匙=写路径流水化 + 构建（lto=fat、target-cpu） | bssh issue #187 / PR #224 |
| SSH 无「会话内免二次加密」标准钩子；免一跳=ProxyJump 直通（内层 SSH 密文透传）或可信后端裸 TCP（需威胁建模） | OpenSSH PROTOCOL / RFC 4254 |
| 换库（libssh2/OpenSSH 子进程）ROI 低；russh 单跳已远超需求 | crates.io / 无公开双跳基准 |

### 建议的下一步（按性价比，均「需实测」）
1. **双腿 `nodelay=true`**（各 1 行）→ 重跑。Nagle×2 + 延迟 ACK 是经典微停顿源。
2. **腿 A/B 隔离诊断**：A=OpenSSH scp→russh server（只 echo 不接后端）；B=russh client 单通道→sshd；C=双跳——定位 27 MB/s 落在哪条腿。
3. **cipher A/B**：默认协商 chacha20-poly1305（软件实现）；用 `Preferred` 提前 `aes-gcm`（Apple Silicon 有 AES 加速）对比。
4. **写路径流水化**（read-ahead + 单写者按序，仿 bssh 6.2x 经验）——须保持 I1~I4 保序。
5. 若仍 <60 MB/s 再评估架构级：ProxyJump 引导（候选 A，省一跳加密，UX/审计需产品决策）或可信后端直通（候选 C，需威胁建模评审）。
6. 长期 KPI 转向**连接级**：ControlMaster 复用摊薄、每连接建立成本、并发会话容量——与 propose §六 容量/稳定性意图一致。

> 参照基线（长期）：direct scp ~186-216 MB/s，via ~26-27 MB/s（损耗 ~85%）。此值存为构建/环境参照，不再作迭代吞吐门禁。
- **结论**：这是本机回环小窗配置下的基线记录，非门禁阻断；目标 ≤15% 在调优预算（M2-U6）内推进，未达成前如实归档。

## 复现
```bash
make bench                 # 默认 64MB / 5 次
BENCH_FILE_MB=32 BENCH_ITERS=3 make bench
```
重跑后更新本表。报告文件随每次 `make bench` 复核更新（若数值显著偏离，注明时间与环境）。

## 证据补充：下行数据路径 micro-bench（2026-10-12，cargo bench）

`benches/downlink.rs`（criterion 0.5，32KB 载荷，本机 Fedora / rustc 1.98，dev profile 无 LTO）：

| 基准 | 中位数 | 说明 |
|---|---|---|
| `downlink_no_tap` | **~16.9 ns** | 零拷贝快路径：owned `Bytes` 直接透传（消除旧实现的冗余 `to_vec()`） |
| `downlink_tap_pass` | **~21.1 ns** | tap 已装但 Pass：仍零拷贝（虚调用 + 判别而已） |
| `downlink_tap_rewrite` | **~454 ns** | tap 改写路径：tap 内 1 次 `to_vec()`，文档化其成本 |
| `uplink_unavoidable_copy` | **~479 ns** | 上行不可避免的 1 次拷贝（`to_vec`+`Bytes::from`），仅作参照，未改动 |

复现：`cargo bench --bench downlink -- --noplot`。此为**每包微基准**，不等价于端到端吞吐（端到端仍受每包 await 串行调度支配，见上文结论）；它只证明下行方向原先每包 ~450ns 级的冗余拷贝已归零。

## 路线一 C3 GO/NO-GO 实测（2026-10-12）——泵解耦无收益，按门禁回退

**变更**：C2 `aed6bf9`（Auditor 内部可变，行为不变）+ C3 `8839f9f`（上行数据面从串行
Handler 回调迁移到独立任务 `pump_client_to_backend`，与下行泵对称；上行 owned-Bytes
零拷贝、读前进 russh 有界 channel mpsc）。门禁要求（plan-route1.md §1）：
**pure-uplink / pure-downlink 相对基线 ≥15% 且 RSS/延迟不回退，否则 revert C3**。

**方法**（比历史「临时脚本」更严格的同方法学 A/B）：`pure_legs.sh`（自包含拓扑同
`scripts/bench.sh`；64MB、best-of-3、远端/本地字节校验独立非计时通过；计时腿为纯管道
`ssh GW 'cat >/dev/null' < f`（上行）/ `ssh GW 'cat f' >/dev/null`（下行），两端无磁盘）。
两个二进制**交替各测 2 轮**（基线 = db05543 重建 release，C3 = 8839f9f release）。

| 腿（经网关） | 基线 db05543 | C3 | 相对 |
|---|---|---|---|
| 纯上行 | 49.4 / 49.4 MB/s | 49.6 / 49.2 MB/s | **≈ 0%** |
| 纯下行 | 52.3 / 53.0 MB/s | 52.0 / 52.1 MB/s | **≈ -1%** |
| 握手（本脚本方法学） | 2060.8 / 2061.1 ms | 2060.6 / 2060.6 ms | 持平 |

`make bench`（64MB×5，含 scp 三张数字）同轮复核：

| 指标 | 基线 db05543 | C3 |
|---|---|---|
| direct scp | 315.4 MB/s | 320.4 MB/s |
| via-gw scp | 45.7 MB/s | **45.6 MB/s** |
| via 握手（bench.sh 方法学） | 1166.4 ms | 1163.0 ms |

**RSS/延迟**：`case_backpressure`（上行 200MB 洪泛）与 `case_backpressure_down` 在 C3 下
PASS（RSS ≤150MB 上界内，无回退）；两方法学的握手延迟均与基线持平。

**判定：NO-GO**（收益 ~0%，远低于 ≥15% 门槛）→ 按门禁执行
`git revert 8839f9f`（回退单元 = C3 全部；**保留 C2 `aed6bf9` 与 sftp clippy 修复
`edbf6ae`**）。回退提交见下方 git log。

**结论**：在本机回环、32KB 包 / 1MB 窗口配置下，「串行 handler 内逐包 await」**不是**
吞吐主因——把上行迁出串行回调并零拷贝化后两条纯腿与 scp 吞吐均无变化（49-53 MB/s
不变）。瓶颈更可能在 russh 双腿自身的每 chunk 写路径（`reserve_writable_chunk` 逐
≤32KB 分片 + 每分片一条 mpsc 消息 + 双腿各自加解密），即库内路径而非本仓库的转发调度。
下一步候选应指向「减少每字节的库内固定成本」（更大 `max_packet` 扫描需重测上限、
单腿 cipher/CPU 亲和、或架构级 ProxyJump 直通/可信后端裸 TCP，见上文调研），
而非继续改转发调度形态（0dc281b、8839f9f 两次实证均为 ~0 收益）。

> 备注：本脚本握手绝对值（~2.06s）高于 bench.sh（~1.17s）系脚本差异（计时含一次
> 认证 backoff 重试窗口），两二进制在两方法学下均完全一致，不影响 A/B 结论。

## 纯腿尺度 nodelay×window A/B（warpgate 对比，2026-10-12）

`scripts/pure_legs.sh`（单方向纯腿探针，bench.sh 拓扑，64MB、2轮×3次、字节校验、交替 A/B）。

| 配置（纯腿 via 网关） | pure-up | pure-down |
|---|---|---|
| 基线（nodelay=false, 1MB） | 49.6 | 52.8 |
| nodelay=true, 1MB | 53.0 | 54.6 |
| nodelay=false, 2MB | 49.2 | 51.8 |
| **nodelay=true, 2MB（=warpgate）** | **53.2** | **54.6** |
| nodelay=true, 8MB | 46.3 | 54.6 |

相对基线：nodelay 单独 +7~8%（上/下）、window 单独 ~0%、nodelay+2MiB 组合 +7.3% 上 / +3.4% 下、8MB 反而伤上行（46.3）。**无任何格达到 ≥10% 门槛** → 此轴不触发默认配置变更。warpgate 对齐开关（nodelay+2MiB）不能复现其宣称性能；盲点闭合，天花板仍在 ~50-54 MB/s。

## 单腿 SSH 吞吐（Phase 2-T1，2026-10-12）

仅一跳 SSH 加密的吞吐（决定 crypto 是否瓶颈）。独立最小 harness（OpenSSH→russh 回显 / russh→sshd，`/tmp/leg-single`），64MiB、5轮中位数、字节校验、回环；协商 aes256-gcm（L1）/ chacha20（L2）。

| 腿 | up | down | round-trip |
|---|---|---|---|
| **L0** OpenSSH→OpenSSH（基线参考） | 377.7 | 330.2 | 256.4 |
| **L1** OpenSSH→russh server | 480.8 | 322.3 | 478.7 |
| **L2** russh client→OpenSSH sshd | 301.1 | 368.4 | 218.8 |

→ 单腿 ≥ ~219 MB/s ≫ 网关 50 MB/s：crypto 不是瓶颈，去一跳加密无法解释 ~6x 差距；天花板属双链窗口/补窗调度。完整裁决见 `docs/perf-investigation.md` Phase 2。
