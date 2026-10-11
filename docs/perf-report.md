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

## scp 吞吐损耗 ~88% 的归因（记录项，供调优）
- 数据路径两段加密（客户端→网关、网关→后端）+ 网关内 await 转发 + `max_packet=32KB` 较小 → 本地回环下包数放大，吞吐受限。
- 已知可调维度：`[relay] max_packet`（SFTP 大读取可调 256KB）、`window_size`；连接复用（ControlMaster/池）摊薄建立成本。
- **结论**：这是本机回环小窗配置下的基线记录，非门禁阻断；目标 ≤15% 在调优预算（M2-U6）内推进，未达成前如实归档。

## 复现
```bash
make bench                 # 默认 64MB / 5 次
BENCH_FILE_MB=32 BENCH_ITERS=3 make bench
```
重跑后更新本表。报告文件随每次 `make bench` 复核更新（若数值显著偏离，注明时间与环境）。
