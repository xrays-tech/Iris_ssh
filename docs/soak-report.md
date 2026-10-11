# soak 报告（A5 长跑稳定性）

> 生成：2026-10-11 18:07:34 ｜ 运行：scripts/run_soak.sh

## 本次运行
- ops(churn): 127  samples: 9  sample_interval: 5s  duration: 45s
- RSS: baseline=15264KB end_window=16997KB peak=17008KB  drift=|1733|KB (threshold 30720)
- live sessions after settle: 0 (must be 0)
- fd: before=15 after=16 drift=1 (threshold 64)
- backend_lost_total: 0  disconnect_reason{11}: 0
- 结论: PASS (RSS 漂移/连接归零/fd 均达阈值)

## 长跑用法（运维）
```
SOAK_DURATION=28800 scripts/run_soak.sh   # 8h；或 SOAK_LOOPS=50000 压缩循环
SOAK_RSS_DRIFT_KB=65536 SOAK_FD_DRIFT=128 scripts/run_soak.sh   # 调阈值
```
