# Performance Investigation — Gateway Throughput Ceiling (~50 MB/s)

> **2026-10-12 最终更正（§16/§18）**：标题所述的 ~50 MB/s "天花板"已被证伪——它是默认配置下**每个新建连接 ~1s 的 initial auth-backoff**被摊到 32-64MiB 小文件上的**测量伪影**。数据面持续吞吐**356–486 MB/s**，复用连接（OpenSSH ControlMaster）端到端**386–602 MB/s**。早期 §3/§4/§5/§11 中"数据面上限 / 窗口补窗调度"的结论**以 §16/§18 为准**，`auth_timeout=1s` 下跑过的 A/B（route1/route2/nodelay/window/max_packet/cipher/lto）均**欠功效**，不能作为"数据面不受该因素影响"的强证据。

Status: **CLOSED** — engineering investigation and route adjudication, archived.
Date: 2026-10-12. Applies to relay/data-plane work on `main`.

This document is the executive record of a full performance investigation into
the SSH gateway's throughput ceiling (~50 MB/s), from initial code review
through architectural experiment and back. It consolidates the analysis, the
decisions, the executed routes, the measurement results, and the retained
outcome. Primary evidence lives in [`perf-report.md`](perf-report.md)
(benchmarks), [`plan-route1.md`](../dev-docs/plan-route1.md) (route-1 plan),
[`propose.md`](../dev-docs/propose.md) (architecture invariants), and
[`known-limitations.md`](known-limitations.md).

---

## 1. Trigger

A code-level review of the relay/server/backend/pool modules produced five
performance-bottleneck claims (P0 data-plane copies, P1 SessionRegistry lock +
O(N) scan, P3 ReplyRouter mutex, P4 OutboundWindow semaphore, P2 missing
cross-session backend pool). Each claim was to be adjudicated against the actual
source before any change; any fix was to be measured, not assumed.

## 2. Adjudication (@oracle, source + vendored russh-0.64.1 verified)

| Original claim | Verdict | Correction |
|---|---|---|
| P0 "double allocation" on data path (`to_vec()` + `Bytes::from`) | **Partly real, severity overstated** | `Bytes::from(Vec)` is a zero-copy takeover — there is **no second allocation**. Uplink `to_vec()` is **unavoidable**: russh's handler callback only lends `&[u8]` (`server/mod.rs:463-470`). The **downlink** copy (`Bytes -> &[u8] -> to_vec()`) is the only *genuinely redundant* one. Per-packet micro-bench: ~454 ns copy vs ~17 ns pass-through. |
| SessionRegistry `Mutex<HashMap>` + `count_from_ip` O(N) | Real code, **impact overestimated** | Only hit on new-connection establishment, not the data path; N bounded by `max_sessions`. Scale/governance item only. |
| ReplyRouter `std::sync::Mutex` | Real code, **non-issue** | Control-plane only (`want_reply`), no `.await` under lock, not on the packet path. |
| OutboundWindow `Semaphore acquire_many+forget` | Real, correctly rated minor | No-contention is ~1 atomic op; mandated by §3.6 as a liveness fuse. |
| Missing cross-session backend pool (russh `Handle` is Send-but-not-Sync) | **Accurate**, root cause correctly attributed | Main short-connection cost is the ~1 s auth anti-bruteforce backoff, not KEX. |

**Adjudicated real bottleneck**: per-packet serial `await` on the relay path +
the double SSH-session crypto chain (~50 MB/s across all traffic shapes), *not*
copies, builds, or tunables (all measured <1%: nodelay, ciphers, lto,
target-cpu, window, max_packet). Prior `0dc281b` "uplink sender task" refactor
was reverted (`d6c4eb5`) — it neither eliminated copies nor decoupled the read
loop.

## 3. Route 2 — executed & retained (commit `db05543`)

Low-risk, high-certainty cleanup of the one truly redundant copy:

- `apply_tap_down` now takes/returns owned `bytes::Bytes`; no-tap and `Pass`
  verdicts forward the buffer with **zero allocation**; only `Rewrite` allocates
  (tap-owned `Vec` takeover).
- `relays` map values `ChannelRelay` -> `Arc<ChannelRelay>` so
  `GatewaySession::data` does a **single lookup** and holds an owned handle
  across awaits.
- Fixed a stale comment claiming the uplink fast path is copy-free (russh lends
  `&[u8]`, one copy is API-constrained).
- Added `benches/downlink.rs` (criterion, 32 KiB): `downlink_no_tap` **~16.9 ns**
  vs `downlink_tap_rewrite` **~454 ns** vs `uplink_unavoidable_copy` **~479 ns**
  — proves the redundant downlink copy is gone.
- `scripts/bench.sh` chmod +x (`make bench` was broken without the exec bit).

End-to-end A/B (old vs new, same machine): via-gw scp 45.0 -> 44.1 MB/s —
**unchanged within noise**, as predicted: the copy was not the ceiling.

## 4. Route 1 — planned, executed one-shot, gated, reverted the no-gain part

**Plan** (`dev-docs/plan-route1.md`, @oracle adjudicated): decouple the data
plane by adding `pump_client_to_backend` consuming the server-side
`ChannelReadHalf` (owned `Bytes` + off the serial handler callback), symmetric
to the existing down-pump. I1 is kept constructively (one ordered stream, one
pump); boundedness from russh's bounded channel sender (§3.6). Mandatory
**GO/NO-GO gate**: pure-uplink and pure-downlink must gain >=15% (relative) with
no RSS/latency regression, else **revert** (C3 is the revert unit).

Executed (commits `aed6bf9` … `688e526`):

- **C2 — Auditor interior mutability** (kept): `Auditor.command` ->
  `Mutex<Option<CommandInfo>>`, `set_command`/`finalize` take `&self`,
  `Arc<Auditor>` in `GatewaySession`. Needed to share audit state into the pump.
- **C3 — uplink pump decoupling** (implemented, measured, **reverted**):
  `src/relay/uplink.rs` (`RelayUpstream` + `pump_client_to_backend`), wiring in
  both channel-open paths, 10 handler callbacks neutralized, uplink zero-copy via
  owned `Bytes`, zero HashMap lookups on the hot path, `OutboundWindow`
  `try_acquire` fast path.
- **sftp clippy fix** (kept): pre-existing `while_let_loop` at
  `src/sftp/mod.rs:401`, unblocked `-D warnings`.

Full verification during C3: `cargo test` 189 lib + 4 bin green; integration
**24 PASS / 2 SKIP / 1 FAIL**; the lone `case_stderr` FAIL was isolated via a
worktree A/B as a **pre-existing environment issue** (system locale zh_CN makes
`ls` report a Chinese error while the assertion expects English "No such file");
its forwarding semantics passed.

**Measurement (same-methodology alternating A/B, byte-verified):**

| Metric | Baseline | With C3 | Δ |
|---|---|---|---|
| make bench via-gw scp | 45.7 MB/s | 45.6 MB/s | ~0% |
| pure-uplink leg | 49.4 MB/s | 49.4 MB/s | ~0% |
| pure-downlink leg | 52.65 MB/s | 52.05 MB/s | ~−1% |
| via handshake | ~1166 ms | ~1163 ms | ~0% |

**Gate verdict: NO-GO** (>=15% gate, achieved ~0%). C3 reverted cleanly
(`git revert 8839f9f`, commit `688e526`). Conclusion recorded in
`perf-report.md` (commit `5abc982`).

## 5. Final conclusion

The gateway's ~50 MB/s ceiling is **not removable in the gateway implementation
layer**. After eliminating every redundant copy (route 2) and fully decoupling
the data plane from the serial handler while making uplink zero-copy and the hot
path lookup-free (route 1), throughput is unchanged. The ceiling is produced by
the two independent SSH sessions' per-packet serial crypto/decrypt chain and the
1 MB window / 32 KiB packet framing — the same conclusion reached by every prior
A/B in this project (`0dc281b`, nodelay/ciphers/lto/target-cpu/window/max_packet
all <1%).

Further gains would require touching russh's crypto/window internals or a
warpgate-style direct-pass architecture — **out of scope** for this project
(see `known-limitations.md`).

## 6. Retained outcome

- Gateway behavior and safety invariants I1~I4, §3.6 unchanged and green.
- Cleaner data path: downlink zero-copy, single-lookup uplink, verified by
  micro-bench and full test suite.
- Interior-mutable `Auditor` (C2) — infrastructure for future shared-state
  refactors.
- Full measurement infrastructure: `benches/downlink.rs` (criterion),
  `scripts/pure_legs.sh` methodology, perf-report A/B evidence chain.
- Definite negative result on pipeline decoupling — saves future attempts the
  same experiment.

## 7. Commit map

```
688e526 Revert "C3 — decouple uplink into pump_client_to_backend (revert unit)"
5abc982 docs: record route-1 C3 GO/NO-GO A/B — no gain, gate says revert
8839f9f perf: C3 — decouple uplink into pump_client_to_backend (reverted)
edbf6ae chore: clippy while_let_loop fix in sftp frame drain
aed6bf9 refactor: C2 — Auditor interior mutability (+ plan-route1.md)
db05543 perf: downlink zero-copy (owned-Bytes passthrough) + per-packet micro-bench
```

## 8. Full test command list (green baseline)

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                      # 181 lib + 4 bin green
cargo build --release
make bench                      # via-gw scp ~45 MB/s, loss ~86% (recorded)
scripts/run_integration.sh      # 24 PASS / 2 SKIP / 1 env-pre-existing FAIL (case_stderr, locale)
```

---

# Phase 2 — warpgate comparison, decisive measurements & closure (2026-10-12)

## 9. warpgate reference study

Research of warp-tech/warpgate (primary source @librarian, russh internals
verified) — motivation: warpgate is often described as "near-direct speed" for
the same dual-hop (client→gateway→target) shape.

**Findings** (evidence marked [X]=external primary-source, [F]=verified in repo/russh):
- warpgate uses **stock russh 0.63.3** (crates.io, not a fork; no custom
  transport). Its data plane is the same decoupled-pump shape we built and
  measured at ~0% gain in route-1 C3; its downlink even has an extra `to_vec()`
  copy [X].
- Its only real config differences vs our defaults: **`nodelay:true` on both
  legs** (we default false = Nagle-on), **2 MiB channel window** (russh default;
  we default 1 MB), `event_buffer_size=100` (russh default 10) [X].
- Its own issue history shows the same walls in the same scenarios: #2292 OOM
  (linear memory growth on large transfers), #2494 high-throughput stall, #459
  ~6-9x slower than direct on Ansible, #479 scp OOM. **No third-party quantified
  "near-direct" throughput evidence exists** [X].
- russh upstream: PR #653 (removed per-packet mlock, +47%, present since
  0.63.3); issue **#770 — client-side `adjust_window` has a code defect**: the
  client leg calls `adjust_window_size` with the constant `config.window_size`
  (`client/encrypted.rs:577`), so the handler's `adjust_window` return value is
  never applied — dynamic receive-window tuning is broken client-side [F].
  russh #770 also demonstrates receive window is the dominant throughput lever
  (2 MiB → 560 MiB/s, 4 KiB → 92, 1 KiB → 28) [X].

**Adjudication of an external "ChannelWriter" proposal** (another AI's analysis
claiming 3-10x from a dedicated writer / event-driven / per-channel tasks): its
claimed mechanism is exactly route-1 C3 (already implemented, measured ~0%,
reverted); its "warpgate zero-copy" claim is false (warpgate has a downlink
`to_vec`); its 150-500 MB/s predictions are unsourced. **Rejected.** The only
real differences are the two config flags above, which we then measured (T2).

## 10. Decisive measurements T1 & T2 (merged with oracle decision tree)

### T1 — single-leg throughput (only ONE SSH crypto pass; decisive fork)

Harness: minimal russh echo server + russh client in `/tmp/leg-single`
(independent project; no production code touched). 64 MiB, 5 runs, medians,
byte-verified, loopback; negotiated aes256-gcm (L1) / chacha20 (L2).

| Leg | up | down | round-trip |
|---|---|---|---|
| **L0** OpenSSH→OpenSSH (baseline ref) | 377.7 | 330.2 | 256.4 MB/s |
| **L1** OpenSSH→russh server | 480.8 | 322.3 | 478.7 MB/s |
| **L2** russh client→OpenSSH sshd | 301.1 | 368.4 | 218.8 MB/s |

→ **min ≈ 219 MB/s ≫ 50 MB/s: a single SSH leg saturates far above the gateway
ceiling.** Crypto is **not** the bottleneck; removing one hop's encryption
cannot produce the ~6x gap. Architecture-level de-encryption (route C) is
**negated**.

### T2 — pure-leg nodelay × window A/B (warpgate-aligned blind spot)

`scripts/pure_legs.sh` (committed), same-methodology via-gateway, 64 MB, 2×3,
byte-verified, alternating:

| config | pure-up | pure-down |
|---|---|---|
| baseline (nodelay=false, 1 MB) | 49.6 | 52.8 |
| nodelay=true, 1 MB | 53.0 | 54.6 |
| nodelay=false, 2 MB | 49.2 | 51.8 |
| nodelay=true, 2 MB (=warpgate) | 53.2 | 54.6 |
| nodelay=true, 8 MB | 46.3 | 54.6 |

→ best cell +7.3% up / +3.4% down — **no combination reaches the ≥10% gate**.
No default-config change is warranted by this axis; warpgate-aligned
`nodelay+2MiB` does not reproduce its reported performance. Blind spot closed.

## 11. Final decision-tree outcome — **SUPERSEDED by §16/§18** (see banner)

> 以下"~50 MB/s 天花板 = 双链窗口/补窗调度"的结论已被 §16/§18 更正：那是每连接 ~1s auth-backoff 摊到小文件的测量伪影。数据面持续 356–486 MB/s。保留本节的**错误分析作为反面记录**，不作操作依据。

| Route | Verdict | Basis |
|---|---|---|
| A — config convergence (window 2 MiB / nodelay default) | **NO-GO** (gate ≥10%) | T2: window ~0%, nodelay +7~8% (below bar, no default flip) |
| B — russh upstream patch (#770 dynamic window / half-window eager top-up) | **GO-candidate — only remaining lever** | T1 ⇒ window/refill scheduling is the binding constraint; targets the effective-window ÷ refill-RTT model; conservative +15~30% [S] |
| C — architecture de-encryption (bare TCP / local channel / ProxyJump) | **NO-GO** | T1 single-leg ≫50 ⇒ crypto not the limit; ProxyJump also violates gateway auth/audit requirement |
| T3 — window-refill RTT / binding-window diagnostic | next measurement | corroborates B before any fork |
| T10 — record ceiling, pivot KPI to connection-level | fallback | if B declined / fails |

**Conclusion**: the ~50 MB/s ceiling is a dual-SSH-chain **window/refill
scheduling** limit (effective receive window of the opponent leg ÷ refill
round-trip across both legs and per-chunk mpsc hops), not implementation copies,
scheduling shape, or crypto. Single-leg plumbing does ~220-480 MB/s on this
host; the gateway spends the rest on window-refill round-trips. The single
promising lever left is a russh upstream patch (B), which requires forking /
vendoring russh — a maintenance commitment to approve explicitly.

---

# T3 — window-binding diagnostic (2026-10-12)

**Scope**: identify which window binds per direction, the refill RTT, and the
effective window, so route B (half-window eager top-up / russh #770) can be
adjudicated. Measurement only — all instrumentation lives in a throwaway copy;
mainline `src/` and `Cargo.toml` are untouched.

## 12. Environment & method

| item | value |
|---|---|
| host | Fedora 44, Linux 7.2.9-200.fc44.x86_64, Intel Core Ultra 5 235 (14C), load 0.06, governor=performance |
| transport | loopback only; OpenSSH_10.2p1 / OpenSSL 3.5.9; russh 0.64.1 |
| payload | 64 MiB, 3 timed runs per direction, **byte-verified every run, 0 failures** |
| gateway config | `relay.window_size=1MB`, `max_packet=32KB`, `nodelay=false`, `outbound_guard=true`, `pool.enabled=false` (i.e. T2 baseline cell) |
| isolation | `cp -a` repo → `/tmp/t3/gw`, `rm -rf target`; russh unpacked to `/tmp/t3/russh-0.64.1`; linked with `cargo --config 'patch.crates-io.russh.path="…"'` (worked first try — no `[patch.crates-io]` edit needed) |
| harness | `/tmp/t3/pure_legs_trace.sh` (derived from `scripts/pure_legs.sh`; WORK pinned to `/tmp/t3/work_$TAG`, `T3_TRACE=1` on gateway stderr → `gw_${TAG}_<dir>.trace`, gateway restarted per direction so traces are unambiguous) |
| artifacts | `/tmp/t3/{gw_*.trace, cpusample_*.txt, metrics_*.txt, parse.py, pure_legs_trace.sh, cpusample.py}` |

Instrumentation (russh copy only) — 7 events, `eprintln!` behind `T3_TRACE=1`,
`OnceLock` gate so the disabled path is one relaxed read:

`TXBLOCK`/`TXWAKE` (`reserve_writable_chunk`, window==0 → parked → woken) ·
`TXQUEUE` (`data_noqueue_direct`, peer window truncated a send) ·
`TXRESUME` (`flush_pending_with_writer`, queued bytes drained) ·
`RXADJ_SEND` (`adjust_window_size`, we refilled **our** advertised window) ·
`WADJ_RX` (peer refilled **our send** window) · `RXADJ_TGT` (client-leg
`tgt_const` vs `tgt_dyn` — the #770 observation point) · `SAMPLE` (per ~1 MiB:
`bytes_total`, `win_now`).

## 13. Results — pure up / pure down, three configurations

All figures MB/s, medians of 3 timed runs, byte-verified.

| configuration | connect-only | denied principal | pure-up | pure-down |
|---|---|---|---|---|
| **mainline** (`auth_timeout=1s`, `auth_rejection_pad=1s`) | 1167 ms | **2062 ms** | **48.8** | **51.8** |
| pad off (`pad=0s`) | 165 ms | 60 ms ⚠ | 202.6 | 266.1 |
| **decoupled** (`auth_timeout=0s`, `pad=1s`) | 170 ms | **1061 ms** ✅ | **202.4** | **264.1** |
| mainline + **one reused connection** (OpenSSH `ControlMaster`) | 1172 ms first, then **54 ms** | — | **386 / 400 / 377 / 402** | **335 / 408 / 602 / 486** |
| *T2 baseline (§10) for reference* | — | — | 49.6 | 52.8 |

Trace-derived **transfer phase only** (per 64 MiB run, from `SAMPLE`
timestamps): up **420–486 MB/s**, down **356–438 MB/s** in *all three*
configurations — the data plane is identical; only the fixed per-connection cost
differs.

Decomposition model `measured = connect_overhead + transfer` reproduces every
cell within noise (e.g. mainline up: 1.167 s + 0.130 s = 1.297 s → 49.3 vs
measured 48.8; decoupled up: 0.170 + 0.142 = 0.312 → 205 vs measured 202).

## 14. Window-binding fields (decoupled suite; pad1s/pad0s agree within noise)

**UP — client → gateway → backend**

| field | value |
|---|---|
| **binding** | leg C (gw→backend) on the **backend sshd's advertised receive window** — *peer-controlled* |
| block/queue events | `TXBLOCK=326`, `TXWAKE=166`, `TXQUEUE=98`, `TXRESUME=98` |
| effective window | mean **715 KiB**, min 32 KiB, max 1664 KiB = **43 %** of the peer's window |
| refill RTT (TXBLOCK→TXWAKE) | p50 **28.96 ms**, p95 **39.56 ms**, max 46.95 ms (n=34) |
| sender duty blocked | 0.119 s of 0.142 s = **83.7 %** (interval-union, not sum) |
| peer top-up granularity | `WADJ_RX` n=931, amount median **64 KiB** |
| **our** advertised window | `RXADJ_SEND` n=480, target **1024 KiB**, low-water mean 480 KiB (47 %) → `target/2` threshold fires as designed; **zero `TXQUEUE side=S` ⇒ our 1 MiB window never constrained the client→gw hop** |
| gw CPU | mean 2.5 %, max 10.0 % of one core — **not processing-bound** |
| `sshgw_window_exhausted_total` | 0 → 168 (relay uplink fuse; orthogonal to the russh window) |
| consistency `est = win/refill_rtt` | ≈ **2 MB/s** vs measured **202 MB/s** → **model decisively falsified** |

**DOWN — backend → gateway → client**

| field | value |
|---|---|
| **binding** | leg S (gw→client) on the **OpenSSH client's advertised receive window** — *peer-controlled* |
| block/queue events | `TXQUEUE=41`, `TXRESUME=41`, **`TXBLOCK=0`** (the downlink sender parks in russh's 100-deep channel mpsc, not in the window) |
| effective window | mean **1322 KiB**, min 0 KiB, max 1920 KiB = **69 %** of the peer's window |
| refill RTT | n/a on this leg (no park) |
| peer top-up granularity | `WADJ_RX side=S` n=838, amount median **64 KiB** |
| **#770 observation point** | `RXADJ_TGT side=C`: `tgt_const == tgt_dyn == 1048576` — the gateway never overrides `adjust_window`, so the dynamic-window defect is **inert today** |
| gw CPU | mean 6.5 %, max 13.0 % |
| `sshgw_window_exhausted_total` | 0 → 0 |
| consistency | window/RTT model inapplicable (no park); trace rate 356 MB/s vs measured 264 MB/s |

## 15. Decision-table adjudication → **route B: NO-GO**

| decision-table row | T3 observation | outcome |
|---|---|---|
| sender frequently blocked **and** binding = *our* advertised receive window → GO B2 | sender is blocked a lot on the uplink (83.7 % duty) but on the **backend sshd's** window, not ours; our own window never truncates a send (`TXQUEUE side=S = 0`) | **fails the GO condition** |
| binding = peer window (sshd / OpenSSH) → NO-GO russh patch | **both** directions bind on a peer's window (backend sshd up, OpenSSH client down) | **NO-GO confirmed** |
| sender rarely blocked / CPU saturated → processing-bound | CPU 2.5–6.5 %, so not processing-bound — but the window row already decides | same verdict |
| refill RTT abnormally large while window near-full → relay queueing / wakeup latency | peer top-up granularity is only ~64 KiB with a ~29 ms adjust latency, yet the transfer still runs at 356–486 MB/s | not limiting; no relay change warranted |
| no `side=C WADJ_RX` / `RXADJ_SEND` frequent but D missing → #770 | `RXADJ_TGT` shows `tgt_const == tgt_dyn` — defect present but **inert** | #770 = robustness value only, **no throughput effect today** |
| consistency check fails → abandon the window hypothesis | `est ≈ 2 MB/s` vs `measured 202 MB/s` | **hypothesis rejected** |

**Verdict: route B (half-window eager top-up at `session.rs:321`, and/or a
russh #770 dynamic-window patch) is NO-GO as a throughput lever.** Neither
bound window belongs to us; enlarging our advertised window or refilling it
earlier cannot raise a peer's window. Expected gain ≈ 0 %, against a
fork/vendoring maintenance cost.

**Additional NO-GO evidence for the "window/refill scheduling" premise itself**:
the data plane is not window-bound at all — it sustains 356–486 MB/s while the
window sits at 43–69 % of the peer's. `est = win/refill_rtt` misses the measured
rate by ~100×.

## 16. Root cause of the ~50 MB/s ceiling (conflicts with §11)

The ceiling is **not** a data-plane limit. It is the **1 s russh auth-rejection
pad charged to the initial `"none"` probe of every connection**.

* russh `server/encrypted.rs` (`process_packet`): when `auth_attempts == 0`
  the session waits `Config::auth_rejection_time_initial` before answering the
  first `USERAUTH_REQUEST` — i.e. before *any* credential is presented.
* Gateway `auth_rejection_timing()`: `initial = auth_timeout.min(rejection_pad)`
  ⇒ **1 s** with the mainline default (`min(30 s, 1 s)`) and **1 s** with
  `pure_legs.sh` (`min(1 s, 1 s)`). The comment says "the initial probe must be
  fast" — the `min` does not achieve that.
* Every OpenSSH client sends that probe, so every timed `ssh` run in T2/bench
  carries a fixed +1 s. At 64 MB that alone maps a true ~200–400 MB/s transfer
  onto an apparent ~50 MB/s.
* Wire-level corroboration (tcpdump, medium confidence): in the decoupled
  capture each 64 MiB run is one continuous burst of ~5 000 packets lasting
  83–193 ms; in the mainline capture the same bursts are each preceded by
  ~1.2 s of silence.
* Accidental control: with `ControlMaster` reusing one connection, the **same
  mainline config** yields 386–602 MB/s; the one run where the master had
  expired and a fresh connection was needed dropped to **48.3 / 51.5 MB/s** —
  exactly the T2 number.

**Recommended fix (config-only, no code)**: set `limits.auth_timeout = "0s"` and
leave `auth_rejection_pad = "1s"` unchanged. Then `initial = 0`, `ongoing` stays
1 s, so a *rejected* principal still pays the pad. Measured on this host:

| | mainline | decoupled | Δ |
|---|---|---|---|
| connect-only | 1167 ms | 170 ms | −85 % |
| denied principal (anti-bruteforce) | 2062 ms | 1061 ms | **still 1 s ✅** |
| pure-up | 48.8 MB/s | 202.4 MB/s | **4.1×** |
| pure-down | 51.8 MB/s | 264.1 MB/s | **5.1×** |

`limits.auth_timeout` is used **only** as an input to `auth_rejection_timing()`
— it is not a stall deadline anywhere in `src/`, and the gateway's own test
helper already builds its "fast" context with `auth_timeout = "0s"`. The doc
comment claiming it is "the deadline for a peer that stalls mid-auth" is not
backed by code. Alternative one-line code fix: `auth_rejection_time_initial:
Some(Duration::ZERO)` at `src/server/mod.rs:523`, keeping `auth_rejection_time`
= the pad (same effect, makes the intent explicit).

## 17. Log-perturbation assessment & engineering notes

* **Perturbation: none measurable.** The instrumented binary with `T3_TRACE`
  *unset* reproduces T2 (48.7 / 52.2 vs T2's 49.6 / 52.8). Traced runs emit
  ~5.5 k lines per 256 MiB up (~1 per 47 KiB) and ~3.3 k down; the three suites'
  trace-derived transfer phases (0.130 / 0.142 / 0.150 s) sit inside run-to-run
  noise. The gate is a `OnceLock` read; `ts()` is only called inside the branch.
* **Line drift vs the approved design**: `data_noqueue_direct` and
  `flush_pending_with_writer` live in the shared `Encrypted` impl in
  `src/session.rs` (not `server/session.rs`). They cannot distinguish the
  server from the client role, so a `t3_side: u8` had to be threaded through
  `data_with_writer`, `extended_data_with_writer`, `flush_channel_with_writer`,
  `flush_pending_with_writer`, `flush_all_pending_with_writer` and
  `adjust_window_size` (`b'S'` from `server/{session,encrypted}.rs`, `b'C'` from
  `client/{session,encrypted}.rs`). Hook A likewise could not hardcode `C`:
  `ChannelWriteHalf<S>` is generic over both roles, so the side comes from
  `std::any::type_name::<S>()`. `ChannelId` is a private-field tuple struct →
  needed a `t3trace::ch()` accessor. Hook F initially double-counted the client
  leg (sampled in both `reserve_writable_chunk` and `data_noqueue_direct`);
  gated to one site per leg.
* **Compile**: one russh build + one gateway build, no errors after the first
  signature-propagation wave (7 × `E0061`, all "missing `t3_side`").
* **Harness issues found and fixed**: `cross_instrument`/`cross_stop` were
  briefly lost in a rewrite; `pidstat` is not installed on this host → replaced
  with a `/proc` sampler (`cpusample.py`); an early probe script had invalid
  JSON in `rules.json` and, more importantly, tested a *wrong key* — but the
  mock control plane grants any key for principal `plegs`, so the correct
  negative test is a **denied principal**; a stray `sudo tcpdump` wrote ~3 GB of
  pcaps (bounded with `-c`, deleted).
* **Design deviations** (deliberate, in service of the same goal): gateway
  restarted per direction so each trace is unambiguous; a third "decoupled"
  configuration added after the pad was found to dominate; `ControlMaster`
  control added as the decisive causality test.
* **Open question for ops**: with the pad removed the per-connection cost is
  ~54 ms (reused) / ~170 ms (fresh), so short-lived and high-connection-rate
  workloads gain the most. Sustained single-connection throughput reaches
  386–602 MB/s on this host.

## 18. Independent reconciliation & unified narrative (2026-10-12, @oracle review)

Independent review of §12–§17. **Agrees with the reversal**; **corrects** the
"defect" framing and downgrades the window quantitative metrics.

### What stands (verified)
- **No ~50 MB/s data-plane ceiling.** Sustained one-way transfer phase
  **356–486 MB/s (up) / 356–438 MB/s (down)**; connection-reused end-to-end
  **386–602 MB/s** (loopback). The ~26–50 MB/s figures were a fixed per-new-
  connection cost amortised over 32–64 MiB files.
- The fixed cost is the **1 s initial auth-backoff** on every connection's first
  `"none"` probe: `initial = min(auth_timeout, auth_rejection_pad)` =
  `min(30s, 1s)` = 1 s (`src/server/mod.rs:392-402`, mapped at `:519-523`).
  This is **russh's stock default** (`auth_rejection_time_initial=None ->
  auth_rejection_time=1s`), adopted, not introduced, by the gateway.
- Causal chain is solid: `auth_timeout` is consumed **only** at
  `src/server/mod.rs:398` (verified by grep); changing it `1s -> 0s` moves
  connect-only 1167→170 ms (≈1 s) and leaves the transfer phase identical;
  `measured = connect + transfer` reproduces every cell.
- **route B NO-GO stands** — but on **binding attribution**, not the blocked%
  metrics: both directions bind on a *peer's* window (backend sshd up;
  OpenSSH client down); our own advertised windows never truncate a send.
- Route C (de-encryption) NO-GO still stands (crypto is not limiting; single
  leg is 218–480 MB/s). warpgate study (stock russh, no magic) unaffected.

### Corrected
- **The 1 s is NOT a code defect.** Existing tests assert `initial=1s` is the
  intended mapping (`:2412-2434`), `config.example.toml` and ops-runbook call
  it deliberate anti-bruteforce/anti-timing, and `docs/perf-report.md:24-26`
  already documented it. The real error was **measurement methodology**: timing
  bulk transfers over fresh connections without charging the fixed per-connection
  cost, then attributing the residual to the data plane.
- **Window quantitative metrics (§14) are unreliable**: `sender duty blocked
  83.7 %` is inconsistent with `444 MB/s` and `est = win/rtt ≈ 2 MB/s`
  (`TXBLOCK=326` vs `TXWAKE=166` — per-32KB pairing under-counts). These
  numbers are **descoped**; the NO-GO decision does not depend on them.
- **Underpowered prior A/Bs**: route1/route2 (decoupling, zero-copy), nodelay,
  window, max_packet, cipher, lto all ran under `auth_timeout=1s`; a fixed 1 s
  per connection swamps <10% data-plane changes. Those runs cannot serve as
  strong evidence the data plane is unaffected — only that no *large* effect
  was measurable in that (flawed) methodology.

### Security posture & operator guidance
- **Ongoing pad retained**: `auth_rejection_pad=1s` + `max_auth_attempts=10` is
  the real anti-bruteforce lever and is unchanged in every option below
  (denied principal still pays ~1 s, measured 1061 ms).
- **Initial back-off (`min(auth_timeout, pad)` = 1 s default)**: gives every
  connection (including attackers) a flat ~1 s cost. For a pubkey/cert-only
  gateway it has little guessing value (guesses pay the ongoing pad); removing
  it halves an attacker's *full-attempt* cost (~2 s -> ~1 s) — a small
  defence-in-depth posture change, not zero-cost.
- **Latency / high-connection-rate pubkey deployments**:
  `[limits] auth_timeout = "0s"` (keep `auth_rejection_pad = "1s"`)
  → new-connection ~1.17 s → ~0.17 s, and 64MiB-scale transfers appear
  4-5× faster. Keep `max_sessions` / `max_sessions_per_ip`.
- **Public-facing / high-risk or russh-default parity**: keep
  `auth_timeout="30s"` (initial = 1 s).
- **Decision: defaults are UNCHANGED** (`auth_timeout=30s`, pad=1s). Flipping
  the default is a separate security-review item (would also require updating
  `src/config.rs:1011` and `:2412-2434` tests).
- **Future measurement rule**: any data-plane A/B must use connection reuse
  (ControlMaster / multi-channel), `auth_timeout="0s"`, or trace transfer-phase;
  otherwise the fixed 1 s/connection makes the experiment underpowered.

## 19. Benchmark v2: the ~50 MB/s figure is retired (2026-10-13)

§16/§18 diagnosed the artifact; v2 removes it from the measurement contract.
`scripts/bench.sh` was rewritten as three tiers with separated duties —
full definition, baselines and the gate self-check live in
`docs/perf-report.md` ("基准定义 v2"):

| Tier | Measures | Duty |
|---|---|---|
| A | new-connection handshake→exit median (`ssh true`) | diagnostic; ALERT only |
| B | **data-plane throughput on one reused ControlMaster** (median MB/s up/down, byte-verified) | **the only throughput regression gate, +-20% of baseline** |
| C | new-connection 64 MB scp (the old v1 number, relabelled `newconn`) | record only; never gates |

The retired rule was "scp loss <= 15% or record" (v1 tail verdict), which
could not see a +-30% data-plane change under the ~1 s per-connection
back-off, and whose headline number (~45 MB/s via) was dominated by it.

Measured on this host (64 MiB, release, Fedora 44): via **423.3 / 528.9
MB/s** up/down against a direct control leg of 809.1 / 961.0 MB/s, i.e. the
gateway's data plane costs ~48% up / ~45% down — the number the old
benchmark could never report. Tier C came out at 41.4 MB/s, matching the old
"~45 MB/s" headline, which is the artifact reproduced end to end.

Reuse is *asserted*: `sshgw_agent_backend_auth_ok_total` must move by exactly
1 across the via master's lifetime (and 0 on the direct leg); anything else
means the rounds silently opened fresh connections and the run is invalid
(exit 2), not slow.

### Defect found by Tier B (fixed in the same change)

The very first Tier B run refused channel #9 of a reused connection with
`ResourceShortage` after ~1 s of bulk transfer. `channels_per_conn` (8) is
specified as an sshd-`MaxSessions`-style **concurrent** cap, but the handler
counted `agent_channels` — a set only `Handler::channel_close` shrinks, and a
close the *server* initiates is never echoed back as a handler callback. The
result was a **cumulative** cap: any long-lived connection died after 8
channels in total, which the multichannel case never reached (it opened 3).

Fix: live-channel accounting shared between the two tasks
(`relay::agent::ChannelSlots`), retired idempotently by whichever side
observes a channel's end first — the supervisor, whose down-pump completion
signal is the authority on liveness, and the handler, on a client-initiated
close or an op it could not hand over. `case_agent_multichannel.sh` now opens
12 further sequential channels on the same connection and asserts none is
denied; `scripts/bench.sh` Tier B exercises it in bulk.

### Gate self-check (a regression must be caught, not just allowed)

`GW_MAXPACKET=1KB` (32x more packets) drops via to 137.9 / 168.8 MB/s while
the direct leg stays at ~963–990 MB/s -> `REGRESSION`, `scripts/bench.sh`
exits 1. `GW_WINDOW=512KB` changes nothing and `256KB` (the config floor)
even *raises* uplink: on loopback (RTT ~0.05 ms) the window does not bind
throughput, which is also why the 2026-10-12 window A/B showed <1%. The gate
is therefore self-checked with `GW_MAXPACKET`, and window is documented as
not a Tier B lever.
