# Plan — User-Key Passthrough (agent forwarding, `ssh -A` semantics)

Status: design adjudicated (@oracle, CONDITIONAL GO). Implementation in progress.
Applies to `main`. Adjudications are authoritative: `propose.md` §3.5/§3.6/§3.8,
your higher-level design intent.

## Goal

Let the backend see the **end user's identity**: the gateway authenticates to the
backend using the **client's ssh-agent** (via agent forwarding), while the
private key never leaves the client. Currently the backend leg only uses the
gateway's own configured keys/CA (`BackendAuthMethod::Key|Cert`); `agent_request`
is default-denied (`src/server/mod.rs:1519-1526`).

## Why a per-session supervisor is mandatory (deadlock)

russh's server is a single serial loop: it reads a packet, awaits the handler,
and does not read the next packet until the handler returns. Agent signature
requests are request/response over the agent channel backed by **the same loop's
reader** — so waiting for an agent signature inside a handler callback (or during
an in-handler backend dial) deadlocks: the loop is busy, the agent reply is never
read. Therefore the agent dial and the agent-mode forwarding must live in a
**per-session supervisor task**; the handler only does non-blocking enqueue. This
is the route-1 C3 shape — previously reverted for **zero performance gain**;
here it is a **correctness requirement**, not a throughput measure.

## Architecture (agent mode only)

```
client --ssh -A--> [russh server leg] Handler (enqueues, never awaits agent)
                       | mpsc (bounded, FIFO) + oneshot/watch (ready)
                       v
        supervisor (per session, one ordered consumer)
          ├─ Handle::channel_open_agent().await  -> Channel<Msg>     (session loop must be idle to confirm)
          ├─ AgentClient::connect(chan.into_stream())                (impl Signer)
          ├─ request_identities() -> pick identity matching grant.fingerprint
          ├─ dialer.connect_agent(&grant, &mut agent).await          (backend auth via user agent)
          └─ consume queue in order: channel_open/pty/shell/exec/subsystem/env/data/eof/close
```

- Non-agent mode: the existing in-handler path is **byte-for-byte unchanged**
  (supervisor never engaged).
- `policy.agent_forwarding` already exists (`src/types.rs:125`,
  `policy/mod.rs:200` agent_forwarding_allowed) and was unwired — wire it now.

## Config / policy

- `BackendAuthMethod` gains `Agent` (`src/backend/mod.rs:33-63`): `parse("agent")`,
  `as_str()`, error text `expected "key", "cert" or "agent"`. `resolve_backend_auth`
  logic unchanged.
- New `[backend] allow_agent_backend_auth = false` (default) — global kill-switch.
  Priority: kill-switch is a veto; `backend_auth` default/override decides intent;
  both true → resolves to `Agent`. Hard-fail (never silently downgrade):
  - default `backend_auth="agent"` while kill-switch off → config-validation error
    (`src/config.rs:745-790`);
  - policy `policy.backend_auth="agent"` while kill-switch off → resolve-time error.
- `agent_request` returns `true` only when
  `allow_agent_backend_auth && policy.agent_forwarding_allowed`; else `false`
  (behavior identical to today's default-deny).
- `pool.enabled && backend_auth=agent` → config-validation error (propose §3.8).
- No-agent / no-matching-identity / dial failure → **protocol-native failure**
  (channel_failure / open-reject), never fallback to gateway key/cert.

## Final red lines (do not violate)

1. Resolver stays the only admission decision; agent only changes *which`
   identity authenticates to the backend, never *where* the user may go.
2. Never forward the agent to the backend: backend leg must NOT implement
   `server_channel_open_agent_forward`.
3. Never silently downgrade to gateway `key`/`cert`; failures use native
   protocol primitives (I4).
4. Minimal signing surface: only the resolve-targeted single backend, only the
   identity whose public-key fingerprint equals the front-leg authenticated
   fingerprint (`grant.fingerprint`).
5. I1 rebuilt on a single consumer: one FIFO consumer per session; no per-request
   spawn; no merging/reordering/injected gateway requests; non-agent path
   byte-for-byte unchanged.
6. Bounded memory (§3.6): queue + pre-auth buffer ≤ `relay.window_size`.
7. D11: no `await` while holding a lock; readiness via `oneshot`/`watch`, not
   `std::sync::Mutex` across await.
8. No-deadlock (C5): inside the agent-auth window the handler must never block
   on the queue (use `try_send`; when the supervisor is Dialing and the queue is
   full → fail the channel natively, never await).
9. §3.8 / MVP: `pool.enabled && agent` is a config error; agent mode is limited
   to 1 channel per session — a 2nd session-channel open is natively rejected
   (`ChannelOpenFailure::ResourceShortage`) + metric + log.
10. Observability: audit/metrics record `auth_kind=agent`, signature count,
    identity fingerprint, target host:port, backend user.
11. Written: `propose.md §3.5.1` agent-mode exception must land before C2
    merges; `config.example.toml` / `ops-runbook.md` document the security
    boundary and limitations.
12. **The C2 diff must be reviewed by @oracle before merge.**

## Layered commits

- **C1** — config/enum/policy (default off, pure addition, zero regression):
  `BackendAuthMethod::Agent`, `allow_agent_backend_auth`, validations
  (agent-mode needs neither key nor CA; `pool×agent` error; kill-switch veto),
  wire `agent_forwarding_allowed`. Unit tests for parse/validate/resolve.
- **C2** — supervisor + `connect_agent` (agent mode only):
  - `src/backend/mod.rs` `connect` → extract `connect_inner`; add generic
    `connect_agent<SG: Signer>` reusing breaker/timeout/hostkey verify, agent
    auth via `authenticate_publickey_with` (`client/mod.rs:503`).
  - new `src/relay/agent.rs`: supervisor (channel_open_agent →
    AgentClient::connect(into_stream()) → request_identities → pick_identity by
    fingerprint → connect_agent → ordered FIFO consume of enqueued ops →
    backend ChannelWriteHalf / server::Handle; failure paths native).
  - `src/server/mod.rs`: agent mode → `channel_open_session` accepts without
    inline dial, hands channel to supervisor; `agent_request` decision; request/
    data callbacks enqueue (non-agent path unchanged); `GatewaySession` holds an
    optional supervisor handle (mpsc sender + state).
  - `propose.md §3.5.1` amendment (single-ordered-consumer exception, this
    adjudication's four qualifiers).
- **C3** — docs (`config.example.toml`, `ops-runbook.md`, propose §3.8 note):
  security boundary, 1-channel limit, no-agent rejection semantics, "enabling
  means you trust that backend".

## Tests

- Unit: BackendAuthMethod parse round-trip + invalid error; resolve_backend_auth
  incl. Agent; config validation (agent needs no key/CA; kill-switch veto; pool×
  agent error; default false); `pick_identity` match/no-match; agent_forwarding
  gating.
- Integration (4 new, real ssh-agent):
  - `case_agent_auth.sh` — `ssh -A` + agent with user key; backend authorized_keys
    has the **user** public key; backend sees the user; byte-verified.
  - `case_agent_missing.sh` — no `-A`: native rejection, assert no gateway-key
    fallback.
  - `case_agent_no_key.sh` — `-A` but agent lacks the matching user key: rejected.
  - `case_agent_target_scope.sh` — MVP: jump refused in agent mode; agent only
    used for the resolved target.
- Regression: existing 25 integration cases must stay green (agent request
  remains denied when kill-switch off ⇒ default = status quo).

## Full verification

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
scripts/run_integration.sh        # incl. new case_agent_*
make bench                        # non-agent path regression check
```

## Rollback

`allow_agent_backend_auth=false` (default) ⇒ no behavior change; C2/C3 revert
cleanly; C1 is side-effect-free retained. C2 is the revert unit.

## Gate / DoD

- DoD: C1+C2+C3 land with §3.5.1 first; 4 agent cases green; full suite green;
  clippy/fmt clean; docs updated; C2 diff reviewed by @oracle before merge.
- If the no-deadlock strategy or §3.5.1 cannot land → C2 NO-GO; deliver C1 and a
  jump-mode recommendation instead.
