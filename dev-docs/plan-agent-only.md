# Plan — agent-only backend auth (remove Key/Cert, jump)

Status: product decision fixed (2026-10-12): (1) only agent-forwarding backend
auth; (2) remove jump/direct-tcpip. Front-leg user auth, host keys,
`[ca] trusted_ca_keys` verification, recording/interception/pool semantics stay.
Baseline: `main` @ 961a672. Awaits implementation; the D3 diff must be re-reviewed
by @oracle before it merges.

## Goal

The backend is **always** authenticated with the end user's forwarded ssh-agent
(`ssh -A` semantics). The gateway holds **no** credential of its own for the
backend leg: no `backend_auth = "key"`, no `credential_map`, no key files, no
cert-dial, no `[ca] signing_key`. `direct-tcpip`/jump is removed.

## Non-goals / preserved

Front-leg auth (resolver public key + CA user certs via `trusted_ca_keys`),
gateway host keys, backend **host-key** verification (`@cert-authority` /
pinned), session recording, SFTP/command interception, dial circuit breaker and
per-connection channel cap (`channels_per_conn`) all stay. `pool.enabled=true`
becomes a config error (agent identity is per-session).

## Key design decisions

1. **Single ordered consumer per session** (propose §3.5.1, now the ONLY data
   path). The supervisor owns one authenticated backend `Handle<BackendClient>`
   (!Sync) and a per-channel state map
   `HashMap<ChannelId, Arc<ChannelRelay>>`. I1 is per-channel FIFO
   (propose.md:120); cross-channel order is not an invariant.
2. **Multi-channel**: `channel_open_session` accepts the client channel, records
   it, and enqueues `OpenChannel{client_id}`. The supervisor opens a backend
   session channel, splits it, builds the relay, and spawns a per-channel
   `pump_backend_to_client`. `channels_per_conn` cap is enforced in the handler.
3. **Close the agent channel right after the one backend auth succeeds** —
   shrinks the signing-oracle window (red lines 4/10); the user's local agent is
   unaffected.
4. **Failures are protocol-native** (I4): no credential fallback exists.

## Deletions (precise)

- backend: `BackendAuthMethod::{Key,Cert}`, `ensure_agent_backend_auth`,
  `resolve_backend_auth`, `CredentialStore`, `connect` Key/Cert arms,
  `authenticate_with_certificate`, `ephemeral_identity`; `connect_agent` becomes
  the sole `connect`. Keep `load_private_key_checked` (host keys),
  `connect_inner`, `settle_auth`, `BackendClient`.
- config: `BackendConfig.{private_key,credential_map,backend_auth,
  allow_agent_backend_auth}` (keep `host_key_policy`); `JumpConfig`/`[jump]`;
  `[ca] signing_key`/`cert_lifetime`; validations for key/cert/jump. Keep
  `pool.enabled && agent` error (now always triggers).
- types: `Policy.backend_auth`/`backend_auth_method`; `tcp_forwarding*`.
- ca: `signing_key`, `can_issue`, `issue_*`; keep `trusted_ca*` + `validate_*`.
- error: `BackendError::{LoadKey, UnsafeKeyPermissions, IssueCert}`.
- server: `channel_open_direct_tcpip` (explicit reject), all inline relay
  branches; `agent_mode()` removed (always agent).
- lib: `pub mod jump`.

## Unified handler table

Every callback becomes "enqueue to the supervisor": OpenChannel / Data /
ExtendedData / Pty / Shell / Exec / Subsystem / Env / WindowChange / Signal /
Eof / Close, each carrying `client_id`. `agent_request` stays. `apply_uplink_tap`
stays in the handler; `taps`/`entry` stay in `GatewaySession`; `relays` moves
into the supervisor. `pump_backend_to_client` is reused per channel.

## Layered commits

- **D1** remove jump (src/jump, [jump] config, direct-tcpip logic, metrics, cases).
- **D2** multi-channel supervisor (AgentOp gains client_id + OpenChannel/Close;
  per-channel relay map + down-pumps; lift 1-channel cap; close agent channel
  after auth). Add multi-channel integration case.
- **D3** delete key/cert/CA-signing + unify handler callbacks (agent-only).
- **D4** tests/topology/docs: agent-ize subtopo/run_integration/common + 6
  harnesses; upgrade `propose §3.5.1` to the default architecture; update
  `config.example.toml`, `ops-runbook.md`, `known-limitations.md`.
- **D5** dead-code/metrics/comment cleanup.

## Tests

- Delete `case_jump`, `case_cert_dial`. Repurpose `case_port_forward_denied`
  (direct-tcpip always refused). Drop the jump sub-check in
  `case_agent_target_scope`.
- Agent-ize all remaining cases at the harness layer: `subtopo.sh` defaults to
  `backend_auth="agent"` + `agent_forwarding=true` + auto ssh-agent +
  `subtopo_ssh -A`; `run_integration.sh` default gateway drops `private_key`;
  `gen_assets.sh` writes the **user** key into `authorized_keys`.
- Key regression cases that must stay green: backpressure(_down), ordering_matrix,
  wire_ordering, rekey_midstream, sftp_intercept, exit_status, slow_link,
  pty_shell, scp, sftp.

## Red lines

I1 is per-channel FIFO; §3.5.1 single-consumer is now the architecture (its
"non-agent path unchanged" qualifier is removed). I2/I3/I4 unchanged. §3.6
bound is per channel; document `channels_per_conn × window`. D11 unchanged.
No credential fallback. Minimal signing surface; agent channel closed after the
single auth. `pool.enabled=true` is a config error. Jump is gone.

## Verification

cargo fmt --check · clippy --all-targets -D warnings · cargo test ·
cargo build --release · scripts/run_integration.sh (agent topology) ·
real-machine/soak/ha per ops window.

## Rollback

D1..D5 are independent commits; D3 is the credential-removal revert unit
(restores key/cert) and depends on D2. If multi-channel (D2) cannot land, stop
before D3 and deliver D1 only.
