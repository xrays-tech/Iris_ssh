//! SFTP command-level interception (propose.md §3.7 / B3).
//!
//! The subsystem is forwarded verbatim when no policy matches — the design's
//! requirement is that the fast path stay cheap, so parsing only happens once a
//! session is actually under audit and only over the *control* packets, never the
//! bulk read/write payloads.
//!
//! ## What is parsed
//!
//! SFTP (draft-ietf-secsh-filexfer-02) frames every message as
//! `uint32 length | byte type | request body`, where `length` covers `type` plus
//! the body. The inspector reassembles the client→server byte stream, decodes
//! each frame's type and — for the path-bearing requests — its string fields, and
//! decides per request. `READ`/`WRITE` payloads are deliberately **not** parsed:
//! they dominate transfer volume and carry no policy-relevant path.
//!
//! ## What a denial looks like on the wire
//!
//! Denying a request must not desynchronise the SFTP stream, so instead of
//! dropping the connection the inspector synthesises a protocol-native
//! `SSH_FXP_STATUS` failure (returned in [`DataVerdict::Rewrite::inject`]) and
//! simply withholds the denied request. The client sees `permission denied` for
//! that one operation — exactly what an OpenSSH-endorsed proxy does.

use std::sync::{Arc, Mutex};

use crate::relay::{ChannelCtx, ChannelTap, DataVerdict, Direction, SubsystemInterceptor, Verdict};

/// A decoded SFTP message of interest.
///
/// The numeric values are the **wire type bytes** from SFTP draft
/// ietf-secsh-filexfer-02; they are not interchangeable — `SSH_FXP_REMOVE` (13)
/// and `SSH_FXP_RMDIR` (15) look adjacent but mean very different things, and a
/// mix-up silently disables a policy rule (that exact bug is why
/// `tests::real_client_wire_bytes_decode` below asserts the golden frames
/// captured from the OpenSSH `sftp` client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SftpCommand {
    /// `SSH_FXP_INIT` — version negotiation; carries no path.
    Init,
    /// `SSH_FXP_VERSION` — the server's version reply.
    Version,
    Open,
    Close,
    Read,
    Write,
    Lstat,
    Fstat,
    SetStat,
    /// `SSH_FXP_FSETSTAT` (10) — by handle, so it carries no path.
    FSetStat,
    Remove,
    Rename,
    Mkdir,
    Rmdir,
    OpenDir,
    ReadDir,
    RealPath,
    Stat,
    /// `SSH_FXP_EXTENDED` — a vendor extension request (e.g. `limits@openssh.com`).
    Extended,
    /// A request this parser does not classify (forwarded as-is).
    Other(u8),
}

impl SftpCommand {
    /// The SFTP message type byte for this command.
    pub fn type_byte(self) -> u8 {
        match self {
            SftpCommand::Init => 1,
            SftpCommand::Version => 2,
            SftpCommand::Open => 3,
            SftpCommand::Close => 4,
            SftpCommand::Read => 5,
            SftpCommand::Write => 6,
            SftpCommand::Lstat => 7,
            SftpCommand::Fstat => 8,
            SftpCommand::SetStat => 9,
            SftpCommand::FSetStat => 10,
            SftpCommand::OpenDir => 11,
            SftpCommand::ReadDir => 12,
            SftpCommand::Remove => 13,
            SftpCommand::Mkdir => 14,
            SftpCommand::Rmdir => 15,
            SftpCommand::RealPath => 16,
            SftpCommand::Stat => 17,
            SftpCommand::Rename => 18,
            SftpCommand::Extended => 200,
            SftpCommand::Other(b) => b,
        }
    }

    /// The stable name used in policy rules, audit records and logs.
    pub fn name(self) -> String {
        match self {
            SftpCommand::Init => "INIT".to_owned(),
            SftpCommand::Version => "VERSION".to_owned(),
            SftpCommand::Open => "OPEN".to_owned(),
            SftpCommand::Close => "CLOSE".to_owned(),
            SftpCommand::Read => "READ".to_owned(),
            SftpCommand::Write => "WRITE".to_owned(),
            SftpCommand::Lstat => "LSTAT".to_owned(),
            SftpCommand::Fstat => "FSTAT".to_owned(),
            SftpCommand::SetStat => "SETSTAT".to_owned(),
            SftpCommand::FSetStat => "FSETSTAT".to_owned(),
            SftpCommand::OpenDir => "OPENDIR".to_owned(),
            SftpCommand::ReadDir => "READDIR".to_owned(),
            SftpCommand::Remove => "REMOVE".to_owned(),
            SftpCommand::Mkdir => "MKDIR".to_owned(),
            SftpCommand::Rmdir => "RMDIR".to_owned(),
            SftpCommand::RealPath => "REALPATH".to_owned(),
            SftpCommand::Stat => "STAT".to_owned(),
            SftpCommand::Rename => "RENAME".to_owned(),
            SftpCommand::Extended => "EXTENDED".to_owned(),
            SftpCommand::Other(b) => format!("OTHER({b})"),
        }
    }

    /// Whether the command is path-bearing (so path rules apply).
    pub fn has_path(self) -> bool {
        matches!(
            self,
            SftpCommand::Open
                | SftpCommand::Lstat
                | SftpCommand::SetStat
                | SftpCommand::Remove
                | SftpCommand::Rename
                | SftpCommand::Mkdir
                | SftpCommand::Rmdir
                | SftpCommand::OpenDir
                | SftpCommand::RealPath
                | SftpCommand::Stat
        )
    }

    /// Whether the message is the **server → client** version reply, which the
    /// inspector must never treat as a request even if it appears in a buffer
    /// handed to the uplink path.
    pub fn is_version(self) -> bool {
        matches!(self, SftpCommand::Version)
    }
}

/// A fully-decoded SFTP request frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SftpRequest {
    /// The client's request id, echoed back in the synthesized status.
    pub request_id: u32,
    pub command: SftpCommand,
    /// The primary path for path-bearing commands (already UTF-8 lossy-decoded).
    pub path: Option<String>,
    /// The destination for `RENAME`.
    pub new_path: Option<String>,
}

/// Minimal big-endian wire cursor.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Some(slice)
    }
}

/// Decode one SFTP frame from `frame` (which must start at the `type` byte,
/// i.e. after the 4-byte length prefix has been stripped).
pub fn decode_request(frame: &[u8]) -> Option<SftpRequest> {
    let mut c = Cursor::new(frame);
    let type_byte = *c.take(1)?.first()?;
    let command = match type_byte {
        1 => SftpCommand::Init,
        2 => SftpCommand::Version,
        3 => SftpCommand::Open,
        4 => SftpCommand::Close,
        5 => SftpCommand::Read,
        6 => SftpCommand::Write,
        7 => SftpCommand::Lstat,
        8 => SftpCommand::Fstat,
        9 => SftpCommand::SetStat,
        10 => SftpCommand::FSetStat,
        11 => SftpCommand::OpenDir,
        12 => SftpCommand::ReadDir,
        13 => SftpCommand::Remove,
        14 => SftpCommand::Mkdir,
        15 => SftpCommand::Rmdir,
        16 => SftpCommand::RealPath,
        17 => SftpCommand::Stat,
        18 => SftpCommand::Rename,
        200 => SftpCommand::Extended,
        other => SftpCommand::Other(other),
    };

    // INIT is the only client message without a request id; everything else —
    // including the server's VERSION reply — starts with one.
    if matches!(command, SftpCommand::Init) {
        return Some(SftpRequest {
            request_id: 0,
            command,
            path: None,
            new_path: None,
        });
    }

    let request_id = u32::from_be_bytes(c.take(4)?.try_into().ok()?);
    let (path, new_path) = match command {
        SftpCommand::Open
        | SftpCommand::Lstat
        | SftpCommand::SetStat
        | SftpCommand::Remove
        | SftpCommand::Mkdir
        | SftpCommand::Rmdir
        | SftpCommand::OpenDir
        | SftpCommand::RealPath
        | SftpCommand::Stat => (Some(read_string(&mut c)?), None),
        // RENAME carries (oldpath, newpath).
        SftpCommand::Rename => (Some(read_string(&mut c)?), Some(read_string(&mut c)?)),
        _ => (None, None),
    };

    Some(SftpRequest {
        request_id,
        command,
        path,
        new_path,
    })
}

/// Read an SFTP `string` (`uint32 length | bytes`).
fn read_string(c: &mut Cursor<'_>) -> Option<String> {
    let len = u32::from_be_bytes(c.take(4)?.try_into().ok()?) as usize;
    let bytes = c.take(len)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Encode a `SSH_FXP_STATUS` failure for `request_id`.
///
/// `status` is an `SSH_FX_*` code (we use `SSH_FX_PERMISSION_DENIED` = 3).
pub fn encode_status_failure(request_id: u32, status: u32, message: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(32);
    body.push(101); // SSH_FXP_STATUS
    body.extend_from_slice(&request_id.to_be_bytes());
    body.extend_from_slice(&status.to_be_bytes());
    body.extend_from_slice(&(message.len() as u32).to_be_bytes());
    body.extend_from_slice(message.as_bytes());
    body.extend_from_slice(&0u32.to_be_bytes()); // language tag
                                                 // Frame it: uint32 length (body) || body.
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// `SSH_FX_PERMISSION_DENIED`.
pub const FX_PERMISSION_DENIED: u32 = 3;
/// `SSH_FX_NO_SUCH_FILE`.
pub const FX_NO_SUCH_FILE: u32 = 2;

/// A normalised, validated SFTP policy (already checked by the config layer).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SftpRules {
    /// Upper-cased command names to refuse.
    pub deny_commands: Vec<String>,
    /// Path prefixes that may be reached; empty means "all allowed".
    pub allowed_path_prefixes: Vec<String>,
    /// Path prefixes always refused (evaluated after the allow-list).
    pub denied_path_prefixes: Vec<String>,
}

impl SftpRules {
    /// Decide whether `request` is permitted, returning the denial reason.
    pub fn check(&self, request: &SftpRequest) -> Result<(), String> {
        let name = request.command.name();
        if self.deny_commands.contains(&name) {
            return Err(format!("SFTP command {name} is not permitted"));
        }
        let Some(path) = request.path.as_deref() else {
            return Ok(());
        };
        // A rename has two paths; both must pass.
        let paths = match request.new_path.as_deref() {
            Some(new_path) => vec![path, new_path],
            None => vec![path],
        };
        for p in paths {
            if self
                .denied_path_prefixes
                .iter()
                .any(|prefix| p.starts_with(prefix.as_str()))
            {
                return Err(format!("path {p:?} is denied by policy"));
            }
            if !self.allowed_path_prefixes.is_empty()
                && !self
                    .allowed_path_prefixes
                    .iter()
                    .any(|prefix| p.starts_with(prefix.as_str()))
            {
                return Err(format!("path {p:?} is outside the allowed prefixes"));
            }
        }
        Ok(())
    }
}

/// The normalised output of [`validate_rules`]:
/// `(deny_commands, allowed_path_prefixes, denied_path_prefixes)`.
type NormalizedRules = (Vec<String>, Vec<String>, Vec<String>);

/// Validate and normalise a raw rule set coming from configuration.
///
/// Command names are upper-cased and checked against the known set so a typo
/// fails at startup instead of silently never matching. Path prefixes must be
/// absolute (a relative prefix is almost always a config bug).
pub fn validate_rules(
    deny_commands: &[String],
    allowed_path_prefixes: &[String],
    denied_path_prefixes: &[String],
) -> std::result::Result<NormalizedRules, crate::error::ConfigError> {
    const KNOWN: &[&str] = &[
        "OPEN", "CLOSE", "READ", "WRITE", "LSTAT", "FSTAT", "SETSTAT", "REMOVE", "RENAME", "MKDIR",
        "RMDIR", "OPENDIR", "READDIR", "REALPATH", "STAT", "INIT",
    ];

    let invalid = |what: &str, value: &str| crate::error::ConfigError::Invalid {
        field: format!("intercept.sftp.{what}"),
        reason: format!("{value:?} is not a valid value"),
    };

    let mut deny = Vec::with_capacity(deny_commands.len());
    for cmd in deny_commands {
        let upper = cmd.trim().to_ascii_uppercase();
        if !KNOWN.contains(&upper.as_str()) {
            return Err(invalid("deny_commands", cmd));
        }
        if !deny.contains(&upper) {
            deny.push(upper);
        }
    }

    let check_prefixes = |prefixes: &[String],
                          field: &str|
     -> std::result::Result<Vec<String>, crate::error::ConfigError> {
        let mut out = Vec::with_capacity(prefixes.len());
        for p in prefixes {
            let trimmed = p.trim();
            if !trimmed.starts_with('/') {
                return Err(invalid(field, p));
            }
            out.push(trimmed.to_owned());
        }
        Ok(out)
    };

    Ok((
        deny,
        check_prefixes(allowed_path_prefixes, "allowed_path_prefixes")?,
        check_prefixes(denied_path_prefixes, "denied_path_prefixes")?,
    ))
}

/// An SFTP-aware [`ChannelTap`]: reassembles the client→server stream, decodes
/// each request, and forwards only what policy permits — synthesising an
/// `SSH_FXP_STATUS` failure for each refused request so the client's SFTP stream
/// stays in sync (I4: refuse with a protocol-native mechanism, never by killing
/// the channel or fabricating success).
pub struct SftpInspector {
    rules: SftpRules,
    /// Reassembly buffer for frames split across SSH data chunks.
    pending: Mutex<Vec<u8>>,
    metrics: crate::metrics::Metrics,
}

impl SftpInspector {
    pub fn new(rules: SftpRules, metrics: crate::metrics::Metrics) -> Self {
        SftpInspector {
            rules,
            pending: Mutex::new(Vec::new()),
            metrics,
        }
    }

    /// Decode the complete frames in `pending`, draining what was consumed and
    /// returning each frame's decoded request together with its **owned** bytes
    /// (so the caller never indexes a buffer that has already been drained).
    fn drain_frames(&self, pending: &mut Vec<u8>) -> Vec<DecodedFrame> {
        let mut frames = Vec::new();
        let mut consumed = 0usize;
        loop {
            let Some(frame) = pending.get(consumed..) else {
                break;
            };
            if frame.len() < 4 {
                break; // not even a length prefix yet
            }
            let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
            // A zero/absurd length means the stream is not SFTP (e.g. some other
            // subsystem); stop interpreting rather than buffering forever.
            if len == 0 || len > 1024 * 1024 {
                break;
            }
            let end = 4 + len;
            if frame.len() < end {
                break; // incomplete frame, wait for more bytes
            }
            if let Some(request) = decode_request(&frame[4..end]) {
                frames.push(DecodedFrame {
                    bytes: frame[..end].to_vec(),
                    request,
                });
            }
            consumed = end;
        }
        if consumed > 0 {
            pending.drain(..consumed);
        }
        frames
    }
}

/// A decoded SFTP frame together with its exact wire bytes, so an inspector can
/// forward or withhold it without reaching back into the reassembly buffer.
struct DecodedFrame {
    bytes: Vec<u8>,
    request: SftpRequest,
}

impl ChannelTap for SftpInspector {
    fn on_data(&self, dir: Direction, buf: &[u8]) -> DataVerdict {
        // Only the client→server direction carries SFTP *requests*; responses
        // pass through untouched (and are recorded if recording is also on).
        if !matches!(dir, Direction::Up) {
            return DataVerdict::Pass;
        }

        let mut pending = match self.pending.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        pending.extend_from_slice(buf);
        let frames = self.drain_frames(&mut pending);
        if frames.is_empty() {
            return DataVerdict::Pass;
        }

        let mut forward = Vec::new();
        let mut inject = Vec::new();
        let mut first_denial: Option<String> = None;
        for DecodedFrame { bytes, request } in frames {
            self.metrics.sftp_request_seen();
            match self.rules.check(&request) {
                Ok(()) => forward.extend_from_slice(&bytes),
                Err(reason) => {
                    self.metrics.sftp_request_denied();
                    if first_denial.is_none() {
                        first_denial = Some(reason);
                    }
                    // Synthesise a protocol-native failure so the client learns
                    // the outcome instead of hanging on a request we dropped.
                    inject.extend_from_slice(&encode_status_failure(
                        request.request_id,
                        FX_PERMISSION_DENIED,
                        "denied by gateway policy",
                    ));
                }
            }
        }

        if first_denial.is_none() {
            // Nothing refused: forward the original slice with no copy.
            return DataVerdict::Pass;
        }
        DataVerdict::Rewrite {
            forward,
            inject,
            denied: first_denial,
        }
    }
}

/// The gateway's SFTP subsystem policy.
#[derive(Clone)]
pub struct SftpAuditInterceptor {
    enabled: bool,
    rules: SftpRules,
    metrics: crate::metrics::Metrics,
}

impl SftpAuditInterceptor {
    /// Build from validated config. A disabled interceptor passes everything
    /// through, including `observe` returning `None`.
    pub fn new(
        config: &crate::config::SftpInterceptConfig,
        metrics: crate::metrics::Metrics,
    ) -> Self {
        SftpAuditInterceptor {
            enabled: config.enabled,
            rules: SftpRules {
                deny_commands: config.deny_commands.clone(),
                allowed_path_prefixes: config.allowed_path_prefixes.clone(),
                denied_path_prefixes: config.denied_path_prefixes.clone(),
            },
            metrics,
        }
    }

    /// The compiled rule set (exposed for assertions and tests).
    pub fn rules(&self) -> &SftpRules {
        &self.rules
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl SubsystemInterceptor for SftpAuditInterceptor {
    fn on_subsystem_request<'a>(
        &'a self,
        name: &'a str,
        _grant: &'a crate::types::Grant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            if self.enabled && name == "sftp" {
                // Tap so a per-channel inspector is created for this channel.
                Verdict::Tap
            } else {
                Verdict::Pass
            }
        })
    }

    fn observe(&self, _ctx: &ChannelCtx) -> Option<Arc<dyn ChannelTap>> {
        if self.enabled {
            Some(Arc::new(SftpInspector::new(
                self.rules.clone(),
                self.metrics.clone(),
            )))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a framed SFTP request (length || type || body).
    ///
    /// The type byte always comes from `SftpCommand::type_byte`, never a literal,
    /// so a fixture can never disagree with the parser (a literal-only fixture is
    /// what let the wrong REMOVE/RMDIR numbering pass unnoticed).
    fn frame(command: SftpCommand, body: &[u8]) -> Vec<u8> {
        let mut inner = vec![command.type_byte()];
        inner.extend_from_slice(body);
        let mut out = Vec::new();
        out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        out.extend_from_slice(&inner);
        out
    }

    fn id_body(id: u32, rest: &[u8]) -> Vec<u8> {
        let mut b = id.to_be_bytes().to_vec();
        b.extend_from_slice(rest);
        b
    }

    fn ssh_string(s: &str) -> Vec<u8> {
        let mut out = (s.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(s.as_bytes());
        out
    }

    /// Golden frames captured from the real OpenSSH `sftp` client on macOS while
    /// running `rm <regular file>` through the gateway (RUST_LOG instrumentation).
    ///
    /// These bytes exist because the first implementation of this table numbered
    /// `SSH_FXP_REMOVE` as 10 and `SSH_FXP_RMDIR` as 13 — self-consistent with
    /// the unit fixtures, and therefore invisible to them, but wrong on the wire,
    /// so a `deny_commands=["REMOVE"]` policy never matched the client's actual
    /// delete request. Asserting the real capture pins the mapping.
    /// Parse a space-separated hex string (line continuations allowed).
    fn hex(spec: &str) -> Vec<u8> {
        let cleaned: String = spec
            .chars()
            .filter(|c| !c.is_whitespace() || *c == ' ')
            .collect();
        cleaned
            .split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).expect("valid hex byte"))
            .collect()
    }

    #[test]
    fn real_client_wire_bytes_decode() {
        // SSH_FXP_INIT (version 3).
        let init = hex("00 00 00 05 01 00 00 00 03");
        assert_eq!(
            decode_request(&init[4..]).expect("decode INIT").command,
            SftpCommand::Init
        );

        // SSH_FXP_EXTENDED "limits@openssh.com" (type 200), id 1.
        let ext = hex("00 00 00 1b c8 00 00 00 01 00 00 00 12 \
             6c 69 6d 69 74 73 40 6f 70 65 6e 73 73 68 2e 63 6f 6d");
        let decoded = decode_request(&ext[4..]).expect("decode EXTENDED");
        assert_eq!(decoded.command, SftpCommand::Extended);
        assert_eq!(decoded.request_id, 1);

        // SSH_FXP_REALPATH"." (type 16), id 2.
        let realpath = hex("00 00 00 0a 10 00 00 00 02 00 00 00 01 2e");
        let decoded = decode_request(&realpath[4..]).expect("decode REALPATH");
        assert_eq!(decoded.command, SftpCommand::RealPath);
        assert_eq!(decoded.path.as_deref(), Some("."));

        // SSH_FXP_LSTAT (type 7), id 3.
        let lstat = hex("00 00 00 17 07 00 00 00 03 00 00 00 0e \
             2f 74 6d 70 2f 61 62 63 64 65 66 67 68 69");
        let decoded = decode_request(&lstat[4..]).expect("decode LSTAT");
        assert_eq!(decoded.command, SftpCommand::Lstat);
        assert_eq!(decoded.request_id, 3);

        // THE delete: SSH_FXP_REMOVE (type **13**), id 4 — the byte the old table
        // read as RMDIR. This is the assertion that would have caught the bug.
        let remove = hex("00 00 00 17 0d 00 00 00 04 00 00 00 0e \
             2f 74 6d 70 2f 61 62 63 64 65 66 67 68 69");
        let decoded = decode_request(&remove[4..]).expect("decode REMOVE");
        assert_eq!(
            decoded.command,
            SftpCommand::Remove,
            "type byte 13 must decode as SSH_FXP_REMOVE, not RMDIR"
        );
        assert_eq!(decoded.command.type_byte(), 13);
        assert_eq!(decoded.command.name(), "REMOVE");
        assert_eq!(decoded.request_id, 4);
        assert!(decoded.command.has_path(), "REMOVE is path-bearing");
    }

    #[test]
    fn sftp_type_bytes_match_the_protocol_spec() {
        // The full wire table, so an off-by-one anywhere else is caught too.
        let expected: &[(SftpCommand, u8)] = &[
            (SftpCommand::Init, 1),
            (SftpCommand::Version, 2),
            (SftpCommand::Open, 3),
            (SftpCommand::Close, 4),
            (SftpCommand::Read, 5),
            (SftpCommand::Write, 6),
            (SftpCommand::Lstat, 7),
            (SftpCommand::Fstat, 8),
            (SftpCommand::SetStat, 9),
            (SftpCommand::FSetStat, 10),
            (SftpCommand::OpenDir, 11),
            (SftpCommand::ReadDir, 12),
            (SftpCommand::Remove, 13),
            (SftpCommand::Mkdir, 14),
            (SftpCommand::Rmdir, 15),
            (SftpCommand::RealPath, 16),
            (SftpCommand::Stat, 17),
            (SftpCommand::Rename, 18),
            (SftpCommand::Extended, 200),
        ];
        for (command, byte) in expected {
            assert_eq!(
                command.type_byte(),
                *byte,
                "{} has the wrong wire byte",
                command.name()
            );
            // And the decoder must round-trip the byte back to the same command.
            let mut frame = vec![*byte, 0, 0, 0, 1]; // type + a plausible request id
                                                     // Two empty string fields: enough for the path-bearing commands, and
                                                     // harmlessly unread by the handle-based ones.
            frame.extend_from_slice(&0u32.to_be_bytes());
            frame.extend_from_slice(&0u32.to_be_bytes());
            let decoded = decode_request(&frame).expect("decode round-trip");
            assert_eq!(
                decoded.command,
                *command,
                "byte {byte} must decode back to {}",
                command.name()
            );
        }
    }

    #[test]
    fn decodes_path_bearing_requests() {
        let open = frame(SftpCommand::Open, &id_body(7, &ssh_string("/etc/passwd")));
        // Strip the length prefix, as the reassembler would.
        let body = &open[4..];
        let req = decode_request(body).expect("decode OPEN");
        assert_eq!(req.command, SftpCommand::Open);
        assert_eq!(req.request_id, 7);
        assert_eq!(req.path.as_deref(), Some("/etc/passwd"));

        let rm = frame(SftpCommand::Remove, &id_body(8, &ssh_string("/tmp/x")));
        let req = decode_request(&rm[4..]).expect("decode REMOVE");
        assert_eq!(req.command, SftpCommand::Remove);
        assert_eq!(req.path.as_deref(), Some("/tmp/x"));
    }

    #[test]
    fn decodes_rename_with_two_paths() {
        let mut body = 9u32.to_be_bytes().to_vec();
        body.extend_from_slice(&ssh_string("/a/old"));
        body.extend_from_slice(&ssh_string("/a/new"));
        let f = frame(SftpCommand::Rename, &body);
        let req = decode_request(&f[4..]).expect("decode RENAME");
        assert_eq!(req.command, SftpCommand::Rename);
        assert_eq!(req.path.as_deref(), Some("/a/old"));
        assert_eq!(req.new_path.as_deref(), Some("/a/new"));
    }

    #[test]
    fn decodes_init_and_unknown_types() {
        let init = frame(SftpCommand::Init, &3u32.to_be_bytes());
        let req = decode_request(&init[4..]).expect("decode INIT");
        assert_eq!(req.command, SftpCommand::Init);
        assert_eq!(req.request_id, 0);
        assert!(!req.command.has_path());

        // Type 77 is genuinely unassigned; 200 is now known (SSH_FXP_EXTENDED).
        let weird = frame(SftpCommand::Other(77), &[0, 0, 0, 1]);
        let req = decode_request(&weird[4..]).expect("decode unknown");
        assert_eq!(req.command, SftpCommand::Other(77));
        assert_eq!(req.command.name(), "OTHER(77)");
        // And type 200 must now decode as the extension request it really is.
        let ext = frame(SftpCommand::Extended, &0u32.to_be_bytes());
        let req = decode_request(&ext[4..]).expect("decode extended");
        assert_eq!(req.command, SftpCommand::Extended);
    }

    #[test]
    fn truncated_frame_fails_cleanly() {
        // A length prefix promising more bytes than present.
        let mut bad = Vec::new();
        bad.extend_from_slice(&64u32.to_be_bytes());
        bad.extend_from_slice(&[3, 0, 0]);
        assert!(decode_request(&bad[4..]).is_none());
    }

    #[test]
    fn deny_rule_blocks_the_named_command() {
        let rules = SftpRules {
            deny_commands: vec!["REMOVE".to_owned()],
            ..Default::default()
        };
        let remove = SftpRequest {
            request_id: 1,
            command: SftpCommand::Remove,
            path: Some("/tmp/x".to_owned()),
            new_path: None,
        };
        assert!(rules.check(&remove).is_err());
        let open = SftpRequest {
            request_id: 2,
            command: SftpCommand::Open,
            path: Some("/tmp/x".to_owned()),
            new_path: None,
        };
        assert!(rules.check(&open).is_ok());
    }

    #[test]
    fn allow_and_deny_prefixes_apply_to_all_paths() {
        let rules = SftpRules {
            deny_commands: Vec::new(),
            allowed_path_prefixes: vec!["/data/".to_owned()],
            denied_path_prefixes: vec!["/data/secret".to_owned()],
        };
        let mk = |p: &str| SftpRequest {
            request_id: 1,
            command: SftpCommand::Open,
            path: Some(p.to_owned()),
            new_path: None,
        };
        assert!(rules.check(&mk("/data/ok.txt")).is_ok());
        assert!(
            rules.check(&mk("/etc/shadow")).is_err(),
            "outside the allow-list"
        );
        assert!(
            rules.check(&mk("/data/secret/x")).is_err(),
            "denied prefix wins"
        );

        // RENAME is checked on both endpoints.
        let rename = SftpRequest {
            request_id: 3,
            command: SftpCommand::Rename,
            path: Some("/data/a".to_owned()),
            new_path: Some("/etc/passwd".to_owned()),
        };
        assert!(
            rules.check(&rename).is_err(),
            "destination escapes the allow-list"
        );
    }

    #[test]
    fn empty_allow_list_permits_all_paths() {
        let rules = SftpRules {
            deny_commands: Vec::new(),
            allowed_path_prefixes: Vec::new(),
            denied_path_prefixes: Vec::new(),
        };
        let open = SftpRequest {
            request_id: 1,
            command: SftpCommand::Open,
            path: Some("/anywhere".to_owned()),
            new_path: None,
        };
        assert!(rules.check(&open).is_ok());
    }

    #[test]
    fn validate_rules_uppercases_and_rejects_junk() {
        let (deny, allow, denied) = validate_rules(
            &["remove".to_owned(), "REMOVE".to_owned()],
            &["/data".to_owned()],
            &["/data/x".to_owned()],
        )
        .unwrap();
        assert_eq!(
            deny,
            vec!["REMOVE".to_owned()],
            "case-insensitive and deduped"
        );
        assert_eq!(allow, vec!["/data".to_owned()]);
        assert_eq!(denied, vec!["/data/x".to_owned()]);

        assert!(validate_rules(&["BOGUS".to_owned()], &[], &[]).is_err());
        assert!(validate_rules(&[], &["relative/path".to_owned()], &[]).is_err());
    }

    #[test]
    fn synthesized_status_frame_is_well_formed() {
        let out = encode_status_failure(42, FX_PERMISSION_DENIED, "nope");
        // length || 101 || id || status || msg || lang
        let len = u32::from_be_bytes(out[..4].try_into().unwrap()) as usize;
        assert_eq!(len + 4, out.len(), "frame length must cover the body");
        assert_eq!(out[4], 101, "SSH_FXP_STATUS");
        assert_eq!(u32::from_be_bytes(out[5..9].try_into().unwrap()), 42);
        assert_eq!(
            u32::from_be_bytes(out[9..13].try_into().unwrap()),
            FX_PERMISSION_DENIED
        );
        // It must round-trip back out of the reassembler's perspective: the body
        // after the length prefix starts with the status type byte.
        let body = &out[4..];
        let req = decode_request(body);
        assert!(
            req.is_some(),
            "the status frame must be decodable as a message"
        );
        assert_eq!(req.unwrap().command.type_byte(), 101);
    }
}
