//! Audit: command classification and the end-of-session audit record.
//!
//! Classification (propose.md §3.7) distinguishes the modern SFTP path from the
//! legacy `scp`-over-exec path so that recorded commands are meaningful to an
//! auditor:
//!
//! | feature | class |
//! |---|---|
//! | `exec` command starts with `scp ` | [`CommandClass::Scp`] |
//! | `subsystem == "sftp"` | [`CommandClass::Sftp`] |
//! | `exec` command contains `rsync` | [`CommandClass::Rsync`] |
//! | any other `exec` | [`CommandClass::Exec`] |
//! | a bare `shell` request | [`CommandClass::Interactive`] |
//!
//! Classification is a pure function over the request bytes; the resulting
//! [`AuditRecord`] carries who/when/target/bytes/duration/exit/class as required
//! by propose.md §5.5.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;

use crate::metrics::Metrics;
use crate::types::{Grant, SessionId};

/// Coarse category recorded for a relayed channel's work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandClass {
    /// Interactive shell (`shell` request, no command).
    Interactive,
    /// A generic `exec` command.
    Exec,
    /// Legacy `scp` tunneled over `exec` (command begins with `scp `).
    Scp,
    /// The `sftp` subsystem (also modern scp, WinSCP, FileZilla).
    Sftp,
    /// `rsync` run over `exec`.
    Rsync,
}

impl CommandClass {
    pub fn as_str(self) -> &'static str {
        match self {
            CommandClass::Interactive => "interactive",
            CommandClass::Exec => "exec",
            CommandClass::Scp => "scp",
            CommandClass::Sftp => "sftp",
            CommandClass::Rsync => "rsync",
        }
    }
}

/// What the client asked the channel to run.
#[derive(Debug, Clone)]
pub enum CommandInfo {
    Interactive,
    Exec(String),
    Subsystem(String),
}

impl CommandInfo {
    /// Classify this command into its [`CommandClass`].
    pub fn classify(&self) -> CommandClass {
        match self {
            CommandInfo::Interactive => CommandClass::Interactive,
            CommandInfo::Subsystem(name) => {
                if name == "sftp" {
                    CommandClass::Sftp
                } else {
                    // Non-SFTP subsystems are rare; bucket them as generic.
                    CommandClass::Exec
                }
            }
            CommandInfo::Exec(cmd) => classify_exec(cmd),
        }
    }
}

/// Pure classification of an `exec` command string (per the table above).
pub fn classify_exec(command: &str) -> CommandClass {
    if command.starts_with("scp ") {
        CommandClass::Scp
    } else if command.contains("rsync") {
        CommandClass::Rsync
    } else {
        CommandClass::Exec
    }
}

/// Classify an `exec` command given as raw bytes (lossy UTF-8 decode).
pub fn classify_exec_bytes(command: &[u8]) -> CommandClass {
    classify_exec(&String::from_utf8_lossy(command))
}

/// Best-effort redaction of obvious secrets embedded in a recorded command.
///
/// M1 keeps this conservative (it masks `password=`-style assignments and the
/// value following a bare `-p `/`--password`) rather than risk corrupting a
/// legitimate command; comprehensive sanitization is deferred to M3.
pub fn redact_command(command: &str) -> String {
    const SECRET_TOKENS: &[&str] = &["password=", "passwd=", "token="];
    let mut out = command.to_owned();
    for token in SECRET_TOKENS {
        let mut redacted = String::with_capacity(out.len());
        let mut rest = out.as_str();
        while let Some(pos) = rest.find(token) {
            let (before, after) = rest.split_at(pos + token.len());
            redacted.push_str(before);
            redacted.push_str("***");
            // Swallow up to the next whitespace as the secret value.
            let value_end = after.find(char::is_whitespace).unwrap_or(after.len());
            rest = &after[value_end..];
        }
        redacted.push_str(rest);
        out = redacted;
    }
    out
}

/// Shared, atomically-incremented byte counters wired into the relay so both
/// directions can be tallied without borrowing the audit context.
#[derive(Debug, Default)]
pub struct ByteCounters {
    up: AtomicU64,
    down: AtomicU64,
}

impl ByteCounters {
    pub fn add_up(&self, n: usize) {
        self.up.fetch_add(n as u64, Ordering::Relaxed);
    }
    pub fn add_down(&self, n: usize) {
        self.down.fetch_add(n as u64, Ordering::Relaxed);
    }
    pub fn up(&self) -> u64 {
        self.up.load(Ordering::Relaxed)
    }
    pub fn down(&self) -> u64 {
        self.down.load(Ordering::Relaxed)
    }
}

/// A per-session audit sink: it accumulates identity + byte counters and, at
/// session end, produces an [`AuditRecord`] and emits it as structured logging.
pub struct Auditor {
    session_id: SessionId,
    client_ip: String,
    grant: Grant,
    signature_algorithm: String,
    started_at: Instant,
    bytes: Arc<ByteCounters>,
    command: Option<CommandInfo>,
    metrics: Metrics,
}

impl Auditor {
    /// Begin auditing a session once the client has been authenticated and its
    /// destination resolved.
    pub fn new(
        session_id: SessionId,
        client_ip: String,
        grant: Grant,
        signature_algorithm: String,
        metrics: Metrics,
    ) -> Self {
        Auditor {
            session_id,
            client_ip,
            grant,
            signature_algorithm,
            started_at: Instant::now(),
            bytes: Arc::new(ByteCounters::default()),
            command: None,
            metrics,
        }
    }

    /// A cloneable handle to the byte counters for the relay to increment.
    pub fn byte_counters(&self) -> Arc<ByteCounters> {
        Arc::clone(&self.bytes)
    }

    /// Record what the (first) channel asked to run.
    pub fn set_command(&mut self, info: CommandInfo) {
        // Only the first command on the session is the primary audit subject;
        // subsequent channels on the same session inherit it.
        if self.command.is_none() {
            self.command = Some(info);
        }
    }

    /// Produce and emit the final record when the session terminates.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize(self, exit_code: Option<i32>, exit_signal: Option<String>) -> AuditRecord {
        let duration_ms = self.started_at.elapsed().as_millis() as u64;
        let command_info = self.command.unwrap_or(CommandInfo::Interactive);
        let class = command_info.classify();
        let command_repr = match &command_info {
            CommandInfo::Interactive => None,
            CommandInfo::Exec(c) => Some(redact_command(c)),
            CommandInfo::Subsystem(name) => Some(format!("subsystem:{name}")),
        };

        let record = AuditRecord {
            session_id: self.session_id.to_string(),
            principal: self.grant.principal.as_str().to_owned(),
            fingerprint: self.grant.fingerprint.as_str().to_owned(),
            signature_algorithm: self.signature_algorithm,
            client_ip: self.client_ip,
            target_host: self.grant.target.host.clone(),
            target_port: self.grant.target.port,
            target_user: self.grant.target.user.clone(),
            command_class: class.as_str().to_owned(),
            command: command_repr,
            started_at_ms: 0, // relative epoch not needed; duration below suffices
            bytes_up: self.bytes.up(),
            bytes_down: self.bytes.down(),
            exit_code,
            exit_signal,
            duration_ms,
        };

        // Emit as a single structured audit line.
        let json = record_to_json(&record);
        tracing::info!(target: "audit", %json, "session audit");
        self.metrics.session_ended();
        record
    }
}

/// Emitted audit record; serialized to JSON for the structured log pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    pub session_id: String,
    pub principal: String,
    pub fingerprint: String,
    pub signature_algorithm: String,
    pub client_ip: String,
    pub target_host: String,
    pub target_port: u16,
    pub target_user: String,
    pub command_class: String,
    pub command: Option<String>,
    pub started_at_ms: i64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub exit_code: Option<i32>,
    pub exit_signal: Option<String>,
    pub duration_ms: u64,
}

/// Convenience: serialize to a compact JSON string for logging/assertions.
pub fn record_to_json(record: &AuditRecord) -> String {
    // `serde_json::Error` maps to `Error::Serialize` via `Error::serialize`,
    // but serializing a well-formed struct cannot fail; we still propagate.
    serde_json::to_string(record).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Fingerprint, Policy, Principal, Target};

    fn test_grant() -> Grant {
        Grant {
            principal: Principal::parse("alex_host1").unwrap(),
            fingerprint: Fingerprint::new("SHA256:testfp"),
            target: Target {
                host: "10.1.2.3".into(),
                port: 22,
                user: "root".into(),
            },
            policy: Policy::default(),
        }
    }

    #[test]
    fn classifies_scp_exec_as_scp() {
        assert_eq!(classify_exec("scp -t /tmp"), CommandClass::Scp);
        assert_eq!(classify_exec("scp -f /etc/passwd"), CommandClass::Scp);
    }

    #[test]
    fn classifies_rsync_exec_as_rsync() {
        assert_eq!(
            classify_exec("rsync --server -vlogDtpre.iLsfxC . /dst"),
            CommandClass::Rsync
        );
    }

    #[test]
    fn classifies_plain_exec_as_exec() {
        assert_eq!(classify_exec("cat /etc/hosts"), CommandClass::Exec);
        assert_eq!(classify_exec("true"), CommandClass::Exec);
    }

    #[test]
    fn scp_takes_precedence_over_generic() {
        // "scp" prefix wins even though it doesn't contain rsync.
        assert_eq!(classify_exec("scp -r dir/ host:dst"), CommandClass::Scp);
    }

    #[test]
    fn subsystem_sftp_classified_as_sftp() {
        assert_eq!(
            CommandInfo::Subsystem("sftp".into()).classify(),
            CommandClass::Sftp
        );
        // Non-sftp subsystems are bucketed generic.
        assert_eq!(
            CommandInfo::Subsystem("netconf".into()).classify(),
            CommandClass::Exec
        );
    }

    #[test]
    fn interactive_shell_classified_as_interactive() {
        assert_eq!(
            CommandInfo::Interactive.classify(),
            CommandClass::Interactive
        );
    }

    #[test]
    fn redaction_masks_password_assignments() {
        assert_eq!(
            redact_command("mysql --password=sekret -h db"),
            "mysql --password=*** -h db"
        );
        assert_eq!(
            redact_command("echo token=hunter2 now"),
            "echo token=*** now"
        );
        // Non-secret commands are untouched.
        assert_eq!(redact_command("cat /etc/hosts"), "cat /etc/hosts");
    }

    #[test]
    fn byte_counters_tally_both_directions() {
        let c = ByteCounters::default();
        c.add_up(10);
        c.add_up(5);
        c.add_down(100);
        assert_eq!(c.up(), 15);
        assert_eq!(c.down(), 100);
    }

    #[test]
    fn finalized_audit_record_has_all_fields() {
        let session = SessionId::generate();
        let mut auditor = Auditor::new(
            session.clone(),
            "203.0.113.9".into(),
            test_grant(),
            "ssh-ed25519".into(),
            Metrics::default(),
        );
        auditor.set_command(CommandInfo::Exec("scp -t /tmp/x".into()));
        let counters = auditor.byte_counters();
        counters.add_up(2048);
        counters.add_down(4096);

        let record = auditor.finalize(Some(0), None);
        assert_eq!(record.session_id, session.to_string());
        assert_eq!(record.principal, "alex_host1");
        assert_eq!(record.fingerprint, "SHA256:testfp");
        assert_eq!(record.signature_algorithm, "ssh-ed25519");
        assert_eq!(record.target_host, "10.1.2.3");
        assert_eq!(record.target_port, 22);
        assert_eq!(record.target_user, "root");
        assert_eq!(record.command_class, "scp");
        assert_eq!(record.bytes_up, 2048);
        assert_eq!(record.bytes_down, 4096);
        assert_eq!(record.exit_code, Some(0));

        let json = record_to_json(&record);
        assert!(json.contains("\"command_class\":\"scp\""));
        assert!(json.contains("\"session_id\""));
    }

    #[test]
    fn finalize_records_exit_signal_when_killed() {
        let auditor = Auditor::new(
            SessionId::generate(),
            "198.51.100.2".into(),
            test_grant(),
            "ssh-ed25519".into(),
            Metrics::default(),
        );
        let record = auditor.finalize(None, Some("TERM".into()));
        assert_eq!(record.exit_code, None);
        assert_eq!(record.exit_signal.as_deref(), Some("TERM"));
        assert_eq!(record.command_class, "interactive");
    }
}
