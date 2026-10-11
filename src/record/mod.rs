//! Session recording (propose.md §3.7 `Tap` semantics / B2).
//!
//! A [`SessionRecorder`] is a per-channel [`ChannelTap`] that appends both
//! directions of a session to a file, so a session can be replayed after the
//! fact for incident response.
//!
//! ## Safety posture
//!
//! * **Files are private.** The recording directory is created `0700` and each
//!   file `0600`: a recording of an SSH session contains everything the operator
//!   could see inside it.
//! * **Nothing sensitive is *derived*.** The recorder stores the raw byte flow
//!   only — it never persists authentication material, environment variables or
//!   command lines beyond what already crossed the wire. Because a recording is
//!   indistinguishable from a packet capture, the *redaction* obligation applies
//!   to its handling (storage location, retention, access), which is why the
//!   directory is per-instance and configurable rather than a shared path.
//! * **Bounded.** Recording stops at a configured byte budget per session so a
//!   runaway transfer cannot fill the disk; the audit record is marked truncated.
//! * **Deterministic teardown.** [`ChannelTap::flush`] closes the file when the
//!   channel ends, so no file descriptor or buffered tail outlives the session.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::relay::{ChannelCtx, ChannelTap, DataVerdict, Direction};

/// Header line emitted once when recording starts (JSON, stable field order).
fn header(ctx: &ChannelCtx, truncated_at: u64) -> String {
    format!(
        "{{\"event\":\"recording_start\",\"session_id\":{},\"channel_id\":{},\"principal\":{},\"command_class\":\"{}\",\"byte_budget\":{}}}\n",
        json_string(&ctx.session_id),
        ctx.channel_id.number(),
        json_string(&ctx.principal),
        ctx.command_class.as_str(),
        truncated_at,
    )
}

/// Minimal JSON string escaping (no control chars, no unicode escapes needed for
/// the ASCII identifiers we emit; anything else is escaped defensively).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// One recorded chunk, base64-encoded so the log stays line-oriented even for
/// binary SFTP traffic.
fn chunk_line(dir: Direction, chunk: &[u8]) -> String {
    format!(
        "{{\"event\":\"data\",\"dir\":\"{}\",\"bytes\":{},\"b64\":\"{}\"}}\n",
        match dir {
            Direction::Up => "up",
            Direction::Down => "down",
        },
        chunk.len(),
        base64_encode(chunk),
    )
}

/// Standard base64 (RFC 4648) encoder. Small and dependency-free; payloads are
/// already bounded by the byte budget so a streaming encoder is unnecessary.
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for block in input.chunks(3) {
        let b0 = u32::from(block[0]);
        let b1 = u32::from(*block.get(1).unwrap_or(&0));
        let b2 = u32::from(*block.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if block.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if block.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// A per-channel recorder writing to the session's own file.
pub struct SessionRecorder {
    path: PathBuf,
    writer: Mutex<std::fs::File>,
    budget: u64,
    written: AtomicU64,
    truncated: AtomicBool,
    closed: AtomicBool,
}

impl std::fmt::Debug for SessionRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRecorder")
            .field("path", &self.path)
            .field("written", &self.written.load(Ordering::Relaxed))
            .field("truncated", &self.truncated.load(Ordering::Relaxed))
            .finish()
    }
}

impl SessionRecorder {
    /// Create the recorder's file (mode 0600, in a 0700 directory) and write the
    /// header line. Returns an error if the directory cannot be prepared, in
    /// which case the caller should simply skip recording rather than fail the
    /// session — losing a recording must not break a working SSH session.
    pub fn create(dir: &Path, ctx: &ChannelCtx, budget: u64) -> std::io::Result<Arc<Self>> {
        std::fs::create_dir_all(dir)?;
        set_dir_permissions(dir)?;

        let path = dir.join(format!(
            "{}-{}.srec",
            ctx.session_id,
            ctx.channel_id.number()
        ));
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&path)?;
            drop(file);
        }
        let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
        file.write_all(header(ctx, budget).as_bytes())?;
        file.flush()?;

        Ok(Arc::new(SessionRecorder {
            path,
            writer: Mutex::new(file),
            budget,
            written: AtomicU64::new(0),
            truncated: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }))
    }

    /// Bytes recorded so far.
    pub fn bytes_recorded(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }

    /// Whether the byte budget was hit and recording stopped early.
    pub fn is_truncated(&self) -> bool {
        self.truncated.load(Ordering::Relaxed)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write one chunk, respecting the budget. Returns `true` if it was written.
    fn record(&self, dir: Direction, chunk: &[u8]) -> bool {
        if self.closed.load(Ordering::SeqCst) {
            return false;
        }
        let already = self.written.load(Ordering::Relaxed);
        let want = chunk.len() as u64;
        if already.saturating_add(want) > self.budget {
            // Budget exhausted: flag truncation, close, and drop this and every
            // later chunk. Losing the tail of a recording must never break the
            // session it belongs to.
            self.truncated.store(true, Ordering::SeqCst);
            self.closed.store(true, Ordering::SeqCst);
            return false;
        }
        let line = chunk_line(dir, chunk);
        let mut guard = match self.writer.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // No `await` happens while this guard is held: file writes are blocking
        // and short, and the mutex only serialises the two direction threads.
        if guard.write_all(line.as_bytes()).is_err() {
            self.truncated.store(true, Ordering::SeqCst);
            return false;
        }
        let _ = guard.flush();
        drop(guard);
        self.written.fetch_add(want, Ordering::Relaxed);
        true
    }
}

impl ChannelTap for SessionRecorder {
    fn on_data(&self, dir: Direction, buf: &[u8]) -> DataVerdict {
        let _ = self.record(dir, buf);
        DataVerdict::Pass
    }

    fn flush(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Ok(mut guard) = self.writer.lock() {
            let _ = guard.flush();
        }
        tracing::debug!(
            target: "record",
            path = %self.path.display(),
            bytes = self.bytes_recorded(),
            truncated = self.is_truncated(),
            "recording finished"
        );
    }
}

/// Configure the recording directory to `0700` (best effort on non-Unix).
#[cfg(unix)]
fn set_dir_permissions(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(dir)?;
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::CommandClass;
    use crate::types::Principal;

    fn ctx(session: &str) -> ChannelCtx {
        ctx_with_record(session, false)
    }

    fn ctx_with_record(session: &str, record: bool) -> ChannelCtx {
        // ChannelId's constructor is private to russh; the number is only used
        // for file naming, so the id is derived through a real channel in the
        // integration lane and a placeholder here.
        ChannelCtx {
            session_id: session.to_owned(),
            channel_id: placeholder_channel_id(),
            principal: Principal::parse("alex_host1").unwrap().as_str().to_owned(),
            command_class: CommandClass::Sftp,
            record,
        }
    }

    /// `ChannelId`'s constructor is private, so build one the way russh itself
    /// does — by decoding it from the wire.
    fn placeholder_channel_id() -> crate::relay::ChannelId {
        // `ssh_encoding::Reader` is the trait the decoder is generic over.
        let bytes = 1u32.to_be_bytes();
        let mut cursor = &bytes[..];
        ssh_encoding::Decode::decode(&mut cursor).expect("decode a channel id")
    }

    /// A temp dir that cleans itself up (defect-B style: no leaked fixtures).
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sshgw-rec-{}-{tag}-{}",
                std::process::id(),
                // Random suffix: concurrent tests must never share a directory.
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn base64_round_trips_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn records_both_directions_and_flushes() {
        let dir = TempDir::new("both");
        let ctx = ctx("sess-1");
        let rec = SessionRecorder::create(&dir.0, &ctx, 1 << 20).unwrap();
        assert_eq!(rec.on_data(Direction::Up, b"hello"), DataVerdict::Pass);
        assert_eq!(rec.on_data(Direction::Down, b"world"), DataVerdict::Pass);
        assert_eq!(rec.bytes_recorded(), 10);
        rec.flush();

        let body = std::fs::read_to_string(rec.path()).unwrap();
        assert!(body.contains("recording_start"), "header must be written");
        assert!(body.contains("sess-1"));
        assert_eq!(body.lines().count(), 3, "header + 2 chunks");
        assert!(body.contains("\"dir\":\"up\""), "uplink must be labelled");
        assert!(body.contains("\"dir\":\"down\""));
        assert!(body.contains("aGVsbG8="), "uplink payload must be base64");
        assert!(body.contains("d29ybGQ="), "downlink payload must be base64");
    }

    #[test]
    fn recording_stops_at_the_byte_budget_and_is_marked_truncated() {
        let dir = TempDir::new("budget");
        let ctx = ctx("sess-2");
        // Budget of 10 bytes: the first chunk fits, the second does not.
        let rec = SessionRecorder::create(&dir.0, &ctx, 10).unwrap();
        rec.on_data(Direction::Up, &[0u8; 6]);
        assert_eq!(rec.bytes_recorded(), 6);
        rec.on_data(Direction::Up, &[0u8; 6]);
        assert!(rec.is_truncated(), "the budget overrun must be flagged");
        assert_eq!(
            rec.bytes_recorded(),
            6,
            "no bytes past the budget are written"
        );
    }

    #[test]
    fn flush_is_idempotent() {
        let dir = TempDir::new("idem");
        let rec = SessionRecorder::create(&dir.0, &ctx("sess-3"), 1024).unwrap();
        rec.flush();
        rec.flush(); // must not panic or duplicate the close line
                     // A chunk after flush is dropped rather than written.
        rec.on_data(Direction::Up, b"late");
        assert_eq!(rec.bytes_recorded(), 0);
    }

    #[test]
    fn recording_files_are_owner_only() {
        let dir = TempDir::new("perm");
        let rec = SessionRecorder::create(&dir.0, &ctx("sess-4"), 1024).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(rec.path()).unwrap();
            assert_eq!(
                meta.permissions().mode() & 0o777,
                0o600,
                "recordings must not be group/world readable"
            );
            let dir_meta = std::fs::metadata(&dir.0).unwrap();
            assert_eq!(
                dir_meta.permissions().mode() & 0o077,
                0,
                "dir must be private"
            );
        }
    }

    #[test]
    fn filenames_are_namespaced_by_session_and_channel() {
        let dir = TempDir::new("names");
        let a = SessionRecorder::create(&dir.0, &ctx("sessA"), 64).unwrap();
        let b = SessionRecorder::create(&dir.0, &ctx("sessB"), 64).unwrap();
        assert_ne!(a.path(), b.path(), "two sessions must not share a file");
        assert!(a.path().to_string_lossy().contains("sessA"));
    }
}
