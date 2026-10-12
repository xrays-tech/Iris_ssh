//! Per-packet micro-bench for the downlink (backend → client) data path.
//!
//! Complements `docs/perf-report.md`: the gateway's throughput ceiling sits on
//! the per-packet relay path, and this bench isolates the *copy* cost of that
//! path's tap step so the zero-copy downlink change is measurable in
//! microseconds per 32 KiB packet:
//!
//! * [`downlink_no_tap`] — the production fast path: `apply_tap_down` hands
//!   back the owned `Bytes` russh already gave us. Near-zero allocation; what
//!   remains is the `Bytes` refcount bump done by the caller's `.clone()`.
//! * [`downlink_tap_pass`] — a tap is installed but verdicts `Pass`: still
//!   zero-copy (the original `Bytes` is forwarded unchanged).
//! * [`downlink_tap_rewrite`] — a tap rewrites every packet: exactly one
//!   `to_vec()` inside the tap, for cost comparison / documentation.
//! * [`uplink_unavoidable_copy`] — the uplink direction, where russh's handler
//!   only lends `&[u8]`, so one `to_vec()` + `Bytes::from` is the
//!   API-constrained minimum. Measured here purely as a reference point — no
//!   uplink code is changed by this bench.

use std::sync::Arc;

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ssh_gateway::relay::{apply_tap_down, ChannelId, ChannelTap, DataVerdict, Direction};

/// The packet size the relay path is tuned for (see perf-report notes).
const PAYLOAD_LEN: usize = 32 * 1024;

/// `ChannelId`'s constructor is private to russh (deliberately); build one by
/// decoding it from the wire, exactly like the in-crate tests do.
fn placeholder_channel_id() -> ChannelId {
    let bytes = 1u32.to_be_bytes();
    let mut cursor = &bytes[..];
    ssh_encoding::Decode::decode(&mut cursor).expect("decode a channel id")
}

/// A tap that always passes the buffer through unchanged.
struct PassTap;

impl ChannelTap for PassTap {
    fn on_data(&self, _dir: Direction, _buf: &[u8]) -> DataVerdict {
        DataVerdict::Pass
    }
}

/// A tap that rewrites every buffer (one copy inside the tap).
struct RewriteTap;

impl ChannelTap for RewriteTap {
    fn on_data(&self, _dir: Direction, buf: &[u8]) -> DataVerdict {
        DataVerdict::Rewrite {
            forward: buf.to_vec(),
            inject: Vec::new(),
            denied: None,
        }
    }
}

fn downlink_benches(c: &mut Criterion) {
    let id = placeholder_channel_id();
    let template = Bytes::from(vec![0x5A_u8; PAYLOAD_LEN]);

    // No tap at all: the owned `Bytes` must come back untouched (zero-copy).
    c.bench_function("downlink_no_tap", |b| {
        b.iter(|| {
            let (forward, inject) = apply_tap_down(None, template.clone(), black_box(id));
            black_box((forward, inject));
        })
    });

    // Tap installed but passing: must also be zero-copy.
    let pass: Arc<dyn ChannelTap> = Arc::new(PassTap);
    c.bench_function("downlink_tap_pass", |b| {
        b.iter(|| {
            let (forward, inject) = apply_tap_down(Some(&pass), template.clone(), black_box(id));
            black_box((forward, inject));
        })
    });

    // Rewrite path: exactly one `to_vec()` (documented cost of a rewriting tap).
    let rewrite: Arc<dyn ChannelTap> = Arc::new(RewriteTap);
    c.bench_function("downlink_tap_rewrite", |b| {
        b.iter(|| {
            let (forward, inject) = apply_tap_down(Some(&rewrite), template.clone(), black_box(id));
            black_box((forward, inject));
        })
    });

    // Uplink reference point: the one copy russh's `&[u8]` handler API makes
    // unavoidable. Not a code change — a measurement to compare against.
    c.bench_function("uplink_unavoidable_copy", |b| {
        b.iter(|| {
            let payload = black_box(&template).to_vec();
            black_box(Bytes::from(payload));
        })
    });
}

criterion_group!(benches, downlink_benches);
criterion_main!(benches);
