//! Production-grade SSH gateway implemented as a **russh dual-session relay pipe**.
//!
//! A client connects to the gateway as an ordinary SSH *server*; the gateway
//! terminates that SSH transport, authenticates the client's public-key
//! signature locally (russh verifies the signature before invoking the
//! handler), resolves+authorizes the `(principal, fingerprint)` tuple against
//! an external control plane, then lazily dials the backend `sshd` as a russh
//! *client* and relays channel traffic through a strict-FIFO, window-bounded
//! engine.
//!
//! The authoritative design lives in `dev-docs/propose.md` (v2); the work
//! breakdown in `dev-docs/plan.md` (v1.2).

pub mod audit;
pub mod backend;
pub mod ca;
pub mod config;
pub mod error;
pub mod mapping;
pub mod metrics;
pub mod openstack;
pub mod policy;
pub mod pool;
pub mod record;
pub mod relay;
pub mod resolve;
pub mod server;
pub mod sftp;
pub mod types;

pub use error::{Error, Result};
