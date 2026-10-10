//! Crate-level error model.
//!
//! Every failure path routes through [`Error`] (a `thiserror` enum) so that
//! context is attached at the boundary where the failure occurs and propagated
//! with `?`. This satisfies the engineering rule *"propagate errors upward and
//! enrich them with context; never swallow an exception"* while keeping call
//! sites free of `unwrap`/`expect`.

use std::io;

/// Convenient alias so call sites read `Result<T>` and lean on `?` propagation.
pub type Result<T> = std::result::Result<T, Error>;

/// Configuration loading / validation failures. Every variant carries enough
/// information for an operator to fix the offending file without a debugger.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path:?}: {source}")]
    ReadFile {
        path: std::path::PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to parse config file {path:?}: {source}")]
    Parse {
        path: std::path::PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("{field}: {reason}")]
    Invalid { field: String, reason: String },
}

/// Resolver / control-plane failures.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The principal failed the `^[a-z0-9][a-z0-9_-]{{0,62}}$` shape check
    /// before any network call was attempted.
    #[error("principal {principal:?} is not a valid opaque token: {reason}")]
    InvalidPrincipal { principal: String, reason: String },

    /// The control plane answered 404: the principal does not exist.
    #[error("principal {principal:?} is unknown to the control plane")]
    NotFound { principal: String },

    /// The control plane answered 403: not authorized for the requested target.
    #[error("principal {principal:?} is not authorized for this key")]
    Forbidden { principal: String },

    /// The control plane answered 429: rate limited.
    #[error("resolve for principal {principal:?} was rate limited")]
    RateLimited { principal: String },

    /// The control plane is unreachable/erroring and policy is fail-closed.
    #[error("control plane unavailable for principal {principal:?} (fail-closed)")]
    Unavailable { principal: String },

    /// The resolver's circuit breaker is open; requests fail fast.
    #[error("resolver circuit breaker is open for principal {principal:?}")]
    CircuitOpen { principal: String },
}

/// Backend credential / host-key loading and dialing failures.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("failed to load backend private key {path:?}: {source}")]
    LoadKey {
        path: std::path::PathBuf,
        #[source]
        source: russh::keys::Error,
    },

    #[error("backend private key file {path:?} has unsafe permissions {perms:#o}; expected 0o600")]
    UnsafeKeyPermissions {
        path: std::path::PathBuf,
        perms: u32,
    },

    #[error("backend host key verification failed for {addr}: {reason}")]
    HostKeyRejected { addr: String, reason: String },

    #[error("backend dial to {addr} failed: {source}")]
    Dial {
        addr: String,
        #[source]
        source: Box<Error>,
    },

    #[error("backend authentication as {user:?} failed")]
    Auth { user: String },

    #[error("backend channel open failed: {reason}")]
    ChannelOpen { reason: String },

    #[error("backend send failed: {reason}")]
    Send { reason: String },
}

/// The single error type used across the whole crate.
///
/// It also serves as the `server::Handler::Error` for the gateway, hence the
/// `From<russh::Error>` and the requirement that it is `Send`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("resolve error: {0}")]
    Resolve(#[from] ResolveError),

    #[error("backend error: {0}")]
    Backend(#[from] BackendError),

    #[error("i/o error while {context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },

    #[error("serialization error while {context}: {source}")]
    Serialize {
        context: String,
        #[source]
        source: serde_json::Error,
    },

    /// A `russh` transport error surfaced from either leg.
    #[error("ssh transport error: {0}")]
    Ssh(#[from] russh::Error),

    #[error("the gateway is draining and no longer accepts new sessions")]
    Draining,

    #[error("internal invariant violated: {0}")]
    Invariant(String),
}

impl Error {
    /// Attach a static context string to a `std::io::Error`.
    ///
    /// Context must be provided at the site of the failure so operators know
    /// *what* operation was attempted, not merely that an OS error occurred.
    pub fn io(source: io::Error, context: impl Into<String>) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }

    /// Attach a static context string to a `serde_json::Error`.
    pub fn serialize(source: serde_json::Error, context: impl Into<String>) -> Self {
        Error::Serialize {
            context: context.into(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_renders_human_readable_message() {
        let err = ConfigError::Invalid {
            field: "listen.addr".into(),
            reason: "missing".into(),
        };
        assert_eq!(err.to_string(), "listen.addr: missing");
    }

    #[test]
    fn io_error_keeps_context() {
        let err = Error::io(io::Error::other("boom"), "dialing backend");
        assert_eq!(err.to_string(), "i/o error while dialing backend: boom");
    }

    #[test]
    fn config_error_converts_into_top_level_error() {
        let cfg = ConfigError::Invalid {
            field: "x".into(),
            reason: "y".into(),
        };
        let top: Error = cfg.into();
        assert!(matches!(top, Error::Config(_)));
    }

    #[test]
    fn principal_validation_error_mentions_reason() {
        let err = ResolveError::InvalidPrincipal {
            principal: "Bad Principal!".into(),
            reason: "contains a space".into(),
        };
        assert!(err.to_string().contains("contains a space"));
    }
}
