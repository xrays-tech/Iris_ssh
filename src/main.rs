//! Binary entrypoint: initialise tracing, load configuration, build the gateway
//! context and run until a graceful-shutdown signal.
//!
//! Configuration is read from the `SSHGW_CONFIG` environment variable, or the
//! first CLI argument, defaulting to `/etc/ssh-gateway/config.toml`.

use std::path::{Path, PathBuf};

use ssh_gateway::config::GatewayConfig;
use ssh_gateway::server;

/// Resolve the configuration path, honouring `--config`/`-c` (as the ops
/// harness invokes it), then `$SSHGW_CONFIG`, then a positional argument, then
/// the default location.
fn config_path() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    config_path_from(&args, std::env::var("SSHGW_CONFIG").ok().as_deref())
}

/// Pure resolution of the config path from an argument slice and the optional
/// `SSHGW_CONFIG` value, so the precedence rules are unit-testable.
fn config_path_from(args: &[String], env_config: Option<&str>) -> PathBuf {
    // `args` includes the program name at index 0; skip it.
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                if let Some(value) = args.get(i + 1) {
                    return PathBuf::from(value);
                }
                // A dangling flag with no value falls through to the default;
                // the resulting load error will make the mistake obvious.
                break;
            }
            other if other.starts_with("--config=") => {
                return PathBuf::from(other.trim_start_matches("--config="));
            }
            other if !other.starts_with('-') => {
                // First bare positional argument is the config path.
                return PathBuf::from(other);
            }
            _ => {}
        }
        i += 1;
    }
    if let Some(path) = env_config {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    PathBuf::from("/etc/ssh-gateway/config.toml")
}

/// Initialise structured JSON logging using the `RUST_LOG` filter (defaults to
/// `info`).
fn init_tracing() {
    use tracing_subscriber::util::SubscriberInitExt;
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .json()
        .finish()
        .try_init();
}

type MainResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn run(config_path: &Path) -> MainResult {
    let config = GatewayConfig::load(config_path).map_err(|e| {
        eprintln!("failed to load config from {}: {e}", config_path.display());
        e
    })?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| ssh_gateway::error::Error::io(e, "building tokio runtime"))?;

    runtime.block_on(async move {
        let ctx = server::GatewayContext::build(config)?;
        server::serve(ctx).await
    })?;
    Ok(())
}

fn main() {
    init_tracing();
    let path = config_path();

    if let Err(e) = run(&path) {
        eprintln!("fatal: {e:#}");
        // Map the error to a meaningful exit code.
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        std::iter::once("ssh-gw")
            .chain(a.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn config_flag_takes_priority() {
        // The ops harness launches: `ssh-gw --config /path/to/config`.
        assert_eq!(
            config_path_from(&args(&["--config", "/tmp/gw.toml"]), Some("/env.toml")),
            PathBuf::from("/tmp/gw.toml")
        );
        assert_eq!(
            config_path_from(&args(&["-c", "/tmp/gw.toml"]), None),
            PathBuf::from("/tmp/gw.toml")
        );
    }

    #[test]
    fn env_is_used_when_no_flag_or_positional() {
        assert_eq!(
            config_path_from(&args(&[]), Some("/env.toml")),
            PathBuf::from("/env.toml")
        );
    }

    #[test]
    fn default_used_when_nothing_given() {
        assert_eq!(
            config_path_from(&args(&[]), None),
            PathBuf::from("/etc/ssh-gateway/config.toml")
        );
    }

    #[test]
    fn positional_argument_is_honored() {
        assert_eq!(
            config_path_from(&args(&["/positional.toml"]), Some("/env.toml")),
            PathBuf::from("/positional.toml")
        );
    }
}
