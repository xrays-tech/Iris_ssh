//! A tiny, dependency-free HTTP server exposing the read-only observability
//! endpoints propose.md §5.5 requires: `/healthz`, `/readyz`, `/metrics`.
//!
//! Routing is a pure function ([`route`]) so it can be exercised without any
//! sockets; the socket driver ([`serve`]) is a minimal HTTP/1.1 loop that only
//! understands the request line — enough for a probe/metrics scrape and no more,
//! keeping the binary lean.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Readiness state mirrored from the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Accepting new sessions.
    Ready,
    /// Draining (LB should route away).
    NotReady,
}

/// Route a request path to an HTTP status + body. Pure; no I/O.
pub fn route(path: &str, readiness: Readiness, metrics_body: &str) -> (u16, String) {
    // Ignore any query string.
    let path = path.split('?').next().unwrap_or(path);
    match path {
        "/healthz" => (200, "ok\n".to_owned()),
        "/readyz" => match readiness {
            Readiness::Ready => (200, "ready\n".to_owned()),
            Readiness::NotReady => (503, "draining\n".to_owned()),
        },
        "/metrics" => (200, metrics_body.to_owned()),
        _ => (404, "not found\n".to_owned()),
    }
}

/// HTTP status reason phrase (for the status line).
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

/// Run the observability HTTP server until the listener errors.
///
/// `readiness` is consulted live on every `/readyz` request and `render_metrics`
/// produces the `/metrics` body on demand.
pub async fn serve<F>(
    listener: TcpListener,
    readiness: Arc<dyn Fn() -> Readiness + Send + Sync>,
    render_metrics: F,
) -> std::io::Result<()>
where
    F: Fn() -> String + Send + Sync + 'static,
{
    let render_metrics = Arc::new(render_metrics);
    loop {
        let (mut socket, _) = listener.accept().await?;
        let readiness = readiness.clone();
        let render_metrics = Arc::clone(&render_metrics);
        // Handle each connection inline (probes are tiny and rare).
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let n = match socket.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            if n == 0 {
                return;
            }
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_owned();

            let (status, body) = route(&path, readiness(), &render_metrics());
            let response = format!(
                "HTTP/1.1 {status} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                reason(status),
                if path.starts_with("/metrics") {
                    "text/plain; version=0.0.4"
                } else {
                    "text/plain; charset=utf-8"
                },
                body.len(),
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthz_is_always_ok() {
        let (s, b) = route("/healthz", Readiness::NotReady, "");
        assert_eq!(s, 200);
        assert_eq!(b, "ok\n");
    }

    #[test]
    fn readyz_reflects_readiness() {
        assert_eq!(route("/readyz", Readiness::Ready, "").0, 200);
        assert_eq!(route("/readyz", Readiness::NotReady, "").0, 503);
    }

    #[test]
    fn metrics_returns_prometheus_body() {
        let (s, b) = route("/metrics", Readiness::Ready, "sshgw_active_sessions 3\n");
        assert_eq!(s, 200);
        assert_eq!(b, "sshgw_active_sessions 3\n");
    }

    #[test]
    fn unknown_path_is_404() {
        assert_eq!(route("/nope", Readiness::Ready, "").0, 404);
    }

    #[test]
    fn query_string_is_ignored() {
        assert_eq!(route("/readyz?probe=1", Readiness::Ready, "").0, 200);
        assert_eq!(route("/metrics?x=y", Readiness::Ready, "M").1, "M");
    }
}
