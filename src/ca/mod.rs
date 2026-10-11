//! Certificate authority (propose.md §八 / B1): trusted-CA verification and
//! short-lived user-certificate issuance.
//!
//! ## Why a CA set shared by user and host certs
//!
//! Both authentication directions anchor on the **signing key** of a
//! certificate:
//!
//! * user auth (`auth_openssh_certificate`) trusts `cert.signature_key()`;
//! * host verification (`@cert-authority`) trusts the *host* certificate's
//!   `cert.signature_key()`.
//!
//! OpenSSH's own `@cert-authority` model is the same, so one configured set is
//! the minimal, honest design. `trusted_ca_fingerprints()` exposes them as
//! `SHA256:` strings so both call sites can do a plain set membership test with
//! no lock, no I/O and no clock — which is what keeps these rules unit-testable
//! (plan §6.4: internal logic is pure, boundaries are mockable).
//!
//! ## Issuance entrypoint
//!
//! `CA_ISSUE_CONFIG` is the documented entrypoint for operators (and for the
//! control plane to call out-of-band): a tiny binary path that loads the CA
//! private key and signs a short-lived certificate. It lives here rather than in
//! the serving path because the gateway never issues certificates while
//! relaying — issuance is an administrative action.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use russh::keys::{PrivateKey, PublicKey};

use crate::error::Result;

/// A loaded certificate authority: the trusted set plus, optionally, the private
/// key used to issue certificates.
#[derive(Debug, Clone)]
pub struct CertificateAuthority {
    /// `SHA256:` fingerprints of trusted CA **signing** keys.
    trusted_ca: Vec<String>,
    /// The CA private key, when configured (verify-only otherwise).
    signing_key: Option<std::sync::Arc<PrivateKey>>,
    /// Default lifetime for issued certificates.
    cert_lifetime: Duration,
}

impl CertificateAuthority {
    /// Build a CA set from config, loading and 0600-checking every private key
    /// involved. An empty set — no trusted CA keys and no signing key — is a
    /// valid "certificate auth disabled" configuration (the config layer accepts
    /// it); only the contradictory combination of a signing key without any
    /// trusted CA key is rejected at the config layer.
    /// In the empty case this yields a CA that trusts nothing and can never
    /// issue, so certificate authentication is effectively disabled loudly.
    pub fn load(config: &crate::config::CaConfig) -> Result<Self> {
        let mut trusted_ca = Vec::with_capacity(config.trusted_ca_keys.len());
        for path in &config.trusted_ca_keys {
            // Trusted entries are CA **public** keys (authorized_keys format), so
            // they are loaded as such — 0600 is not required of a public key.
            let key = russh::keys::load_public_key(path).map_err(|source| {
                crate::error::Error::Invariant(format!(
                    "failed to load CA public key {}: {source}",
                    path.display()
                ))
            })?;
            trusted_ca.push(sha256_fingerprint(&key));
        }
        let signing_key = match &config.signing_key {
            Some(path) => Some(std::sync::Arc::new(
                crate::backend::load_private_key_checked(path, false)?,
            )),
            None => None,
        };
        Ok(CertificateAuthority {
            trusted_ca,
            signing_key,
            cert_lifetime: config.cert_lifetime,
        })
    }

    /// Trusted CA signing-key fingerprints (canonical `SHA256:` form).
    pub fn trusted_ca_fingerprints(&self) -> &[String] {
        &self.trusted_ca
    }

    /// Whether `fingerprint` names a trusted CA signing key.
    pub fn is_trusted_ca(&self, fingerprint: &str) -> bool {
        self.trusted_ca.iter().any(|fp| fp == fingerprint)
    }

    /// Whether this CA can issue certificates (a signing key is configured).
    pub fn can_issue(&self) -> bool {
        self.signing_key.is_some()
    }

    /// The configured certificate lifetime for issued certificates.
    pub fn cert_lifetime(&self) -> Duration {
        self.cert_lifetime
    }

    /// Issue a short-lived user certificate for `subject_key`.
    ///
    /// `principals` are the usernames the certificate is valid for (OpenSSH's
    /// `valid principals`); `key_id` is the human-readable label sshd shows in
    /// logs. Validity starts now and ends after [`Self::cert_lifetime`].
    pub fn issue_user_certificate(
        &self,
        subject_key: &PublicKey,
        principals: &[String],
        key_id: &str,
    ) -> Result<russh::keys::Certificate> {
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            crate::error::Error::Invariant(
                "CA has no signing key configured; cannot issue certificates".into(),
            )
        })?;
        issue_user_certificate_with(
            signing_key,
            subject_key,
            principals,
            key_id,
            self.cert_lifetime,
        )
    }
}

/// Seconds since the Unix epoch, mapped to a context-rich error.
fn duration_since_epoch(context: &str) -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| crate::error::Error::io(std::io::Error::other(e.to_string()), context))
}

/// Canonical `SHA256:` fingerprint of a public key.
pub fn sha256_fingerprint(key: &PublicKey) -> String {
    key.fingerprint(russh::keys::HashAlg::Sha256).to_string()
}

/// Canonical `SHA256:` fingerprint of a certificate's **signing key** — i.e. the
/// issuing CA, which is the trust anchor for both user and host certificates.
pub fn certificate_ca_fingerprint(cert: &russh::keys::Certificate) -> String {
    sha256_fingerprint(&PublicKey::from(cert.signature_key().clone()))
}

/// Issue a short-lived user certificate (the pure core of
/// [`CertificateAuthority::issue_user_certificate`], split out so it can be
/// exercised with a generated key and no config plumbing).
pub fn issue_user_certificate_with(
    signing_key: &PrivateKey,
    subject_key: &PublicKey,
    principals: &[String],
    key_id: &str,
    lifetime: Duration,
) -> Result<russh::keys::Certificate> {
    let now = duration_since_epoch("reading system clock for certificate validity")?;
    let valid_after = now.saturating_sub(1); // tolerate small clock skew
    let valid_before = now
        .checked_add(lifetime.as_secs())
        .ok_or_else(|| crate::error::Error::Invariant("certificate lifetime overflowed".into()))?;

    // A certificate with no principals is a "golden ticket" in OpenSSH, so refuse
    // to mint one without an explicit operator-supplied principal list.
    if principals.is_empty() {
        return Err(crate::error::Error::Invariant(
            "refusing to issue a certificate with no principals".into(),
        ));
    }

    // 32 random bytes of nonce, as OpenSSH does.
    let nonce = { rand::random::<[u8; 32]>().to_vec() };

    let mut builder = ssh_key::certificate::Builder::new(
        nonce,
        subject_key.key_data().clone(),
        valid_after,
        valid_before,
    )
    .map_err(|e| crate::error::Error::Invariant(format!("building certificate envelope: {e}")))?;
    builder
        .cert_type(ssh_key::certificate::CertType::User)
        .map_err(|e| crate::error::Error::Invariant(format!("setting cert type: {e}")))?;
    builder
        .key_id(key_id)
        .map_err(|e| crate::error::Error::Invariant(format!("setting key id: {e}")))?;
    for principal in principals {
        builder.valid_principal(principal).map_err(|e| {
            crate::error::Error::Invariant(format!("adding principal {principal:?}: {e}"))
        })?;
    }

    builder.sign(signing_key).map_err(|e| {
        // ssh-key's error surface is its own enum; wrap with context so operators
        // see the CA signing failure rather than a bare "signature error".
        crate::error::Error::Invariant(format!("signing user certificate: {e}"))
    })
}

/// Outcome of validating a user certificate against a CA set at time `now`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateCheck {
    /// The certificate is well-formed, correctly CA-signed, within its validity
    /// window, and names the requested principal.
    Trusted,
    /// The issuing CA is not in the trusted set.
    UnknownCa,
    /// The certificate does not list `principal` in its valid principals.
    PrincipalMismatch { expected: String },
    /// The certificate is outside its validity window.
    Expired,
    /// The certificate's own signature does not verify (tampered body).
    BadSignature,
}

/// Pure validation of a user certificate against a trusted CA set at time `now`
/// (seconds since the Unix epoch).
///
/// `is_valid_at` is the clock seam: production passes `SystemTime::now()`, tests
/// pass an arbitrary instant, which is what makes expiry testable without
/// sleeping (plan §6.4 — clock injection, no Mock).
pub fn validate_user_certificate_at(
    cert: &russh::keys::Certificate,
    ca_fingerprints: &[String],
    principal: &str,
    now_unix: u64,
) -> CertificateCheck {
    // 1. Trust anchor: the *signing* key must be a trusted CA. Doing this before
    //    the signature check means an untrusted CA fails fast and we never waste
    //    crypto on it.
    if !ca_fingerprints
        .iter()
        .any(|fp| fp == &certificate_ca_fingerprint(cert))
    {
        return CertificateCheck::UnknownCa;
    }

    // 2. Integrity: the certificate body must be signed by that CA. ssh-key
    //    re-verifies the signature, so a tampered certificate is caught here.
    if cert.verify_signature().is_err() {
        return CertificateCheck::BadSignature;
    }

    // 3. Validity window. ssh-key exposes the OpenSSH sentinels ("always
    //    valid", 0) as `None` from `*_time()`, and the raw seconds otherwise, so
    //    checking the seconds against the injected clock covers both.
    if cert.valid_after() > now_unix || cert.valid_before() <= now_unix {
        return CertificateCheck::Expired;
    }

    // 4. The requested principal must be one of the certificate's valid
    //    principals, otherwise a certificate minted for `bob` could log in as
    //    `alex_host1`.
    if !cert.valid_principals().iter().any(|p| p == principal) {
        return CertificateCheck::PrincipalMismatch {
            expected: principal.to_owned(),
        };
    }

    CertificateCheck::Trusted
}

/// Current Unix time in seconds, or an error if the clock is behind the epoch.
pub fn now_unix_secs() -> Result<u64> {
    duration_since_epoch("reading system clock")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca_key() -> PrivateKey {
        let mut rng = rand::rng();
        PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap()
    }

    fn subject_key() -> PublicKey {
        ca_key().public_key().clone()
    }

    fn issue(
        ca: &PrivateKey,
        principals: &[&str],
        key_id: &str,
        lifetime: Duration,
    ) -> russh::keys::Certificate {
        let principals: Vec<String> = principals.iter().map(|s| (*s).to_owned()).collect();
        issue_user_certificate_with(ca, &subject_key(), &principals, key_id, lifetime).unwrap()
    }

    #[test]
    fn issued_certificate_carries_principals_lifetime_and_key_id() {
        let ca = ca_key();
        let before = now_unix_secs().unwrap();
        let cert = issue(&ca, &["alex_host1"], "alex@dev", Duration::from_secs(300));

        assert_eq!(cert.valid_principals(), ["alex_host1".to_string()]);
        assert_eq!(cert.key_id(), "alex@dev");
        assert_eq!(cert.cert_type(), ssh_key::certificate::CertType::User);
        // Validity starts ~now and ends after the lifetime.
        assert!(
            cert.valid_after() <= before + 1,
            "should be valid immediately"
        );
        assert!(cert.valid_before() > before, "must expire in the future");
        assert!(
            cert.valid_before() - cert.valid_after() >= 299,
            "lifetime must be honoured, got {}s",
            cert.valid_before() - cert.valid_after()
        );
        // The issuing CA is the signing key we used.
        assert_eq!(
            certificate_ca_fingerprint(&cert),
            sha256_fingerprint(ca.public_key())
        );
    }

    #[test]
    fn certificate_trusted_by_the_issuing_ca_only() {
        let ca = ca_key();
        let other_ca = ca_key();
        let cert = issue(&ca, &["alex_host1"], "k", Duration::from_secs(300));
        let trusted = [sha256_fingerprint(ca.public_key())];

        assert_eq!(
            validate_user_certificate_at(&cert, &trusted, "alex_host1", now_unix_secs().unwrap()),
            CertificateCheck::Trusted
        );
        assert_eq!(
            validate_user_certificate_at(
                &cert,
                &[sha256_fingerprint(other_ca.public_key())],
                "alex_host1",
                now_unix_secs().unwrap(),
            ),
            CertificateCheck::UnknownCa,
            "a certificate issued by an untrusted CA must not validate"
        );
    }

    #[test]
    fn tampered_certificate_is_rejected() {
        let ca = ca_key();
        let cert = issue(&ca, &["alex_host1"], "k", Duration::from_secs(300));
        // Corrupt the certificate's *signature* at the wire level (the comment
        // field is deliberately outside the signed blob in SSH certificates, so
        // mutating that would not be a tamper at all).
        let mut bytes = cert.to_bytes().unwrap();
        let len = bytes.len();
        bytes[len - 32] ^= 0xff; // deep inside the trailing ed25519 signature
        let tampered = russh::keys::Certificate::from_bytes(&bytes)
            .expect("a length-preserving flip still decodes");
        let trusted = [sha256_fingerprint(ca.public_key())];
        assert_eq!(
            validate_user_certificate_at(
                &tampered,
                &trusted,
                "alex_host1",
                now_unix_secs().unwrap()
            ),
            CertificateCheck::BadSignature,
            "a corrupted signature must be caught beyond the CA check"
        );
    }

    #[test]
    fn expired_certificate_is_rejected() {
        let ca = ca_key();
        let cert = issue(&ca, &["alex_host1"], "k", Duration::from_secs(300));
        let trusted = [sha256_fingerprint(ca.public_key())];
        // A clock far in the future must fail the validity window.
        let far_future = cert.valid_before().saturating_add(60);
        assert_eq!(
            validate_user_certificate_at(&cert, &trusted, "alex_host1", far_future),
            CertificateCheck::Expired
        );
        // ...and so must a clock before `valid_after`.
        let before = cert.valid_after().saturating_sub(60);
        assert_eq!(
            validate_user_certificate_at(&cert, &trusted, "alex_host1", before),
            CertificateCheck::Expired
        );
    }

    #[test]
    fn principal_mismatch_is_rejected() {
        let ca = ca_key();
        let cert = issue(&ca, &["bob"], "k", Duration::from_secs(300));
        let trusted = [sha256_fingerprint(ca.public_key())];
        assert_eq!(
            validate_user_certificate_at(&cert, &trusted, "alex_host1", now_unix_secs().unwrap()),
            CertificateCheck::PrincipalMismatch {
                expected: "alex_host1".to_owned()
            }
        );
    }

    #[test]
    fn issuing_without_principals_is_refused() {
        let ca = ca_key();
        let err =
            issue_user_certificate_with(&ca, &subject_key(), &[], "k", Duration::from_secs(300))
                .unwrap_err();
        assert!(
            err.to_string().contains("no principals"),
            "expected a golden-ticket refusal, got {err}"
        );
    }

    #[test]
    fn issuing_without_a_signing_key_is_refused() {
        // A verify-only CA must not silently produce certificates.
        let ca = CertificateAuthority {
            trusted_ca: Vec::new(),
            signing_key: None,
            cert_lifetime: Duration::from_secs(60),
        };
        assert!(!ca.can_issue());
        let principals = vec!["alex_host1".to_owned()];
        assert!(ca
            .issue_user_certificate(&subject_key(), &principals, "k")
            .is_err());
    }
}
