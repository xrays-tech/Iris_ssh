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
    /// The trusted CA public keys themselves, retained so the gateway can report
    /// which certificate *algorithms* it is able to verify. KEX needs that list:
    /// a client leg that advertises no host-certificate algorithms will never be
    /// offered one, however many CAs it trusts.
    trusted_ca_keys: Vec<PublicKey>,
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
        let mut trusted_ca_keys = Vec::with_capacity(config.trusted_ca_keys.len());
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
            trusted_ca_keys.push(key);
        }
        let signing_key = match &config.signing_key {
            Some(path) => Some(std::sync::Arc::new(
                crate::backend::load_private_key_checked(path, false)?,
            )),
            None => None,
        };
        Ok(CertificateAuthority {
            trusted_ca,
            trusted_ca_keys,
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

    /// The key algorithms of the trusted CAs, de-duplicated — exactly the
    /// certificate algorithms this gateway can verify.
    ///
    /// The backend leg advertises these during KEX (russh turns each into its
    /// `…-cert-v01@openssh.com` name), so a backend that only offers certificate
    /// types we cannot check is never negotiated. Advertising only what we can
    /// verify is what keeps a *narrower* trust set from causing a confusing
    /// "no matching host key type" failure.
    pub fn trusted_cert_algorithms(&self) -> Vec<ssh_key::Algorithm> {
        let mut algos: Vec<ssh_key::Algorithm> = Vec::new();
        for key in &self.trusted_ca_keys {
            let algo = key.algorithm().clone();
            if !algos.contains(&algo) {
                algos.push(algo);
            }
        }
        algos
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

/// Issue a short-lived **user** certificate (the pure core of
/// [`CertificateAuthority::issue_user_certificate`], split out so it can be
/// exercised with a generated key and no config plumbing).
pub fn issue_user_certificate_with(
    signing_key: &PrivateKey,
    subject_key: &PublicKey,
    principals: &[String],
    key_id: &str,
    lifetime: Duration,
) -> Result<russh::keys::Certificate> {
    issue_certificate_with(
        signing_key,
        subject_key,
        ssh_key::certificate::CertType::User,
        principals,
        key_id,
        lifetime,
    )
}

/// Issue a short-lived **host** certificate (M4-T1's counterpart on the backend
/// side: a backend `sshd` presents this during KEX, and the gateway's
/// `@cert-authority` chain verifies it).
pub fn issue_host_certificate_with(
    signing_key: &PrivateKey,
    subject_key: &PublicKey,
    principals: &[String],
    key_id: &str,
    lifetime: Duration,
) -> Result<russh::keys::Certificate> {
    issue_certificate_with(
        signing_key,
        subject_key,
        ssh_key::certificate::CertType::Host,
        principals,
        key_id,
        lifetime,
    )
}

/// Issue a short-lived certificate of an explicit [`CertType`](ssh_key::certificate::CertType).
///
/// The type is part of the signed body, so a user certificate can never be
/// replayed as a host certificate (or vice versa) — which is what the
/// verification chain asserts on the accepting side.
pub fn issue_certificate_with(
    signing_key: &PrivateKey,
    subject_key: &PublicKey,
    cert_type: ssh_key::certificate::CertType,
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
        .cert_type(cert_type)
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

/// Outcome of validating a certificate against a CA set at time `now`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateCheck {
    /// The certificate is well-formed, correctly CA-signed, within its validity
    /// window, and names the requested principal.
    Trusted,
    /// The certificate is of the wrong type for the context it was presented in
    /// (e.g. a user certificate offered where a host certificate is required).
    WrongCertType { expected: &'static str },
    /// The issuing CA is not in the trusted set.
    UnknownCa,
    /// The certificate does not list `principal` in its valid principals.
    PrincipalMismatch { expected: String },
    /// The certificate is outside its validity window.
    Expired,
    /// The certificate's own signature does not verify (tampered body).
    BadSignature,
}

/// Pure validation of a **user** certificate (M3's entry point; delegates to
/// [`validate_certificate_at`] with the user type required).
pub fn validate_user_certificate_at(
    cert: &russh::keys::Certificate,
    ca_fingerprints: &[String],
    principal: &str,
    now_unix: u64,
) -> CertificateCheck {
    validate_certificate_at(
        CertContext::User,
        cert,
        ca_fingerprints,
        principal,
        now_unix,
    )
}

/// Pure validation of a **host** certificate (M4-T1's `@cert-authority` chain).
///
/// Same chain as the user path, but the principal is the backend's host name and
/// the certificate type must be a host certificate.
pub fn validate_host_certificate_at(
    cert: &russh::keys::Certificate,
    ca_fingerprints: &[String],
    host: &str,
    now_unix: u64,
) -> CertificateCheck {
    validate_certificate_at(CertContext::Host, cert, ca_fingerprints, host, now_unix)
}

/// Which context a certificate is being presented in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertContext {
    /// OpenSSH *user* authentication.
    User,
    /// KEX *host* authentication (`@cert-authority`).
    Host,
}

impl CertContext {
    fn expected_type(self) -> ssh_key::certificate::CertType {
        match self {
            CertContext::User => ssh_key::certificate::CertType::User,
            CertContext::Host => ssh_key::certificate::CertType::Host,
        }
    }

    /// Label used in the [`CertificateCheck::WrongCertType`] reason.
    fn label(self) -> &'static str {
        match self {
            CertContext::User => "user",
            CertContext::Host => "host",
        }
    }
}

/// Pure validation of a certificate against a trusted CA set at time `now`
/// (seconds since the Unix epoch).
///
/// `now_unix` is the clock seam: production passes `SystemTime::now()`, tests pass
/// an arbitrary instant, which is what makes expiry testable without sleeping
/// (plan §6.4 — clock injection, no Mock).
///
/// The four-step chain (propose §3.3 / plan-m4 M4-T1):
/// 1. the **signing** key is a trusted CA (fails fast, before any crypto);
/// 2. the certificate's own signature verifies (catches a tampered body);
/// 3. `valid_after < now < valid_before`;
/// 4. the requested principal/host is one of the certificate's valid principals,
///    compared case-insensitively after trimming (host names are not case
///    significant, and a trailing dot or stray whitespace must not be the reason
///    a legitimate certificate is refused).
pub fn validate_certificate_at(
    context: CertContext,
    cert: &russh::keys::Certificate,
    ca_fingerprints: &[String],
    principal: &str,
    now_unix: u64,
) -> CertificateCheck {
    // 0. The certificate must be of the right kind for where it appeared: a
    //    user certificate must never satisfy the host-key check, or a holder of
    //    an ordinary user cert could impersonate the backend during KEX.
    if cert.cert_type() != context.expected_type() {
        return CertificateCheck::WrongCertType {
            expected: context.label(),
        };
    }

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
    //    `alex_host1` — or, on the host path, a certificate minted for one
    //    backend could stand in for another.
    if !principals_contain(cert.valid_principals(), principal) {
        return CertificateCheck::PrincipalMismatch {
            expected: principal.to_owned(),
        };
    }

    CertificateCheck::Trusted
}

/// Case-insensitive, whitespace-insensitive principal/host-name containment.
///
/// Host names are not case significant (RFC 4343) and both sides may carry a
/// trailing root dot, so `DB.Example.COM.` must match `db.example.com`. Being
/// lenient here cannot widen trust: the entry still has to name exactly this
/// principal.
fn principals_contain(principals: &[String], wanted: &str) -> bool {
    let wanted = normalize_principal(wanted);
    principals.iter().any(|p| normalize_principal(p) == wanted)
}

/// Lower-case and strip surrounding whitespace plus a trailing root dot.
fn normalize_principal(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
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
    fn host_certificate_is_typed_as_host_and_verified_by_the_same_chain() {
        let ca = ca_key();
        let inner = subject_key();
        let cert = issue_host_certificate_with(
            &ca,
            &inner,
            &["db.example.com".to_owned()],
            "backend-host",
            Duration::from_secs(300),
        )
        .expect("issue a host cert");
        assert_eq!(
            cert.cert_type(),
            ssh_key::certificate::CertType::Host,
            "a host certificate must be typed Host, or the host-key check cannot tell it apart"
        );
        let trusted = [sha256_fingerprint(ca.public_key())];
        assert_eq!(
            validate_host_certificate_at(
                &cert,
                &trusted,
                "db.example.com",
                now_unix_secs().unwrap()
            ),
            CertificateCheck::Trusted
        );
    }

    #[test]
    fn user_and_host_certificates_are_not_interchangeable() {
        // The type is inside the signed body, so a user certificate can never
        // satisfy the host check (and vice versa) — even from the same CA with
        // the same principals.
        let ca = ca_key();
        let inner = subject_key();
        let principals = vec!["db.example.com".to_owned()];
        let user =
            issue_user_certificate_with(&ca, &inner, &principals, "u", Duration::from_secs(300))
                .expect("user cert");
        let host =
            issue_host_certificate_with(&ca, &inner, &principals, "h", Duration::from_secs(300))
                .expect("host cert");
        let trusted = [sha256_fingerprint(ca.public_key())];
        let now = now_unix_secs().unwrap();

        assert_eq!(
            validate_user_certificate_at(&user, &trusted, "db.example.com", now),
            CertificateCheck::Trusted
        );
        assert_eq!(
            validate_host_certificate_at(&host, &trusted, "db.example.com", now),
            CertificateCheck::Trusted
        );
        assert_eq!(
            validate_host_certificate_at(&user, &trusted, "db.example.com", now),
            CertificateCheck::WrongCertType { expected: "host" },
            "a user certificate must not pass the host check"
        );
        assert_eq!(
            validate_user_certificate_at(&host, &trusted, "db.example.com", now),
            CertificateCheck::WrongCertType { expected: "user" },
            "a host certificate must not pass the user check"
        );
    }

    #[test]
    fn host_certificate_for_another_host_fails_the_chain() {
        let ca = ca_key();
        let inner = subject_key();
        let cert = issue_host_certificate_with(
            &ca,
            &inner,
            &["payroll.example.com".to_owned()],
            "other",
            Duration::from_secs(300),
        )
        .unwrap();
        let trusted = [sha256_fingerprint(ca.public_key())];
        assert_eq!(
            validate_host_certificate_at(
                &cert,
                &trusted,
                "db.example.com",
                now_unix_secs().unwrap()
            ),
            CertificateCheck::PrincipalMismatch {
                expected: "db.example.com".to_owned()
            }
        );
    }

    #[test]
    fn host_name_principal_matching_normalises_case_and_root_dot() {
        // `DB.Example.COM.` and `db.example.com` denote the same host, so both
        // must validate. Being lenient cannot widen trust: the entry still has to
        // name exactly this principal.
        let ca = ca_key();
        let inner = subject_key();
        let cert = issue_host_certificate_with(
            &ca,
            &inner,
            &["db.example.com".to_owned()],
            "h",
            Duration::from_secs(300),
        )
        .unwrap();
        let trusted = [sha256_fingerprint(ca.public_key())];
        let now = now_unix_secs().unwrap();
        for alias in ["db.example.com", "DB.EXAMPLE.COM", "db.example.com."] {
            assert_eq!(
                validate_host_certificate_at(&cert, &trusted, alias, now),
                CertificateCheck::Trusted,
                "{alias} must be accepted"
            );
        }
        assert_eq!(
            validate_host_certificate_at(&cert, &trusted, "evil-db.example.com", now),
            CertificateCheck::PrincipalMismatch {
                expected: "evil-db.example.com".to_owned()
            },
            "leniency must not turn into a suffix match"
        );
    }

    #[test]
    fn issuing_without_a_signing_key_is_refused() {
        // A verify-only CA must not silently produce certificates.
        let ca = CertificateAuthority {
            trusted_ca: Vec::new(),
            trusted_ca_keys: Vec::new(),
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
