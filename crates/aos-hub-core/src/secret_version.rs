//! Runtime resolution of immutable provider-managed secret versions.
//!
//! Control-plane records carry only an opaque [`SecretVersionRef`]-shaped
//! string and a required SHA-256 fingerprint. Platform adapters resolve the
//! reference at the last possible moment; plaintext is never represented in a
//! plan, API response, revision, audit record, or topology event.

#[cfg(test)]
use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::backend::BackendBounds;

/// Drop-zeroed bytes owned only by runtime secret adapters.
struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
}

#[cfg(test)]
impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self {
            bytes: Zeroizing::new(self.bytes.to_vec()),
        }
    }
}

/// Plaintext material confined to the runtime adapter that immediately uses it.
///
/// This type intentionally implements neither `Debug` nor serialization and
/// zeroes its owned buffer on drop.
pub struct ResolvedSecretVersion(SecretBytes);

impl ResolvedSecretVersion {
    /// Takes ownership of provider bytes and immediately places them in a
    /// zeroizing allocation.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(SecretBytes {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Takes ownership of an allocation that was zeroizing from its creation.
    #[must_use]
    pub fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(SecretBytes { bytes })
    }
    /// Borrows the resolved bytes for an immediate protocol adapter.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    /// Borrows UTF-8 material for text-only protocol adapters.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider value is not UTF-8.
    pub fn expose_utf8(&self) -> Result<&str> {
        std::str::from_utf8(self.expose_bytes()).context("resolved secret version is not UTF-8")
    }
}

/// Resolves one exact opaque provider version without consulting Hub storage.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait SecretVersionResolver: BackendBounds {
    /// Resolves `version_ref` to its current provider value.
    ///
    /// # Errors
    ///
    /// Returns an error when the reference is invalid, absent, or unavailable.
    async fn resolve(&self, version_ref: &str) -> Result<ResolvedSecretVersion>;
}

/// Test-only byte map for exercising exact-version consumers.
///
/// Production native and Worker adapters retain only provider handles and
/// resolve bytes on demand. This map is compiled only for core unit tests.
#[cfg(test)]
pub struct BoundSecretVersionResolver {
    versions: BTreeMap<String, SecretBytes>,
}

#[cfg(test)]
impl BoundSecretVersionResolver {
    /// Builds a resolver from an exact reference-to-value map.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid reference or duplicate entry.
    pub fn new(versions: impl IntoIterator<Item = (String, String)>) -> Result<Self> {
        Self::new_bytes(
            versions
                .into_iter()
                .map(|(version_ref, value)| (version_ref, value.into_bytes())),
        )
    }

    /// Builds a resolver whose provider values may contain arbitrary bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid reference, empty value, or duplicate entry.
    pub fn new_bytes(versions: impl IntoIterator<Item = (String, Vec<u8>)>) -> Result<Self> {
        let mut resolver = Self {
            versions: BTreeMap::new(),
        };
        for (version_ref, value) in versions {
            resolver.bind_bytes(version_ref, value)?;
        }
        Ok(resolver)
    }

    /// Adds one exact provider value while the platform adapter is starting.
    ///
    /// The input allocation is transferred directly into a zeroizing owner
    /// before validation, so failure paths do not leave an unprotected copy.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid reference, empty value, or duplicate entry.
    pub fn bind_bytes(&mut self, version_ref: String, value: Vec<u8>) -> Result<()> {
        let value = SecretBytes {
            bytes: Zeroizing::new(value),
        };
        validate_secret_version_ref(&version_ref)?;
        anyhow::ensure!(!value.bytes.is_empty(), "secret version value is empty");
        anyhow::ensure!(
            !self.versions.contains_key(&version_ref),
            "duplicate secret version reference '{version_ref}'"
        );
        self.versions.insert(version_ref, value);
        Ok(())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg(test)]
impl SecretVersionResolver for BoundSecretVersionResolver {
    async fn resolve(&self, version_ref: &str) -> Result<ResolvedSecretVersion> {
        validate_secret_version_ref(version_ref)?;
        self.versions
            .get(version_ref)
            .cloned()
            .map(ResolvedSecretVersion)
            .with_context(|| format!("secret provider has no version '{version_ref}'"))
    }
}

/// Fail-closed resolver used when no provider is configured.
pub struct EmptySecretVersionResolver;

impl EmptySecretVersionResolver {
    /// Returns the shared resolver trait object.
    #[must_use]
    pub fn shared() -> Arc<dyn SecretVersionResolver> {
        Arc::new(Self)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl SecretVersionResolver for EmptySecretVersionResolver {
    async fn resolve(&self, version_ref: &str) -> Result<ResolvedSecretVersion> {
        validate_secret_version_ref(version_ref)?;
        anyhow::bail!("secret-version provider is not configured")
    }
}

/// Validates the closed, non-secret provider-reference grammar.
///
/// References have the form `provider://namespace/name/version`. Every segment
/// is an opaque identifier containing only ASCII alphanumerics, `.`, `_`, or
/// `-`. Userinfo, query strings, fragments, whitespace, encoded delimiters, and
/// bare values are rejected.
///
/// # Errors
///
/// Returns an error when `version_ref` is not a non-secret opaque identifier.
pub fn validate_secret_version_ref(version_ref: &str) -> Result<()> {
    anyhow::ensure!(
        (1..=128).contains(&version_ref.len()),
        "secret version reference must contain 1 to 128 bytes"
    );
    anyhow::ensure!(
        !version_ref.bytes().any(|byte| byte.is_ascii_whitespace())
            && !version_ref.contains(['@', '?', '#', '%']),
        "secret version reference contains a forbidden URI component"
    );
    let (provider, remainder) = version_ref
        .split_once("://")
        .context("secret version reference must use provider://namespace/name/version")?;
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    };
    anyhow::ensure!(
        valid_segment(provider),
        "invalid secret provider identifier"
    );
    let supported = matches!(provider, "vault" | "worker" | "native" | "secret")
        || cfg!(test) && provider == "test";
    anyhow::ensure!(supported, "unsupported secret provider");
    let segments = remainder.split('/').collect::<Vec<_>>();
    anyhow::ensure!(
        segments.len() >= 3,
        "secret version reference must name namespace, secret, and version"
    );
    anyhow::ensure!(
        segments.iter().all(|segment| valid_segment(segment)),
        "invalid secret version reference segment"
    );
    let version = segments
        .last()
        .copied()
        .context("secret version is missing")?;
    anyhow::ensure!(
        version.strip_prefix('v').is_some_and(
            |number| !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        ),
        "secret version reference must end in an immutable v<number> version"
    );
    Ok(())
}

/// Verifies resolved material against a mandatory SHA-256 fingerprint.
///
/// # Errors
///
/// Returns an error for a malformed fingerprint or a digest mismatch.
pub fn verify_secret_fingerprint(secret: &ResolvedSecretVersion, fingerprint: &str) -> Result<()> {
    anyhow::ensure!(
        fingerprint.len() == 64 && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "secret fingerprint must be a 64-character SHA-256 hex digest"
    );
    let actual = hex::encode(Sha256::digest(secret.expose_bytes()));
    anyhow::ensure!(
        actual.eq_ignore_ascii_case(fingerprint),
        "resolved secret version fingerprint mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_grammar_rejects_secret_bearing_uri_shapes() {
        for rejected in [
            "plaintext",
            "vault://user@host/name/v1",
            "vault://tenant/name/v1?token=x",
            "vault://tenant/name/v1#fragment",
            "vault://tenant/name/%76%31",
            "vault://tenant/v1",
            "vault://tenant/../v1",
            "vault://tenant/./v1",
        ] {
            assert!(validate_secret_version_ref(rejected).is_err(), "{rejected}");
        }
        assert!(validate_secret_version_ref("vault://tenant/webhook/v1").is_ok());
    }

    #[tokio::test]
    async fn resolver_supports_bytes_and_fails_closed_on_fingerprint_drift() {
        let reference = "worker://tenant/webhook/v1".to_string();
        let resolver = BoundSecretVersionResolver::new_bytes([(
            reference.clone(),
            vec![0, 159, 146, 150, 255],
        )])
        .unwrap();
        let secret = resolver.resolve(&reference).await.unwrap();
        assert_eq!(secret.expose_bytes(), &[0, 159, 146, 150, 255]);
        assert!(secret.expose_utf8().is_err());
        assert!(verify_secret_fingerprint(&secret, &"0".repeat(64)).is_err());
    }
}
