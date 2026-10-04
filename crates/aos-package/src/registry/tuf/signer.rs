//! Public signing identities and exact requests for registry catalog metadata.
//!
//! Catalog authority stays bound to the committed registry root and roster.
//! The file-key adapter preserves APR's synchronous API; external adapters
//! implement the same async trait without exposing private key material.

use anyhow::{Context as _, Result};

use crate::security::sign_payload_signature;
use super::{MetadataSigningKey, REGISTRY_METADATA_SIGNATURE_NAMESPACE};

/// Public identity available to sign registry catalog metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSigningIdentity {
    /// Key id bound by the current or previous catalog root policy.
    pub key_id: String,
    /// Public registry trust line; private material stays with the provider.
    pub key: String,
    /// Whether this identity belongs to the new catalog root policy.
    pub role_key: bool,
}

/// Exact role payload requested by the shared catalog metadata producer.
#[derive(Debug, Clone)]
pub struct MetadataSigningRequest {
    /// Registry identity selected for the candidate catalog.
    pub registry: String,
    /// Semver release containing this catalog.
    pub release: String,
    /// Catalog metadata role: root, targets, snapshot, or timestamp.
    pub role: String,
    /// Monotonic metadata version included in the signed payload.
    pub version: u64,
    /// Exact authorized public identity to use.
    pub key_id: String,
    /// Deterministic signed JSON bytes, without the envelope signatures.
    pub payload: Vec<u8>,
}

/// Signs catalog metadata with an independently pinned registry authority.
///
/// Catalog metadata retains the committed registry root and its rotation
/// rules. Distribution-bundle TUF authorities are a separate protocol.
#[async_trait::async_trait]
pub trait RegistryMetadataSigner: Send {
    /// Returns the available public signing identities and root-policy keys.
    fn signing_identities(&self) -> Vec<MetadataSigningIdentity>;

    /// Signs exact role bytes in [`REGISTRY_METADATA_SIGNATURE_NAMESPACE`].
    ///
    /// # Errors
    ///
    /// Returns an error when authorization, provider availability, or signing
    /// fails. The shared producer independently verifies returned signatures.
    async fn sign_metadata(&mut self, request: MetadataSigningRequest) -> Result<String>;
}

pub(super) struct FileMetadataSigner<'a> {
    pub(super) keys: &'a [MetadataSigningKey],
}

#[async_trait::async_trait]
impl RegistryMetadataSigner for FileMetadataSigner<'_> {
    fn signing_identities(&self) -> Vec<MetadataSigningIdentity> {
        self.keys.iter().map(|key| MetadataSigningIdentity {
            key_id: key.key_id.clone(),
            key: key.key.clone(),
            role_key: key.role_key,
        }).collect()
    }

    async fn sign_metadata(&mut self, request: MetadataSigningRequest) -> Result<String> {
        let key = self.keys.iter().find(|key| key.key_id == request.key_id)
            .context("catalog metadata signer key is unavailable")?;
        sign_payload_signature(&key.key_path, REGISTRY_METADATA_SIGNATURE_NAMESPACE, &request.payload)
    }
}
