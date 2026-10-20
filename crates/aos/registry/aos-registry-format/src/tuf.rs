//! Signed registry catalog metadata envelopes and rollback identity formats.
//!
//! ```text
//! tuf/root.json       authority keys and thresholds
//! tuf/targets.json    catalog file commitments
//! tuf/snapshot.json   root and target version commitments
//! tuf/timestamp.json  snapshot version commitment
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Directory holding committed registry TUF metadata.
pub const TUF_DIR: &str = "tuf";

/// Relative path of the signed root-authority envelope.
pub const ROOT_JSON: &str = "tuf/root.json";
/// Relative path of the signed catalog-target envelope.
pub const TARGETS_JSON: &str = "tuf/targets.json";
/// Relative path of the signed metadata-version snapshot.
pub const SNAPSHOT_JSON: &str = "tuf/snapshot.json";
/// Relative path of the signed snapshot freshness envelope.
pub const TIMESTAMP_JSON: &str = "tuf/timestamp.json";

/// Role authorized to establish and rotate root authority.
pub const ROLE_ROOT: &str = "root";
/// Role authorized to sign package catalog commitments.
pub const ROLE_TARGETS: &str = "targets";
/// Role authorized to sign metadata-version snapshots.
pub const ROLE_SNAPSHOT: &str = "snapshot";
/// Role authorized to sign freshness metadata.
pub const ROLE_TIMESTAMP: &str = "timestamp";

/// Wire schema identifier for root-authority payloads.
pub const SCHEMA_ROOT: &str = "https://andyl.com/aos/registry/tuf/root/v1";
/// Wire schema identifier for catalog-target payloads.
pub const SCHEMA_TARGETS: &str = "https://andyl.com/aos/registry/tuf/targets/v1";
/// Wire schema identifier for metadata-version snapshots.
pub const SCHEMA_SNAPSHOT: &str = "https://andyl.com/aos/registry/tuf/snapshot/v1";
/// Wire schema identifier for snapshot freshness payloads.
pub const SCHEMA_TIMESTAMP: &str = "https://andyl.com/aos/registry/tuf/timestamp/v1";
/// Protocol version recorded in all registry catalog payloads.
pub const SPEC_VERSION: &str = "aos-tuf-1";
/// SSHSIG namespace authenticating registry catalog metadata.
pub const REGISTRY_METADATA_SIGNATURE_NAMESPACE: &str = "aos-registry-tuf-v1";

/// SSHSIG namespace used by the registry catalog envelope verifier.
pub const SIGNATURE_NAMESPACE: &str = REGISTRY_METADATA_SIGNATURE_NAMESPACE;

/// Default root-authority validity period, in seconds.
pub const ROOT_EXPIRES_SECONDS: u64 = 365 * 24 * 60 * 60;
/// Default catalog-target validity period, in seconds.
pub const TARGETS_EXPIRES_SECONDS: u64 = 90 * 24 * 60 * 60;
/// Default metadata-snapshot validity period, in seconds.
pub const SNAPSHOT_EXPIRES_SECONDS: u64 = 30 * 24 * 60 * 60;
/// Default freshness-envelope validity period, in seconds.
pub const TIMESTAMP_EXPIRES_SECONDS: u64 = 14 * 24 * 60 * 60;

/// Successful TUF verification result for a selected registry commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMetadata {
    /// Accepted root metadata version.
    pub root_version: u64,
    /// Accepted targets metadata version.
    pub targets_version: u64,
    /// Accepted snapshot metadata version.
    pub snapshot_version: u64,
    /// Accepted timestamp metadata version.
    pub timestamp_version: u64,
}

/// Carries an authenticated payload and its detached role signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// Payload whose compact JSON bytes are authenticated by the signatures.
    pub signed: T,
    #[serde(default)]
    /// Detached signatures evaluated against the payload's authorized role.
    pub signatures: Vec<TufSignature>,
}

/// Binds an armored SSHSIG signature to a root-policy key identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufSignature {
    /// Identifier of the signing key in the root-authority key map.
    pub key_id: String,
    /// Armored SSHSIG signature using the registry metadata namespace.
    pub sig: String,
}

/// Stores an authorized registry public key in trust-line format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufKey {
    /// Ed25519 public key in `registry:Ed25519:<base64>` trust-line format.
    pub key: String,
}

/// Names the keys and distinct-signature threshold for one metadata role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufRoleSpec {
    /// Identifiers of keys authorized for this role.
    pub key_ids: Vec<String>,
    /// Minimum number of distinct authorized keys that must verify.
    pub threshold: u32,
}

/// Defines a registry's catalog-signing keys and role policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSigned {
    /// Wire schema identifier for this payload kind.
    pub schema: String,
    /// Registry catalog protocol version.
    pub spec_version: String,
    /// Registry name bound into the authenticated payload.
    pub registry: String,
    /// Monotonic metadata version used to prevent rollback.
    pub version: u64,
    /// UTC expiration timestamp in `YYYY-MM-DDTHH:MM:SSZ` form.
    pub expires: String,
    /// Authorized public keys indexed by policy identifier.
    pub keys: BTreeMap<String, TufKey>,
    /// Required role policies indexed by role name.
    pub roles: BTreeMap<String, TufRoleSpec>,
}

/// Commits to the package catalog for a selected registry release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetsSigned {
    /// Wire schema identifier for this payload kind.
    pub schema: String,
    /// Registry catalog protocol version.
    pub spec_version: String,
    /// Registry name bound into the authenticated payload.
    pub registry: String,
    /// Monotonic metadata version used to prevent rollback.
    pub version: u64,
    /// UTC expiration timestamp in `YYYY-MM-DDTHH:MM:SSZ` form.
    pub expires: String,
    /// Semver release tag associated with this catalog.
    pub release: String,
    /// SHA-256 hex digest of the ordered catalog commitment map.
    pub catalog_hash: String,
    /// Catalog files indexed by their registry-relative paths.
    pub targets: BTreeMap<String, TufFileMeta>,
}

/// Commits to the versions and bytes of root and target metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSigned {
    /// Wire schema identifier for this payload kind.
    pub schema: String,
    /// Registry catalog protocol version.
    pub spec_version: String,
    /// Registry name bound into the authenticated payload.
    pub registry: String,
    /// Monotonic metadata version used to prevent rollback.
    pub version: u64,
    /// UTC expiration timestamp in `YYYY-MM-DDTHH:MM:SSZ` form.
    pub expires: String,
    /// Versioned metadata commitments indexed by envelope path.
    pub meta: BTreeMap<String, TufVersionedMeta>,
}

/// Commits to a metadata snapshot and its freshness deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampSigned {
    /// Wire schema identifier for this payload kind.
    pub schema: String,
    /// Registry catalog protocol version.
    pub spec_version: String,
    /// Registry name bound into the authenticated payload.
    pub registry: String,
    /// Monotonic metadata version used to prevent rollback.
    pub version: u64,
    /// UTC expiration timestamp in `YYYY-MM-DDTHH:MM:SSZ` form.
    pub expires: String,
    /// Version and byte identity of the authenticated snapshot envelope.
    pub snapshot: TufVersionedMeta,
}

/// Commits to the length and SHA-256 identity of one catalog file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufFileMeta {
    /// Exact envelope or file length in bytes.
    pub length: u64,
    /// Lowercase hexadecimal SHA-256 digest of the committed bytes.
    pub sha256: String,
}

/// Commits to a metadata envelope's version, length, and SHA-256 identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufVersionedMeta {
    /// Monotonic metadata version used to prevent rollback.
    pub version: u64,
    /// Exact envelope or file length in bytes.
    pub length: u64,
    /// Lowercase hexadecimal SHA-256 digest of the committed bytes.
    pub sha256: String,
}
