//! Signed registry catalog metadata envelopes and rollback identity formats.
//!
//! ```text
//! tuf/root.json       authority keys and thresholds
//! tuf/targets.json    catalog file commitments
//! tuf/snapshot.json   root and target version commitments
//! tuf/timestamp.json  snapshot version commitment
//! ```

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

/// Directory holding committed registry TUF metadata.
pub const TUF_DIR: &str = "tuf";

pub const ROOT_JSON: &str = "tuf/root.json";
pub const TARGETS_JSON: &str = "tuf/targets.json";
pub const SNAPSHOT_JSON: &str = "tuf/snapshot.json";
pub const TIMESTAMP_JSON: &str = "tuf/timestamp.json";

pub const ROLE_ROOT: &str = "root";
pub const ROLE_TARGETS: &str = "targets";
pub const ROLE_SNAPSHOT: &str = "snapshot";
pub const ROLE_TIMESTAMP: &str = "timestamp";

pub const SCHEMA_ROOT: &str = "https://andyl.com/aos/registry/tuf/root/v1";
pub const SCHEMA_TARGETS: &str = "https://andyl.com/aos/registry/tuf/targets/v1";
pub const SCHEMA_SNAPSHOT: &str = "https://andyl.com/aos/registry/tuf/snapshot/v1";
pub const SCHEMA_TIMESTAMP: &str = "https://andyl.com/aos/registry/tuf/timestamp/v1";
pub const SPEC_VERSION: &str = "aos-tuf-1";
/// SSHSIG namespace authenticating registry catalog metadata.
pub const REGISTRY_METADATA_SIGNATURE_NAMESPACE: &str = "aos-registry-tuf-v1";

pub const SIGNATURE_NAMESPACE: &str = REGISTRY_METADATA_SIGNATURE_NAMESPACE;

pub const ROOT_EXPIRES_SECONDS: u64 = 365 * 24 * 60 * 60;
pub const TARGETS_EXPIRES_SECONDS: u64 = 90 * 24 * 60 * 60;
pub const SNAPSHOT_EXPIRES_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const TIMESTAMP_EXPIRES_SECONDS: u64 = 14 * 24 * 60 * 60;

/// Successful TUF verification result for a selected registry commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMetadata {
    /// Accepted root metadata version.
    /// Root version.
    pub root_version: u64,
    /// Accepted targets metadata version.
    /// Targets version.
    pub targets_version: u64,
    /// Accepted snapshot metadata version.
    /// Snapshot version.
    pub snapshot_version: u64,
    /// Accepted timestamp metadata version.
    /// Timestamp version.
    pub timestamp_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// Signed.
    pub signed: T,
    #[serde(default)]
    /// Signatures.
    pub signatures: Vec<TufSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufSignature {
    /// Key id.
    pub key_id: String,
    /// Sig.
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufKey {
    /// Key.
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufRoleSpec {
    /// Key ids.
    pub key_ids: Vec<String>,
    /// Threshold.
    pub threshold: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSigned {
    /// Schema.
    pub schema: String,
    /// Spec version.
    pub spec_version: String,
    /// Registry.
    pub registry: String,
    /// Version.
    pub version: u64,
    /// Expires.
    pub expires: String,
    /// Keys.
    pub keys: BTreeMap<String, TufKey>,
    /// Roles.
    pub roles: BTreeMap<String, TufRoleSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetsSigned {
    /// Schema.
    pub schema: String,
    /// Spec version.
    pub spec_version: String,
    /// Registry.
    pub registry: String,
    /// Version.
    pub version: u64,
    /// Expires.
    pub expires: String,
    /// Release.
    pub release: String,
    /// Catalog hash.
    pub catalog_hash: String,
    /// Targets.
    pub targets: BTreeMap<String, TufFileMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSigned {
    /// Schema.
    pub schema: String,
    /// Spec version.
    pub spec_version: String,
    /// Registry.
    pub registry: String,
    /// Version.
    pub version: u64,
    /// Expires.
    pub expires: String,
    /// Meta.
    pub meta: BTreeMap<String, TufVersionedMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampSigned {
    /// Schema.
    pub schema: String,
    /// Spec version.
    pub spec_version: String,
    /// Registry.
    pub registry: String,
    /// Version.
    pub version: u64,
    /// Expires.
    pub expires: String,
    /// Snapshot.
    pub snapshot: TufVersionedMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufFileMeta {
    /// Length.
    pub length: u64,
    /// Sha256.
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufVersionedMeta {
    /// Version.
    pub version: u64,
    /// Length.
    pub length: u64,
    /// Sha256.
    pub sha256: String,
}
