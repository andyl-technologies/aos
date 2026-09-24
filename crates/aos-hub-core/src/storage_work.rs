//! Bounded, authenticated storage work issued by a hybrid Native Hub.
//!
//! Plans name one frozen placement and one object-store operation. The Worker
//! verifies the exact request bytes before parsing the plan, then executes
//! beside storage and returns a bounded semantic result. SQL decisions remain
//! with Native.

use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Internal Worker route for Native-issued storage work.
pub const STORAGE_WORK_PATH: &str = "/_internal/storage/v1/execute";
/// Internal capability route used before a Native hybrid origin becomes ready.
pub const STORAGE_CAPABILITIES_PATH: &str = "/_internal/storage/v1/capabilities";
/// Fixed authenticated challenge for the storage executor capability route.
pub const STORAGE_CAPABILITIES_CHALLENGE: &[u8] = b"aos-storage-capabilities-v1";
/// Header authenticating the exact JSON request body.
pub const STORAGE_WORK_SIGNATURE_HEADER: &str = "x-aos-storage-work-signature";
/// Maximum accepted JSON plan size.
pub const MAX_PLAN_BYTES: usize = 16 * 1024;
/// Maximum semantic response size sent back to Native.
pub const MAX_RESULT_BYTES: usize = 256 * 1024;
/// Maximum full-object verification size in the first streaming R2 executor.
pub const MAX_VERIFY_SOURCE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Exact storage executor features required by the first hybrid protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageCapabilities {
    /// Supported storage-work protocol version.
    pub version: u8,
    /// Deployment identity shared with the Native Hub.
    pub deployment_id: String,
    /// Physical binding resolved by this executor.
    pub binding_kind: String,
    /// Closed operation names accepted by this executor.
    pub operations: Vec<String>,
    /// Maximum bytes returned in one semantic result.
    pub max_result_bytes: usize,
    /// Maximum source bytes read for one streaming verification.
    pub max_verify_source_bytes: u64,
}

const MAX_PLAN_LIFETIME_SECONDS: i64 = 30;

/// The exact storage operation admitted by one plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StorageWorkOperation {
    /// Reads provider metadata without transferring the body.
    Head {
        /// Surface-relative object path.
        path: String,
    },
    /// Lists one bounded provider page under the placement prefix.
    ListPage {
        /// Surface-relative listing prefix, possibly empty.
        prefix: String,
        /// Opaque provider continuation from a prior result.
        cursor: Option<String>,
        /// Maximum objects returned on this page.
        limit: usize,
    },
    /// Hashes one complete object beside storage and returns its digest.
    InspectSha256 {
        /// Surface-relative object path.
        path: String,
        /// Expected digest, or `None` when taking inventory evidence.
        expected_sha256: Option<String>,
        /// Maximum source bytes the executor may read.
        max_source_bytes: u64,
    },
}

/// One short-lived Native authorization to inspect a frozen R2 placement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageWorkPlan {
    /// Protocol version. Only version 1 is accepted.
    pub version: u8,
    /// Stable request and retry identity.
    pub plan_id: String,
    /// Shared edge and Native deployment identity.
    pub deployment_id: String,
    /// Unix time when the Native Hub issued the plan.
    pub issued_at: i64,
    /// Unix time after which the Worker rejects the plan.
    pub expires_at: i64,
    /// Frozen placement identity authorized by Native SQL.
    pub placement_id: i64,
    /// Placement resource version authorized by Native SQL.
    pub placement_resource_version: i64,
    /// Frozen storage binding identity.
    pub binding_id: i64,
    /// Binding resource version authorized by Native SQL.
    pub binding_resource_version: i64,
    /// Only the deployment R2 attachment is supported by this executor.
    pub binding_kind: String,
    /// Exact object-key prefix from the frozen placement.
    pub placement_prefix: String,
    /// Closed operation and its bounded selector.
    pub operation: StorageWorkOperation,
}

/// Provider identity for one observed object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageObjectIdentity {
    /// Full bucket key within the placement.
    pub key: String,
    /// Provider-observed object size.
    pub size: u64,
    /// Provider-issued strong entity tag.
    pub etag: String,
}

/// Bounded result of one storage work plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StorageWorkOutcome {
    /// The selected object does not exist.
    NotFound,
    /// Provider metadata for one object.
    Head { object: StorageObjectIdentity },
    /// One ordered provider listing page.
    ListPage {
        /// Object identities observed in this page.
        objects: Vec<StorageObjectIdentity>,
        /// Opaque provider continuation, if another page exists.
        cursor: Option<String>,
    },
    /// Digest observed from one bounded provider object snapshot.
    Sha256Evidence {
        /// Provider identity observed with the body snapshot.
        object: StorageObjectIdentity,
        /// SHA-256 of the bytes read by the executor.
        sha256: String,
    },
}

/// Work result tied back to the exact plan and placement fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageWorkResult {
    /// Plan whose operation produced this result.
    pub plan_id: String,
    /// Frozen placement identity from the plan.
    pub placement_id: i64,
    /// Frozen placement resource version from the plan.
    pub placement_resource_version: i64,
    /// Frozen binding identity from the plan.
    pub binding_id: i64,
    /// Frozen binding resource version from the plan.
    pub binding_resource_version: i64,
    /// Actual source bytes read by the executor.
    pub source_bytes: u64,
    /// Typed semantic result.
    pub outcome: StorageWorkOutcome,
}

/// Validation or authentication failure for storage work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StorageWorkError {
    /// The service key is too short.
    #[error("storage work key must contain at least 32 bytes")]
    WeakKey,
    /// The HMAC header is malformed or does not authenticate the body.
    #[error("storage work signature is invalid")]
    InvalidSignature,
    /// The plan or its object selector is malformed or unsupported.
    #[error("storage work plan is invalid")]
    InvalidPlan,
    /// The plan is expired, premature, or excessively long-lived.
    #[error("storage work plan is outside its validity window")]
    InvalidTime,
    /// The plan names another deployment.
    #[error("storage work deployment does not match")]
    DeploymentMismatch,
}

/// HMAC key for the Native-to-Worker storage work trust domain.
#[derive(Clone)]
pub struct StorageWorkKey {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for StorageWorkKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StorageWorkKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl StorageWorkKey {
    /// Creates a signer and verifier from one deployment secret.
    ///
    /// # Errors
    ///
    /// Returns an error when the secret contains fewer than 32 bytes.
    pub fn new(bytes: impl AsRef<[u8]>) -> Result<Self, StorageWorkError> {
        let bytes = bytes.as_ref();
        if bytes.len() < 32 {
            return Err(StorageWorkError::WeakKey);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Signs the exact JSON body sent to the Worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the body exceeds the wire cap.
    pub fn sign_body(&self, body: &[u8]) -> Result<String, StorageWorkError> {
        if body.len() > MAX_PLAN_BYTES {
            return Err(StorageWorkError::InvalidPlan);
        }
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.bytes).map_err(|_| StorageWorkError::WeakKey)?;
        mac.update(b"aos-storage-work-v1\0");
        mac.update(body);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Verifies the exact body and parses one bounded storage plan.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid signature, plan, time, or deployment.
    pub fn verify_plan(
        &self,
        signature: &str,
        body: &[u8],
        deployment_id: &str,
        now: i64,
    ) -> Result<StorageWorkPlan, StorageWorkError> {
        self.verify_body(signature, body)?;

        let plan: StorageWorkPlan =
            serde_json::from_slice(body).map_err(|_| StorageWorkError::InvalidPlan)?;
        plan.validate(deployment_id, now)?;
        Ok(plan)
    }

    /// Verifies an exact bounded body without interpreting its payload.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized body or invalid HMAC signature.
    pub fn verify_body(&self, signature: &str, body: &[u8]) -> Result<(), StorageWorkError> {
        if body.len() > MAX_PLAN_BYTES {
            return Err(StorageWorkError::InvalidPlan);
        }
        let signature = hex::decode(signature).map_err(|_| StorageWorkError::InvalidSignature)?;
        if signature.len() != 32 {
            return Err(StorageWorkError::InvalidSignature);
        }
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.bytes).map_err(|_| StorageWorkError::WeakKey)?;
        mac.update(b"aos-storage-work-v1\0");
        mac.update(body);
        mac.verify_slice(&signature)
            .map_err(|_| StorageWorkError::InvalidSignature)
    }
}

impl StorageWorkPlan {
    /// Validates one plan before issuing or executing it.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale, malformed, or unsupported plan.
    pub fn validate(&self, deployment_id: &str, now: i64) -> Result<(), StorageWorkError> {
        if self.version != 1
            || self.plan_id.len() != 32
            || !self.plan_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.binding_kind != "deployment_r2"
            || self.placement_id <= 0
            || self.placement_resource_version <= 0
            || self.binding_id <= 0
            || self.binding_resource_version <= 0
            || !valid_relative_path(&self.placement_prefix, true)
        {
            return Err(StorageWorkError::InvalidPlan);
        }
        if self.deployment_id != deployment_id {
            return Err(StorageWorkError::DeploymentMismatch);
        }
        if self.issued_at > now.saturating_add(5)
            || self.expires_at < now
            || self.expires_at < self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_PLAN_LIFETIME_SECONDS
        {
            return Err(StorageWorkError::InvalidTime);
        }
        match &self.operation {
            StorageWorkOperation::Head { path } => {
                if !valid_relative_path(path, false) {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
            StorageWorkOperation::ListPage {
                prefix,
                cursor,
                limit,
            } => {
                if !valid_relative_path(prefix, true)
                    || !(1..=1000).contains(limit)
                    || cursor.as_ref().is_some_and(|value| {
                        value.len() > crate::fetch::WORKER_MAX_SURFACE_LIST_CURSOR_BYTES
                    })
                {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
            StorageWorkOperation::InspectSha256 {
                path,
                expected_sha256,
                max_source_bytes,
            } => {
                if !valid_relative_path(path, false)
                    || expected_sha256.as_ref().is_some_and(|digest| {
                        digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                    || !(1..=MAX_VERIFY_SOURCE_BYTES).contains(max_source_bytes)
                {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
        }
        Ok(())
    }

    /// Maps a validated surface-relative selector to the exact bucket key.
    ///
    /// # Errors
    ///
    /// Returns an error if the selector is not a canonical relative path.
    pub fn object_key(&self, relative: &str) -> Result<String, StorageWorkError> {
        if !valid_relative_path(relative, true) {
            return Err(StorageWorkError::InvalidPlan);
        }
        Ok(crate::keymap::r2_key(&self.placement_prefix, relative))
    }
}

fn valid_relative_path(path: &str, allow_empty: bool) -> bool {
    if path.len() > 2048 || (!allow_empty && path.is_empty()) {
        return false;
    }
    if !allow_empty && path.ends_with('/') {
        return false;
    }
    if path.is_empty() {
        return true;
    }
    if path.starts_with('/')
        || path.starts_with('\\')
        || path.ends_with("//")
        || path.contains('%')
        || path.contains('?')
        || path.contains('#')
        || path.contains('\\')
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return false;
    }
    let trimmed = path.trim_end_matches('/');
    !trimmed.is_empty()
        && trimmed
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(now: i64) -> StorageWorkPlan {
        StorageWorkPlan {
            version: 1,
            plan_id: "a".repeat(32),
            deployment_id: "deployment-1".into(),
            issued_at: now,
            expires_at: now + 30,
            placement_id: 12,
            placement_resource_version: 4,
            binding_id: 3,
            binding_resource_version: 2,
            binding_kind: "deployment_r2".into(),
            placement_prefix: "tenant/registry/".into(),
            operation: StorageWorkOperation::Head {
                path: "objects/ab/1234".into(),
            },
        }
    }

    #[test]
    fn storage_work_is_signed_and_scoped_to_one_placement() {
        let key = StorageWorkKey::new([7; 32]).unwrap();
        let plan = plan(100);
        let body = serde_json::to_vec(&plan).unwrap();
        let signature = key.sign_body(&body).unwrap();
        let verified = key
            .verify_plan(&signature, &body, "deployment-1", 101)
            .unwrap();
        assert_eq!(verified, plan);
        assert_eq!(
            verified.object_key("objects/ab/1234").unwrap(),
            "tenant/registry/objects/ab/1234"
        );
        assert_eq!(
            key.verify_plan(&signature, &body, "deployment-2", 101),
            Err(StorageWorkError::DeploymentMismatch)
        );
        assert_eq!(
            key.verify_plan(&signature, &body, "deployment-1", 131),
            Err(StorageWorkError::InvalidTime)
        );
    }

    #[test]
    fn selector_cannot_escape_its_placement() {
        for invalid in ["/absolute", "../sibling", "a/../b", "a//b", "a%2fb", "a\\b"] {
            assert!(!valid_relative_path(invalid, false), "{invalid}");
        }
    }
}
