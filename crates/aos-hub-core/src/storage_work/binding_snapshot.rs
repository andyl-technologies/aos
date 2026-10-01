//! Frozen external storage bindings for the hybrid executor.
//!
//! These nonsecret coordinates and exact credential references are the input
//! to Native publication. The Worker can check a plan against the immutable
//! snapshot while secret bytes travel through a separate channel.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use super::{valid_relative_path, valid_sha256_hex, StorageWorkError, StorageWorkPlan};

const MAX_SNAPSHOT_LIFETIME_SECONDS: i64 = 60 * 60;

/// Internal Worker route for binding publication and revocation.
pub const STORAGE_BINDING_CONTROL_PATH: &str = "/_internal/storage/v1/bindings";
/// Maximum body size for one signed binding control request.
pub const MAX_BINDING_CONTROL_BYTES: usize = 64 * 1024;
/// Internal Worker route for one signed credential capability probe.
pub const STORAGE_CREDENTIAL_PROBE_PATH: &str = "/_internal/storage/v1/credential-probe";
/// Maximum body size for a signed credential probe request.
pub const MAX_CREDENTIAL_PROBE_BYTES: usize = 16 * 1024;
/// Closed, nonsecret failure stages that the Worker may return for a probe.
pub const STORAGE_CREDENTIAL_PROBE_FAILURE_STAGES: &[&str] = &[
    "multipart recovery URL construction failed",
    "multipart recovery request failed",
    "multipart recovery listing was rejected",
    "multipart recovery response failed",
    "credential multipart recovery listing is not UTF-8",
    "multipart recovery listing parse failed",
    "multipart recovery abort URL construction failed",
    "multipart recovery abort request failed",
    "multipart recovery abort was rejected",
    "multipart create URL construction failed",
    "multipart create request failed",
    "multipart create response failed",
    "credential multipart-create response is not UTF-8",
    "multipart create response parse failed",
    "multipart probe abort URL construction failed",
    "multipart probe abort request failed",
    "provider request failed",
];

/// One short-lived credential probe; it never enters published binding state.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageCredentialProbeRequest {
    /// Protocol version.
    pub version: u8,
    /// Single unvalidated credential and its exact resolved secret.
    pub publication: StorageBindingPublication,
    /// Opaque, unique token used only in the probe object key.
    pub probe_token: String,
}

impl StorageCredentialProbeRequest {
    /// Checks the single credential, short lifetime, and secret fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid, stale, or mismatched request.
    pub fn validate(&self, deployment_id: &str, now: i64) -> Result<(), StorageWorkError> {
        self.publication.validate(deployment_id, now)?;
        let snapshot = &self.publication.snapshot;
        if self.version != 1
            || snapshot.access_mode != "private"
            || snapshot.credentials.len() != 1
            || snapshot.expires_at.saturating_sub(snapshot.issued_at) > 30
            || self.probe_token.len() != 64
            || !self
                .probe_token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(StorageWorkError::InvalidSnapshot);
        }
        Ok(())
    }
}

/// Executor acknowledgement of one exact published or revoked revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageBindingAcknowledgement {
    /// Exact content revision named by the control request.
    pub revision: String,
}

/// One immutable, nonsecret credential revision available to a storage executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageCredentialReference {
    /// Capability purpose (`read`, `write`, `list`, `delete`, or `presign`).
    pub purpose: String,
    /// Purpose-local credential generation selected by Native SQL.
    pub generation: i64,
    /// Immutable secret-manager reference distributed separately from plans.
    pub secret_version_ref: String,
    /// Fingerprint used to check the separately supplied secret bytes.
    pub fingerprint: String,
}

/// Exact credential generation named by one private-binding work plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageCredentialSelector {
    /// Capability purpose required by the operation.
    pub purpose: String,
    /// Purpose-local generation admitted by the binding snapshot.
    pub generation: i64,
}

/// One resolved provider secret, confined to an authenticated control request.
///
/// The value is standard-base64 encoded for the bounded JSON wire format. It
/// never appears in a work plan or semantic result, and its owned string is
/// zeroed when this value is dropped.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageCredentialMaterial {
    /// Exact purpose and generation admitted by the paired snapshot.
    pub selector: StorageCredentialSelector,
    /// Standard-base64 provider credential bytes.
    pub value_base64: String,
}

impl Drop for StorageCredentialMaterial {
    fn drop(&mut self) {
        self.value_base64.zeroize();
    }
}

/// One nonsecret snapshot paired with its separately resolved credentials.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageBindingPublication {
    /// Frozen provider coordinates and immutable credential references.
    pub snapshot: StorageBindingSnapshot,
    /// Resolved values ordered by credential purpose.
    pub materials: Vec<StorageCredentialMaterial>,
}

impl StorageBindingPublication {
    /// Checks every supplied secret against the exact snapshot fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale snapshot, missing or extra purpose,
    /// malformed base64 value, oversized secret, or fingerprint mismatch.
    pub fn validate(&self, deployment_id: &str, now: i64) -> Result<(), StorageWorkError> {
        use base64::Engine as _;

        self.snapshot.validate(deployment_id, now)?;
        if self.materials.len() != self.snapshot.credentials.len() {
            return Err(StorageWorkError::InvalidSnapshot);
        }
        for (material, reference) in self.materials.iter().zip(&self.snapshot.credentials) {
            if material.selector.purpose != reference.purpose
                || material.selector.generation != reference.generation
                || material.value_base64.len() > 5_464
            {
                return Err(StorageWorkError::InvalidSnapshot);
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&material.value_base64)
                .map_err(|_| StorageWorkError::InvalidSnapshot)?;
            let decoded = Zeroizing::new(decoded);
            if decoded.is_empty()
                || decoded.len() > 4 * 1024
                || hex::encode(Sha256::digest(decoded.as_slice())) != reference.fingerprint
            {
                return Err(StorageWorkError::InvalidSnapshot);
            }
        }
        Ok(())
    }

    /// Resolves one admitted textual S3 capability without exposing it in a plan.
    ///
    /// The caller receives an owned, zeroing string and must keep it within the
    /// storage executor. Binary or malformed provider values fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error for stale publication state, an unknown selector, or a
    /// malformed or non-UTF-8 credential value.
    pub fn credential_text(
        &self,
        selector: &StorageCredentialSelector,
        deployment_id: &str,
        now: i64,
    ) -> Result<Zeroizing<String>, StorageWorkError> {
        use base64::Engine as _;

        self.validate(deployment_id, now)?;
        let material = self
            .materials
            .iter()
            .find(|material| material.selector == *selector)
            .ok_or(StorageWorkError::InvalidSnapshot)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&material.value_base64)
            .map_err(|_| StorageWorkError::InvalidSnapshot)?;
        let text = String::from_utf8(bytes).map_err(|error| {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            StorageWorkError::InvalidSnapshot
        })?;
        Ok(Zeroizing::new(text))
    }
}

/// Signed Native instruction to publish or revoke one external binding.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StorageBindingControl {
    /// Publishes an exact immutable snapshot and its provider credentials.
    Publish {
        /// Snapshot and purpose-scoped secret values.
        publication: StorageBindingPublication,
    },
    /// Rejects future plans for an exact active snapshot.
    Revoke {
        /// Deployment identity shared with the Worker.
        deployment_id: String,
        /// Binding whose active snapshot is withdrawn.
        binding_id: i64,
        /// Exact snapshot revision expected to be active.
        revision: String,
        /// Unix time when Native issued this revocation.
        issued_at: i64,
        /// Unix time after which this instruction is invalid.
        expires_at: i64,
    },
}

impl StorageBindingControl {
    /// Validates the bounded, signed control body before it reaches storage.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed publication, mismatched deployment,
    /// or stale revocation instruction.
    pub fn validate(&self, deployment_id: &str, now: i64) -> Result<(), StorageWorkError> {
        match self {
            Self::Publish { publication } => publication.validate(deployment_id, now),
            Self::Revoke {
                deployment_id: actual,
                binding_id,
                revision,
                issued_at,
                expires_at,
            } => {
                if actual != deployment_id {
                    return Err(StorageWorkError::DeploymentMismatch);
                }
                if *binding_id <= 0 || !valid_sha256_hex(revision) {
                    return Err(StorageWorkError::InvalidSnapshot);
                }
                if *issued_at > now.saturating_add(5)
                    || *expires_at < now
                    || *expires_at < *issued_at
                    || expires_at.saturating_sub(*issued_at) > 30
                {
                    return Err(StorageWorkError::InvalidTime);
                }
                Ok(())
            }
        }
    }

    /// Returns the one binding identity used to select its Durable Object.
    #[must_use]
    pub fn binding_id(&self) -> i64 {
        match self {
            Self::Publish { publication } => publication.snapshot.binding_id,
            Self::Revoke { binding_id, .. } => *binding_id,
        }
    }
}

/// Frozen external S3-compatible binding coordinates published by Native.
///
/// This snapshot contains no credential material. Its revision is the SHA-256
/// digest of its canonical JSON encoding, and a work plan names that revision
/// before the Worker may open the provider. Secret bytes are distributed on a
/// separate authenticated channel and checked against an exact credential
/// reference from this snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageBindingSnapshot {
    /// Snapshot schema version.
    pub version: u8,
    /// Deployment identity shared by Native and the executor.
    pub deployment_id: String,
    /// SQL identity of the frozen binding.
    pub binding_id: i64,
    /// SQL resource version of the frozen binding.
    pub binding_resource_version: i64,
    /// Stable binding identity across database exports.
    pub binding_stable_id: String,
    /// External object-store kind (`s3` or `r2`).
    pub binding_kind: String,
    /// Exact bucket selected by the binding.
    pub object_bucket: String,
    /// Binding-owned key prefix within the bucket.
    pub object_prefix: String,
    /// Canonical endpoint scheme.
    pub endpoint_scheme: String,
    /// Canonical endpoint host representation (`dns`, `ipv4`, or `ipv6`).
    pub endpoint_host_kind: String,
    /// Canonical endpoint host bytes.
    pub endpoint_host_bytes: Vec<u8>,
    /// Explicit endpoint port, when present.
    pub endpoint_port: Option<i64>,
    /// SigV4 signing region.
    pub signing_region: String,
    /// `public` or `private` provider access.
    pub access_mode: String,
    /// Exact immutable credential references admitted by this snapshot.
    pub credentials: Vec<StorageCredentialReference>,
    /// Unix time at which Native published the snapshot.
    pub issued_at: i64,
    /// Unix time after which the executor must reject the snapshot.
    pub expires_at: i64,
}

impl StorageBindingSnapshot {
    /// Freezes one unvalidated credential solely for an immediate probe.
    ///
    /// # Errors
    ///
    /// Returns an error for mismatched identities or malformed binding coordinates.
    pub fn for_credential_probe(
        deployment_id: String,
        binding: &crate::db::BindingRecord,
        credential: &crate::db::BindingCredentialRevisionRecord,
        now: i64,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            credential.binding_id == binding.id,
            "credential binding mismatch"
        );
        let expires_at = now
            .checked_add(30)
            .ok_or_else(|| anyhow::anyhow!("credential probe expiry overflowed"))?;
        Self::build_from_binding(
            deployment_id,
            binding,
            std::slice::from_ref(credential),
            now,
            expires_at,
            false,
        )
    }

    /// Freezes an external binding and its validated current credential heads.
    ///
    /// The caller must load the binding and heads from one consistent SQL
    /// observation, then publish this immutable value before issuing plans that
    /// name its revision.
    ///
    /// # Errors
    ///
    /// Returns an error for incomplete provider coordinates, unvalidated
    /// credentials, or malformed snapshot fields.
    pub fn from_binding(
        deployment_id: String,
        binding: &crate::db::BindingRecord,
        credentials: &[crate::db::BindingCredentialRevisionRecord],
        issued_at: i64,
        expires_at: i64,
    ) -> anyhow::Result<Self> {
        Self::build_from_binding(
            deployment_id,
            binding,
            credentials,
            issued_at,
            expires_at,
            true,
        )
    }

    fn build_from_binding(
        deployment_id: String,
        binding: &crate::db::BindingRecord,
        credentials: &[crate::db::BindingCredentialRevisionRecord],
        issued_at: i64,
        expires_at: i64,
        require_validated: bool,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !binding.is_instance_default && matches!(binding.kind.as_str(), "s3" | "r2"),
            "storage binding snapshot requires an external S3-compatible binding"
        );
        let mut references = credentials
            .iter()
            .map(|credential| {
                anyhow::ensure!(
                    credential.binding_id == binding.id
                        && (!require_validated
                            || (credential.validation_state == "valid"
                                && credential.validated_at.is_some())),
                    "storage binding snapshot requires validated credential heads"
                );
                Ok(StorageCredentialReference {
                    purpose: credential.purpose.clone(),
                    generation: credential.generation,
                    secret_version_ref: credential.secret_version_ref.clone(),
                    fingerprint: credential.credential_fingerprint.clone(),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        references.sort_by(|left, right| left.purpose.cmp(&right.purpose));

        let snapshot = Self {
            version: 1,
            deployment_id,
            binding_id: binding.id,
            binding_resource_version: binding.resource_version,
            binding_stable_id: binding.stable_id.clone(),
            binding_kind: binding.kind.clone(),
            object_bucket: binding.object_bucket.clone().unwrap_or_default(),
            object_prefix: binding.object_prefix.clone().unwrap_or_default(),
            endpoint_scheme: binding.endpoint_scheme.clone().unwrap_or_default(),
            endpoint_host_kind: binding.endpoint_host_kind.clone().unwrap_or_default(),
            endpoint_host_bytes: binding.endpoint_host_bytes.clone().unwrap_or_default(),
            endpoint_port: binding.endpoint_port,
            signing_region: binding.signing_region.clone().unwrap_or_default(),
            access_mode: binding.access_mode.clone().unwrap_or_default(),
            credentials: references,
            issued_at,
            expires_at,
        };
        snapshot
            .validate(&snapshot.deployment_id, issued_at)
            .map_err(|error| anyhow::anyhow!(error))?;
        Ok(snapshot)
    }

    /// Validates the frozen provider coordinates and credential references.
    ///
    /// # Errors
    ///
    /// Returns an error for a different deployment, malformed endpoint,
    /// duplicate credential purpose, or expired snapshot.
    pub fn validate(&self, deployment_id: &str, now: i64) -> Result<(), StorageWorkError> {
        self.validate_context(deployment_id, Some(now))
    }

    /// Checks retained binding structure without asserting current eligibility.
    ///
    /// Coordinates, credential references, deployment and the original bounded
    /// lifetime remain validated. This observation-only check grants no provider
    /// authority and establishes no freshness; execution uses [`Self::validate`].
    ///
    /// # Errors
    /// Returns an error for malformed coordinates, references, audience or lifetime.
    pub fn validate_observation_shape(&self, deployment_id: &str) -> Result<(), StorageWorkError> {
        self.validate_context(deployment_id, None)
    }

    fn validate_context(
        &self,
        deployment_id: &str,
        now: Option<i64>,
    ) -> Result<(), StorageWorkError> {
        let valid_endpoint = self.endpoint_scheme == "https"
            && match self.endpoint_host_kind.as_str() {
                "dns" => std::str::from_utf8(&self.endpoint_host_bytes).is_ok_and(|host| {
                    !host.is_empty()
                        && host.len() <= 253
                        && host
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
                }),
                "ipv4" => self.endpoint_host_bytes.len() == 4,
                "ipv6" => self.endpoint_host_bytes.len() == 16,
                _ => false,
            }
            && self
                .endpoint_port
                .is_some_and(|port| (1..=65535).contains(&port));
        let valid_credentials = self
            .credentials
            .windows(2)
            .all(|pair| pair[0].purpose < pair[1].purpose)
            && self.credentials.iter().all(|credential| {
                matches!(
                    credential.purpose.as_str(),
                    "read" | "write" | "list" | "delete" | "presign"
                ) && credential.generation > 0
                    && crate::secret_version::validate_secret_version_ref(
                        &credential.secret_version_ref,
                    )
                    .is_ok()
                    && valid_sha256_hex(&credential.fingerprint)
            });
        if self.version != 1
            || self.deployment_id.is_empty()
            || self.deployment_id.len() > 128
            || self.deployment_id.chars().any(char::is_control)
            || self.binding_id <= 0
            || self.binding_resource_version <= 0
            || self.binding_stable_id.is_empty()
            || self.binding_stable_id.len() > 128
            || self.binding_stable_id.chars().any(char::is_control)
            || !matches!(self.binding_kind.as_str(), "s3" | "r2")
            || self.object_bucket.is_empty()
            || self.object_bucket.len() > 255
            || self.object_bucket.contains('/')
            || !valid_relative_path(&self.object_bucket, false)
            || !valid_relative_path(&self.object_prefix, true)
            || !valid_endpoint
            || self.signing_region.is_empty()
            || self.signing_region.len() > 128
            || self.signing_region.chars().any(char::is_control)
            || !matches!(self.access_mode.as_str(), "public" | "private")
            || (self.access_mode == "public" && !self.credentials.is_empty())
            || !valid_credentials
        {
            return Err(StorageWorkError::InvalidSnapshot);
        }
        if self.deployment_id != deployment_id {
            return Err(StorageWorkError::DeploymentMismatch);
        }
        if now.is_some_and(|now| self.issued_at > now.saturating_add(5) || self.expires_at < now)
            || self.expires_at < self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_SNAPSHOT_LIFETIME_SECONDS
        {
            return Err(StorageWorkError::InvalidTime);
        }
        Ok(())
    }

    /// Returns the lowercase SHA-256 revision of the canonical snapshot body.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn revision(&self) -> Result<String, serde_json::Error> {
        let body = serde_json::to_vec(self)?;
        Ok(hex::encode(Sha256::digest(body)))
    }

    /// Returns the fingerprint of binding coordinates, excluding credentials and time.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn binding_spec_revision(&self) -> Result<String, serde_json::Error> {
        let body = serde_json::to_vec(&(
            &self.binding_stable_id,
            &self.binding_kind,
            &self.object_bucket,
            &self.object_prefix,
            &self.endpoint_scheme,
            &self.endpoint_host_kind,
            &self.endpoint_host_bytes,
            &self.endpoint_port,
            &self.signing_region,
            &self.access_mode,
        ))?;
        Ok(hex::encode(Sha256::digest(body)))
    }

    /// Checks that a plan uses this exact frozen snapshot and credential.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale snapshot, a mismatched binding revision,
    /// or a credential generation absent from the published snapshot.
    pub fn authorizes(
        &self,
        plan: &StorageWorkPlan,
        deployment_id: &str,
        now: i64,
    ) -> Result<(), StorageWorkError> {
        self.validate(deployment_id, now)?;
        plan.validate(deployment_id, now)?;
        let revision = self
            .revision()
            .map_err(|_| StorageWorkError::InvalidSnapshot)?;
        if plan.binding_id != self.binding_id
            || plan.binding_resource_version != self.binding_resource_version
            || plan.binding_kind != self.binding_kind
            || plan.binding_snapshot_revision.as_deref() != Some(revision.as_str())
        {
            return Err(StorageWorkError::InvalidSnapshot);
        }
        if self.access_mode == "public" {
            return if plan.credential_references.is_empty()
                && plan
                    .operation
                    .credential_purposes()
                    .iter()
                    .all(|purpose| matches!(*purpose, "read" | "list"))
            {
                Ok(())
            } else {
                Err(StorageWorkError::InvalidSnapshot)
            };
        }

        if plan.credential_references.is_empty()
            || plan.credential_references.iter().any(|selector| {
                !self.credentials.iter().any(|reference| {
                    reference.purpose == selector.purpose
                        && reference.generation == selector.generation
                })
            })
        {
            return Err(StorageWorkError::InvalidSnapshot);
        }
        Ok(())
    }
}
