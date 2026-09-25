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
pub const MAX_PLAN_BYTES: usize = 1024 * 1024;
// Provider multipart tags are opaque and can exceed an MD5-sized ETag.
const MAX_MULTIPART_PART_ETAG_BYTES: usize = 1024;
/// Maximum semantic response size sent back to Native.
pub const MAX_RESULT_BYTES: usize = 256 * 1024;
/// Maximum full-object verification size in the streaming R2 executor.
pub const MAX_VERIFY_SOURCE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Maximum decoded Git object content returned by one storage-local inspection.
pub const MAX_GIT_INSPECTION_CONTENT_BYTES: usize = 128 * 1024;
/// Maximum Git objects admitted in one storage-local inspection plan.
pub const MAX_GIT_INSPECTION_BATCH: usize = 8;
/// Maximum signed registry metadata returned across the cloud boundary.
pub const MAX_METADATA_BYTES: usize = 128 * 1024;
/// Maximum OCI blob range returned for legacy layer metadata inspection.
pub const MAX_OCI_RANGE_BYTES: usize = 128 * 1024;
/// Maximum OCI bytes hashed beside storage in one resumable inventory step.
pub const MAX_OCI_HASH_RANGE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum staged chunks admitted in one storage-local OCI composition.
pub const MAX_OCI_COMPOSE_CHUNKS: usize = 4096;
/// Maximum canonical OCI blob accepted by the Hub upload contract.
pub const MAX_OCI_COMPOSE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Maximum documentation index fields returned in one storage work page.
pub const MAX_DOCUMENTATION_PAGE_BYTES: usize = 128 * 1024;
/// Maximum rows admitted from one canonical package document.
pub const MAX_DOCUMENTATION_ROWS: usize = 100_000;

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

/// One frozen staged object consumed by an OCI blob composition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageOciChunkSource {
    /// Surface-relative key written during the upload session.
    pub path: String,
    /// Exact SQL-committed length of this staging object.
    pub size: u64,
    /// Lowercase SHA-256 of the complete staged object.
    pub sha256: String,
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
    /// Extracts one Git object from its fixed shard or canonical loose path.
    InspectGitObject {
        /// Lowercase SHA-256 Git object identifier.
        oid: String,
    },
    /// Extracts a bounded ordered batch of Git objects beside storage.
    InspectGitObjects {
        /// Strictly increasing canonical SHA-256 Git object identifiers.
        oids: Vec<String>,
    },
    /// Reads one bounded signed registry metadata document beside storage.
    InspectMetadata {
        /// Surface-relative metadata path from the closed admitted set.
        path: String,
    },
    /// Verifies a signed documentation NAR and returns only index fields.
    InspectDocumentation {
        /// Exact package name from the signed release manifest.
        package_name: String,
        /// Exact package version from the signed release manifest.
        package_version: String,
        /// Exact platform from the signed release manifest.
        platform: String,
        /// Signed immutable NAR and document identity.
        artifact: aos_registry_surface::manifest::DocumentationArtifactMeta,
        /// Zero-based position in the deterministic search-then-option rows.
        cursor: usize,
    },
    /// Reads one bounded range from a canonical OCI content-addressed blob.
    InspectOciRange {
        /// Canonical OCI blob key.
        path: String,
        /// Inclusive first byte.
        start: u64,
        /// Inclusive last byte.
        end: u64,
    },
    /// Advances a portable OCI inventory hash without returning object bytes.
    HashOciRange {
        /// Canonical OCI blob key.
        path: String,
        /// Inclusive first byte, equal to the prior hash state's byte count.
        start: u64,
        /// Inclusive last byte in this bounded step.
        end: u64,
        /// Frozen full object length from the inventory continuation.
        total: u64,
        /// Frozen strong provider tag from the inventory continuation.
        strong_etag: String,
        /// Portable SHA-256 state after exactly `start` bytes.
        sha256_state: crate::db::OciSha256State,
    },
    /// Copies one frozen object between prefixes in the deployment R2 bucket.
    CopyObject {
        /// Source placement frozen by the reviewed copy operation.
        source_placement_id: i64,
        /// Source placement resource version frozen by the copy operation.
        source_placement_resource_version: i64,
        /// Source placement prefix in the same R2 binding.
        source_prefix: String,
        /// Surface-relative object path in both placements.
        path: String,
        /// Listed source size that the Worker must observe on the body snapshot.
        expected_size: u64,
        /// Listed source strong ETag that the Worker must observe.
        expected_etag: String,
    },
    /// Assembles SQL-frozen OCI chunks into one content-addressed R2 blob.
    ComposeOciBlob {
        /// Canonical destination OCI blob path within the selected placement.
        path: String,
        /// Prefix of the frozen staging placement in the same R2 binding.
        staging_prefix: String,
        /// Ordered chunks from the claimed upload session.
        chunks: Vec<StorageOciChunkSource>,
        /// Expected length of the canonical blob.
        expected_size: u64,
        /// Lowercase expected SHA-256 of the assembled blob.
        expected_sha256: String,
    },
    /// Removes one terminal OCI upload chunk from its frozen R2 placement.
    DeleteOciStaging {
        /// Exact surface-relative staging key recorded in the upload session.
        path: String,
    },
    /// Creates one provider multipart upload for a SQL-frozen object path.
    CreateMultipart {
        /// Surface-relative object path selected by Native.
        path: String,
    },
    /// Completes one provider multipart upload using exact durable part tags.
    CompleteMultipart {
        /// Surface-relative object path selected by Native.
        path: String,
        /// Opaque provider upload identity recorded by Native SQL.
        upload_id: String,
        /// Contiguous provider part tags admitted by Native SQL.
        parts: Vec<crate::surface_write::PartTag>,
    },
    /// Aborts one provider multipart upload without deleting a completed object.
    AbortMultipart {
        /// Surface-relative object path selected by Native.
        path: String,
        /// Opaque provider upload identity recorded by Native SQL.
        upload_id: String,
    },
}

impl StorageWorkOperation {
    /// Names the operation for capability checks and boundary measurements.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Head { .. } => "head",
            Self::ListPage { .. } => "list_page",
            Self::InspectSha256 { .. } => "inspect_sha256",
            Self::InspectGitObject { .. } => "inspect_git_object",
            Self::InspectGitObjects { .. } => "inspect_git_objects",
            Self::InspectMetadata { .. } => "inspect_metadata",
            Self::InspectDocumentation { .. } => "inspect_documentation",
            Self::InspectOciRange { .. } => "inspect_oci_range",
            Self::HashOciRange { .. } => "hash_oci_range",
            Self::CopyObject { .. } => "copy_object",
            Self::ComposeOciBlob { .. } => "compose_oci_blob",
            Self::DeleteOciStaging { .. } => "delete_oci_staging",
            Self::CreateMultipart { .. } => "create_multipart",
            Self::CompleteMultipart { .. } => "complete_multipart",
            Self::AbortMultipart { .. } => "abort_multipart",
        }
    }
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

/// One hash-checked Git object decoded beside a storage placement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageGitObjectProjection {
    /// Source bundle shard or loose object snapshot.
    pub source: StorageObjectIdentity,
    /// Requested SHA-256 Git object identifier.
    pub oid: String,
    /// Git object kind (`commit`, `tree`, `tag`, or `blob`).
    pub object_kind: String,
    /// Standard-base64 decoded Git object content.
    pub content_base64: String,
}

/// One bounded page of fields derived from a verified documentation NAR.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageDocumentationPage {
    /// Artifact identities repeated inside the canonical documentation.
    pub identity: aos_doc_model::DocumentationIdentity,
    /// Search rows in deterministic document order.
    pub search: Vec<aos_doc_model::SearchDocument>,
    /// Option rows following all search rows.
    pub options: Vec<crate::fetch::DocumentationOptionInspection>,
    /// Total rows in the complete verified projection.
    pub total_rows: usize,
    /// Next row position, absent when this is the final page.
    pub next_cursor: Option<usize>,
}

impl StorageDocumentationPage {
    /// Selects one bounded page from a complete verified projection.
    ///
    /// # Errors
    ///
    /// Returns an error for a cursor outside the projection, excessive row
    /// count, or an individual row larger than the page budget.
    pub fn from_inspection(
        inspection: &crate::fetch::DocumentationInspection,
        cursor: usize,
    ) -> anyhow::Result<Self> {
        let total_rows = inspection
            .search
            .len()
            .checked_add(inspection.options.len())
            .ok_or_else(|| anyhow::anyhow!("documentation row count overflowed"))?;
        anyhow::ensure!(
            total_rows <= MAX_DOCUMENTATION_ROWS
                && cursor <= total_rows
                && (cursor == 0 || cursor < total_rows),
            "documentation page cursor or row count is invalid"
        );

        let mut page = Self {
            identity: inspection.identity.clone(),
            search: Vec::new(),
            options: Vec::new(),
            total_rows,
            next_cursor: None,
        };
        let mut used_bytes = serde_json::to_vec(&page.identity)?.len() + 256;
        for position in cursor..total_rows {
            let row_bytes = if position < inspection.search.len() {
                serde_json::to_vec(&inspection.search[position])?.len()
            } else {
                serde_json::to_vec(&inspection.options[position - inspection.search.len()])?.len()
            };
            let next_bytes = used_bytes
                .checked_add(row_bytes + 4)
                .ok_or_else(|| anyhow::anyhow!("documentation page size overflowed"))?;
            if next_bytes > MAX_DOCUMENTATION_PAGE_BYTES {
                break;
            }
            if position < inspection.search.len() {
                page.search.push(inspection.search[position].clone());
            } else {
                page.options
                    .push(inspection.options[position - inspection.search.len()].clone());
            }
            used_bytes = next_bytes;
        }
        let returned = page.search.len() + page.options.len();
        anyhow::ensure!(
            returned > 0 || total_rows == 0,
            "documentation row exceeds the page budget"
        );
        let end = cursor + returned;
        page.next_cursor = (end < total_rows).then_some(end);
        Ok(page)
    }
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
    /// One decoded and hash-checked Git object extracted beside storage.
    GitObject {
        /// Source bundle shard or loose object snapshot.
        source: StorageObjectIdentity,
        /// Requested Git object identifier.
        oid: String,
        /// Git object kind (`commit`, `tree`, `tag`, or `blob`).
        object_kind: String,
        /// Standard-base64 decoded Git object content.
        content_base64: String,
    },
    /// Ordered Git projections for one bounded batch plan.
    GitObjects {
        /// One result for every requested OID, in request order.
        objects: Vec<StorageGitObjectProjection>,
    },
    /// One bounded registry metadata document observed on an exact R2 snapshot.
    Metadata {
        /// Source object identity.
        source: StorageObjectIdentity,
        /// Standard-base64 exact document bytes.
        content_base64: String,
    },
    /// Verified documentation identity and bounded index fields.
    Documentation {
        /// Fields parsed beside the selected storage placement.
        page: StorageDocumentationPage,
    },
    /// One exact bounded OCI range from a versioned object snapshot.
    OciRange {
        /// Source OCI blob identity and its total size.
        source: StorageObjectIdentity,
        /// Inclusive first and last bytes returned.
        start: u64,
        end: u64,
        /// Standard-base64 exact range bytes.
        content_base64: String,
    },
    /// Portable hash state after one exact R2 range, with its provider identity.
    OciRangeHashed {
        /// Source object identity observed during the ranged read.
        source: StorageObjectIdentity,
        /// Inclusive first byte hashed.
        start: u64,
        /// Inclusive last byte hashed.
        end: u64,
        /// SHA-256 state after the exact range.
        sha256_state: crate::db::OciSha256State,
    },
    /// Provider identities after a storage-local object copy.
    ObjectCopied {
        /// Source snapshot that supplied the bytes.
        source: StorageObjectIdentity,
        /// Destination object observed after the copy.
        destination: StorageObjectIdentity,
    },
    /// Canonical blob acknowledged by R2 after storage-local assembly.
    OciBlobComposed {
        /// Physical object identity observed after multipart completion.
        object: StorageObjectIdentity,
        /// Lowercase SHA-256 of the staged bytes fed into multipart.
        sha256: String,
    },
    /// R2 acknowledged idempotent removal of one unreachable staging object.
    OciStagingDeleted,
    /// R2 accepted a new multipart upload and returned its opaque identity.
    MultipartCreated {
        /// Opaque provider upload identity to persist in Native SQL.
        upload_id: String,
    },
    /// R2 completed a multipart upload and exposed the resulting object.
    MultipartCompleted {
        /// Physical object identity observed after completion.
        object: StorageObjectIdentity,
    },
    /// R2 reported the significance of aborting an upload identity.
    MultipartAborted {
        /// Whether staging was removed, absent, or possibly already completed.
        outcome: crate::surface_write::MultipartAbortOutcome,
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
            StorageWorkOperation::InspectGitObject { oid } => {
                if !valid_git_oid(oid) {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
            StorageWorkOperation::InspectGitObjects { oids } => {
                if oids.is_empty()
                    || oids.len() > MAX_GIT_INSPECTION_BATCH
                    || oids.iter().any(|oid| !valid_git_oid(oid))
                    || oids.windows(2).any(|pair| pair[0] >= pair[1])
                {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
            StorageWorkOperation::InspectMetadata { path } => {
                if !valid_relative_path(path, false) || !admitted_metadata_path(path) {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
            StorageWorkOperation::InspectDocumentation {
                package_name,
                package_version,
                platform,
                artifact,
                cursor,
            } => {
                let valid_selection =
                    [package_name, package_version, platform]
                        .iter()
                        .all(|value| {
                            !value.is_empty()
                                && value.len() <= 255
                                && !value.chars().any(char::is_control)
                        });
                let valid_artifact = artifact.format == aos_doc_model::DOCUMENT_FORMAT
                    && aos_registry_surface::store::store_path_hash(&artifact.store_path).is_ok()
                    && aos_registry_surface::store::normalize_digest(&artifact.nar_hash).is_ok()
                    && aos_registry_surface::store::normalize_digest(&artifact.document_sha256)
                        .is_ok()
                    && aos_registry_surface::store::normalize_digest(
                        &artifact.semantic_schema_sha256,
                    )
                    .is_ok()
                    && artifact.references.is_empty()
                    && artifact.nar_size > 0
                    && artifact.nar_size <= (aos_doc_model::MAX_DOCUMENT_BYTES + 512) as u64
                    && artifact.document_size > 0
                    && artifact.document_size <= aos_doc_model::MAX_DOCUMENT_BYTES as u64;
                if !valid_selection || !valid_artifact || *cursor > MAX_DOCUMENTATION_ROWS {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
            StorageWorkOperation::InspectOciRange { path, start, end } => {
                if !admitted_oci_blob_path(path)
                    || start > end
                    || end.saturating_sub(*start).saturating_add(1) > MAX_OCI_RANGE_BYTES as u64
                {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
            StorageWorkOperation::HashOciRange {
                path,
                start,
                end,
                total,
                strong_etag,
                sha256_state,
            } => {
                if !admitted_oci_blob_path(path)
                    || start > end
                    || *end >= *total
                    || end.saturating_sub(*start).saturating_add(1)
                        > MAX_OCI_HASH_RANGE_BYTES as u64
                    || sha256_state.validate().is_err()
                    || sha256_state.total_bytes != *start
                    || crate::surface_write::strong_if_match_etag(strong_etag).is_err()
                {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
            StorageWorkOperation::CopyObject {
                source_placement_id,
                source_placement_resource_version,
                source_prefix,
                path,
                expected_size,
                expected_etag,
            } => {
                if *source_placement_id <= 0
                    || *source_placement_id == self.placement_id
                    || *source_placement_resource_version <= 0
                    || !valid_relative_path(source_prefix, true)
                    || source_prefix.trim_end_matches('/')
                        == self.placement_prefix.trim_end_matches('/')
                    || !valid_relative_path(path, false)
                    || *expected_size > MAX_VERIFY_SOURCE_BYTES
                    || crate::surface_write::strong_if_match_etag(expected_etag).is_err()
                {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
            StorageWorkOperation::ComposeOciBlob {
                path,
                staging_prefix,
                chunks,
                expected_size,
                expected_sha256,
            } => {
                let staged_size = chunks
                    .iter()
                    .try_fold(0_u64, |sum, chunk| sum.checked_add(chunk.size));
                if !admitted_oci_blob_path(path)
                    || !valid_relative_path(staging_prefix, true)
                    || chunks.len() > MAX_OCI_COMPOSE_CHUNKS
                    || *expected_size > MAX_OCI_COMPOSE_BYTES
                    || staged_size != Some(*expected_size)
                    || path.strip_prefix("oci/blobs/sha256/") != Some(expected_sha256.as_str())
                    || chunks.iter().any(|chunk| {
                        !valid_relative_path(&chunk.path, false)
                            || !chunk.path.starts_with("oci/uploads/")
                            || !chunk.path.contains("/chunks/")
                            || chunk.size == 0
                            || chunk.size > crate::hybrid_ingress::MAX_HYBRID_OCI_CHUNK_BYTES as u64
                            || !valid_sha256_hex(&chunk.sha256)
                    })
                {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
            StorageWorkOperation::DeleteOciStaging { path } => {
                if !valid_relative_path(path, false)
                    || !path.starts_with("oci/uploads/")
                    || !path.contains("/chunks/")
                {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
            StorageWorkOperation::CreateMultipart { path } => {
                if !valid_relative_path(path, false) {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
            StorageWorkOperation::CompleteMultipart {
                path,
                upload_id,
                parts,
            } => {
                if !valid_relative_path(path, false)
                    || !valid_multipart_upload_id(upload_id)
                    || parts.is_empty()
                    || parts.len() > 10_000
                    || parts.iter().enumerate().any(|(index, part)| {
                        part.part_number as usize != index + 1
                            || part.etag.len() > MAX_MULTIPART_PART_ETAG_BYTES
                            || crate::surface_write::strong_if_match_etag(&part.etag).is_err()
                    })
                {
                    return Err(StorageWorkError::InvalidPlan);
                }
            }
            StorageWorkOperation::AbortMultipart { path, upload_id } => {
                if !valid_relative_path(path, false) || !valid_multipart_upload_id(upload_id) {
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

/// Reports whether a path can cross the hybrid boundary as bounded metadata.
#[must_use]
pub fn admitted_metadata_path(path: &str) -> bool {
    matches!(path, "HEAD" | "info/refs" | "objects/info/packs")
        || path.starts_with("channels/")
        || path.starts_with("releases/")
        || path.strip_suffix(".narinfo").is_some_and(|hash| {
            hash.len() >= 2
                && hash
                    .bytes()
                    .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
        })
        || admitted_oci_blob_path(path)
}

/// Reports whether a path is one canonical SHA-256 OCI blob key.
#[must_use]
pub fn admitted_oci_blob_path(path: &str) -> bool {
    path.strip_prefix("oci/blobs/sha256/")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
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

/// Provider upload IDs are opaque, but must remain bounded and printable on the wire.
fn valid_multipart_upload_id(upload_id: &str) -> bool {
    !upload_id.is_empty()
        && upload_id.len() <= 1024
        && upload_id
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
}

fn valid_git_oid(oid: &str) -> bool {
    valid_sha256_hex(oid)
}

fn valid_sha256_hex(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

    #[test]
    fn git_inspection_requires_a_canonical_sha256_oid() {
        let mut work = plan(100);
        work.operation = StorageWorkOperation::InspectGitObject {
            oid: "a".repeat(64),
        };
        assert!(work.validate("deployment-1", 101).is_ok());
        work.operation = StorageWorkOperation::InspectGitObject {
            oid: "A".repeat(64),
        };
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
    }

    #[test]
    fn git_batch_requires_sorted_unique_bounded_oids() {
        let mut work = plan(100);
        work.operation = StorageWorkOperation::InspectGitObjects {
            oids: vec!["a".repeat(64), "b".repeat(64)],
        };
        assert!(work.validate("deployment-1", 101).is_ok());
        work.operation = StorageWorkOperation::InspectGitObjects {
            oids: vec!["b".repeat(64), "a".repeat(64)],
        };
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
        work.operation = StorageWorkOperation::InspectGitObjects {
            oids: vec!["a".repeat(64); MAX_GIT_INSPECTION_BATCH + 1],
        };
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
    }

    #[test]
    fn oci_composition_binds_canonical_destination_and_staged_chunks() {
        let mut work = plan(100);
        let digest = "a".repeat(64);
        let chunk = StorageOciChunkSource {
            path: "oci/uploads/session/chunks/0-attempt".into(),
            size: 4,
            sha256: "b".repeat(64),
        };
        work.operation = StorageWorkOperation::ComposeOciBlob {
            path: format!("oci/blobs/sha256/{digest}"),
            staging_prefix: "staging/registry".into(),
            chunks: vec![chunk.clone()],
            expected_size: 4,
            expected_sha256: digest.clone(),
        };
        assert!(work.validate("deployment-1", 101).is_ok());
        let encoded = serde_json::to_vec(&work).unwrap();
        let decoded: StorageWorkPlan = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, work);

        if let StorageWorkOperation::ComposeOciBlob { expected_size, .. } = &mut work.operation {
            *expected_size = 5;
        }
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
        if let StorageWorkOperation::ComposeOciBlob {
            expected_size,
            chunks,
            ..
        } = &mut work.operation
        {
            *expected_size = 4;
            chunks[0].path = "../outside".into();
        }
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
        if let StorageWorkOperation::ComposeOciBlob {
            chunks,
            expected_sha256,
            ..
        } = &mut work.operation
        {
            chunks[0] = chunk;
            *expected_sha256 = "c".repeat(64);
        }
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
    }

    #[test]
    fn oci_staging_delete_cannot_select_a_canonical_blob() {
        let mut work = plan(100);
        work.operation = StorageWorkOperation::DeleteOciStaging {
            path: "oci/uploads/session/chunks/0-attempt".into(),
        };
        assert!(work.validate("deployment-1", 101).is_ok());

        for path in [
            "oci/blobs/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "oci/uploads/session/metadata",
            "oci/uploads/../other/chunks/0-attempt",
        ] {
            work.operation = StorageWorkOperation::DeleteOciStaging { path: path.into() };
            assert_eq!(
                work.validate("deployment-1", 101),
                Err(StorageWorkError::InvalidPlan),
                "{path}"
            );
        }
    }

    #[test]
    fn multipart_completion_requires_one_bounded_contiguous_manifest() {
        let mut work = plan(100);
        work.operation = StorageWorkOperation::CompleteMultipart {
            path: "objects/archive.nar".into(),
            upload_id: "r2-upload-1".into(),
            parts: vec![
                crate::surface_write::PartTag {
                    part_number: 1,
                    etag: "a".repeat(32),
                },
                crate::surface_write::PartTag {
                    part_number: 2,
                    etag: "b".repeat(32),
                },
            ],
        };
        assert!(work.validate("deployment-1", 101).is_ok());
        let encoded = serde_json::to_vec(&work).unwrap();
        let decoded: StorageWorkPlan = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, work);

        if let StorageWorkOperation::CompleteMultipart { parts, .. } = &mut work.operation {
            parts[0].etag = "a".repeat(192);
        }
        assert!(work.validate("deployment-1", 101).is_ok());
        if let StorageWorkOperation::CompleteMultipart { parts, .. } = &mut work.operation {
            parts[0].etag = "a".repeat(MAX_MULTIPART_PART_ETAG_BYTES + 1);
        }
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );

        if let StorageWorkOperation::CompleteMultipart { parts, .. } = &mut work.operation {
            parts[0].etag = "a".repeat(32);
            parts[1].part_number = 3;
        }
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
        if let StorageWorkOperation::CompleteMultipart {
            upload_id, parts, ..
        } = &mut work.operation
        {
            parts[1].part_number = 2;
            *upload_id = "bad\nidentity".into();
        }
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
    }

    #[test]
    fn metadata_inspection_excludes_bulk_object_paths() {
        let mut work = plan(100);
        for path in [
            "HEAD",
            "info/refs",
            "channels/stable/00",
            "abcdf.narinfo",
            "oci/blobs/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            work.operation = StorageWorkOperation::InspectMetadata { path: path.into() };
            assert!(work.validate("deployment-1", 101).is_ok(), "{path}");
        }
        for path in [
            "nar/large.nar",
            "images/disk.qcow2",
            "objects/ab/1234",
            "bad-store-hash.narinfo",
            "oci/blobs/sha256/not-a-digest",
        ] {
            work.operation = StorageWorkOperation::InspectMetadata { path: path.into() };
            assert_eq!(
                work.validate("deployment-1", 101),
                Err(StorageWorkError::InvalidPlan),
                "{path}"
            );
        }
    }

    #[test]
    fn documentation_inspection_requires_one_bounded_signed_artifact() {
        let mut work = plan(100);
        let mut artifact = aos_registry_surface::manifest::DocumentationArtifactMeta {
            format: aos_doc_model::DOCUMENT_FORMAT.into(),
            store_path: "/nix/store/abcdf-package-docs".into(),
            nar_hash: format!("sha256:{}", "a".repeat(64)),
            nar_size: 1024,
            document_sha256: format!("sha256:{}", "b".repeat(64)),
            document_size: 512,
            semantic_schema_sha256: format!("sha256:{}", "c".repeat(64)),
            system_module_nar_hash: None,
            references: Vec::new(),
        };
        work.operation = StorageWorkOperation::InspectDocumentation {
            package_name: "example".into(),
            package_version: "1.0.0".into(),
            platform: "x86_64-linux".into(),
            artifact: artifact.clone(),
            cursor: 0,
        };
        assert!(work.validate("deployment-1", 101).is_ok());

        artifact.nar_size = (aos_doc_model::MAX_DOCUMENT_BYTES + 513) as u64;
        work.operation = StorageWorkOperation::InspectDocumentation {
            package_name: "example".into(),
            package_version: "1.0.0".into(),
            platform: "x86_64-linux".into(),
            artifact,
            cursor: 0,
        };
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
    }

    #[test]
    fn documentation_pages_cover_large_projections_without_bulk_results() {
        let inspection = crate::fetch::DocumentationInspection {
            identity: aos_doc_model::DocumentationIdentity {
                semantic_schema_sha256: format!("sha256:{}", "a".repeat(64)),
                runtime_nar_hash: format!("sha256:{}", "b".repeat(64)),
                config_module_nar_hash: None,
                system_module_nar_hash: None,
                expose_artifact_nar_hash: None,
                source_nar_hash: format!("sha256:{}", "c".repeat(64)),
            },
            search: (0..200)
                .map(|index| aos_doc_model::SearchDocument {
                    kind: "option".into(),
                    key: format!("option-{index}"),
                    title: format!("Option {index}"),
                    summary: "x".repeat(1024),
                    terms: std::collections::BTreeMap::new(),
                })
                .collect(),
            options: vec![crate::fetch::DocumentationOptionInspection {
                key: "services.example.enable".into(),
                path: vec![aos_doc_model::PathSegment::Literal {
                    value: "services".into(),
                }],
                type_signature: "bool".into(),
            }],
        };

        let mut cursor = 0;
        let mut rows = 0;
        let mut pages = 0;
        let mut search_keys = Vec::new();
        let mut option_keys = Vec::new();
        loop {
            let page = StorageDocumentationPage::from_inspection(&inspection, cursor).unwrap();
            assert!(serde_json::to_vec(&page).unwrap().len() < MAX_RESULT_BYTES);
            rows += page.search.len() + page.options.len();
            search_keys.extend(page.search.iter().map(|row| row.key.clone()));
            option_keys.extend(page.options.iter().map(|row| row.key.clone()));
            pages += 1;
            match page.next_cursor {
                Some(next) => cursor = next,
                None => break,
            }
        }
        assert!(pages > 1);
        assert_eq!(rows, inspection.search.len() + inspection.options.len());
        assert_eq!(
            search_keys,
            inspection
                .search
                .iter()
                .map(|row| row.key.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(option_keys, vec!["services.example.enable"]);
        assert!(StorageDocumentationPage::from_inspection(&inspection, rows).is_err());
    }

    #[test]
    fn oci_range_inspection_is_canonical_and_bounded() {
        let mut work = plan(100);
        let path = format!("oci/blobs/sha256/{}", "a".repeat(64));
        work.operation = StorageWorkOperation::InspectOciRange {
            path: path.clone(),
            start: 3,
            end: 6,
        };
        assert!(work.validate("deployment-1", 101).is_ok());

        work.operation = StorageWorkOperation::InspectOciRange {
            path: path.replace('a', "A"),
            start: 3,
            end: 6,
        };
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
        work.operation = StorageWorkOperation::InspectOciRange {
            path,
            start: 3,
            end: 3 + MAX_OCI_RANGE_BYTES as u64,
        };
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
    }

    #[test]
    fn oci_inventory_hash_plan_binds_state_range_and_object_identity() {
        let mut work = plan(100);
        let path = format!("oci/blobs/sha256/{}", "a".repeat(64));
        work.operation = StorageWorkOperation::HashOciRange {
            path,
            start: 0,
            end: 3,
            total: 4,
            strong_etag: "\"object-version\"".into(),
            sha256_state: crate::db::OciSha256State::initial(),
        };
        assert!(work.validate("deployment-1", 101).is_ok());

        if let StorageWorkOperation::HashOciRange { start, .. } = &mut work.operation {
            *start = 1;
        }
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
        if let StorageWorkOperation::HashOciRange {
            start,
            sha256_state,
            ..
        } = &mut work.operation
        {
            *start = 0;
            sha256_state.update(b"x").unwrap();
        }
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
    }

    #[test]
    fn placement_copy_plan_rejects_the_destination_as_its_source() {
        let mut work = plan(100);
        work.operation = StorageWorkOperation::CopyObject {
            source_placement_id: 11,
            source_placement_resource_version: 3,
            source_prefix: "tenant/source/".into(),
            path: "web/object.bin".into(),
            expected_size: 10,
            expected_etag: "\"source-version\"".into(),
        };
        assert!(work.validate("deployment-1", 101).is_ok());

        let destination_prefix = work.placement_prefix.clone();
        if let StorageWorkOperation::CopyObject { source_prefix, .. } = &mut work.operation {
            *source_prefix = destination_prefix;
        }
        assert_eq!(
            work.validate("deployment-1", 101),
            Err(StorageWorkError::InvalidPlan)
        );
    }
}
