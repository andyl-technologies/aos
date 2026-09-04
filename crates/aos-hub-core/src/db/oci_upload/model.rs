//! Durable data contracts for resumable OCI uploads.
//!
//! These records are shared by database transactions, Distribution request
//! handling, and bounded maintenance recovery.

use super::*;

/// Durable state for one repository-scoped blob upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciUploadRecord {
    /// Stable upload UUID-like identifier.
    pub id: String,
    /// Owning registry id.
    pub registry_id: i64,
    /// Destination repository id.
    pub repository_id: i64,
    /// Optional verified-publication owner.
    pub publication_id: Option<String>,
    /// Quota reservation recovery owner.
    pub quota_reservation_id: String,
    /// Stable authenticated writer id.
    pub writer_id: String,
    /// Authentication token/session id which opened the upload.
    pub token_id: String,
    /// Optional client-declared final digest.
    pub expected_digest: Option<Sha256Digest>,
    /// Optional client-declared exact final byte count.
    pub expected_size: Option<u64>,
    /// Frozen server-side upper bound for this blob.
    pub maximum_size: u64,
    /// Contiguous accepted byte count.
    pub uploaded_size: u64,
    /// Placement that owns every immutable staging chunk, once bytes exist.
    pub staging_placement_id: Option<i64>,
    /// Frozen placement revision used to write every staging chunk.
    pub staging_placement_resource_version: Option<i64>,
    /// Storage binding containing every immutable staging chunk.
    pub staging_binding_id: Option<i64>,
    /// Immutable binding write revision used for staging and cleanup.
    pub staging_binding_write_revision: Option<i64>,
    /// Final content digest frozen when materialization is claimed.
    pub final_digest: Option<Sha256Digest>,
    /// Placement selected for canonical blob materialization.
    pub materialization_placement_id: Option<i64>,
    /// Frozen placement revision selected for canonical materialization.
    pub materialization_placement_resource_version: Option<i64>,
    /// Storage binding selected for canonical materialization.
    pub materialization_binding_id: Option<i64>,
    /// Immutable binding write revision used for canonical materialization.
    pub materialization_binding_write_revision: Option<i64>,
    /// Resumable SHA-256 continuation state.
    pub sha256: OciSha256State,
    /// `active`, `completing`, `complete`, `cancelled`, or `failed`.
    pub state: String,
    /// Unix expiry time for nonterminal work.
    pub expires_at: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Terminal transition time.
    pub finished_at: Option<i64>,
    /// `none`, `pending`, or `complete` staging cleanup state.
    pub cleanup_state: String,
    /// Time at which every recorded staging key was confirmed absent.
    pub cleanup_finished_at: Option<i64>,
    /// Optimistic concurrency version.
    pub resource_version: i64,
}

/// Parameters for opening a bounded, durable upload session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginOciUpload {
    /// Owning registry id.
    pub registry_id: i64,
    /// Destination repository id.
    pub repository_id: i64,
    /// Optional publication which owns the upload.
    pub publication_id: Option<String>,
    /// Stable authenticated writer identity.
    pub writer_id: String,
    /// Authentication token/session identity.
    pub token_id: String,
    /// Retry identity scoped to registry and writer.
    pub idempotency_key: String,
    /// Optional client-declared final digest.
    pub expected_digest: Option<Sha256Digest>,
    /// Optional exact final size extension supplied by a client.
    pub expected_size: Option<u64>,
    /// Frozen server-side maximum accepted blob size.
    pub maximum_size: u64,
    /// Positive current Unix time.
    pub now: i64,
    /// Expiry no more than [`OCI_MAX_SESSION_SECONDS`] after `now`.
    pub expires_at: i64,
}

/// One immutable staged PATCH body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciUploadChunkRecord {
    /// Upload-local zero-based chunk ordinal.
    pub ordinal: u32,
    /// Contiguous byte offset.
    pub byte_offset: u64,
    /// Exact chunk byte size.
    pub byte_size: u64,
    /// SHA-256 digest of the staged chunk bytes.
    pub digest: Sha256Digest,
    /// Immutable staging-surface object key.
    pub staging_object_key: String,
    /// Creation time in Unix seconds.
    pub created_at: i64,
}

/// Parameters for atomically appending one immutable upload chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendOciUploadChunk {
    /// Upload id.
    pub upload_id: String,
    /// Required writer owner.
    pub writer_id: String,
    /// Required token owner.
    pub token_id: String,
    /// Expected upload version.
    pub expected_resource_version: i64,
    /// Exact placement receiving this immutable staging object.
    pub staging_placement_id: i64,
    /// Exact placement revision used for the staging write.
    pub staging_placement_resource_version: i64,
    /// Storage binding containing the frozen staging placement.
    pub staging_binding_id: i64,
    /// Immutable binding revision used by the staging write.
    pub staging_binding_write_revision: i64,
    /// Immutable chunk identity.
    pub chunk: OciUploadChunkRecord,
    /// SHA-256 state after this chunk.
    pub next_sha256: OciSha256State,
    /// Positive current Unix time.
    pub now: i64,
}

/// Result of claiming a completed byte stream for digest materialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciBlobClaimOutcome {
    /// This upload owns registry/digest materialization.
    Claimed,
    /// The immutable blob already exists and only repository linkage is needed.
    AlreadyPresent,
    /// Another upload currently owns materialization.
    InProgress,
}

/// Parameters for claiming an upload's final digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimOciUpload {
    /// Upload id.
    pub upload_id: String,
    /// Required writer owner.
    pub writer_id: String,
    /// Required token owner.
    pub token_id: String,
    /// Expected upload version.
    pub expected_resource_version: i64,
    /// Placement selected for canonical blob materialization.
    pub materialization_placement_id: i64,
    /// Exact placement revision selected for materialization.
    pub materialization_placement_resource_version: i64,
    /// Storage binding containing the materialization placement.
    pub materialization_binding_id: i64,
    /// Immutable binding revision selected for materialization.
    pub materialization_binding_write_revision: i64,
    /// Final digest computed from the resumed SHA state.
    pub digest: Sha256Digest,
    /// Positive current Unix time.
    pub now: i64,
    /// Durable completion lease expiry.
    pub lease_expires_at: i64,
}

/// One terminal upload whose immutable staging objects require reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciUploadCleanupRecord {
    /// Terminal upload identity and its frozen placement metadata.
    pub upload: OciUploadRecord,
    /// Exact immutable staging keys to delete from the frozen placement.
    pub chunks: Vec<OciUploadChunkRecord>,
}

/// Exact immutable-object and placement evidence used to finish an upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteOciUpload {
    /// Upload id.
    pub upload_id: String,
    /// Required writer owner.
    pub writer_id: String,
    /// Required token owner.
    pub token_id: String,
    /// Expected upload version in `completing` state.
    pub expected_resource_version: i64,
    /// Final digest computed from the resumed SHA state.
    pub digest: Sha256Digest,
    /// Exact final byte count.
    pub byte_size: u64,
    /// Backing logical surface-object id.
    pub surface_object_id: i64,
    /// Placement holding exact bytes.
    pub placement_id: i64,
    /// Positive current Unix time.
    pub now: i64,
}

/// Exact logical-object and placement evidence admitted immediately after a
/// successful registry writer operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciUploadedObjectEvidence {
    /// Backing logical surface-object id.
    pub surface_object_id: i64,
    /// Exact placement id.
    pub placement_id: i64,
    /// Logical object resource version.
    pub object_resource_version: i64,
    /// Placement configuration resource version.
    pub placement_resource_version: i64,
    /// Placement observation version.
    pub placement_observation_version: i64,
    /// Inventory generation assigned to this writer observation.
    pub observed_inventory_generation: i64,
    /// Strong physical etag.
    pub observed_etag: String,
    /// Physical observation time.
    pub observed_at: i64,
}

pub(super) fn row_to_oci_upload(row: &Row) -> Result<OciUploadRecord> {
    let word = |index| -> Result<u32> {
        u32::try_from(row.get::<i64>(index)?).context("persisted OCI SHA-256 word is outside u32")
    };
    let sha256 = OciSha256State {
        version: u32::try_from(row.get::<i64>(20)?)
            .context("persisted OCI SHA-256 state version is outside u32")?,
        words: [
            word(21)?,
            word(22)?,
            word(23)?,
            word(24)?,
            word(25)?,
            word(26)?,
            word(27)?,
            word(28)?,
        ],
        total_bytes: parse_size(row.get(29)?)?,
        tail_hex: row.get(30)?,
    };
    let uploaded_size = parse_size(row.get(10)?)?;
    validate_sha_progress(&sha256, uploaded_size)?;
    Ok(OciUploadRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        repository_id: row.get(2)?,
        publication_id: row.get(3)?,
        quota_reservation_id: row.get(4)?,
        writer_id: row.get(5)?,
        token_id: row.get(6)?,
        expected_digest: row
            .get::<Option<String>>(7)?
            .map(parse_digest)
            .transpose()?,
        expected_size: row.get::<Option<i64>>(8)?.map(parse_size).transpose()?,
        maximum_size: parse_size(row.get(9)?)?,
        uploaded_size,
        staging_placement_id: row.get(11)?,
        staging_placement_resource_version: row.get(12)?,
        staging_binding_id: row.get(13)?,
        staging_binding_write_revision: row.get(14)?,
        final_digest: row
            .get::<Option<String>>(15)?
            .map(parse_digest)
            .transpose()?,
        materialization_placement_id: row.get(16)?,
        materialization_placement_resource_version: row.get(17)?,
        materialization_binding_id: row.get(18)?,
        materialization_binding_write_revision: row.get(19)?,
        sha256,
        state: row.get(31)?,
        expires_at: row.get(32)?,
        created_at: row.get(33)?,
        finished_at: row.get(34)?,
        cleanup_state: row.get(35)?,
        cleanup_finished_at: row.get(36)?,
        resource_version: row.get(37)?,
    })
}

pub(super) fn row_to_oci_upload_chunk(row: &Row) -> Result<OciUploadChunkRecord> {
    Ok(OciUploadChunkRecord {
        ordinal: u32::try_from(row.get::<i64>(0)?)
            .context("persisted OCI chunk ordinal is outside u32")?,
        byte_offset: parse_size(row.get(1)?)?,
        byte_size: parse_size(row.get(2)?)?,
        digest: parse_digest(row.get(3)?)?,
        staging_object_key: row.get(4)?,
        created_at: row.get(5)?,
    })
}
