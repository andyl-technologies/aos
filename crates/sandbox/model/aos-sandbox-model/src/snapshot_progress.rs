//! Pure immutable-transfer progress comparisons and prefix commitments.
//!
//! These helpers inspect DATA only. Authenticated-range context checks and
//! private verified-byte/publication constructors remain with native issuers.
//! No returned selector, offset or digest is an authority or durability proof.

use crate::{
    InvalidSnapshotTransfer, ObjectDescriptor, ObjectDigest, SnapshotDependencyRangeV1,
    SnapshotTransferIdentityV1, SnapshotTransferManifestV1, SnapshotTransferResumeV1,
};
use sha2::{Digest as _, Sha256};

/// Selects a DATA-only replay or next contiguous chunk comparison result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotChunkProgressDataV1 {
    /// The exact chunk precedes the currently tracked next boundary.
    Replay,
    /// The exact chunk is at the currently tracked next boundary.
    Advance,
}

/// Compares immutable bytes and a contiguous DATA boundary without authenticating them.
///
/// # Errors
///
/// Returns the original chunk-integrity or skipped-boundary refusal.
pub fn compare_snapshot_chunk_progress_data_v1(
    manifest: &SnapshotTransferManifestV1,
    next_chunk: u32,
    index: u32,
    bytes: &[u8],
) -> Result<SnapshotChunkProgressDataV1, InvalidSnapshotTransfer> {
    manifest.verify_chunk(index, bytes)?;
    if index > next_chunk {
        return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
    }
    Ok(if index < next_chunk {
        SnapshotChunkProgressDataV1::Replay
    } else {
        SnapshotChunkProgressDataV1::Advance
    })
}

/// Compares one exact dependency range to its existing immutable DATA prefix.
///
/// # Errors
///
/// Returns the original overflow, identity, descriptor, gap or bound refusal.
pub fn require_dependency_range_progress_data_v1(
    identity: SnapshotTransferIdentityV1,
    descriptor: &ObjectDescriptor,
    next_offset: u64,
    request: &SnapshotDependencyRangeV1,
) -> Result<u64, InvalidSnapshotTransfer> {
    let end = request
        .offset()
        .checked_add(u64::from(request.length()))
        .ok_or(InvalidSnapshotTransfer::ChunkIntegrityMismatch)?;
    if request.identity() != identity
        || request.dependency() != descriptor
        || request.offset() != next_offset
        || end > descriptor.encoded_size()
    {
        return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch);
    }
    Ok(end)
}

/// Checks immutable resume DATA before the separate actual context-currentness checks.
///
/// # Errors
///
/// Returns the original identity, prefix commitment, length or byte-digest refusal.
pub fn require_snapshot_resume_data_v1(
    manifest: &SnapshotTransferManifestV1,
    checkpoint: SnapshotTransferResumeV1,
    staged_bytes: u64,
    staged_prefix_digest: ObjectDigest,
    staged_prefix: &[u8],
) -> Result<(), InvalidSnapshotTransfer> {
    if checkpoint.identity() != manifest.identity()
        || manifest.prefix_commitment(checkpoint.next_chunk())?
            != checkpoint.verified_prefix_digest()
        || staged_prefix.len() as u64 != staged_bytes
        || staged_prefix_commitment(manifest.identity(), checkpoint, staged_prefix)
            != staged_prefix_digest
    {
        return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
    }
    Ok(())
}

/// Computes the existing canonical staged-prefix DATA commitment.
#[must_use]
pub fn staged_prefix_commitment(
    identity: SnapshotTransferIdentityV1,
    checkpoint: SnapshotTransferResumeV1,
    staged_prefix: &[u8],
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.snapshot-transfer.staged-prefix.v1\0");
    hasher.update(identity.operation().as_bytes());
    hasher.update(identity.manifest_digest().as_bytes());
    hasher.update(identity.destination_node().as_bytes());
    hasher.update(identity.storage_domain_digest().as_bytes());
    hasher.update(identity.audience_digest().as_bytes());
    hasher.update(identity.disclosure_domain_digest().as_bytes());
    hasher.update(checkpoint.next_chunk().to_be_bytes());
    hasher.update(checkpoint.verified_prefix_digest().as_bytes());
    hasher.update((staged_prefix.len() as u64).to_be_bytes());
    hasher.update(Sha256::digest(staged_prefix));
    ObjectDigest::from_bytes(hasher.finalize().into())
}
