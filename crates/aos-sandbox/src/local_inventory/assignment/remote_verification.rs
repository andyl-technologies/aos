//! Selected streaming verification of authenticated cross-node snapshot bytes.
//!
//! These reducers construct the existing private-field verified receipts only
//! after contiguous authenticated bytes satisfy the manifest and digest checks.
//! Shared snapshot models, checkpoints, receipt types and local history
//! validation remain in the parent module and are not feature-gated.

use aos_sandbox_core::{ObjectDescriptor, ObjectDigest, PortableMediaType};
use sha2::{Digest as _, Sha256};

use super::{
    AuthenticatedSnapshotChunkV1, AuthenticatedSnapshotDependencyRangeV1,
    DurableSnapshotTransferCheckpointV1, InvalidSnapshotTransfer, SnapshotTransferIdentityV1,
    SnapshotTransferManifestV1, SnapshotTransferResumeV1, VerifiedSnapshotDependencyV1,
    VerifiedStagedSnapshotV1, is_inert_transfer_dependency, staged_prefix_commitment,
};

/// Hashes contiguous authenticated dependency ranges without trusting metadata.
#[derive(Clone, Debug)]
pub struct SnapshotDependencyReducerV1 {
    identity: SnapshotTransferIdentityV1,
    descriptor: ObjectDescriptor,
    next_offset: u64,
    hasher: Sha256,
}

impl SnapshotDependencyReducerV1 {
    /// Starts verification for one exact manifest dependency.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::DependenciesNotCanonical`] for an
    /// unknown dependency index.
    pub fn new(
        manifest: &SnapshotTransferManifestV1,
        dependency_index: u32,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let descriptor = manifest
            .dependencies()
            .get(
                usize::try_from(dependency_index)
                    .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?,
            )
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?
            .clone();
        Ok(Self {
            identity: manifest.identity(),
            descriptor,
            next_offset: 0,
            hasher: Sha256::new(),
        })
    }

    /// Applies one exact contiguous authenticated range.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::ChunkIntegrityMismatch`] for another
    /// transfer or dependency, a gap, replay, overflow, or out-of-bounds bytes.
    pub fn apply_range(
        &mut self,
        range: AuthenticatedSnapshotDependencyRangeV1,
        coordinator_unix_seconds: u64,
    ) -> Result<(), InvalidSnapshotTransfer> {
        let request = range.request();
        let end = request
            .offset()
            .checked_add(u64::from(request.length()))
            .ok_or(InvalidSnapshotTransfer::ChunkIntegrityMismatch)?;
        if request.identity() != self.identity
            || request.dependency() != &self.descriptor
            || request.offset() != self.next_offset
            || end > self.descriptor.encoded_size()
            || !range.context().is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch);
        }
        self.hasher.update(range.bytes());
        self.next_offset = end;
        Ok(())
    }

    /// Finishes only after actual authenticated bytes match the descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] unless all bytes arrived and their
    /// streaming SHA-256 digest matches the immutable descriptor.
    pub fn finish(self) -> Result<VerifiedSnapshotDependencyV1, InvalidSnapshotTransfer> {
        let media_type = PortableMediaType::parse(self.descriptor.media_type().as_str())
            .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        if !is_inert_transfer_dependency(media_type) {
            return Err(InvalidSnapshotTransfer::AuthorityBearingDependency);
        }
        if self.next_offset != self.descriptor.encoded_size()
            || ObjectDigest::from_bytes(self.hasher.finalize().into()) != self.descriptor.digest()
        {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch);
        }
        Ok(VerifiedSnapshotDependencyV1 {
            identity: self.identity,
            descriptor: self.descriptor,
        })
    }
}

/// Reports a sequential immutable chunk reduction result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotTransferApplyOutcomeV1 {
    /// A newly verified chunk advanced the in-memory verified boundary.
    Applied(SnapshotTransferResumeV1),
    /// An already verified committed chunk was replayed exactly.
    Replay(SnapshotTransferResumeV1),
}

/// Reduces bounded immutable chunk bytes into a resumable verified prefix.
#[derive(Clone, Debug)]
pub struct SnapshotTransferReducerV1 {
    manifest: SnapshotTransferManifestV1,
    next_chunk: u32,
    verified_bytes: u64,
    root_hasher: Sha256,
}

impl SnapshotTransferReducerV1 {
    /// Starts one transfer at the beginning of its validated manifest.
    #[must_use]
    pub fn new(manifest: SnapshotTransferManifestV1) -> Self {
        Self {
            manifest,
            next_chunk: 0,
            verified_bytes: 0,
            root_hasher: Sha256::new(),
        }
    }

    /// Resumes only after re-verifying the exact durably staged byte prefix.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] when the checkpoint, staged length,
    /// any chunk digest, or the canonical prefix commitment differs.
    pub fn resume_from_staged_prefix(
        manifest: SnapshotTransferManifestV1,
        durable_checkpoint: DurableSnapshotTransferCheckpointV1,
        staged_prefix: &[u8],
        coordinator_unix_seconds: u64,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let checkpoint = durable_checkpoint.resume();
        if checkpoint.identity() != manifest.identity()
            || manifest.prefix_commitment(checkpoint.next_chunk())?
                != checkpoint.verified_prefix_digest()
            || staged_prefix.len() as u64 != durable_checkpoint.staged_bytes()
            || staged_prefix_commitment(manifest.identity(), checkpoint, staged_prefix)
                != durable_checkpoint.staged_prefix_digest()
            || !durable_checkpoint
                .evidence_context()
                .is_current_at(coordinator_unix_seconds)
            || !durable_checkpoint
                .journal_record()
                .context()
                .is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
        }
        let boundary = usize::try_from(checkpoint.next_chunk())
            .map_err(|_| InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let chunks = manifest
            .chunks()
            .get(..boundary)
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let expected_bytes = chunks.iter().try_fold(0_usize, |total, chunk| {
            total
                .checked_add(chunk.length() as usize)
                .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)
        })?;
        if staged_prefix.len() != expected_bytes {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
        }

        let mut root_hasher = Sha256::new();
        let mut offset = 0_usize;
        for chunk in chunks {
            let end = offset
                .checked_add(chunk.length() as usize)
                .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
            let bytes = staged_prefix
                .get(offset..end)
                .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
            chunk.verify_bytes(bytes)?;
            root_hasher.update(bytes);
            offset = end;
        }
        Ok(Self {
            manifest,
            next_chunk: checkpoint.next_chunk(),
            verified_bytes: expected_bytes as u64,
            root_hasher,
        })
    }

    /// Returns the immutable manifest being reduced.
    #[must_use]
    pub const fn manifest(&self) -> &SnapshotTransferManifestV1 {
        &self.manifest
    }

    /// Returns the current integrity-bound in-memory resume position.
    ///
    /// Resumption still requires a [`DurableSnapshotTransferCheckpointV1`]
    /// issued after exact staged bytes and a committed journal record agree.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::InvalidResumeCheckpoint`] only if
    /// internal state is inconsistent with the immutable manifest.
    pub fn checkpoint(&self) -> Result<SnapshotTransferResumeV1, InvalidSnapshotTransfer> {
        SnapshotTransferResumeV1::new(&self.manifest, self.manifest.identity(), self.next_chunk)
    }

    /// Verifies one exact chunk and advances only the next contiguous boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] for integrity failure, an unknown
    /// index, or an attempt to skip an unverified chunk.
    pub fn apply_chunk(
        &mut self,
        authenticated_chunk: AuthenticatedSnapshotChunkV1,
        coordinator_unix_seconds: u64,
    ) -> Result<SnapshotTransferApplyOutcomeV1, InvalidSnapshotTransfer> {
        let index = authenticated_chunk.request().chunk().index();
        let bytes = authenticated_chunk.bytes();
        if authenticated_chunk.request().identity() != self.manifest.identity() {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        if !authenticated_chunk
            .context()
            .is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        self.manifest.verify_chunk(index, bytes)?;
        if index > self.next_chunk {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
        }
        if index < self.next_chunk {
            return Ok(SnapshotTransferApplyOutcomeV1::Replay(self.checkpoint()?));
        }
        self.next_chunk = self
            .next_chunk
            .checked_add(1)
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        self.verified_bytes = self
            .verified_bytes
            .checked_add(bytes.len() as u64)
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        self.root_hasher.update(bytes);
        Ok(SnapshotTransferApplyOutcomeV1::Applied(self.checkpoint()?))
    }

    /// Finishes only after all actual staged bytes match chunks and the root digest.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] when chunks remain, byte totals
    /// differ, or the streaming SHA-256 root does not match the manifest.
    pub fn finish(self) -> Result<VerifiedStagedSnapshotV1, InvalidSnapshotTransfer> {
        if usize::try_from(self.next_chunk).ok() != Some(self.manifest.chunks().len())
            || self.verified_bytes != self.manifest.root().encoded_size()
        {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
        }
        let root_digest = ObjectDigest::from_bytes(self.root_hasher.finalize().into());
        if root_digest != self.manifest.root().digest() {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch);
        }
        Ok(VerifiedStagedSnapshotV1 {
            identity: self.manifest.identity(),
            root: self.manifest.root().clone(),
            verified_bytes: self.verified_bytes,
            final_prefix_digest: self.manifest.prefix_commitment(self.next_chunk)?,
        })
    }
}
