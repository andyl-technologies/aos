//! Selected authenticated snapshot handoffs and streaming verification.
//!
//! This owner retains authenticated chunk/range bytes, protected streaming
//! checkpoints, and reducers that verify contiguous manifest-bound bytes.
//! Immutable manifests, resume DATA, completed snapshot receipts and local history
//! remain available by default outside this selected owner.

use aos_sandbox_core::{ObjectDescriptor, ObjectDigest, PortableMediaType};
use sha2::{Digest as _, Sha256};

use crate::local_inventory::carrier_authority::AuthenticatedFrameSealV1;
use crate::local_inventory::evidence::AuthenticatedEvidenceContextV1;
use crate::local_inventory::evidence_authority::VerifierEvidenceGrantV1;
use crate::local_inventory::journal::{
    JournalEffectStateV1, MultiNodeJournalDomainV1, ProtectedJournalRecordV1,
};

use super::{
    InvalidSnapshotTransfer, SnapshotDependencyRangeV1, SnapshotTransferChunkRequestV1,
    SnapshotTransferIdentityV1, SnapshotTransferManifestV1, SnapshotTransferResumeV1,
    VerifiedSnapshotDependencyV1, VerifiedStagedSnapshotV1, is_inert_transfer_dependency,
};

/// Carries one exact chunk whose carrier, audience, and bytes were authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSnapshotChunkV1 {
    request: SnapshotTransferChunkRequestV1,
    bytes: Vec<u8>,
    context: AuthenticatedEvidenceContextV1,
}

impl AuthenticatedSnapshotChunkV1 {
    /// Constructs chunk evidence only inside the authenticated carrier boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] for source, disclosure, currentness,
    /// exact length, or chunk digest mismatch.
    pub(in crate::local_inventory) fn from_authenticated_carrier(
        request: SnapshotTransferChunkRequestV1,
        bytes: Vec<u8>,
        context: AuthenticatedEvidenceContextV1,
        frame_seal: &AuthenticatedFrameSealV1,
        canonical_body_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if context.node() != request.identity().source_node()
            || context.audience_digest() != request.identity().audience_digest()
            || context.disclosure_domain_digest() != request.identity().disclosure_domain_digest()
            || !context.is_current_at(verified_at_unix_seconds)
            || !frame_seal.matches(
                super::protocol::CanonicalNodeFrameKindV1::SnapshotChunkResponse,
                canonical_body_digest,
                context,
            )
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        request.chunk().verify_bytes(&bytes)?;
        Ok(Self {
            request,
            bytes,
            context,
        })
    }

    /// Returns the exact manifest-derived chunk request.
    #[must_use]
    pub const fn request(&self) -> SnapshotTransferChunkRequestV1 {
        self.request
    }

    /// Returns exact authenticated immutable chunk bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns exact carrier/audience/boot/currentness evidence.
    #[must_use]
    pub const fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }
}

/// Carries one manifest-bound dependency range from an authenticated source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSnapshotDependencyRangeV1 {
    request: SnapshotDependencyRangeV1,
    bytes: Vec<u8>,
    context: AuthenticatedEvidenceContextV1,
}

impl AuthenticatedSnapshotDependencyRangeV1 {
    /// Constructs dependency bytes only inside the authenticated carrier boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] unless source, disclosure domain,
    /// currentness, descriptor, offset, and exact bounded byte count match.
    pub(in crate::local_inventory) fn from_authenticated_carrier(
        request: SnapshotDependencyRangeV1,
        bytes: Vec<u8>,
        context: AuthenticatedEvidenceContextV1,
        frame_seal: &AuthenticatedFrameSealV1,
        canonical_body_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if context.node() != request.identity().source_node()
            || context.audience_digest() != request.identity().audience_digest()
            || context.disclosure_domain_digest() != request.identity().disclosure_domain_digest()
            || !context.is_current_at(verified_at_unix_seconds)
            || !frame_seal.matches(
                super::protocol::CanonicalNodeFrameKindV1::SnapshotDependencyResponse,
                canonical_body_digest,
                context,
            )
            || bytes.len() != request.length() as usize
        {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch);
        }
        Ok(Self {
            request,
            bytes,
            context,
        })
    }

    /// Returns the exact manifest-derived dependency range request.
    #[must_use]
    pub const fn request(&self) -> &SnapshotDependencyRangeV1 {
        &self.request
    }

    /// Returns the exact authenticated range bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns exact carrier/audience/boot/currentness evidence.
    #[must_use]
    pub const fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }
}

/// Proves that a resume boundary and its exact staged bytes are durably committed.
///
/// This verifier-issued value is inert recovery evidence. It cannot publish,
/// restore, or grant access to the staged snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableSnapshotTransferCheckpointV1 {
    resume: SnapshotTransferResumeV1,
    staged_bytes: u64,
    staged_prefix_digest: ObjectDigest,
    journal_record: ProtectedJournalRecordV1,
    evidence_context: AuthenticatedEvidenceContextV1,
}

impl DurableSnapshotTransferCheckpointV1 {
    /// Constructs a checkpoint only inside the destination storage verifier.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] unless the exact chunk boundary,
    /// staged length, committed journal record, destination, disclosure domain,
    /// and verifier currentness all match the immutable manifest.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::local_inventory) fn from_storage_verifier(
        grant: VerifierEvidenceGrantV1<(
            SnapshotTransferManifestV1,
            SnapshotTransferResumeV1,
            Vec<u8>,
            ProtectedJournalRecordV1,
            u64,
        )>,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let (
            (manifest, resume, staged_prefix, journal_record, verified_at_unix_seconds),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        let evidence_context = journal_record.context();
        let boundary = usize::try_from(resume.next_chunk())
            .map_err(|_| InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let expected_bytes = manifest
            .chunks()
            .get(..boundary)
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?
            .iter()
            .try_fold(0_u64, |total, chunk| {
                total
                    .checked_add(u64::from(chunk.length()))
                    .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)
            })?;
        let staged_bytes = u64::try_from(staged_prefix.len())
            .map_err(|_| InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let staged_prefix_digest =
            staged_prefix_commitment(manifest.identity(), resume, &staged_prefix);
        let durable_state = journal_record
            .record()
            .state_payload()
            .snapshot_transfer_state()
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || replay_fence != verifier_context.replay_fence()
            || issuance_sequence == 0
            || verifier_context != evidence_context
            || resume.identity() != manifest.identity()
            || manifest.prefix_commitment(resume.next_chunk())? != resume.verified_prefix_digest()
            || staged_bytes != expected_bytes
            || journal_record.record().domain() != MultiNodeJournalDomainV1::SnapshotTransfer
            || journal_record.record().operation() != manifest.identity().operation()
            || journal_record.record().payload_digest() != resume.verified_prefix_digest()
            || journal_record.record().effect_state() != JournalEffectStateV1::Committed
            || journal_record.record().effect_digest() != staged_prefix_digest
            || durable_state.manifest() != &manifest
            || durable_state.resume() != resume
            || durable_state.staged_chunks().len() != boundary
            || durable_state.publication().is_some()
            || journal_record.storage_domain_digest() != manifest.identity().storage_domain_digest()
            || !journal_record
                .context()
                .is_current_at(verified_at_unix_seconds)
            || evidence_context.node() != manifest.identity().destination_node()
            || evidence_context.audience_digest() != manifest.identity().audience_digest()
            || evidence_context.disclosure_domain_digest()
                != manifest.identity().disclosure_domain_digest()
            || !evidence_context.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
        }
        Ok(Self {
            resume,
            staged_bytes,
            staged_prefix_digest,
            journal_record,
            evidence_context,
        })
    }

    /// Returns the exact integrity-verified chunk boundary.
    #[must_use]
    pub const fn resume(&self) -> SnapshotTransferResumeV1 {
        self.resume
    }

    /// Returns the exact scoped immutable transfer identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.resume.identity()
    }

    /// Returns the first chunk not covered by the durable staged prefix.
    #[must_use]
    pub const fn next_chunk(&self) -> u32 {
        self.resume.next_chunk()
    }

    /// Returns the exact durably staged byte count.
    #[must_use]
    pub const fn staged_bytes(&self) -> u64 {
        self.staged_bytes
    }

    /// Returns the storage verifier's exact staged-byte commitment.
    #[must_use]
    pub const fn staged_prefix_digest(&self) -> ObjectDigest {
        self.staged_prefix_digest
    }

    /// Returns the committed journal record covering this boundary.
    #[must_use]
    pub const fn journal_record(&self) -> &ProtectedJournalRecordV1 {
        &self.journal_record
    }

    /// Returns the exact authenticated destination verifier context.
    #[must_use]
    pub const fn evidence_context(&self) -> AuthenticatedEvidenceContextV1 {
        self.evidence_context
    }
}

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

pub(in crate::local_inventory) fn staged_prefix_commitment(
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
