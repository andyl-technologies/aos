//! Immutable snapshot-transfer identity, manifest, ranges and resume DATA.
//!
//! Canonical validation commits immutable objects and bounded ranges only.
//! It does not authenticate source bytes, prove storage, publish a snapshot or
//! admit restore. Actual streaming verification and private native publication,
//! durability and destination admission factories remain separate originals.

use sha2::{Digest as _, Sha256};

use crate::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NodeId, ObjectDescriptor, ObjectDigest,
    OperationId, PortableMediaType, ProjectId, SandboxId, SnapshotId,
};

/// Maximum immutable snapshot chunks described by one transfer manifest.
pub const MAX_SNAPSHOT_TRANSFER_CHUNKS: usize = 65_536;
/// Maximum immutable dependencies admitted by one transfer manifest.
pub const MAX_SNAPSHOT_TRANSFER_DEPENDENCIES: usize = 4_096;
/// Maximum required features encoded in a snapshot transfer manifest.
pub const MAX_SNAPSHOT_TRANSFER_REQUIRED_FEATURES: usize = 64;
/// Maximum bytes in one independently verified snapshot chunk.
pub const MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES: u32 = 4 * 1024 * 1024;
/// Maximum conservative canonical-wire charge for one complete manifest.
///
/// Each bounded row is charged at more than its closed V1 JSON schema can
/// encode, including maximum-length media types and feature names. This keeps
/// all 65,536 chunk commitments representable without permitting an
/// allocation proportional to attacker-controlled, unvalidated bytes.
pub const MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES: usize = 15 * 1024 * 1024;

const SNAPSHOT_MANIFEST_FIXED_WIRE_BYTES: usize = 16 * 1024;
const SNAPSHOT_CHUNK_MAX_WIRE_BYTES: usize = 192;
const SNAPSHOT_DEPENDENCY_MAX_WIRE_BYTES: usize = 768;
const SNAPSHOT_FEATURE_MAX_WIRE_BYTES: usize = 512;

/// Reports malformed immutable transfer or restore-admission evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidSnapshotTransfer {
    /// An identity, digest, generation, or size uses its zero sentinel.
    #[error("snapshot transfer contains an unspecified value")]
    Unspecified,
    /// The transfer semantic version is not exactly supported.
    #[error("snapshot transfer semantic version is unsupported")]
    IncompatibleVersion,
    /// The root object is not an immutable snapshot descriptor.
    #[error("snapshot transfer root descriptor is not a snapshot")]
    WrongRootMediaType,
    /// Chunks are oversized, unordered, overlapping, gapped, or incomplete.
    #[error("snapshot transfer chunks do not canonically cover the root object")]
    ChunksNotCanonical,
    /// Dependencies are oversized, duplicated, unordered, or malformed.
    #[error("snapshot transfer dependencies are not canonical")]
    DependenciesNotCanonical,
    /// A dependency could carry lease, signature, trust, or grant authority.
    #[error("snapshot transfer dependencies must be inert immutable data")]
    AuthorityBearingDependency,
    /// Required features are oversized, duplicated, or unordered.
    #[error("snapshot transfer required features are not canonical")]
    FeaturesNotCanonical,
    /// The bounded manifest rows exceed the canonical wire allocation ceiling.
    #[error("snapshot transfer manifest exceeds its canonical wire ceiling")]
    ManifestTooLarge,
    /// The supplied manifest commitment does not match its canonical fields.
    #[error("snapshot transfer manifest commitment does not match")]
    ManifestDigestMismatch,
    /// A supplied chunk does not match the committed length or digest.
    #[error("snapshot transfer chunk failed integrity validation")]
    ChunkIntegrityMismatch,
    /// A resume checkpoint does not name a valid committed chunk boundary.
    #[error("snapshot transfer resume checkpoint is invalid")]
    InvalidResumeCheckpoint,
    /// Restore admission evidence does not name the manifest destination.
    #[error("snapshot restore admission evidence does not match the manifest")]
    RestoreAdmissionMismatch,
}

/// Selects the immutable snapshot-transfer semantic protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotTransferVersionV1 {
    major: u16,
    minor: u16,
}

impl SnapshotTransferVersionV1 {
    /// Returns the only transfer semantics understood by this model.
    #[must_use]
    pub const fn v1_0() -> Self {
        Self { major: 1, minor: 0 }
    }

    /// Constructs an explicitly versioned transfer request.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::IncompatibleVersion`] unless the
    /// version is exactly 1.0. Transfer compatibility is independent from the
    /// coordinator-to-node protocol.
    pub const fn new(major: u16, minor: u16) -> Result<Self, InvalidSnapshotTransfer> {
        if major != 1 || minor != 0 {
            return Err(InvalidSnapshotTransfer::IncompatibleVersion);
        }
        Ok(Self { major, minor })
    }

    /// Returns the breaking semantic major version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Returns the additive semantic minor version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

/// Identifies one immutable transfer without granting source or destination authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotTransferIdentityV1 {
    operation: OperationId,
    project: ProjectId,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    assignment_digest: ObjectDigest,
    snapshot: SnapshotId,
    source_node: NodeId,
    destination_node: NodeId,
    storage_domain_digest: ObjectDigest,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    manifest_digest: ObjectDigest,
}

impl SnapshotTransferIdentityV1 {
    /// Constructs an inert transfer identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::Unspecified`] for any zero value.
    pub fn new(
        operation: OperationId,
        project: ProjectId,
        sandbox: SandboxId,
        incarnation: IncarnationId,
        assignment_epoch: AssignmentEpoch,
        desired_generation: DesiredGeneration,
        assignment_digest: ObjectDigest,
        snapshot: SnapshotId,
        source_node: NodeId,
        destination_node: NodeId,
        storage_domain_digest: ObjectDigest,
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        manifest_digest: ObjectDigest,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if operation.as_bytes() == &[0; 16]
            || project.as_bytes() == &[0; 16]
            || sandbox.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || assignment_epoch.get() == 0
            || desired_generation.get() == 0
            || assignment_digest.as_bytes() == &[0; 32]
            || snapshot.as_bytes() == &[0; 16]
            || source_node.as_bytes() == &[0; 16]
            || destination_node.as_bytes() == &[0; 16]
            || storage_domain_digest.as_bytes() == &[0; 32]
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || manifest_digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidSnapshotTransfer::Unspecified);
        }
        Ok(Self {
            operation,
            project,
            sandbox,
            incarnation,
            assignment_epoch,
            desired_generation,
            assignment_digest,
            snapshot,
            source_node,
            destination_node,
            storage_domain_digest,
            audience_digest,
            disclosure_domain_digest,
            manifest_digest,
        })
    }

    /// Returns the idempotent operation identity.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the logical snapshot identity.
    #[must_use]
    pub const fn snapshot(self) -> SnapshotId {
        self.snapshot
    }

    /// Returns the project authority domain bound to immutable data.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the logical sandbox bound to the snapshot.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the exact runtime incarnation captured by the snapshot.
    #[must_use]
    pub const fn incarnation(self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the exact assignment fencing epoch captured by the snapshot.
    #[must_use]
    pub const fn assignment_epoch(self) -> AssignmentEpoch {
        self.assignment_epoch
    }

    /// Returns the exact desired assignment generation captured by the snapshot.
    #[must_use]
    pub const fn desired_generation(self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the exact canonical assignment commitment captured by the snapshot.
    #[must_use]
    pub const fn assignment_digest(self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the node that may serve immutable bytes.
    #[must_use]
    pub const fn source_node(self) -> NodeId {
        self.source_node
    }

    /// Returns the only admitted destination node.
    #[must_use]
    pub const fn destination_node(self) -> NodeId {
        self.destination_node
    }

    /// Returns the immutable storage-domain commitment.
    #[must_use]
    pub const fn storage_domain_digest(self) -> ObjectDigest {
        self.storage_domain_digest
    }

    /// Returns the exact authenticated transfer audience commitment.
    #[must_use]
    pub const fn audience_digest(self) -> ObjectDigest {
        self.audience_digest
    }

    /// Returns the disclosure-domain commitment.
    #[must_use]
    pub const fn disclosure_domain_digest(self) -> ObjectDigest {
        self.disclosure_domain_digest
    }

    /// Returns the canonical manifest commitment.
    #[must_use]
    pub const fn manifest_digest(self) -> ObjectDigest {
        self.manifest_digest
    }
}

/// Commits one bounded, independently verifiable snapshot byte range.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotTransferChunkV1 {
    index: u32,
    offset: u64,
    length: u32,
    digest: ObjectDigest,
}

impl SnapshotTransferChunkV1 {
    /// Constructs one chunk commitment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::ChunksNotCanonical`] for an empty or
    /// oversized chunk or a zero digest.
    pub fn new(
        index: u32,
        offset: u64,
        length: u32,
        digest: ObjectDigest,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if length == 0
            || length > MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES
            || digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidSnapshotTransfer::ChunksNotCanonical);
        }
        Ok(Self {
            index,
            offset,
            length,
            digest,
        })
    }

    /// Returns the zero-based chunk index.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Returns the byte offset in the immutable root object.
    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// Returns the exact chunk length.
    #[must_use]
    pub const fn length(self) -> u32 {
        self.length
    }

    /// Returns the SHA-256 commitment to the exact chunk bytes.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }

    /// Verifies exact immutable bytes against this chunk commitment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::ChunkIntegrityMismatch`] for a
    /// length or SHA-256 mismatch.
    pub fn verify_bytes(self, bytes: &[u8]) -> Result<(), InvalidSnapshotTransfer> {
        if bytes.len() != self.length as usize
            || ObjectDigest::from_bytes(Sha256::digest(bytes).into()) != self.digest
        {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch);
        }
        Ok(())
    }
}

/// Describes all immutable data and semantic prerequisites for one transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotTransferManifestV1 {
    identity: SnapshotTransferIdentityV1,
    version: SnapshotTransferVersionV1,
    root: ObjectDescriptor,
    chunks: Vec<SnapshotTransferChunkV1>,
    dependencies: Vec<ObjectDescriptor>,
    required_features: Vec<crate::FeatureRef>,
}

impl SnapshotTransferManifestV1 {
    /// Computes the canonical commitment used to construct a transfer identity.
    ///
    /// Inputs must still pass [`Self::new`] before use. This helper only
    /// exposes the deterministic source codec and grants no authority.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn canonical_commitment_for(
        operation: OperationId,
        project: ProjectId,
        sandbox: SandboxId,
        incarnation: IncarnationId,
        assignment_epoch: AssignmentEpoch,
        desired_generation: DesiredGeneration,
        assignment_digest: ObjectDigest,
        snapshot: SnapshotId,
        source_node: NodeId,
        destination_node: NodeId,
        storage_domain_digest: ObjectDigest,
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        version: SnapshotTransferVersionV1,
        root: &ObjectDescriptor,
        chunks: &[SnapshotTransferChunkV1],
        dependencies: &[ObjectDescriptor],
        required_features: &[crate::FeatureRef],
    ) -> ObjectDigest {
        canonical_manifest_commitment(
            operation,
            project,
            sandbox,
            incarnation,
            assignment_epoch,
            desired_generation,
            assignment_digest,
            snapshot,
            source_node,
            destination_node,
            storage_domain_digest,
            audience_digest,
            disclosure_domain_digest,
            version,
            root,
            chunks,
            dependencies,
            required_features,
        )
    }

    /// Constructs and verifies one immutable transfer manifest.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer`] unless the root is a snapshot,
    /// chunks exactly and contiguously cover it, dependencies and features are
    /// canonical bounded sets, and the identity commits the canonical fields.
    pub fn new(
        identity: SnapshotTransferIdentityV1,
        version: SnapshotTransferVersionV1,
        root: ObjectDescriptor,
        chunks: Vec<SnapshotTransferChunkV1>,
        dependencies: Vec<ObjectDescriptor>,
        required_features: Vec<crate::FeatureRef>,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if root.media_type().as_str() != PortableMediaType::Snapshot.as_str()
            || root.digest().as_bytes() == &[0; 32]
            || root.encoded_size() == 0
        {
            return Err(InvalidSnapshotTransfer::WrongRootMediaType);
        }
        validate_transfer_chunks(root.encoded_size(), &chunks)?;
        if dependencies.len() > MAX_SNAPSHOT_TRANSFER_DEPENDENCIES
            || dependencies.iter().any(|object| {
                object.digest().as_bytes() == &[0; 32]
                    || object.encoded_size() == 0
                    || PortableMediaType::parse(object.media_type().as_str()).is_err()
            })
            || !dependencies.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(InvalidSnapshotTransfer::DependenciesNotCanonical);
        }
        if dependencies.iter().any(|object| {
            PortableMediaType::parse(object.media_type().as_str())
                .is_ok_and(|media_type| !is_inert_transfer_dependency(media_type))
        }) {
            return Err(InvalidSnapshotTransfer::AuthorityBearingDependency);
        }
        if required_features.len() > MAX_SNAPSHOT_TRANSFER_REQUIRED_FEATURES
            || !required_features.windows(2).all(|pair| pair[0] < pair[1])
            || crate::validate_required_features(&required_features).is_err()
        {
            return Err(InvalidSnapshotTransfer::FeaturesNotCanonical);
        }
        snapshot_manifest_aggregate_wire_bytes(
            chunks.len(),
            dependencies.len(),
            required_features.len(),
        )?;

        let manifest = Self {
            identity,
            version,
            root,
            chunks,
            dependencies,
            required_features,
        };
        if manifest.canonical_commitment() != identity.manifest_digest() {
            return Err(InvalidSnapshotTransfer::ManifestDigestMismatch);
        }
        Ok(manifest)
    }

    /// Returns the inert transfer identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the exact independent transfer protocol version.
    #[must_use]
    pub const fn version(&self) -> SnapshotTransferVersionV1 {
        self.version
    }

    /// Returns the immutable snapshot root descriptor.
    #[must_use]
    pub const fn root(&self) -> &ObjectDescriptor {
        &self.root
    }

    /// Returns contiguous chunk commitments in transfer order.
    #[must_use]
    pub fn chunks(&self) -> &[SnapshotTransferChunkV1] {
        &self.chunks
    }

    /// Returns immutable prerequisite objects in canonical order.
    #[must_use]
    pub fn dependencies(&self) -> &[ObjectDescriptor] {
        &self.dependencies
    }

    /// Returns hard destination feature requirements in canonical order.
    #[must_use]
    pub fn required_features(&self) -> &[crate::FeatureRef] {
        &self.required_features
    }

    /// Verifies one received chunk before it can advance a resume boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::ChunkIntegrityMismatch`] when the
    /// index is absent or exact bytes differ in length or SHA-256 digest.
    pub fn verify_chunk(&self, index: u32, bytes: &[u8]) -> Result<(), InvalidSnapshotTransfer> {
        let chunk = self
            .chunks
            .get(
                usize::try_from(index)
                    .map_err(|_| InvalidSnapshotTransfer::ChunkIntegrityMismatch)?,
            )
            .filter(|chunk| chunk.index() == index)
            .ok_or(InvalidSnapshotTransfer::ChunkIntegrityMismatch)?;
        chunk.verify_bytes(bytes)
    }

    /// Computes the canonical commitment to a verified chunk prefix.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::InvalidResumeCheckpoint`] when the
    /// boundary exceeds the committed chunk count.
    pub fn prefix_commitment(
        &self,
        next_chunk: u32,
    ) -> Result<ObjectDigest, InvalidSnapshotTransfer> {
        let boundary = usize::try_from(next_chunk)
            .map_err(|_| InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let prefix = self
            .chunks
            .get(..boundary)
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let mut hasher = Sha256::new();
        hasher.update(b"aos.snapshot-transfer-prefix.v1\0");
        hasher.update(self.identity.manifest_digest().as_bytes());
        hasher.update(next_chunk.to_be_bytes());
        for chunk in prefix {
            hasher.update(chunk.index().to_be_bytes());
            hasher.update(chunk.digest().as_bytes());
        }
        Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
    }

    fn canonical_commitment(&self) -> ObjectDigest {
        canonical_manifest_commitment(
            self.identity.operation(),
            self.identity.project(),
            self.identity.sandbox(),
            self.identity.incarnation(),
            self.identity.assignment_epoch(),
            self.identity.desired_generation(),
            self.identity.assignment_digest(),
            self.identity.snapshot(),
            self.identity.source_node(),
            self.identity.destination_node(),
            self.identity.storage_domain_digest(),
            self.identity.audience_digest(),
            self.identity.disclosure_domain_digest(),
            self.version,
            &self.root,
            &self.chunks,
            &self.dependencies,
            &self.required_features,
        )
    }
}

fn snapshot_manifest_aggregate_wire_bytes(
    chunks: usize,
    dependencies: usize,
    features: usize,
) -> Result<usize, InvalidSnapshotTransfer> {
    let charge = SNAPSHOT_MANIFEST_FIXED_WIRE_BYTES
        .checked_add(
            chunks
                .checked_mul(SNAPSHOT_CHUNK_MAX_WIRE_BYTES)
                .ok_or(InvalidSnapshotTransfer::ManifestTooLarge)?,
        )
        .and_then(|value| {
            dependencies
                .checked_mul(SNAPSHOT_DEPENDENCY_MAX_WIRE_BYTES)
                .and_then(|rows| value.checked_add(rows))
        })
        .and_then(|value| {
            features
                .checked_mul(SNAPSHOT_FEATURE_MAX_WIRE_BYTES)
                .and_then(|rows| value.checked_add(rows))
        })
        .ok_or(InvalidSnapshotTransfer::ManifestTooLarge)?;
    if charge > MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES {
        return Err(InvalidSnapshotTransfer::ManifestTooLarge);
    }
    Ok(charge)
}

/// Binds one requested chunk to the immutable manifest that commits it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotTransferChunkRequestV1 {
    identity: SnapshotTransferIdentityV1,
    chunk: SnapshotTransferChunkV1,
}

impl SnapshotTransferChunkRequestV1 {
    /// Reconstructs an inert request from an exact identity and chunk commitment.
    ///
    /// This does not prove that the chunk belongs to a manifest; the receiving
    /// transfer reducer must match both fields to its already validated manifest.
    #[must_use]
    pub const fn from_exact_commitment(
        identity: SnapshotTransferIdentityV1,
        chunk: SnapshotTransferChunkV1,
    ) -> Self {
        Self { identity, chunk }
    }

    /// Derives one exact chunk request from a validated manifest.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::ChunkIntegrityMismatch`] when the
    /// index is outside the manifest's committed chunk sequence.
    pub fn new(
        manifest: &SnapshotTransferManifestV1,
        index: u32,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let chunk = manifest
            .chunks()
            .get(
                usize::try_from(index)
                    .map_err(|_| InvalidSnapshotTransfer::ChunkIntegrityMismatch)?,
            )
            .copied()
            .filter(|chunk| chunk.index() == index)
            .ok_or(InvalidSnapshotTransfer::ChunkIntegrityMismatch)?;
        Ok(Self {
            identity: manifest.identity(),
            chunk,
        })
    }

    /// Returns the exact immutable transfer identity.
    #[must_use]
    pub const fn identity(self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the exact manifest-committed chunk.
    #[must_use]
    pub const fn chunk(self) -> SnapshotTransferChunkV1 {
        self.chunk
    }
}

/// Binds one bounded dependency byte range to its manifest descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotDependencyRangeV1 {
    identity: SnapshotTransferIdentityV1,
    dependency: ObjectDescriptor,
    offset: u64,
    length: u32,
}

impl SnapshotDependencyRangeV1 {
    /// Reconstructs one inert manifest-bound dependency range.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::DependenciesNotCanonical`] for an
    /// invalid descriptor or an empty, oversized, overflowing, or out-of-range span.
    pub fn from_exact_commitment(
        identity: SnapshotTransferIdentityV1,
        dependency: ObjectDescriptor,
        offset: u64,
        length: u32,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let end = offset
            .checked_add(u64::from(length))
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        if dependency.digest().as_bytes() == &[0; 32]
            || dependency.encoded_size() == 0
            || PortableMediaType::parse(dependency.media_type().as_str()).is_err()
            || length == 0
            || length > MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES
            || end > dependency.encoded_size()
        {
            return Err(InvalidSnapshotTransfer::DependenciesNotCanonical);
        }
        Ok(Self {
            identity,
            dependency,
            offset,
            length,
        })
    }

    /// Derives one bounded range request from a validated manifest dependency.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::DependenciesNotCanonical`] for an
    /// unknown dependency, zero/oversized range, overflow, or out-of-bounds end.
    pub fn new(
        manifest: &SnapshotTransferManifestV1,
        dependency_index: u32,
        offset: u64,
        length: u32,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        let dependency = manifest
            .dependencies()
            .get(
                usize::try_from(dependency_index)
                    .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?,
            )
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let end = offset
            .checked_add(u64::from(length))
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        if length == 0
            || length > MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES
            || end > dependency.encoded_size()
        {
            return Err(InvalidSnapshotTransfer::DependenciesNotCanonical);
        }
        Ok(Self {
            identity: manifest.identity(),
            dependency: dependency.clone(),
            offset,
            length,
        })
    }

    /// Returns the exact scoped transfer identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the manifest-bound immutable dependency descriptor.
    #[must_use]
    pub const fn dependency(&self) -> &ObjectDescriptor {
        &self.dependency
    }

    /// Returns the exact dependency byte offset.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the bounded byte count.
    #[must_use]
    pub const fn length(&self) -> u32 {
        self.length
    }
}

/// Commits resumable progress only at an already verified chunk boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotTransferResumeV1 {
    identity: SnapshotTransferIdentityV1,
    next_chunk: u32,
    verified_prefix_digest: ObjectDigest,
}

impl SnapshotTransferResumeV1 {
    /// Constructs an integrity-bound resume checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSnapshotTransfer::InvalidResumeCheckpoint`] when the
    /// identity differs or the boundary exceeds the manifest. The prefix
    /// commitment is derived from the manifest rather than accepted as input.
    pub fn new(
        manifest: &SnapshotTransferManifestV1,
        identity: SnapshotTransferIdentityV1,
        next_chunk: u32,
    ) -> Result<Self, InvalidSnapshotTransfer> {
        if identity != manifest.identity()
            || usize::try_from(next_chunk)
                .ok()
                .is_none_or(|index| index > manifest.chunks().len())
        {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint);
        }
        let verified_prefix_digest = manifest.prefix_commitment(next_chunk)?;
        Ok(Self {
            identity,
            next_chunk,
            verified_prefix_digest,
        })
    }

    /// Returns the exact transfer identity.
    #[must_use]
    pub const fn identity(self) -> SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the first not-yet-verified chunk index.
    #[must_use]
    pub const fn next_chunk(self) -> u32 {
        self.next_chunk
    }

    /// Returns the digest of the exact verified prefix bytes.
    #[must_use]
    pub const fn verified_prefix_digest(self) -> ObjectDigest {
        self.verified_prefix_digest
    }
}
fn validate_transfer_chunks(
    encoded_size: u64,
    chunks: &[SnapshotTransferChunkV1],
) -> Result<(), InvalidSnapshotTransfer> {
    if chunks.is_empty() || chunks.len() > MAX_SNAPSHOT_TRANSFER_CHUNKS {
        return Err(InvalidSnapshotTransfer::ChunksNotCanonical);
    }
    let mut expected_offset = 0_u64;
    for (expected_index, chunk) in chunks.iter().enumerate() {
        let Ok(expected_index) = u32::try_from(expected_index) else {
            return Err(InvalidSnapshotTransfer::ChunksNotCanonical);
        };
        if chunk.index() != expected_index || chunk.offset() != expected_offset {
            return Err(InvalidSnapshotTransfer::ChunksNotCanonical);
        }
        expected_offset = expected_offset
            .checked_add(u64::from(chunk.length()))
            .ok_or(InvalidSnapshotTransfer::ChunksNotCanonical)?;
    }
    if expected_offset != encoded_size {
        return Err(InvalidSnapshotTransfer::ChunksNotCanonical);
    }
    Ok(())
}

/// Extends the canonical snapshot commitment with one immutable descriptor.
pub fn hash_descriptor(hasher: &mut Sha256, descriptor: &ObjectDescriptor) {
    let media_type = descriptor.media_type().as_str();
    hasher.update((media_type.len() as u16).to_be_bytes());
    hasher.update(media_type.as_bytes());
    hasher.update(descriptor.digest().as_bytes());
    hasher.update(descriptor.encoded_size().to_be_bytes());
}

/// Reports whether an immutable transfer dependency carries no authority format.
#[must_use]
pub fn is_inert_transfer_dependency(media_type: PortableMediaType) -> bool {
    matches!(
        media_type,
        PortableMediaType::Content
            | PortableMediaType::Directory
            | PortableMediaType::Tree
            | PortableMediaType::Delta
            | PortableMediaType::View
            | PortableMediaType::Environment
            | PortableMediaType::Optimization
            | PortableMediaType::SandboxSpec
            | PortableMediaType::Policy
            | PortableMediaType::Snapshot
    )
}

#[allow(clippy::too_many_arguments)]
fn canonical_manifest_commitment(
    operation: OperationId,
    project: ProjectId,
    sandbox: SandboxId,
    incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
    desired_generation: DesiredGeneration,
    assignment_digest: ObjectDigest,
    snapshot: SnapshotId,
    source_node: NodeId,
    destination_node: NodeId,
    storage_domain_digest: ObjectDigest,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    version: SnapshotTransferVersionV1,
    root: &ObjectDescriptor,
    chunks: &[SnapshotTransferChunkV1],
    dependencies: &[ObjectDescriptor],
    required_features: &[crate::FeatureRef],
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.snapshot-transfer-manifest.v1\0");
    hasher.update(operation.as_bytes());
    hasher.update(project.as_bytes());
    hasher.update(sandbox.as_bytes());
    hasher.update(incarnation.as_bytes());
    hasher.update(assignment_epoch.get().to_be_bytes());
    hasher.update(desired_generation.get().to_be_bytes());
    hasher.update(assignment_digest.as_bytes());
    hasher.update(snapshot.as_bytes());
    hasher.update(source_node.as_bytes());
    hasher.update(destination_node.as_bytes());
    hasher.update(storage_domain_digest.as_bytes());
    hasher.update(audience_digest.as_bytes());
    hasher.update(disclosure_domain_digest.as_bytes());
    hasher.update(version.major().to_be_bytes());
    hasher.update(version.minor().to_be_bytes());
    hash_descriptor(&mut hasher, root);
    hasher.update((chunks.len() as u32).to_be_bytes());
    for chunk in chunks {
        hasher.update(chunk.index().to_be_bytes());
        hasher.update(chunk.offset().to_be_bytes());
        hasher.update(chunk.length().to_be_bytes());
        hasher.update(chunk.digest().as_bytes());
    }
    hasher.update((dependencies.len() as u32).to_be_bytes());
    for dependency in dependencies {
        hash_descriptor(&mut hasher, dependency);
    }
    hasher.update((required_features.len() as u32).to_be_bytes());
    for feature in required_features {
        hasher.update((feature.namespace().len() as u16).to_be_bytes());
        hasher.update(feature.namespace().as_bytes());
        hasher.update(feature.major().to_be_bytes());
        hasher.update(feature.minor().to_be_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Stores durable dependency staging and protected-liveness commitments.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDependencyProjectionV1 {
    /// Immutable dependency descriptor.
    pub descriptor: ObjectDescriptor,
    /// Bytes verified so far, always a contiguous prefix.
    pub next_offset: u64,
    /// Streaming commitment derived from the actual staged prefix bytes.
    pub verified_prefix_digest: ObjectDigest,
    /// Opaque protected-object receipt for the staged prefix.
    pub protected_object_receipt: ObjectDigest,
    /// Protected current-liveness proof commitment, when complete.
    pub liveness_digest: Option<ObjectDigest>,
    /// Currentness deadline of the liveness proof.
    pub live_until_unix_seconds: Option<u64>,
}
