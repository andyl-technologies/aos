//! Checks an already adopted manifest body while retaining actual recovery custody.
//!
//! The registered IPC producer supplies the body, durable metadata backing and
//! same-response lifecycle observation. Inventory supplies only the original key;
//! no prior canonical inode observation is required or invented. This module
//! performs reads only and grants no consumer pin, serving or recovery completion.

use super::{
    NativeRecoveryCandidate, NativeRecoveryInspector,
    files::{invalid, read_bounded, same_file},
    verification::{self, DerivedIndexRepair, DetachedIndexStatus, VerifiedEncodedBody},
};
use crate::{
    host_quota::NativeProject,
    publisher_local::{
        client::{PublisherRecoveryContext, recovery_manifest::RecoveryManifestBody},
        wire::{BodyKey, BodyKind},
    },
};
use std::{
    fmt,
    fs::{File, Metadata},
    io::{self, Read},
    os::unix::fs::{FileExt, MetadataExt},
    sync::Arc,
};
use terrane::{
    host::{
        cache::{HostDomainLocation, ResidenceRecord},
        publication::{PublicationClaim, PublicationRecipe},
    },
    pack::{EntryKind, HEADER_SIZE, NativeBodyDecoder, PackClass, PackId},
    store::ByteRange,
};
use terrane_core::{chunking::ChunkProfile, pack_format::Header};

/// Retains an inspected body and its actual durable metadata and lifecycle custody.
///
/// This is evidence for owner reconciliation, not an admission, consumer pin,
/// serving handle or complete inventory. It retains no executor borrow. The
/// physical owner must keep its original opaque context for subsequent checks.
pub(in crate::host_cache) struct VerifiedRecoveryManifest {
    context: NativeRecoveryInspector,
    candidate: NativeRecoveryCandidate,
    body: RecoveryManifestBody,
    metadata: DerivedIndexRepair,
    observed: Metadata,
    project: NativeProject,
}

impl VerifiedRecoveryManifest {
    /// Borrows the canonical claim independently verified against actual metadata and plaintext.
    pub(in crate::host_cache) fn claim(&self) -> &PublicationClaim {
        self.body.retained().backing().claim()
    }

    /// Derives bounded ordered chunk ranges for the actual adopted whole file.
    ///
    /// These are candidate policy records, not persisted residence or pin state.
    /// Repeated chunk occurrences remain visible. The owner must choose one
    /// residence per chunk across its complete inventory before persisting state.
    ///
    /// # Errors
    /// Refuses record payloads exceeding the configured allocation budget,
    /// unavailable allocation or an inconsistent manifest range sum.
    pub(in crate::host_cache) fn residences(&self) -> io::Result<Vec<ResidenceRecord>> {
        manifest_residences(self.claim(), self.context.reads.max_allocation_bytes)
    }

    /// Borrows the original candidate, including every unresolved pending observation.
    pub(in crate::host_cache) fn candidate(&self) -> &NativeRecoveryCandidate {
        &self.candidate
    }

    /// Borrows the genuine registered body/backing pair and same-response observation.
    pub(in crate::host_cache) fn body(&self) -> &RecoveryManifestBody {
        &self.body
    }

    /// Rechecks original drain custody, actual metadata bytes, project and kernel seal.
    ///
    /// A stable kernel seal protects the already verified plaintext. This checks
    /// the retained actual files, without reading publisher-private directories.
    /// It must run outside an embedded-state guard or publisher RPC mutex.
    ///
    /// # Errors
    /// Refuses changed process/root/session/drain, metadata paths or bytes,
    /// backing inode/project and kernel measurement. It grants no lifecycle effect.
    pub(in crate::host_cache) fn check_current(
        &self,
        original: &PublisherRecoveryContext<HostDomainLocation>,
    ) -> io::Result<()> {
        self.context.check_current()?;
        self.context
            .session
            .check_recovery_manifest_body(&self.body, original)
            .map_err(invalid)?;
        check_key(self.candidate.key(), self.body.retained().backing().claim())?;
        self.metadata.check_current()?;
        let body = self.body.retained().body();
        if !same_file(&self.observed, &body.handle().metadata()?)
            || check_project(&self.context, body.handle())? != self.project
            || crate::verity::measure(body.handle())? != *body.binding()
        {
            return Err(invalid("verified manifest backing changed"));
        }
        self.context
            .session
            .check_recovery_manifest_body(&self.body, original)
            .map_err(invalid)
    }
}

/// Preserves an unresolved candidate and genuine body pair after inspection fails.
pub(in crate::host_cache) struct ManifestInspectionFailure {
    error: io::Error,
    resources: Box<UnresolvedManifest>,
}

struct UnresolvedManifest {
    candidate: NativeRecoveryCandidate,
    body: RecoveryManifestBody,
}

impl ManifestInspectionFailure {
    fn new(
        error: io::Error,
        candidate: NativeRecoveryCandidate,
        body: RecoveryManifestBody,
    ) -> Self {
        Self {
            error,
            resources: Box::new(UnresolvedManifest { candidate, body }),
        }
    }

    /// Returns the typed cause and original resources for physical owner reconciliation.
    pub(in crate::host_cache) fn into_parts(
        self,
    ) -> (io::Error, NativeRecoveryCandidate, RecoveryManifestBody) {
        let UnresolvedManifest { candidate, body } = *self.resources;
        (self.error, candidate, body)
    }
}

impl fmt::Debug for ManifestInspectionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManifestInspectionFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ManifestInspectionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, formatter)
    }
}

impl std::error::Error for ManifestInspectionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl NativeRecoveryInspector {
    /// Verifies one actual retained-manifest response against its original candidate.
    ///
    /// The caller supplies the original opaque context from its real live owner,
    /// never a fresh drain snapshot. The IPC producer has already reserved,
    /// adopted, registered and reconciled the actual body/metadata pair. This
    /// operation adds bounded independent metadata/plaintext verification only.
    /// The owner must retain its accepted live turn and separately recheck its
    /// durable holds. Pending observations and other candidate issues remain
    /// owner work; this result never completes those decisions.
    ///
    /// # Errors
    /// Returns the original candidate and body pair on stale custody, another
    /// complete key, corrupt/missing metadata, allocation limits, plaintext or
    /// kernel-seal mismatch. Every error leaves physical owner registries intact.
    pub(in crate::host_cache) fn inspect_retained_manifest(
        &self,
        candidate: NativeRecoveryCandidate,
        body: RecoveryManifestBody,
        original: &PublisherRecoveryContext<HostDomainLocation>,
    ) -> Result<VerifiedRecoveryManifest, ManifestInspectionFailure> {
        let verified = (|| {
            self.check_current()?;
            self.session
                .check_recovery_manifest_body(&body, original)
                .map_err(invalid)?;
            let backing = body.retained().backing();
            check_key(candidate.key(), backing.claim())?;
            if !Arc::ptr_eq(&self.layout, backing.layout()) {
                return Err(invalid(
                    "manifest backing belongs to another inspected root",
                ));
            }
            let metadata = metadata_source(self, &body)?;
            let bytes = read_bounded(metadata.pack_file(), self.reads.max_allocation_bytes)?;
            let claim = manifest_from_pack(
                &bytes,
                backing.claim(),
                backing.manifest_range(),
                self.layout.layout().chunk_profile(),
                self.reads,
            )?;
            let handle = body.retained().body().handle();
            let observed = handle.metadata()?;
            let project = check_project(self, handle)?;
            if crate::verity::measure(handle)? != *body.retained().body().binding() {
                return Err(invalid(
                    "manifest backing kernel seal differs from adopted binding",
                ));
            }
            verify_file_plaintext(&claim, handle, self.reads.max_allocation_bytes)?;
            metadata.check_current()?;
            if !same_file(&observed, &handle.metadata()?) || check_project(self, handle)? != project
            {
                return Err(invalid(
                    "manifest backing changed during plaintext verification",
                ));
            }
            self.session
                .check_recovery_manifest_body(&body, original)
                .map_err(invalid)?;
            Ok((metadata, observed, project))
        })();
        let (metadata, observed, project) = match verified {
            Ok(verified) => verified,
            Err(error) => {
                return Err(ManifestInspectionFailure::new(error, candidate, body));
            }
        };
        let verified = VerifiedRecoveryManifest {
            context: self.clone(),
            candidate,
            body,
            metadata,
            observed,
            project,
        };
        if let Err(error) = verified.check_current(original) {
            return Err(ManifestInspectionFailure::new(
                error,
                verified.candidate,
                verified.body,
            ));
        }
        Ok(verified)
    }
}

fn metadata_source(
    context: &NativeRecoveryInspector,
    body: &RecoveryManifestBody,
) -> io::Result<DerivedIndexRepair> {
    let backing = body.retained().backing();
    let file = backing.metadata_file();
    context.custody.check(&file.metadata()?, false)?;
    check_project(context, file)?;
    let mut bytes = [0; HEADER_SIZE];
    file.read_exact_at(&mut bytes, 0)?;
    let header = Header::decode(&bytes).map_err(invalid)?;
    if !header.is_meta() {
        return Err(invalid(
            "retained reconstruction metadata is not a metadata pack",
        ));
    }
    let id = PackId::from_random_bytes(*header.id());
    let metadata = match verification::pack(context, id, Some(file), &[])? {
        VerifiedEncodedBody::Pack(metadata) => *metadata,
        VerifiedEncodedBody::Chunk(_) => {
            return Err(invalid("metadata inspection returned a chunk"));
        }
    };
    if metadata.detached_index_status() != DetachedIndexStatus::Matches
        || metadata.pack_identity() != backing.pack_identity()
    {
        return Err(invalid(
            "retained manifest pack identity or detached index disagrees",
        ));
    }
    Ok(metadata)
}

pub(super) fn check_key(key: &BodyKey, claim: &PublicationClaim) -> io::Result<()> {
    if claim.canonical_manifest().is_none()
        || key
            != &(BodyKey {
                kind: BodyKind::Sealed as i32,
                descriptor: claim.descriptor().encode(),
                ..Default::default()
            })
    {
        return Err(invalid(
            "sealed candidate differs from retained canonical manifest",
        ));
    }
    Ok(())
}

pub(super) fn manifest_from_pack(
    bytes: &[u8],
    original: &PublicationClaim,
    range: ByteRange,
    profile: &ChunkProfile,
    limits: terrane::host::cache::HostReadLimits,
) -> io::Result<PublicationClaim> {
    let reader = verification::bounded_pack(bytes, limits)?;
    let entry = reader
        .entries()
        .iter()
        .find(|entry| {
            entry.kind() == EntryKind::Manifest
                && entry.hash().as_slice() == original.descriptor().digest()
        })
        .ok_or_else(|| invalid("retained manifest is absent from actual metadata pack"))?;
    if reader.header().class() != PackClass::Meta
        || entry.offset() != range.start
        || u64::from(entry.body_len()) != range.length
        || range.length != original.descriptor().size()
    {
        return Err(invalid(
            "retained manifest range differs from actual pack record",
        ));
    }
    if entry.plaintext_len() as usize > limits.max_allocation_bytes {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "manifest exceeds recovery read budget",
        ));
    }
    let digest = entry.hash();
    let canonical = reader
        .read(
            EntryKind::Manifest,
            digest,
            &NativeBodyDecoder::without_dictionaries(profile),
        )
        .map_err(invalid)?;
    if Some(canonical.as_slice()) != original.canonical_manifest() {
        return Err(invalid(
            "actual manifest differs from independently retained canonical bytes",
        ));
    }
    PublicationClaim::new(
        original.domain().to_owned(),
        PublicationRecipe::Manifest {
            object: original.descriptor().clone(),
            canonical_manifest: canonical,
        },
        profile,
    )
    .map_err(invalid)
}

pub(super) fn verify_plaintext(
    claim: &PublicationClaim,
    reader: &mut impl Read,
    budget: usize,
) -> io::Result<()> {
    let manifest = claim
        .manifest()
        .ok_or_else(|| invalid("sealed recovery requires a canonical manifest"))?;
    if manifest
        .chunks
        .iter()
        .any(|chunk| chunk.length > budget as u64)
    {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "manifest chunk exceeds recovery plaintext budget",
        ));
    }
    claim.verify_reader(reader)
}

pub(super) fn verify_file_plaintext(
    claim: &PublicationClaim,
    file: &File,
    budget: usize,
) -> io::Result<()> {
    verify_plaintext(claim, &mut PositionedReader { file, offset: 0 }, budget)
}

pub(super) fn manifest_residences(
    claim: &PublicationClaim,
    budget: usize,
) -> io::Result<Vec<ResidenceRecord>> {
    let manifest = claim
        .manifest()
        .ok_or_else(|| invalid("residence reconstruction requires a manifest"))?;
    // Bound the derived record payload before allocation. This does not claim
    // to predict allocator overhead, native allocation or future quota charge.
    let per_record = std::mem::size_of::<ResidenceRecord>() + 128;
    if manifest
        .chunks
        .len()
        .checked_mul(per_record)
        .is_none_or(|bytes| bytes > budget)
    {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "manifest residences exceed recovery allocation budget",
        ));
    }
    let object: String = claim
        .descriptor()
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut records = Vec::new();
    records
        .try_reserve_exact(manifest.chunks.len())
        .map_err(invalid)?;
    let mut offset = 0_u64;
    for chunk in &manifest.chunks {
        records.push(ResidenceRecord {
            chunk: chunk
                .digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            object: object.clone(),
            offset,
            length: chunk.length,
        });
        offset = offset
            .checked_add(chunk.length)
            .ok_or_else(|| invalid("manifest residence range overflow"))?;
    }
    if offset != claim.plaintext_size() {
        return Err(invalid("manifest residences do not cover the adopted body"));
    }
    Ok(records)
}

fn check_project(context: &NativeRecoveryInspector, file: &File) -> io::Result<NativeProject> {
    let flags = rustix::fs::fcntl_getfl(file)?;
    let metadata = file.metadata()?;
    let project = NativeProject::inspect(file)?;
    if flags.intersects(
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR,
    ) || !metadata.is_file()
        || metadata.nlink() == 0
        || metadata.dev() != context.layout.directory_binding("layout-root")?.0
        || (metadata.dev(), metadata.ino()) != (project.device, project.inode)
        || project.project_id != context.project_id
    {
        return Err(invalid(
            "manifest recovery file has foreign descriptor or project custody",
        ));
    }
    Ok(project)
}

/// Streams the retained actual inode without altering its shared open-description cursor.
struct PositionedReader<'file> {
    file: &'file File,
    offset: u64,
}

impl Read for PositionedReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read_at(output, self.offset)?;
        self.offset = self
            .offset
            .checked_add(count as u64)
            .ok_or_else(|| invalid("sealed positioned-read offset overflow"))?;
        Ok(count)
    }
}
