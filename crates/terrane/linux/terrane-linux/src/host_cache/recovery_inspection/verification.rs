//! Verifies actual encoded candidates and retains derived, non-durable repair data.

use super::{
    NativeRecoveryInspector,
    dictionaries::resolve as dictionary,
    files::{CanonicalName, RetainedFile, invalid},
};
use crate::{host_cache::NativeHostLayout, publisher_local::wire::BodyKey};
use std::{collections::BTreeMap, fs::File, io, sync::Arc};
use terrane_format::{
    chunking::ChunkProfile,
    codec::Codec,
    identity::{Descriptor, Digest, Identity, IdentityKind, TERRANE_V1},
    pack_format::{RECORD_SIZE, Record, index_count},
};
use terrane_sdk::{
    host::cache::{
        HostDomainLocation, HostReadLimits, ReconstructedPackIndex, inspect_standalone_length,
        maximum_encoded_chunk_bytes, reconstruct_pack_index,
    },
    pack::{EntryKind, FOOTER_SIZE, HEADER_SIZE, IndexEntry, PackId, PackReader},
    repository::MetadataValidator,
};

/// Describes the observed detached index, never a future namespace guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetachedIndexStatus {
    /// No canonical index existed at inspection; creation still requires no-replace.
    Missing,
    /// Actual detached bytes equal the header and authoritative trailing index.
    Matches,
    /// An actual retained index disagrees; it must not be silently overwritten.
    Mismatch,
}

/// Retains actual source custody and exact derived index bytes without repairing.
///
/// Construction verifies every pack body, metadata schema and dictionary, the
/// configured profile and canonical pack ID. The physical owner must separately
/// reserve and reconcile actual charges, publish durably and complete recovery.
pub struct DerivedIndexRepair {
    pack: RetainedFile,
    index: Option<RetainedFile>,
    dependencies: Vec<VerifiedDependency>,
    dictionary_edges: Vec<(Digest, usize)>,
    derived: ReconstructedPackIndex,
    status: DetachedIndexStatus,
    index_hash: Option<blake3::Hash>,
}

impl DerivedIndexRepair {
    /// Borrows the actual read-only source pack, with no cursor assumption.
    pub fn pack_file(&self) -> &File {
        self.pack.file()
    }

    /// Borrows the actual canonical pack shard directory retained by inspection.
    pub fn parent_file(&self) -> &File {
        self.pack.parent()
    }

    /// Returns the existing random pack key identifier.
    pub fn pack_id(&self) -> PackId {
        self.derived.pack_id()
    }

    /// Borrows the identity verified over the complete source pack bytes.
    pub fn pack_identity(&self) -> &Identity {
        self.derived.pack_identity()
    }

    /// Borrows exact existing-format detached index bytes awaiting owner effects.
    pub fn index_bytes(&self) -> &[u8] {
        self.derived.bytes()
    }

    /// Borrows genuine retained domain roots and the provisioning guard.
    pub fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        &self.pack.context().layout
    }

    /// Returns the captured detached-index observation, not current absence proof.
    pub fn detached_index_status(&self) -> DetachedIndexStatus {
        self.status
    }

    /// Borrows the actual index inode when inspection found one, including mismatch.
    pub fn present_index_file(&self) -> Option<&File> {
        self.index.as_ref().map(RetainedFile::file)
    }

    /// Returns finite read and inventory policy from the original preparation.
    pub(in crate::host_cache) fn read_policy(&self) -> (HostReadLimits, usize) {
        (
            self.pack.context().reads,
            self.pack.context().max_candidates,
        )
    }

    /// Borrows exact external dictionary edges and their inspected original files.
    ///
    /// # Errors
    /// Refuses changed native custody or a lost original dependency binding.
    pub(in crate::host_cache) fn dictionary_sources(&self) -> io::Result<Vec<(Digest, &File)>> {
        self.check_current()?;
        let mut sources = Vec::new();
        sources
            .try_reserve_exact(self.dictionary_edges.len())
            .map_err(io::Error::other)?;
        for (digest, index) in &self.dictionary_edges {
            let source = self
                .dependencies
                .get(*index)
                .ok_or_else(|| invalid("inspected dictionary lost its original source"))?;
            sources.push((*digest, source.source.file()));
        }
        Ok(sources)
    }

    /// Borrows one exact external edge's original source file.
    ///
    /// # Errors
    /// Refuses changed sources and missing or duplicate original edge bindings.
    pub(in crate::host_cache) fn dictionary_source(&self, digest: &Digest) -> io::Result<&File> {
        self.check_current()?;
        let mut edges = self
            .dictionary_edges
            .iter()
            .filter(|(edge, _)| edge == digest);
        let (_, index) = edges
            .next()
            .ok_or_else(|| invalid("inspected external dictionary edge absent"))?;
        if edges.next().is_some() {
            return Err(invalid("inspected external dictionary edge is ambiguous"));
        }
        self.dependencies
            .get(*index)
            .map(|source| source.source.file())
            .ok_or_else(|| invalid("inspected dictionary source disappeared"))
    }

    /// Reads a chunk's original envelope from the independently verified pack.
    ///
    /// The descriptor comes from the original verified record. Whole-pack and
    /// dictionary-source hashes are checked before and after selection, using
    /// the retained native descriptors. No pathname selects replacement bytes.
    /// The returned payload reuses the bounded pack buffer and preserves the
    /// exact stored codec, including an ordinary dictionary dependency.
    ///
    /// This read grants no admission, pin or serving authority. An owner importing
    /// the bytes must fund its actual writes and retain the dictionary's genuine
    /// admission before admitting a dependent chunk. This is a content read;
    /// metadata-only GC must use its separate tracing path.
    ///
    /// # Errors
    /// Refuses a foreign identity profile or kind, an absent chunk, exceeded
    /// allocation bounds, and changed pack, index or dictionary-source custody.
    pub fn read_chunk_encoded(&self, identity: &Identity) -> io::Result<(Descriptor, Vec<u8>)> {
        self.check_current()?;
        let limits = self.pack.context().reads;
        let bytes = self.pack.read(limits.max_allocation_bytes)?;
        TERRANE_V1
            .verify(self.pack_identity(), &bytes)
            .map_err(invalid)?;
        let selected = super::packed_chunks::select(bytes, identity, limits)?;
        self.check_current()?;
        Ok(selected)
    }

    /// Reads the exact original verified pair without granting admission authority.
    ///
    /// # Errors
    /// Refuses changed sources, an absent or mismatched index, and a pair larger
    /// than the original authenticated preparation's bounded read window.
    pub(in crate::host_cache) fn pair_bytes(&self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        self.check_current()?;
        if self.status != DetachedIndexStatus::Matches {
            return Err(invalid(
                "recovered metadata requires a matching actual index",
            ));
        }
        let limit = self.pack.context().reads.max_allocation_bytes;
        let pack = self.pack.read(limit)?;
        TERRANE_V1
            .verify(self.pack_identity(), &pack)
            .map_err(invalid)?;
        let index = self
            .index
            .as_ref()
            .ok_or_else(|| invalid("matched index is absent"))?;
        let remaining = limit
            .checked_sub(pack.len())
            .ok_or_else(|| invalid("metadata pair exceeds read window"))?;
        let index = index.read(remaining)?;
        if index != self.index_bytes() {
            return Err(invalid("recovered detached index changed"));
        }
        self.check_current()?;
        Ok((pack, index))
    }

    /// Rechecks source paths, project/root custody, dependencies and full pack hash.
    ///
    /// An originally missing index may now exist. The owner must use no-replace
    /// publication and independently verify a raced existing index. This method
    /// grants neither repair permission nor evidence of durable completion.
    ///
    /// # Errors
    /// Refuses stale confinement, roots, sources, project assignments or pack bytes.
    pub fn check_pack_current(&self) -> io::Result<()> {
        for source in &self.dependencies {
            source.check_current()?;
        }
        let bytes = self
            .pack
            .read(self.pack.context().reads.max_allocation_bytes)?;
        TERRANE_V1
            .verify(self.pack_identity(), &bytes)
            .map_err(invalid)?;
        self.pack.recheck()
    }

    /// Rechecks the pack and any originally present detached-index incarnation.
    ///
    /// # Errors
    /// Refuses changed pack/dependency custody or a modified/replaced observed index.
    pub fn check_current(&self) -> io::Result<()> {
        self.check_pack_current()?;
        if let Some(index) = &self.index {
            index.recheck()?;
            if let Some(expected) = self.index_hash {
                index.check_hash(expected)?;
            }
        }
        Ok(())
    }

    /// Correlates actual retained session identity without asserting a drain epoch.
    pub(in crate::host_cache) fn matches_client(
        &self,
        client: &crate::publisher_local::client::Client<HostDomainLocation>,
    ) -> bool {
        std::ptr::eq(self.pack.context().session.as_ref(), client)
    }
}

/// Retains independently verified bytes without granting adoption or service.
pub enum VerifiedEncodedBody {
    /// Contains a verified standalone chunk and its actual retained dependencies.
    Chunk(Arc<VerifiedStandaloneChunk>),
    /// Contains a complete verified pack and its captured detached-index state.
    Pack(Arc<DerivedIndexRepair>),
}

/// Retains a verified actual standalone chunk, without manifest boundary context.
///
/// Final-chunk verification is used because standalone filenames do not encode
/// an object's final/nonfinal position. No object reconstruction is authorized.
pub struct VerifiedStandaloneChunk {
    source: RetainedFile,
    dependencies: Vec<VerifiedDependency>,
    identity: Identity,
    length: usize,
    encoded_hash: blake3::Hash,
    descriptor: Descriptor,
    codec: u32,
}

impl VerifiedStandaloneChunk {
    /// Borrows the descriptor checked against actual decoded bytes.
    pub(in crate::host_cache) fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    /// Returns the codec checked against the canonical name and envelope.
    pub(in crate::host_cache) fn codec(&self) -> u32 {
        self.codec
    }

    /// Borrows the original native domain roots retained during inspection.
    pub(in crate::host_cache) fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        &self.source.context().layout
    }

    /// Reads the original bounded bytes without treating a later filename as proof.
    ///
    /// # Errors
    /// Refuses changed original custody, bytes or dependency inodes.
    pub(in crate::host_cache) fn encoded(&self) -> io::Result<Vec<u8>> {
        self.check_current()?;
        let bytes = self
            .source
            .read(self.source.context().reads.max_allocation_bytes)?;
        if blake3::hash(&bytes) != self.encoded_hash {
            return Err(invalid("verified standalone bytes changed during recovery"));
        }
        self.check_current()?;
        Ok(bytes)
    }

    /// Borrows the verified plaintext identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Returns the verified plaintext length.
    pub fn plaintext_length(&self) -> usize {
        self.length
    }

    /// Borrows the retained actual read-only encoded file.
    pub fn file(&self) -> &File {
        self.source.file()
    }

    /// Rechecks actual canonical source bytes and dictionary incarnations.
    ///
    /// # Errors
    /// Refuses changed roots, process confinement, project assignment or source inodes.
    pub fn check_current(&self) -> io::Result<()> {
        self.source.check_hash(self.encoded_hash)?;
        for dependency in &self.dependencies {
            dependency.check_current()?;
        }
        Ok(())
    }
}

/// Retains the exact verified dependency bytes, without relying on timestamp resolution.
pub(super) struct VerifiedDependency {
    pub(super) source: RetainedFile,
    pub(super) encoded_hash: blake3::Hash,
}

impl VerifiedDependency {
    pub(super) fn check_current(&self) -> io::Result<()> {
        self.source.check_hash(self.encoded_hash)
    }
}

pub(super) fn chunk(
    context: &NativeRecoveryInspector,
    key: &BodyKey,
    publisher: &File,
    packs: &[PackId],
) -> io::Result<VerifiedEncodedBody> {
    let descriptor = Descriptor::decode(&TERRANE_V1, &key.descriptor).map_err(invalid)?;
    if TERRANE_V1.kind(descriptor.domain()).map_err(invalid)? != IdentityKind::Chunk
        || key.codec > 2
        || !key.pack_id.is_empty()
    {
        return Err(invalid("standalone recovery key has another kind or codec"));
    }
    let length = usize::try_from(descriptor.size()).map_err(invalid)?;
    check_plaintext_budget(length, context.reads.max_allocation_bytes)?;
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Chunk, descriptor.digest())
        .map_err(invalid)?;
    let source = RetainedFile::open(
        context,
        CanonicalName::Chunk {
            digest: hex(descriptor.digest()),
            codec: key.codec,
        },
    )?;
    source.matches(publisher)?;
    let bound = maximum_encoded_chunk_bytes(context.layout.layout().chunk_profile())
        .map_err(invalid)?
        .min(context.reads.max_allocation_bytes);
    let encoded = source.read(bound)?;
    if encoded.first().copied().map(u32::from) != Some(key.codec) {
        return Err(invalid(
            "actual standalone codec differs from inventory key",
        ));
    }
    if bounded_standalone_length(
        &encoded,
        context.layout.layout().chunk_profile(),
        context.reads.max_allocation_bytes,
    )? != length
    {
        return Err(invalid(
            "actual standalone length differs from inventory descriptor",
        ));
    }
    let mut dependencies = Vec::new();
    let dictionary = match terrane_format::codec::parse_envelope(&encoded)
        .map_err(invalid)?
        .codec
    {
        Codec::ZstdDictionary(digest) => Some(dictionary(
            context,
            &digest,
            None,
            packs,
            &mut dependencies,
            context.reads.max_allocation_bytes,
        )?),
        _ => None,
    };
    terrane_sdk::codec::decode_verified(
        &encoded,
        length,
        context.layout.layout().chunk_profile(),
        true,
        &identity,
        dictionary.as_deref(),
    )
    .map_err(invalid)?;
    let chunk = VerifiedStandaloneChunk {
        source,
        dependencies,
        identity,
        length,
        encoded_hash: blake3::hash(&encoded),
        descriptor,
        codec: key.codec,
    };
    chunk.check_current()?;
    Ok(VerifiedEncodedBody::Chunk(Arc::new(chunk)))
}

pub(super) fn pack(
    context: &NativeRecoveryInspector,
    id: PackId,
    publisher: Option<&File>,
    packs: &[PackId],
) -> io::Result<VerifiedEncodedBody> {
    let source = RetainedFile::open(context, CanonicalName::Pack { id, index: false })?;
    if let Some(publisher) = publisher {
        source.matches(publisher)?;
    }
    let bytes = source.read(context.reads.max_allocation_bytes)?;
    let reader = bounded_pack(&bytes, context.reads)?;
    if reader.header().id() != id {
        return Err(invalid("actual pack header differs from canonical pack ID"));
    }
    let mut dictionaries = BTreeMap::new();
    let mut dependencies = Vec::new();
    let mut dictionary_bytes = 0_usize;
    let mut dictionary_edges = Vec::new();
    for entry in reader
        .entries()
        .iter()
        .filter(|entry| entry.kind() == EntryKind::Chunk)
    {
        let start = usize::try_from(entry.offset()).map_err(invalid)?;
        let end = start
            .checked_add(entry.body_len() as usize)
            .ok_or_else(|| invalid("pack body range overflow"))?;
        let encoded = bytes
            .get(start..end)
            .ok_or_else(|| invalid("pack body range is absent"))?;
        if let Codec::ZstdDictionary(digest) = terrane_format::codec::parse_envelope(encoded)
            .map_err(invalid)?
            .codec
            && let std::collections::btree_map::Entry::Vacant(slot) = dictionaries.entry(digest)
        {
            let remaining = context
                .reads
                .max_allocation_bytes
                .checked_sub(dictionary_bytes)
                .ok_or_else(|| invalid("dictionary budget overflow"))?;
            let (plaintext, source) = super::dictionaries::resolve_with_source(
                context,
                &digest,
                Some((&reader, &bytes)),
                packs,
                &mut dependencies,
                remaining,
            )?;
            if let Some(source) = source {
                dictionary_edges
                    .try_reserve_exact(1)
                    .map_err(io::Error::other)?;
                dictionary_edges.push((digest, source));
            }
            dictionary_bytes = dictionary_bytes
                .checked_add(plaintext.len())
                .ok_or_else(|| invalid("dictionary budget overflow"))?;
            if dictionary_bytes > context.reads.max_allocation_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "pack dictionaries exceed aggregate read budget",
                ));
            }
            slot.insert(plaintext);
        }
    }
    let profile = context.layout.layout().chunk_profile();
    let derived = reconstruct_pack_index(
        &bytes,
        id,
        profile,
        &MetadataValidator::new(profile.clone()),
        &dictionaries,
        context.reads,
    )
    .map_err(invalid)?;
    let index = match RetainedFile::open(context, CanonicalName::Pack { id, index: true }) {
        Ok(index) => Some(index),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let (status, index_hash) = match &index {
        None => (DetachedIndexStatus::Missing, None),
        Some(index) if index.file().metadata()?.len() != derived.bytes().len() as u64 => {
            (DetachedIndexStatus::Mismatch, None)
        }
        Some(index) => {
            let bytes = index.read(context.reads.max_allocation_bytes)?;
            let status = if bytes == derived.bytes() {
                DetachedIndexStatus::Matches
            } else {
                DetachedIndexStatus::Mismatch
            };
            (status, Some(blake3::hash(&bytes)))
        }
    };
    let plan = DerivedIndexRepair {
        pack: source,
        index,
        dependencies,
        dictionary_edges,
        derived,
        status,
        index_hash,
    };
    plan.check_current()?;
    Ok(VerifiedEncodedBody::Pack(Arc::new(plan)))
}

/// Checks frame-declared plaintext against policy before any decode allocation.
pub(super) fn bounded_standalone_length(
    encoded: &[u8],
    profile: &ChunkProfile,
    plaintext_budget: usize,
) -> io::Result<usize> {
    let length = inspect_standalone_length(encoded, profile).map_err(invalid)?;
    check_plaintext_budget(length, plaintext_budget)?;
    Ok(length)
}

pub(super) fn check_plaintext_budget(length: usize, plaintext_budget: usize) -> io::Result<()> {
    if length > plaintext_budget {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "decoded plaintext exceeds recovery allocation budget",
        ));
    }
    Ok(())
}

/// PackReader allocates decoded records. Bound those before parsing untrusted counts.
///
/// # Errors
/// Refuses invalid framing, unchecked record allocations and exceeded read bounds.
pub(in crate::host_cache) fn bounded_pack(
    bytes: &[u8],
    limits: HostReadLimits,
) -> io::Result<PackReader<'_>> {
    let footer = bytes
        .len()
        .checked_sub(FOOTER_SIZE)
        .ok_or_else(|| invalid("pack footer absent"))?;
    let offset = bytes
        .get(footer..footer + 8)
        .ok_or_else(|| invalid("pack footer absent"))?;
    let offset = usize::try_from(u64::from_le_bytes(offset.try_into().map_err(invalid)?))
        .map_err(invalid)?;
    let index = bytes
        .get(offset..footer)
        .ok_or_else(|| invalid("pack index range invalid"))?;
    let count = index_count(index, RECORD_SIZE).map_err(invalid)?;
    let allocation = count
        .checked_mul(std::mem::size_of::<Record>().max(std::mem::size_of::<IndexEntry>()))
        .ok_or_else(|| invalid("pack index allocation overflow"))?;
    if bytes.len() > limits.max_allocation_bytes
        || allocation > limits.max_allocation_bytes
        || index
            .len()
            .checked_add(HEADER_SIZE)
            .is_none_or(|length| length > limits.max_allocation_bytes)
    {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "pack index exceeds read budget",
        ));
    }
    PackReader::recover(bytes).map_err(invalid)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
