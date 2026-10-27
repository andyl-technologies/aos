//! Reads flat dictionary chains from genuine original admission resources.
//!
//! Each source retains its original job and one or two native members. Chain
//! nodes select ranges in those sources; reverse decoding never recursively
//! locks jobs or retains every intermediate plaintext at once.

mod selection;

use super::{AdmissionJob, read_member::ReadMember, state};
use crate::{
    host_cache::{
        NativeHostLayout,
        owner::{
            publication::residence::check_snapshot,
            retention::{Custody, NativeOwnerExecutor},
        },
    },
    publisher_local::client::EncodedReadObservation,
};
use std::{
    fs::File,
    io,
    ops::Range,
    sync::{Arc, Mutex},
};
use terrane_format::{
    chunking::ChunkProfile,
    codec::Codec,
    identity::{Digest, Identity, IdentityKind, TERRANE_V1},
};
use terrane_sdk::host::cache::HostDomainLocation;

/// Retains the original native source closure for one external dictionary.
pub(in crate::host_cache::owner) struct DictionaryRead {
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    identity: Identity,
    sources: Vec<Source>,
    nodes: Vec<Node>,
    profile: ChunkProfile,
    limit: usize,
    project: u32,
    uid: u32,
    gid: u32,
    object_root: bool,
}

struct Source {
    job: Arc<Mutex<AdmissionJob>>,
    order: u64,
    observation: Option<Arc<EncodedReadObservation>>,
    members: Vec<ReadMember>,
    container: Option<Identity>,
}

struct Node {
    source: usize,
    identity: Identity,
    range: Range<usize>,
    length: usize,
    codec: Codec,
    final_chunk: bool,
}

impl DictionaryRead {
    /// Selects and retains one actual original dictionary source closure.
    ///
    /// # Errors
    /// Refuses unavailable dictionaries, foreign custody or invalid source graphs.
    pub(in crate::host_cache::owner) fn select(
        executor: &NativeOwnerExecutor,
        owner: &Custody,
        digest: &Digest,
    ) -> io::Result<Self> {
        let source = selection::find(executor, None, digest, None)?;
        Self::prepare(executor, owner, &source, digest)
    }

    /// Checks that every retained original still belongs to this physical worker.
    ///
    /// # Errors
    /// Refuses another worker, a missing original registry entry or lost protection.
    pub(in crate::host_cache::owner) fn check_registered(
        &self,
        executor: &NativeOwnerExecutor,
        owner: &Custody,
    ) -> io::Result<()> {
        executor.check_physical_worker()?;
        if self.sources.iter().any(|source| {
            !executor
                .admission_jobs()
                .iter()
                .any(|registered| Arc::ptr_eq(registered, &source.job))
        }) {
            return Err(invalid(
                "dictionary read lost its original physical registry",
            ));
        }
        self.check_protected(owner)
    }

    /// Retains a verified external dependency under the actual physical turn.
    ///
    /// # Errors
    /// Refuses another worker, unavailable observations, invalid graph or backing.
    pub(super) fn prepare(
        executor: &NativeOwnerExecutor,
        owner: &Custody,
        source: &Arc<Mutex<AdmissionJob>>,
        digest: &Digest,
    ) -> io::Result<Self> {
        executor.check_physical_worker()?;
        executor.admission_context_locked(owner)?;
        let read = selection::capture(owner, executor.custody(), source, digest, true)?;
        if read.sources.iter().any(|source| {
            !executor
                .admission_jobs()
                .iter()
                .any(|registered| Arc::ptr_eq(registered, &source.job))
        }) {
            return Err(invalid(
                "dictionary read lost its original physical registry",
            ));
        }
        read.check_protected(owner)?;
        Ok(read)
    }

    /// Borrows the actual dictionary identity selected from original inputs.
    pub(in crate::host_cache::owner) fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Requires the selected root to end at its first object chunk boundary.
    pub(super) fn require_object_boundary(&mut self) {
        self.object_root = true;
    }

    /// Checks actual protection separately from read-only native custody.
    ///
    /// # Errors
    /// Refuses another root, changed original observations or durable promises.
    pub(super) fn check_protected(&self, owner: &Custody) -> io::Result<()> {
        self.check_consumer_backing(owner)?;
        for source in &self.sources {
            let job = super::backing::lock(&source.job)?;
            if !job.complete
                || !matches!((&source.observation, &job.read_observation),
                (Some(original), Some(current)) if Arc::ptr_eq(original, current))
            {
                return Err(invalid("dictionary read changed its original observation"));
            }
            state::check_registration(owner, &job)?;
        }
        Ok(())
    }

    /// Checks consumer-held original backing independently of producer funding.
    ///
    /// # Errors
    /// Refuses another owner, stale snapshot or changed native members.
    pub(super) fn check_consumer_backing(&self, owner: &Custody) -> io::Result<()> {
        check_snapshot(owner)?;
        if !Arc::ptr_eq(&self.layout, owner.preparation.layout())
            || self.project != owner.preparation.config.project_id
        {
            return Err(invalid("dictionary read belongs to another native owner"));
        }
        self.check_native()
    }

    /// Decodes actual positioned reads while retaining only adjacent plaintexts.
    ///
    /// # Errors
    /// Refuses changed bytes or codec edges, invalid content and exceeded bounds.
    pub(in crate::host_cache::owner) fn read_verified(&self) -> io::Result<Vec<u8>> {
        self.read(false)
    }

    /// Returns the original root envelope after verifying its complete chain.
    ///
    /// # Errors
    /// Refuses changed original bytes, invalid chunk boundaries or read bounds.
    pub(super) fn read_encoded(&self) -> io::Result<Vec<u8>> {
        self.read(true)
    }

    fn read(&self, encoded_output: bool) -> io::Result<Vec<u8>> {
        self.check_native()?;
        let result = (|| {
            self.check_bytes()?;
            let mut plaintext: Option<Vec<u8>> = None;
            let mut previous = None;
            let mut original_encoded = None;
            for (position, node) in self.nodes.iter().enumerate().rev() {
                let source = &self.sources[node.source];
                let member = source
                    .members
                    .last()
                    .ok_or_else(|| invalid("dictionary original body absent"))?;
                let mut encoded = Vec::new();
                encoded
                    .try_reserve_exact(node.range.len())
                    .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
                if encoded.capacity() > self.limit {
                    return Err(io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "dictionary read allocation exceeds its configured window",
                    ));
                }
                encoded.resize(node.range.len(), 0);
                std::os::unix::fs::FileExt::read_exact_at(
                    &member.file,
                    &mut encoded,
                    u64::try_from(node.range.start).map_err(io::Error::other)?,
                )?;
                let codec = terrane_format::codec::parse_envelope(&encoded)
                    .map_err(io::Error::other)?
                    .codec;
                if codec != node.codec
                    || matches!(codec, Codec::ZstdDictionary(digest) if Some(digest) != previous)
                {
                    return Err(invalid("dictionary original envelope edge changed"));
                }
                let verified = terrane_sdk::codec::decode_verified(
                    &encoded,
                    node.length,
                    &self.profile,
                    node.final_chunk,
                    &node.identity,
                    plaintext.as_deref(),
                )
                .map_err(io::Error::other)?;
                if self.object_root
                    && position == 0
                    && self.profile.first_boundary(verified.plaintext()) != node.length
                {
                    return Err(invalid(
                        "admitted root differs from its ordered chunk boundary",
                    ));
                }
                if encoded_output && position == 0 {
                    // Return the exact bytes just verified, rather than a
                    // second read that could race another writer.
                    original_encoded = Some(encoded);
                } else {
                    let mut decoded = Vec::new();
                    decoded
                        .try_reserve_exact(verified.plaintext().len())
                        .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
                    if decoded.capacity() > self.limit {
                        return Err(io::Error::new(
                            io::ErrorKind::OutOfMemory,
                            "dictionary plaintext allocation exceeds its configured window",
                        ));
                    }
                    decoded.extend_from_slice(verified.plaintext());
                    plaintext = Some(decoded);
                }
                previous = Some(
                    node.identity
                        .terrane_v1_digest()
                        .map_err(io::Error::other)?,
                );
            }
            self.check_bytes()?;
            original_encoded
                .or(plaintext)
                .ok_or_else(|| invalid("dictionary read chain is empty"))
        })();
        if let Err(error) = &result
            && !matches!(
                error.kind(),
                io::ErrorKind::OutOfMemory | io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            )
        {
            self.reject(2);
        }
        let plaintext = result?;
        self.check_native()?;
        Ok(plaintext)
    }

    /// Checks every actual native source without policy or job locks.
    ///
    /// # Errors
    /// Refuses changed native members, failed observations or root custody.
    pub(super) fn check_native(&self) -> io::Result<()> {
        let checked = (|| {
            self.layout.recheck()?;
            for source in &self.sources {
                if let Some(observation) = &source.observation {
                    observation.check_readable()?;
                }
                for member in &source.members {
                    member.check_native(&self.layout, self.project, self.uid, self.gid)?;
                }
            }
            self.layout.recheck()
        })();
        checked.inspect_err(|_| self.reject(1))
    }

    /// Recognizes actual retained source jobs until the last consumer closes.
    pub(in crate::host_cache::owner) fn retains(
        &self,
        resource: &Arc<Mutex<AdmissionJob>>,
    ) -> bool {
        self.sources
            .iter()
            .any(|source| Arc::ptr_eq(&source.job, resource))
    }

    /// Includes every dictionary identity and its original whole-pack container.
    pub(in crate::host_cache::owner) fn digests(&self) -> impl Iterator<Item = &[u8]> {
        self.nodes.iter().map(|node| node.identity.digest()).chain(
            self.sources
                .iter()
                .filter_map(|source| source.container.as_ref().map(Identity::digest)),
        )
    }

    /// Iterates original allocations with their actual owner registration order.
    pub(super) fn original_allocations(&self) -> impl Iterator<Item = ((u64, u64), u64)> {
        self.sources.iter().flat_map(|source| {
            source
                .members
                .iter()
                .map(move |member| ((member.inode.0, member.inode.1), source.order))
        })
    }

    /// Borrows original native files for deduplicated synchronized measurement.
    pub(super) fn original_files(&self) -> impl Iterator<Item = &File> {
        self.sources
            .iter()
            .flat_map(|source| source.members.iter().map(|member| &member.file))
    }

    /// Bounds flat nodes and original member headers without copying payloads.
    ///
    /// # Errors
    /// Refuses arithmetic overflow in configured finite storage.
    pub(super) fn storage_bytes(domain: usize, records: usize) -> io::Result<usize> {
        let per_source = std::mem::size_of::<Source>()
            + std::mem::size_of::<Node>()
            + 2 * std::mem::size_of::<ReadMember>()
            + 3 * (TERRANE_V1.name().len() + TERRANE_V1.digest_len());
        records
            .checked_mul(per_source)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(domain))
            .ok_or_else(|| invalid("dictionary read header storage overflow"))
    }

    fn check_bytes(&self) -> io::Result<()> {
        for source in &self.sources {
            for member in &source.members {
                member.check_bytes()?;
            }
        }
        Ok(())
    }

    fn reject(&self, reason: u8) {
        for source in &self.sources {
            if let Some(observation) = &source.observation {
                observation.reject(reason);
            }
        }
    }
}

/// Verifies a dictionary using only this worker's actual completed admissions.
///
/// # Errors
/// Refuses missing or changed sources, invalid content or exceeded finite bounds.
pub(super) fn verify(
    executor: &NativeOwnerExecutor,
    current: Option<&Arc<Mutex<AdmissionJob>>>,
    owner: &Custody,
    digest: &Digest,
    original: Option<&File>,
) -> io::Result<(Vec<u8>, Arc<Mutex<AdmissionJob>>)> {
    let source = selection::find(executor, current, digest, original)?;
    let read = selection::capture(owner, executor.custody(), &source, digest, false)?;
    if read.sources.iter().any(|source| {
        !executor
            .admission_jobs()
            .iter()
            .any(|registered| Arc::ptr_eq(registered, &source.job))
    }) {
        return Err(invalid(
            "dictionary verification lost its original registry",
        ));
    }
    Ok((read.read_verified()?, source))
}

/// Records one verified original edge and protects its actual pack container.
///
/// # Errors
/// Refuses another owner, changed source identity/order, repeated edges or
/// exhausted allocation capacity before changing the dependent job.
pub(super) fn retain(
    job: &mut AdmissionJob,
    digest: Digest,
    source: Arc<Mutex<AdmissionJob>>,
    hashes: &mut Vec<String>,
) -> io::Result<()> {
    let dependency = super::backing::lock(&source)?;
    if !dependency.complete
        || dependency.order >= job.order
        || !Arc::ptr_eq(&dependency.custody, &job.custody)
        || !selection::contains(&dependency, &digest)?
        || job.dictionary_edges.iter().any(|(edge, _)| edge == &digest)
    {
        return Err(invalid("dictionary changed its original selected edge"));
    }
    let container = match &dependency.input {
        super::Input::DataPack { pack, .. } => Some(
            TERRANE_V1
                .calculate(IdentityKind::Pack, pack)
                .map_err(io::Error::other)?,
        ),
        _ => None,
    };
    let order = dependency.order;
    drop(dependency);
    job.dictionary_edges
        .try_reserve_exact(1)
        .map_err(io::Error::other)?;
    job.dependencies
        .try_reserve_exact(1)
        .map_err(io::Error::other)?;
    hashes.try_reserve_exact(2).map_err(io::Error::other)?;
    job.dictionary_edges.push((digest, order));
    job.dependencies.push(source);
    hashes.push(state::hex(&digest));
    if let Some(container) = container {
        hashes.push(state::hex(container.digest()));
    }
    Ok(())
}

/// Rechecks the original dependency graph without recursively locking jobs.
///
/// # Errors
/// Refuses changed registration, graph bounds or any original native bytes.
pub(super) fn check(
    owner: &Custody,
    custody: &Arc<Mutex<Custody>>,
    source: &Arc<Mutex<AdmissionJob>>,
    digest: &Digest,
) -> io::Result<()> {
    let read = selection::capture(owner, custody, source, digest, false)?;
    read.check_native()?;
    read.check_bytes()
}

/// Matches exact external envelope edges to genuine original dependency jobs.
///
/// Several dictionaries may share one pack; each retained job must participate
/// in at least one edge, and every edge selects exactly one actual source.
///
/// # Errors
/// Refuses missing, duplicate, unused or changed dependency sources and bounds.
pub(super) fn roots(
    owner: &Custody,
    job: &AdmissionJob,
) -> io::Result<Vec<(Digest, Arc<Mutex<AdmissionJob>>)>> {
    let config = &owner.preparation.config;
    let digests = match &job.input {
        super::Input::DataPack { pack, .. } => super::packed_body::external_dictionaries(
            pack,
            config.reads,
            config.inventory_entries.min(config.state.records),
        )?,
        super::Input::Chunk { encoded, .. } => match terrane_format::codec::parse_envelope(encoded)
            .map_err(io::Error::other)?
            .codec
        {
            Codec::ZstdDictionary(digest) => vec![digest],
            _ => Vec::new(),
        },
        super::Input::Metadata { .. } => Vec::new(),
    };
    if digests.len() != job.dictionary_edges.len() {
        return Err(invalid("data dictionary edge closure changed"));
    }
    let mut used = Vec::new();
    used.try_reserve_exact(job.dependencies.len())
        .map_err(io::Error::other)?;
    used.resize(job.dependencies.len(), false);
    let mut roots = Vec::new();
    roots
        .try_reserve_exact(digests.len())
        .map_err(io::Error::other)?;
    for digest in digests {
        let order = selection::edge_order(job, &digest)?;
        let mut selected = None;
        for (position, source) in job.dependencies.iter().enumerate() {
            let dependency = super::backing::lock(source)?;
            if dependency.order == order && selection::contains(&dependency, &digest)? {
                if selected.is_some()
                    || !dependency.complete
                    || dependency.order >= job.order
                    || !Arc::ptr_eq(&dependency.custody, &job.custody)
                {
                    return Err(invalid("data dictionary changed original source custody"));
                }
                used[position] = true;
                selected = Some(Arc::clone(source));
            }
        }
        roots.push((
            digest,
            selected.ok_or_else(|| invalid("data dictionary source absent"))?,
        ));
    }
    if used.iter().any(|used| !used) {
        return Err(invalid("data dictionary retains an unused source job"));
    }
    Ok(roots)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
