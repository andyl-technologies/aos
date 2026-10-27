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
pub(super) struct DictionaryRead {
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    identity: Identity,
    sources: Vec<Source>,
    nodes: Vec<Node>,
    profile: ChunkProfile,
    limit: usize,
    project: u32,
    uid: u32,
    gid: u32,
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
}

impl DictionaryRead {
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
    pub(super) fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Checks actual protection separately from read-only native custody.
    ///
    /// # Errors
    /// Refuses another root, changed original observations or durable promises.
    pub(super) fn check_protected(&self, owner: &Custody) -> io::Result<()> {
        check_snapshot(owner)?;
        if !Arc::ptr_eq(&self.layout, owner.preparation.layout())
            || self.project != owner.preparation.config.project_id
        {
            return Err(invalid("dictionary read belongs to another native owner"));
        }
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
        self.check_native()
    }

    /// Decodes actual positioned reads while retaining only adjacent plaintexts.
    ///
    /// # Errors
    /// Refuses changed bytes or codec edges, invalid content and exceeded bounds.
    pub(super) fn read_verified(&self) -> io::Result<Vec<u8>> {
        self.check_native()?;
        let result = (|| {
            self.check_bytes()?;
            let mut plaintext: Option<Vec<u8>> = None;
            let mut previous = None;
            for node in self.nodes.iter().rev() {
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
                    true,
                    &node.identity,
                    plaintext.as_deref(),
                )
                .map_err(io::Error::other)?;
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
                previous = Some(
                    node.identity
                        .terrane_v1_digest()
                        .map_err(io::Error::other)?,
                );
            }
            self.check_bytes()?;
            plaintext.ok_or_else(|| invalid("dictionary read chain is empty"))
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
    pub(super) fn retains(&self, resource: &Arc<Mutex<AdmissionJob>>) -> bool {
        self.sources
            .iter()
            .any(|source| Arc::ptr_eq(&source.job, resource))
    }

    /// Includes every dictionary identity and its original whole-pack container.
    pub(super) fn digests(&self) -> impl Iterator<Item = &[u8]> {
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
    let super::Input::DataPack { pack, .. } = &job.input else {
        if job.dependencies.is_empty() && job.dictionary_edges.is_empty() {
            return Ok(Vec::new());
        }
        return Err(invalid("non-data pair retains external dictionary sources"));
    };
    let config = &owner.preparation.config;
    let digests = super::packed_body::external_dictionaries(
        pack,
        config.reads,
        config.inventory_entries.min(config.state.records),
    )?;
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
