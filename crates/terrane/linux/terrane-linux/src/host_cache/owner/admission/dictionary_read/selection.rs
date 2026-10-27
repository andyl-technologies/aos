//! Selects flat read nodes from original registered jobs and dependency edges.

use super::*;
use crate::host_cache::owner::admission::{Input, backing};
use std::os::unix::fs::MetadataExt;
use terrane_sdk::pack::{PackClass, PackReader};

/// Selects a completed source in this physical worker's actual registry.
///
/// # Errors
/// Refuses missing sources, poisoned custody or malformed original pack metadata.
pub(super) fn find(
    executor: &NativeOwnerExecutor,
    current: Option<&Arc<Mutex<AdmissionJob>>>,
    digest: &Digest,
    original: Option<&File>,
) -> io::Result<Arc<Mutex<AdmissionJob>>> {
    let original = original.map(File::metadata).transpose()?;
    // Prefer the existing standalone registration when both representations
    // exist. A damaged chosen original is an error, never a source fallback.
    for standalone in [true, false] {
        for resource in executor.admission_jobs() {
            if current.is_some_and(|current| Arc::ptr_eq(resource, current)) {
                continue;
            }
            let job = backing::lock(resource)?;
            if let Some(original) = &original {
                let Some(file) = job.files.last().and_then(|member| member.readonly.as_ref())
                else {
                    continue;
                };
                let current = file.metadata()?;
                if (current.dev(), current.ino()) != (original.dev(), original.ino()) {
                    continue;
                }
            }
            if job.complete
                && matches!(&job.input, Input::Chunk { .. }) == standalone
                && contains(&job, digest)?
            {
                return Ok(Arc::clone(resource));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "dictionary is not genuinely admitted by this owner",
    ))
}

/// Recognizes an identity in a source's immutable verified input.
///
/// # Errors
/// Refuses malformed data packs or a changed pack class.
pub(super) fn contains(job: &AdmissionJob, digest: &Digest) -> io::Result<bool> {
    match &job.input {
        Input::Chunk { descriptor, .. } => Ok(descriptor.digest() == digest),
        Input::DataPack { pack, .. } => {
            let reader = PackReader::open(pack).map_err(io::Error::other)?;
            if reader.header().class() != PackClass::Data {
                return Err(invalid("dictionary source changed its data pack class"));
            }
            Ok(reader.entries().iter().any(|entry| {
                entry.kind().identity_kind() == IdentityKind::Chunk && entry.hash() == digest
            }))
        }
        Input::Metadata { .. } => Ok(false),
    }
}

/// Captures a bounded flat closure of original source members and codec edges.
///
/// # Errors
/// Refuses incomplete custody, changed native backing, cycles or exceeded bounds.
pub(super) fn capture(
    owner: &Custody,
    custody: &Arc<Mutex<Custody>>,
    source: &Arc<Mutex<AdmissionJob>>,
    digest: &Digest,
    observed: bool,
) -> io::Result<DictionaryRead> {
    check_snapshot(owner)?;
    let config = &owner.preparation.config;
    let mut read = DictionaryRead {
        layout: Arc::clone(owner.preparation.layout()),
        identity: TERRANE_V1
            .from_digest(IdentityKind::Chunk, digest)
            .map_err(io::Error::other)?,
        sources: Vec::new(),
        nodes: Vec::new(),
        profile: config.location.chunk_profile().clone(),
        limit: config.reads.max_allocation_bytes,
        project: config.project_id,
        uid: config.content_uid,
        gid: config.content_gid,
        object_root: false,
    };
    let mut next = Some((Arc::clone(source), *digest));
    while let Some((resource, digest)) = next {
        if read.nodes.len() >= config.state.records {
            return Err(invalid("dictionary read exceeds its original member bound"));
        }
        let job = backing::lock(&resource)?;
        if !job.complete || !Arc::ptr_eq(&job.custody, custody) {
            return Err(invalid("dictionary lost completed original owner custody"));
        }
        state::check_registration(owner, &job)?;
        let source_index = if let Some(position) = read
            .sources
            .iter()
            .position(|source| Arc::ptr_eq(&source.job, &resource))
        {
            position
        } else {
            let source = bind(owner, &resource, &job, observed)?;
            read.sources
                .try_reserve_exact(1)
                .map_err(io::Error::other)?;
            read.sources.push(source);
            read.sources.len() - 1
        };
        if read
            .nodes
            .iter()
            .any(|node| node.source == source_index && node.identity.digest() == digest)
        {
            return Err(invalid("dictionary original source graph contains a cycle"));
        }
        let node = node(&job, source_index, &digest)?;
        if node.range.len() > read.limit || node.length > read.limit {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "dictionary original range exceeds configured read window",
            ));
        }
        next = match node.codec {
            Codec::ZstdDictionary(digest) => {
                if matches!(&job.input, Input::DataPack { .. }) && contains(&job, &digest)? {
                    Some((Arc::clone(&resource), digest))
                } else {
                    Some((external(&job, &digest)?, digest))
                }
            }
            _ => None,
        };
        read.nodes.try_reserve_exact(1).map_err(io::Error::other)?;
        read.nodes.push(node);
    }
    if read.nodes.is_empty() {
        return Err(invalid("dictionary read has no original node"));
    }
    read.check_native()?;
    read.check_bytes()?;
    Ok(read)
}

fn bind(
    owner: &Custody,
    resource: &Arc<Mutex<AdmissionJob>>,
    job: &AdmissionJob,
    observed: bool,
) -> io::Result<Source> {
    if observed && job.read_observation.is_none() {
        return Err(invalid(
            "dictionary read lacks original publisher observation",
        ));
    }
    if let Some(observation) = &job.read_observation {
        observation.check_readable()?;
    }
    let mut members = Vec::new();
    members.try_reserve_exact(2).map_err(io::Error::other)?;
    let expected = match &job.input {
        Input::Chunk { encoded, .. } if job.files.len() == 1 => vec![encoded],
        Input::DataPack { pack, index, .. } if job.files.len() == 2 => vec![index, pack],
        _ => {
            return Err(invalid(
                "dictionary source lost its original member closure",
            ));
        }
    };
    for (original, expected) in job.files.iter().zip(expected) {
        let stamp = original.read_stamp(owner).inspect_err(|_| {
            if let Some(observation) = &job.read_observation {
                observation.reject(1);
            }
        })?;
        members.push(ReadMember::bind(original, Arc::clone(expected), stamp)?);
    }
    if members.len() == 2
        && members[0].inode.0 == members[1].inode.0
        && members[0].inode.1 == members[1].inode.1
    {
        return Err(invalid("dictionary source pair aliases one original inode"));
    }
    let container = match &job.input {
        Input::DataPack { pack, .. } => Some(
            TERRANE_V1
                .calculate(IdentityKind::Pack, pack)
                .map_err(io::Error::other)?,
        ),
        _ => None,
    };
    Ok(Source {
        job: Arc::clone(resource),
        order: job.order,
        observation: job.read_observation.as_ref().map(Arc::clone),
        members,
        container,
    })
}

fn node(job: &AdmissionJob, source: usize, digest: &Digest) -> io::Result<Node> {
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Chunk, digest)
        .map_err(io::Error::other)?;
    let (range, length, encoded, expected_codec) = match &job.input {
        Input::Chunk {
            descriptor,
            encoded,
            ..
        } if descriptor.digest() == digest => (
            0..encoded.len(),
            usize::try_from(descriptor.size()).map_err(io::Error::other)?,
            encoded.as_slice(),
            None,
        ),
        Input::DataPack { pack, .. } => {
            let reader = PackReader::open(pack).map_err(io::Error::other)?;
            if reader.header().class() != PackClass::Data {
                return Err(invalid("dictionary source is not a data-class pack"));
            }
            let entry = reader
                .entries()
                .iter()
                .find(|entry| {
                    entry.kind().identity_kind() == IdentityKind::Chunk && entry.hash() == digest
                })
                .ok_or_else(|| invalid("dictionary identity absent from its original pack"))?;
            let start = usize::try_from(entry.offset()).map_err(io::Error::other)?;
            let end = start
                .checked_add(entry.body_len() as usize)
                .ok_or_else(|| invalid("dictionary original range overflow"))?;
            let encoded = pack
                .get(start..end)
                .ok_or_else(|| invalid("dictionary original range absent"))?;
            (
                start..end,
                entry.plaintext_len() as usize,
                encoded,
                Some(entry.codec() as u32),
            )
        }
        _ => {
            return Err(invalid(
                "dictionary identity differs from its original source",
            ));
        }
    };
    if expected_codec.is_some_and(|codec| encoded.first().copied().map(u32::from) != Some(codec)) {
        return Err(invalid(
            "dictionary envelope differs from its original index codec",
        ));
    }
    let codec = terrane_format::codec::parse_envelope(encoded)
        .map_err(io::Error::other)?
        .codec;
    Ok(Node {
        source,
        identity,
        range,
        length,
        codec,
        final_chunk: !matches!(&job.input, Input::Chunk { position, .. }
            if *position != terrane_sdk::store::ChunkPosition::Final),
    })
}

fn external(job: &AdmissionJob, digest: &Digest) -> io::Result<Arc<Mutex<AdmissionJob>>> {
    let order = edge_order(job, digest)?;
    let mut selected = None;
    for resource in &job.dependencies {
        let source = backing::lock(resource)?;
        if source.order == order && contains(&source, digest)? {
            if selected.is_some()
                || !source.complete
                || source.order >= job.order
                || !Arc::ptr_eq(&source.custody, &job.custody)
            {
                return Err(invalid(
                    "dictionary source changed its original dependency order",
                ));
            }
            selected = Some(Arc::clone(resource));
        }
    }
    selected.ok_or_else(|| invalid("dictionary lacks its original external dependency"))
}

/// Borrows an original edge's source order without minting source authority.
///
/// # Errors
/// Refuses missing or duplicate edge records in actual admission custody.
pub(super) fn edge_order(job: &AdmissionJob, digest: &Digest) -> io::Result<u64> {
    let mut matches = job
        .dictionary_edges
        .iter()
        .filter(|(edge, _)| edge == digest);
    let (_, order) = matches
        .next()
        .ok_or_else(|| invalid("dictionary lacks its original selected edge"))?;
    if matches.next().is_some() {
        return Err(invalid("dictionary repeats an original selected edge"));
    }
    Ok(*order)
}
