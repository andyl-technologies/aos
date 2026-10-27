//! Measures synchronized native completion separately from project quota charge.

use super::{super::retention::Custody, Input, backing::AdmissionJob, io as native, state};
use crate::host_quota::synchronized_allocated_bytes;
use rustix::fs::{Mode, OFlags, openat};
use std::{collections::BTreeMap, fs::File, io, os::unix::fs::MetadataExt, sync::Arc};
use terrane_format::codec::Codec;

/// Reconciles actual synchronized member allocation and fresh quota before acknowledgment.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) fn finish(owner: &mut Custody, job: &mut AdmissionJob) -> io::Result<(u64, u64)> {
    verify(owner, job)?;
    let layout = owner.preparation.layout();
    let root = File::from(openat(
        &layout.root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = root.metadata()?;
    if (metadata.dev(), metadata.ino()) != layout.directory_binding("layout-root")? {
        return Err(io::Error::other("admission synchronization root replaced"));
    }
    // This actual barrier covers the complete filesystem and may wait for
    // unrelated writers. Private publisher allocations are still measured by Q.
    rustix::fs::syncfs(&root)?;
    let mut measured = BTreeMap::new();
    for member in &job.files {
        let file = member
            .readonly
            .as_ref()
            .ok_or_else(|| io::Error::other("admission member absent"))?;
        let metadata = file.metadata()?;
        measured.insert(
            (metadata.dev(), metadata.ino()),
            synchronized_allocated_bytes(file)?,
        );
    }
    let allocated = measured.values().try_fold(0u64, |sum, bytes| {
        sum.checked_add(*bytes)
            .ok_or_else(|| io::Error::other("admission allocation overflow"))
    })?;
    let mut directories = BTreeMap::new();
    for member in &job.files {
        for directory in member.parent.chain() {
            let metadata = directory.metadata()?;
            directories.insert(
                (metadata.dev(), metadata.ino()),
                synchronized_allocated_bytes(directory)?,
            );
        }
    }
    job.directory_bytes = directories.values().try_fold(0u64, |sum, bytes| {
        sum.checked_add(*bytes)
            .ok_or_else(|| io::Error::other("admission directory allocation overflow"))
    })?;
    owner.snapshot_allocated_bytes = owner
        .snapshot
        .as_ref()
        .ok_or_else(|| io::Error::other("admission snapshot absent"))
        .and_then(|(file, _)| synchronized_allocated_bytes(file))?;
    owner.directory_allocated_bytes = synchronized_allocated_bytes(&owner.directory)?;
    owner.preparation.recheck()?;
    let future = owner.state.reservations.iter().try_fold(0u64, |sum, row| {
        sum.checked_add(row.bytes)
            .ok_or_else(|| io::Error::other("admission hold sum overflow"))
    })?;
    state::check_charge(owner, future)?;
    verify(owner, job)?;
    owner.check_current()?;
    let charged = owner
        .preparation
        .quota()
        .observation()
        .charged_reserved_bytes;
    job.complete = true;
    owner.faulted = false;
    Ok((allocated, charged))
}

/// Checks actual original member bytes and every retained dependency.
///
/// # Errors
/// Refuses changed registration, incomplete pairs, dictionaries or native bytes.
pub(super) fn verify(owner: &Custody, job: &AdmissionJob) -> io::Result<()> {
    state::check_registration(owner, job)?;
    for root in dictionary_roots(owner, job)? {
        let mut next = Some(root);
        let mut previous_order = job.order;
        let mut remaining = owner.preparation.config.state.records;
        while let Some(edge) = next {
            let source = super::backing::lock(&edge.source)?;
            // Every external standalone source completed before its dependent.
            // Walk one chain at a time without recursive dependency job locks.
            if remaining == 0
                || source.order >= previous_order
                || !Arc::ptr_eq(&source.custody, &job.custody)
            {
                return Err(io::Error::other(
                    "admission dictionary order, owner or member bound changed",
                ));
            }
            let (identity, _, _) = super::chunk::checked_dictionary(owner, &source)?;
            if identity.digest() != edge.digest {
                return Err(io::Error::other(
                    "admission dictionary differs from its original envelope dependency",
                ));
            }
            next = dependency(&source)?;
            previous_order = source.order;
            remaining -= 1;
        }
    }
    match &job.input {
        Input::Chunk { encoded, .. } if job.files.len() == 1 => {
            native::check_current(owner, &job.files[0], encoded)
        }
        Input::Metadata { pack, index, .. } | Input::DataPack { pack, index, .. }
            if job.files.len() == 2 =>
        {
            native::check_current(owner, &job.files[0], index)?;
            native::check_current(owner, &job.files[1], pack)
        }
        _ => Err(io::Error::other("admission pair closure is incomplete")),
    }
}

/// Matches every external pack edge to one genuine retained standalone job.
fn dictionary_roots(owner: &Custody, job: &AdmissionJob) -> io::Result<Vec<Dependency>> {
    let Input::DataPack { pack, .. } = &job.input else {
        return dependency(job).map(|edge| edge.into_iter().collect());
    };
    let config = &owner.preparation.config;
    let digests = super::packed_body::external_dictionaries(
        pack,
        config.reads,
        config.inventory_entries.min(config.state.records),
    )?;
    if digests.len() != job.dependencies.len() {
        return Err(io::Error::other(
            "data admission changed its external dictionary closure",
        ));
    }
    let mut roots = Vec::new();
    roots
        .try_reserve_exact(digests.len())
        .map_err(io::Error::other)?;
    for digest in digests {
        let mut found = None;
        for source in &job.dependencies {
            let dictionary = super::backing::lock(source)?;
            let Input::Chunk { descriptor, .. } = &dictionary.input else {
                return Err(io::Error::other(
                    "data dictionary is not a standalone admission",
                ));
            };
            if descriptor.digest() == digest {
                if found.is_some() {
                    return Err(io::Error::other(
                        "data dictionary retains duplicate source jobs",
                    ));
                }
                found = Some(Arc::clone(source));
            }
        }
        roots.push(Dependency {
            digest,
            source: found
                .ok_or_else(|| io::Error::other("data dictionary lacks its original source job"))?,
        });
    }
    Ok(roots)
}

/// Checks each original envelope edge before following its genuine job custody.
fn dependency(job: &AdmissionJob) -> io::Result<Option<Dependency>> {
    let codec = match &job.input {
        Input::Chunk { encoded, .. } => {
            terrane_format::codec::parse_envelope(encoded)
                .map_err(io::Error::other)?
                .codec
        }
        Input::Metadata { .. } | Input::DataPack { .. } => Codec::Raw,
    };
    match (codec, job.dependencies.as_slice()) {
        (Codec::ZstdDictionary(digest), [source]) => Ok(Some(Dependency {
            digest,
            source: Arc::clone(source),
        })),
        (Codec::ZstdDictionary(_), _) => Err(io::Error::other(
            "admission lacks its original dictionary dependency",
        )),
        (_, []) => Ok(None),
        _ => Err(io::Error::other(
            "terminal admission retains unexpected dependencies",
        )),
    }
}

struct Dependency {
    digest: [u8; 32],
    source: Arc<std::sync::Mutex<AdmissionJob>>,
}
