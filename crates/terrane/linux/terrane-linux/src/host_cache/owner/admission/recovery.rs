//! Imports original verified recovery inodes into the running admission registry.
//!
//! Import follows acknowledged Resume on the sole physical executor. A new
//! synchronized metadata hold funds the state transition; existing payload is
//! already charged. Cold promises survive, and every started job remains owned
//! if a later step fails or the Resume waiter's reply is cancelled.

use super::{AdmissionBounds, Input, backing, chunk, handoff, io as native, reconcile, state};
use crate::host_cache::{VerifiedStandaloneChunk, owner::retention::NativeOwnerExecutor};
use std::{io, sync::Arc};
use terrane_format::codec::Codec;
use terrane_sdk::store::ChunkPosition;

/// Registers and synchronizes one original independently verified canonical inode.
///
/// # Errors
/// Refuses changed native bytes, absent one-hop dictionaries, exhausted registry
/// or state capacity, insufficient quota and failed durable synchronization.
pub(in crate::host_cache::owner) async fn import(
    executor: &mut NativeOwnerExecutor,
    source: &VerifiedStandaloneChunk,
) -> io::Result<()> {
    executor
        .admission_context()?
        .check_current()
        .map_err(io::Error::other)?;
    source.check_current()?;
    let custody = Arc::clone(executor.custody());
    let encoded = Arc::new(source.encoded()?);
    {
        let owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        if !Arc::ptr_eq(source.layout(), owner.preparation.layout()) {
            return Err(io::Error::other(
                "recovered chunk belongs to another native domain",
            ));
        }
        let bounds = AdmissionBounds::new(&owner.preparation.config)?;
        bounds.check(encoded.len(), 0)?;
        bounds.check(encoded.capacity(), 0)?;
    }
    let resource = executor.register_admission(Input::Chunk {
        descriptor: source.descriptor().clone(),
        position: ChunkPosition::Final,
        encoded: Arc::clone(&encoded),
    })?;
    let result = async {
        let reservation = {
            let mut job = backing::lock(&resource)?;
            let mut owner = custody
                .lock()
                .map_err(|_| io::Error::other("recovery custody poisoned"))?;
            super::refuse_completed(executor, &owner, &resource, &job.input)?;
            let mut hashes = vec![state::hex(source.identity().digest())];
            if let Codec::ZstdDictionary(digest) = terrane_format::codec::parse_envelope(&encoded)
                .map_err(io::Error::other)?
                .codec
            {
                let (_, dependency) =
                    chunk::dictionary(executor, Some(&resource), &owner, &digest)?;
                hashes.push(state::hex(&digest));
                job.dependencies.push(dependency);
            }
            source.check_current()?;
            state::begin(executor, &mut owner, &mut job, 0, &hashes)?
        };
        super::super::snapshot::persist(executor, reservation).await?;
        let completion = {
            let mut job = backing::lock(&resource)?;
            let mut owner = custody
                .lock()
                .map_err(|_| io::Error::other("recovery custody poisoned"))?;
            state::check_registration(&owner, &job)?;
            source.check_current()?;
            let hash = state::hex(source.identity().digest());
            let parent =
                native::parent(&owner, "chunks", &[&hash[..2]], &mut job.directory_progress)?;
            let name = format!("{hash}.{}", source.codec());
            job.files.push(native::recover(
                &owner,
                parent,
                name,
                source.file(),
                &encoded,
            )?);
            super::super::snapshot::prepare(executor, &mut owner)?
        };
        super::super::snapshot::persist(executor, completion).await?;
        {
            let mut job = backing::lock(&resource)?;
            let mut owner = custody
                .lock()
                .map_err(|_| io::Error::other("recovery custody poisoned"))?;
            source.check_current()?;
            reconcile::finish(&mut owner, &mut job)?;
        }
        handoff::execute(executor, &resource).await?;
        Ok(())
    }
    .await;
    if result.is_err() {
        executor.reclaim_rejected_admission(&resource)?;
    }
    result
}

/// Registers an original verified pair without replacing either canonical inode.
///
/// # Errors
/// Refuses changed sources, unavailable dictionary admissions, invalid indexes, exhausted bounds,
/// insufficient metadata funding and failed durable registration or handoff.
pub(in crate::host_cache::owner) async fn import_metadata(
    executor: &mut NativeOwnerExecutor,
    source: &crate::host_cache::DerivedIndexRepair,
) -> io::Result<()> {
    executor
        .admission_context()?
        .check_current()
        .map_err(io::Error::other)?;
    let (pack, index) = source.pair_bytes()?;
    let pack = Arc::new(pack);
    let index = Arc::new(index);
    let data = terrane_sdk::pack::PackReader::open(&pack)
        .map_err(io::Error::other)?
        .header()
        .class()
        == terrane_sdk::pack::PackClass::Data;
    let input = if data {
        Input::DataPack {
            expected_id: source.pack_id(),
            pack: Arc::clone(&pack),
            index: Arc::clone(&index),
        }
    } else {
        Input::Metadata {
            expected_id: source.pack_id(),
            pack: Arc::clone(&pack),
            index: Arc::clone(&index),
        }
    };
    let custody = Arc::clone(executor.custody());
    let (hashes, dependencies, edges) = {
        let owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        if !Arc::ptr_eq(source.layout(), owner.preparation.layout()) {
            return Err(io::Error::other(
                "recovered metadata belongs to another native domain",
            ));
        }
        let config = &owner.preparation.config;
        let bounds = AdmissionBounds::new(config)?;
        bounds.check(pack.len(), index.len())?;
        bounds.check(pack.capacity(), index.capacity())?;
        if data {
            let verified = super::metadata::verify_data(executor, &owner, None, &input)?;
            (verified.hashes, verified.dependencies, verified.edges)
        } else {
            let hashes = super::metadata::verify(
                &pack,
                &index,
                source.pack_id(),
                config.location.chunk_profile(),
                config.reads,
                config.inventory_entries.min(config.state.records),
            )?;
            (hashes, Vec::new(), Vec::new())
        }
    };
    let resource = executor.register_admission(input)?;
    let result = async {
        let reservation = {
            let mut job = backing::lock(&resource)?;
            let mut owner = custody
                .lock()
                .map_err(|_| io::Error::other("recovery custody poisoned"))?;
            super::refuse_completed(executor, &owner, &resource, &job.input)?;
            source.check_current()?;
            job.dependencies = dependencies;
            job.dictionary_edges = edges;
            state::begin(executor, &mut owner, &mut job, 0, &hashes)?
        };
        super::super::snapshot::persist(executor, reservation).await?;
        let completion = {
            let mut job = backing::lock(&resource)?;
            let mut owner = custody
                .lock()
                .map_err(|_| io::Error::other("recovery custody poisoned"))?;
            state::check_registration(&owner, &job)?;
            source.check_current()?;
            let id = source.pack_id();
            let shard = format!("{:02x}", id.as_bytes()[0]);
            let parent = native::parent(
                &owner,
                "objects",
                &["pack", &shard],
                &mut job.directory_progress,
            )?;
            let original_index = source
                .present_index_file()
                .ok_or_else(|| io::Error::other("verified metadata index absent"))?;
            job.files.push(native::recover_metadata(
                &owner,
                parent.try_clone()?,
                format!("{id}.idx"),
                original_index,
                &index,
            )?);
            job.files.push(native::recover_metadata(
                &owner,
                parent,
                format!("{id}.pack"),
                source.pack_file(),
                &pack,
            )?);
            super::super::snapshot::prepare(executor, &mut owner)?
        };
        super::super::snapshot::persist(executor, completion).await?;
        {
            let mut job = backing::lock(&resource)?;
            let mut owner = custody
                .lock()
                .map_err(|_| io::Error::other("recovery custody poisoned"))?;
            source.check_current()?;
            reconcile::finish(&mut owner, &mut job)?;
        }
        handoff::execute(executor, &resource).await?;
        Ok(())
    }
    .await;
    if result.is_err() {
        executor.reclaim_rejected_admission(&resource)?;
    }
    result
}
