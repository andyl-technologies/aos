//! Re-extracts verified sealed ranges before their containing body can retire.
//!
//! The physical worker retains the original source, payload and admission job.
//! A durable future hold precedes removing the old residence assertion, and
//! that removal precedes publishing the replacement canonical encoding. Recovery
//! can reconstruct the original range before publication or select the genuine
//! standalone chunk afterward. Neither cut invents free quota or serving custody.

use super::{
    AdmissionBounds, FailureGuard, Input, backing, handoff, io as native, reconcile, state,
};
use crate::host_cache::{NativeResidentChunkSource, owner::retention::NativeOwnerExecutor};
use std::{io, sync::Arc};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_sdk::store::ChunkPosition;

/// Copies one original verified range into an actual cache-owned admission.
///
/// No recursive eviction is attempted: replacement requires real copy headroom
/// while the original sealed inode remains charged. The original object and
/// replacement chunk retain the ordinary durable release grace after handoff.
///
/// # Errors
/// Refuses absent or changed native backing, conflicting residences, exhausted
/// bounds or quota, duplicate admissions and failed synchronization. Started
/// work retains its original job and future hold on every failure.
pub(in crate::host_cache::owner) async fn run(
    executor: &mut NativeOwnerExecutor,
    source: NativeResidentChunkSource,
) -> io::Result<()> {
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let plaintext = source.read_verified()?;
    let descriptor = Descriptor::from_identity(&TERRANE_V1, source.identity(), &plaintext)
        .map_err(io::Error::other)?;
    descriptor
        .verify_bytes(&TERRANE_V1, IdentityKind::Chunk, &plaintext)
        .map_err(io::Error::other)?;
    let length = plaintext
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid("re-extraction envelope overflows"))?;
    let custody = Arc::clone(executor.custody());
    {
        let owner = custody
            .lock()
            .map_err(|_| invalid("re-extraction custody poisoned"))?;
        AdmissionBounds::new(&owner.preparation.config)?.check(length, 0)?;
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(length)
        .map_err(io::Error::other)?;
    encoded.push(0);
    encoded.extend_from_slice(&plaintext);
    drop(plaintext);
    let encoded = Arc::new(encoded);
    let hash = state::hex(source.identity().digest());
    let object = state::hex(source.protected_object_digest());
    let span = source.span();
    let resource = executor.register_admission(Input::Chunk {
        descriptor,
        position: if span.final_chunk {
            ChunkPosition::Final
        } else {
            ChunkPosition::NonFinal
        },
        encoded: Arc::clone(&encoded),
    })?;
    let mut failure = FailureGuard::new(&custody, &resource)?;
    let result = async {
        let (original, funding) = {
            let mut job = backing::lock(&resource)?;
            let mut owner = custody
                .lock()
                .map_err(|_| invalid("re-extraction custody poisoned"))?;
            AdmissionBounds::new(&owner.preparation.config)?.check(encoded.capacity(), 0)?;
            super::refuse_completed(executor, &owner, &resource, &job.input)?;
            source.check_consumer_backing(&owner)?;
            let original = owner
                .state
                .residences
                .iter()
                .find(|row| row.chunk == hash)
                .filter(|row| {
                    row.object == object
                        && row.offset == span.offset
                        && row.length == span.length as u64
                })
                .cloned()
                .ok_or_else(|| invalid("re-extraction lost its original residence"))?;
            let funding = state::begin(
                executor,
                &mut owner,
                &mut job,
                encoded.len(),
                &[hash.clone(), object],
            )?;
            (original, funding)
        };
        super::super::snapshot::persist(executor, funding).await?;

        let removal = {
            let job = backing::lock(&resource)?;
            let mut owner = custody
                .lock()
                .map_err(|_| invalid("re-extraction custody poisoned"))?;
            state::check_registration(&owner, &job)?;
            source.check_consumer_backing(&owner)?;
            let index = owner
                .state
                .residences
                .iter()
                .position(|row| {
                    row.chunk == original.chunk
                        && row.object == original.object
                        && row.offset == original.offset
                        && row.length == original.length
                })
                .ok_or_else(|| invalid("re-extraction residence changed after funding"))?;
            owner.state.residences.remove(index);
            super::super::snapshot::prepare(executor, &mut owner)?
        };
        // Publishing first would leave a cold snapshot asserting two residences
        // for one chunk. Never create the canonical replacement before this cut.
        super::super::snapshot::persist(executor, removal).await?;

        let completion = {
            let mut job = backing::lock(&resource)?;
            let mut owner = custody
                .lock()
                .map_err(|_| invalid("re-extraction custody poisoned"))?;
            state::check_registration(&owner, &job)?;
            source.check_consumer_backing(&owner)?;
            if owner.state.residences.iter().any(|row| row.chunk == hash) {
                return Err(invalid("re-extraction still has a sealed residence"));
            }
            let parent =
                native::parent(&owner, "chunks", &[&hash[..2]], &mut job.directory_progress)?;
            for codec in 0..=2 {
                native::refuse_existing(&parent, &format!("{hash}.{codec}"))?;
            }
            let pending = native::pending(parent, format!("{hash}.0"))?;
            job.files.push(pending);
            native::write(&owner, &mut job.files[0], &encoded)?;
            native::publish(&owner, &mut job.files[0], &encoded)?;
            super::super::snapshot::prepare(executor, &mut owner)?
        };
        super::super::snapshot::persist(executor, completion).await?;
        {
            let mut job = backing::lock(&resource)?;
            let mut owner = custody
                .lock()
                .map_err(|_| invalid("re-extraction custody poisoned"))?;
            source.check_consumer_backing(&owner)?;
            reconcile::finish(&mut owner, &mut job)?;
        }
        running.check_current().map_err(io::Error::other)?;
        handoff::execute(executor, &resource).await?;
        Ok(())
    }
    .await;
    if result.is_err() {
        executor.reclaim_rejected_admission(&resource)?;
    } else {
        failure.settled = true;
    }
    result
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
