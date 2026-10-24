//! Synchronizes original sealed output before settling future copy capacity.
//!
//! Only the physical publication owner constructs this receipt, from its actual
//! registered result after its owned source descriptions close. It retains the
//! original body and custody across native synchronization. The receipt permits
//! the final policy transition; it grants no consumer lease or Store readiness.

use super::{PublicationJob, invalid, residence, state};
use crate::{
    host_cache::owner::retention::{Custody, NativeOwnerExecutor},
    publisher_local::client::PeerPublishedObject,
};
use std::{
    io,
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex},
    thread::{self, ThreadId},
};
use terrane_sdk::host::cache::HostDomainLocation;

/// Retains actual native completion of one original registered publication.
pub(super) struct SynchronizedPublication {
    custody: Arc<Mutex<Custody>>,
    body: Arc<PeerPublishedObject<HostDomainLocation>>,
    generation: u64,
    worker: ThreadId,
    allocated: u64,
}

/// Synchronizes actual closed-source output without embedded or job locks held.
///
/// # Errors
/// Refuses another physical worker/resource, incomplete or changed funding,
/// remaining owned source descriptions, and native seal or synchronization errors.
pub(super) fn synchronize(
    executor: &NativeOwnerExecutor,
    resource: &Arc<Mutex<PublicationJob>>,
) -> io::Result<()> {
    executor.check_physical_worker()?;
    if !executor
        .publication_jobs()
        .iter()
        .any(|job| Arc::ptr_eq(job, resource))
    {
        return Err(invalid("publication completion resource is not registered"));
    }
    let (custody, body, generation, project, publisher_uid) = {
        let job = resource
            .lock()
            .map_err(|_| invalid("publication completion poisoned"))?;
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("publication custody poisoned"))?;
        if !Arc::ptr_eq(&job.custody, executor.custody())
            || job.complete
            || job.writer.is_some()
            || job.reader.is_some()
            || job.synchronized.is_some()
        {
            return Err(invalid(
                "publication completion has live source or changed phase",
            ));
        }
        state::check_funding(
            &owner,
            &job.token,
            &state::hex(job.claim.descriptor().digest()),
            job.hold,
            job.generation,
        )?;
        let body = job
            .body
            .as_ref()
            .ok_or_else(|| invalid("publication result absent"))?;
        if !Arc::ptr_eq(body.layout(), owner.preparation.layout())
            || body.claim().descriptor() != job.claim.descriptor()
            || body.claim().domain() != job.claim.domain()
            || body.claim().canonical_manifest() != job.claim.canonical_manifest()
        {
            return Err(invalid(
                "publication completion differs from original native result",
            ));
        }
        (
            Arc::clone(&job.custody),
            Arc::clone(body),
            job.generation,
            owner.preparation.config.project_id,
            owner.preparation.config.publisher.identities.publish_uid,
        )
    };
    let allocated = residence::synchronize_body(&body, project, publisher_uid)?;
    let completed = SynchronizedPublication {
        custody,
        body,
        generation,
        worker: thread::current().id(),
        allocated,
    };
    let mut job = resource
        .lock()
        .map_err(|_| invalid("publication completion poisoned"))?;
    completed.check(&job)?;
    // Retain the actual native result before later fallible policy work. A
    // cancelled reply never discards original physical publication custody.
    job.synchronized = Some(completed);
    Ok(())
}

impl SynchronizedPublication {
    fn check(&self, job: &PublicationJob) -> io::Result<()> {
        // This compares allocation of the original immutable inode. Durability
        // came from the actual earlier synchronization outside both mutexes.
        let allocated = self
            .body
            .handle()
            .metadata()?
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| invalid("publication allocation comparison overflows"))?;
        if self.worker != thread::current().id()
            || self.generation != job.generation
            || !Arc::ptr_eq(&self.custody, &job.custody)
            || !job
                .body
                .as_ref()
                .is_some_and(|body| Arc::ptr_eq(body, &self.body))
            || job.writer.is_some()
            || job.reader.is_some()
            || allocated != self.allocated
        {
            return Err(invalid(
                "publication completion lost original native custody",
            ));
        }
        Ok(())
    }
}

/// Requires the original native IO completion before reducing future capacity.
///
/// # Errors
/// Refuses absent completion, another worker, changed body/generation or sources.
pub(super) fn check(job: &PublicationJob) -> io::Result<()> {
    job.synchronized
        .as_ref()
        .ok_or_else(|| invalid("publication native completion has not synchronized"))?
        .check(job)
}
