//! Closes externally issued reads through their original physical publication.
//!
//! Current Running custody, the exact registered job and synchronized durable
//! funding precede revocation. Closure retains every durable pin and hold;
//! cache ownership and retirement remain separate transitions.

use super::{NativeProducerReadClosure, PublicationJob, invalid, residence};
use crate::host_cache::owner::retention::{Command, NativeMetadataOwner, NativeOwnerExecutor};
use std::{
    io,
    sync::{Arc, Mutex, mpsc},
};
use tokio::sync::oneshot;

/// Transfers original publication custody into the retained command queue.
///
/// # Errors
/// Refuses a stopped/full queue or a missing physical worker response.
pub(super) async fn submit(
    owner: &NativeMetadataOwner,
    resource: &Arc<Mutex<PublicationJob>>,
) -> io::Result<NativeProducerReadClosure> {
    let (response, receive) = oneshot::channel();
    owner
        .commands
        .as_ref()
        .ok_or_else(|| invalid("producer read owner stopped"))?
        .try_send(Command::ClosePublicationReads {
            resource: Arc::clone(resource),
            response,
        })
        .map_err(|error| match error {
            mpsc::TrySendError::Full(_) => {
                io::Error::new(io::ErrorKind::WouldBlock, "producer read queue full")
            }
            mpsc::TrySendError::Disconnected(_) => {
                io::Error::new(io::ErrorKind::BrokenPipe, "producer read owner stopped")
            }
        })?;
    receive
        .await
        .map_err(|_| invalid("producer read worker terminated"))?
}

/// Revokes only original external reads after checking genuine current funding.
///
/// # Errors
/// Refuses another physical worker/publication, missing Running custody, changed
/// snapshot or durable funding, stale native backing or poisoned ownership.
pub(in crate::host_cache::owner) fn execute(
    executor: &mut NativeOwnerExecutor,
    resource: &Arc<Mutex<PublicationJob>>,
) -> io::Result<NativeProducerReadClosure> {
    executor.check_physical_worker()?;
    if !executor
        .publication_jobs()
        .iter()
        .any(|job| Arc::ptr_eq(job, resource))
    {
        return Err(invalid("producer reads belong to another physical owner"));
    }
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let custody = Arc::clone(executor.custody());
    let (body, project, publisher_uid) = {
        let mut job = resource
            .lock()
            .map_err(|_| invalid("producer publication poisoned"))?;
        let owner = custody
            .lock()
            .map_err(|_| invalid("producer custody poisoned"))?;
        if !Arc::ptr_eq(&job.custody, &custody) {
            return Err(invalid("producer publication changed original custody"));
        }
        let body = Arc::clone(residence::registered_body(&owner, &job)?);
        job.producer_reads_closed = true;
        (
            body,
            owner.preparation.config.project_id,
            owner.preparation.config.publisher.identities.publish_uid,
        )
    };
    residence::check_native_body(&body, project, publisher_uid)?;

    // Neither embedded state nor the publication job is locked while backing
    // references are relinquished. Independently granted consumers are absent
    // from this weak registry and retain their actual original source.
    let report = executor.close_producer_reads(resource);
    running.check_current().map_err(io::Error::other)?;
    let job = resource
        .lock()
        .map_err(|_| invalid("producer publication poisoned"))?;
    let owner = custody
        .lock()
        .map_err(|_| invalid("producer custody poisoned"))?;
    if !Arc::ptr_eq(&body, residence::registered_body(&owner, &job)?) {
        return Err(invalid("producer read closure changed original backing"));
    }
    Ok(report)
}
