//! Completes original standalone-source retirement on the physical owner.
//!
//! Original registered jobs, durable funding and native inode observations
//! remain retained through every RPC and accounting check. Acknowledgements
//! come only from real correlated publisher replies, before closing the owner's
//! original source descriptions. Independently retained descriptions may still
//! retain quota after pending names and the owner's descriptions are gone.

use super::{PublicationJob, invalid, residence, state};
use crate::{
    host_cache::{
        owner::admission::TransferSource,
        owner::retention::{Command, Custody, NativeMetadataOwner, NativeOwnerExecutor},
    },
    publisher_local::client::{
        AcknowledgedSourceRetirement, BodyIncarnationObservation, Client, PeerPublishedObject,
        PublisherRunningContext,
    },
    publisher_local::socket::ReceivedPacket,
};
use std::{
    io,
    sync::{Arc, Mutex, mpsc},
};
use terrane::host::cache::HostDomainLocation;
use tokio::sync::oneshot;

/// Reports native pending-name removal and separately measured retained charge.
///
/// This report releases no producer or consumer pin and grants no serving
/// authority. Open source descriptions may still retain unlinked allocation.
#[derive(Clone, Copy, Debug)]
pub struct NativeSourceCleanupReport {
    /// Number of original standalone sources with actual removal acknowledgements.
    pub completed_sources: usize,
    /// Synchronized allocated blocks of the original sealed output inode alone.
    pub synchronized_sealed_inode_bytes: u64,
    /// Fresh complete-project kernel charged-and-reserved usage after cleanup.
    pub charged_reserved_bytes: u64,
    /// Independent future-capacity policy holds, not freed physical allocation.
    pub future_hold_bytes: u64,
}

/// Retains the actual completed job and one original pending inode observation.
pub(in crate::host_cache::owner) struct CleanupFunding {
    resource: Arc<Mutex<PublicationJob>>,
    custody: Arc<Mutex<Custody>>,
    body: Arc<PeerPublishedObject<HostDomainLocation>>,
    session: Arc<Client<HostDomainLocation>>,
    observation: Arc<BodyIncarnationObservation<HostDomainLocation>>,
    index: usize,
    project: u32,
    publisher_uid: u32,
}

struct RetiredSource<'job> {
    source: &'job TransferSource,
    observation: &'job Arc<BodyIncarnationObservation<HostDomainLocation>>,
    acknowledgement: Option<&'job AcknowledgedSourceRetirement>,
}

/// Borrows one genuine original transfer only after its correlated final removal.
///
/// Only this module constructs the scope, while holding the actual completed
/// publication job. It releases descriptors, never pins or serving authority.
pub(in crate::host_cache::owner) struct AcknowledgedSource<'job> {
    source: &'job TransferSource,
    observation: &'job Arc<BodyIncarnationObservation<HostDomainLocation>>,
    acknowledgement: &'job AcknowledgedSourceRetirement,
    session: &'job Arc<Client<HostDomainLocation>>,
    custody: &'job Arc<Mutex<Custody>>,
}

impl AcknowledgedSource<'_> {
    /// Checks the same original transfer, physical worker and native response.
    ///
    /// # Errors
    /// Refuses another worker, transfer, observation, session or acknowledgement.
    pub(in crate::host_cache::owner) fn check(
        &self,
        executor: &NativeOwnerExecutor,
        source: &TransferSource,
    ) -> io::Result<()> {
        executor.check_physical_worker()?;
        if !std::ptr::eq(self.source, source)
            || !Arc::ptr_eq(self.custody, executor.custody())
            || self.observation.key() != source.key()
        {
            return Err(invalid("source closure differs from acknowledged transfer"));
        }
        self.acknowledgement.check(self.session, self.observation)
    }
}

impl CleanupFunding {
    fn capture(
        executor: &NativeOwnerExecutor,
        resource: &Arc<Mutex<PublicationJob>>,
        index: usize,
    ) -> io::Result<Self> {
        require_registration(executor, resource)?;
        let job = resource
            .lock()
            .map_err(|_| invalid("cleanup publication poisoned"))?;
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("cleanup custody poisoned"))?;
        let body = residence::registered_body(&owner, &job)?;
        let source = retired_source(&job, index)?;
        if !Arc::ptr_eq(&job.custody, executor.custody())
            || source.source.key() != source.observation.key()
        {
            return Err(invalid("cleanup source differs from original publication"));
        }
        Ok(Self {
            resource: Arc::clone(resource),
            custody: Arc::clone(executor.custody()),
            body: Arc::clone(body),
            session: owner.preparation.publisher_session(),
            observation: Arc::clone(source.observation),
            index,
            project: owner.preparation.config.project_id,
            publisher_uid: owner.preparation.config.publisher.identities.publish_uid,
        })
    }

    /// Checks the genuine registered source and current completed funding.
    ///
    /// # Errors
    /// Refuses another worker/job, changed snapshot, source, session or backing.
    pub(in crate::host_cache::owner) fn check(
        &self,
        executor: &NativeOwnerExecutor,
    ) -> io::Result<()> {
        require_registration(executor, &self.resource)?;
        {
            let job = self
                .resource
                .lock()
                .map_err(|_| invalid("cleanup publication poisoned"))?;
            let owner = executor
                .custody()
                .lock()
                .map_err(|_| invalid("cleanup custody poisoned"))?;
            let actual = residence::registered_body(&owner, &job)?;
            let source = retired_source(&job, self.index)?;
            if !Arc::ptr_eq(&self.custody, executor.custody())
                || !Arc::ptr_eq(&self.body, actual)
                || !Arc::ptr_eq(&self.observation, source.observation)
                || source.source.key() != self.observation.key()
                || !Arc::ptr_eq(&self.session, &owner.preparation.publisher_session())
            {
                return Err(invalid("cleanup funding changed original custody"));
            }
        }
        // Native seal/project IO holds neither the job nor embedded-state lock.
        residence::check_native_body(&self.body, self.project, self.publisher_uid)
    }

    /// Borrows only the original observed inode retained by this funded source.
    pub(in crate::host_cache::owner) fn observation(
        &self,
    ) -> Arc<BodyIncarnationObservation<HostDomainLocation>> {
        Arc::clone(&self.observation)
    }

    fn acknowledged(&self) -> io::Result<bool> {
        let job = self
            .resource
            .lock()
            .map_err(|_| invalid("cleanup publication poisoned"))?;
        let source = retired_source(&job, self.index)?;
        match source.acknowledgement {
            Some(completed) => {
                completed.check(&self.session, &self.observation)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn retain_acknowledgement(&self, completed: AcknowledgedSourceRetirement) -> io::Result<()> {
        let mut job = self
            .resource
            .lock()
            .map_err(|_| invalid("cleanup publication poisoned"))?;
        let source = retired_source(&job, self.index)?;
        completed.check(&self.session, source.observation)?;
        if source.acknowledgement.is_some() {
            return Err(invalid("source cleanup already acknowledged"));
        }
        if let Some(manifest) = &mut job.manifest {
            let source = manifest
                .transfers
                .get_mut(self.index)
                .ok_or_else(|| invalid("cleanup manifest source absent"))?;
            source.cleanup = Some(completed);
        } else {
            job.transfer_cleanup = Some(completed);
        }
        Ok(())
    }

    fn close_descriptors(&self, executor: &NativeOwnerExecutor) -> io::Result<()> {
        require_registration(executor, &self.resource)?;
        let mut guard = self
            .resource
            .lock()
            .map_err(|_| invalid("cleanup publication poisoned"))?;
        let job = &mut *guard;
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("cleanup custody poisoned"))?;
        let actual = residence::registered_body(&owner, job)?;
        if !Arc::ptr_eq(actual, &self.body)
            || !Arc::ptr_eq(&job.custody, &self.custody)
            || !Arc::ptr_eq(&owner.preparation.publisher_session(), &self.session)
        {
            return Err(invalid(
                "source closure changed original publication custody",
            ));
        }
        let close = |source: &TransferSource,
                     observation: &Arc<BodyIncarnationObservation<HostDomainLocation>>,
                     acknowledgement: &AcknowledgedSourceRetirement,
                     reply: &mut ReceivedPacket| {
            if !Arc::ptr_eq(observation, &self.observation) {
                return Err(invalid("source closure changed original observation"));
            }
            let acknowledged = AcknowledgedSource {
                source,
                observation,
                acknowledgement,
                session: &self.session,
                custody: &self.custody,
            };
            source.close_finished_source(executor, &owner, &acknowledged, &mut reply.files)
        };
        if let Some(manifest) = &mut job.manifest {
            let source = manifest
                .transfers
                .get_mut(self.index)
                .ok_or_else(|| invalid("cleanup manifest source absent"))?;
            if !source.retired {
                return Err(invalid("source closure lacks original retirement"));
            }
            close(
                &source.source,
                source
                    .observation
                    .as_ref()
                    .ok_or_else(|| invalid("cleanup observation absent"))?,
                source
                    .cleanup
                    .as_ref()
                    .ok_or_else(|| invalid("cleanup acknowledgement absent"))?,
                source
                    .reply
                    .as_mut()
                    .ok_or_else(|| invalid("cleanup inspection reply absent"))?,
            )
        } else {
            if self.index != 0 || !job.transfer_retired {
                return Err(invalid("inline source closure lacks original retirement"));
            }
            close(
                job.transfer
                    .as_ref()
                    .ok_or_else(|| invalid("inline transfer absent"))?,
                job.transfer_observation
                    .as_ref()
                    .ok_or_else(|| invalid("inline observation absent"))?,
                job.transfer_cleanup
                    .as_ref()
                    .ok_or_else(|| invalid("inline cleanup acknowledgement absent"))?,
                job.reply
                    .as_mut()
                    .ok_or_else(|| invalid("inline inspection reply absent"))?,
            )
        }
    }
}

fn require_registration(
    executor: &NativeOwnerExecutor,
    resource: &Arc<Mutex<PublicationJob>>,
) -> io::Result<()> {
    executor.check_physical_worker()?;
    if !executor
        .publication_jobs()
        .iter()
        .any(|job| Arc::ptr_eq(job, resource))
    {
        return Err(invalid(
            "cleanup publication belongs to another physical owner",
        ));
    }
    Ok(())
}

/// Retains only original standalone funding after final acknowledgment and closure.
///
/// # Errors
/// Refuses missing original transfers, acknowledgments or closed inspection slots.
pub(super) fn closed_funding(
    executor: &NativeOwnerExecutor,
    owner: &Custody,
    job: &PublicationJob,
) -> io::Result<Vec<super::super::admission::TransferredFunding>> {
    if !Arc::ptr_eq(&job.custody, executor.custody()) {
        return Err(invalid("handoff sources belong to another physical owner"));
    }
    let count = job
        .manifest
        .as_ref()
        .map_or(usize::from(job.transfer.is_some()), |input| {
            input.transfers.len()
        });
    let mut result = Vec::new();
    result.try_reserve_exact(count).map_err(io::Error::other)?;
    let session = owner.preparation.publisher_session();
    for index in 0..count {
        let retired = retired_source(job, index)?;
        let reply = if let Some(input) = &job.manifest {
            input.transfers[index].reply.as_ref()
        } else {
            job.reply.as_ref()
        }
        .ok_or_else(|| invalid("handoff source inspection absent"))?;
        if !reply.files.is_empty() {
            return Err(invalid("handoff source inspection descriptors remain"));
        }
        let acknowledged = AcknowledgedSource {
            source: retired.source,
            observation: retired.observation,
            acknowledgement: retired
                .acknowledgement
                .ok_or_else(|| invalid("handoff source final acknowledgment absent"))?,
            session: &session,
            custody: &job.custody,
        };
        result.push(
            retired
                .source
                .closed_funding(executor, owner, &acknowledged)?,
        );
    }
    if job
        .manifest
        .as_ref()
        .is_some_and(|input| input.plan.is_some())
    {
        return Err(invalid("handoff reassembly descriptors remain"));
    }
    Ok(result)
}

fn retired_source(job: &PublicationJob, index: usize) -> io::Result<RetiredSource<'_>> {
    if let Some(manifest) = &job.manifest {
        let source = manifest
            .transfers
            .get(index)
            .ok_or_else(|| invalid("cleanup manifest source absent"))?;
        if !source.retired || source.reply.is_none() {
            return Err(invalid("manifest source retirement not acknowledged"));
        }
        Ok(RetiredSource {
            source: &source.source,
            observation: source
                .observation
                .as_ref()
                .ok_or_else(|| invalid("manifest retirement observation absent"))?,
            acknowledgement: source.cleanup.as_ref(),
        })
    } else {
        if index != 0 || !job.transfer_retired || job.reply.is_none() {
            return Err(invalid("inline source retirement not acknowledged"));
        }
        Ok(RetiredSource {
            source: job
                .transfer
                .as_ref()
                .ok_or_else(|| invalid("inline transfer absent"))?,
            observation: job
                .transfer_observation
                .as_ref()
                .ok_or_else(|| invalid("inline retirement observation absent"))?,
            acknowledgement: job.transfer_cleanup.as_ref(),
        })
    }
}

/// Enqueues only the completed publication's original registered resource.
///
/// # Errors
/// Refuses stopped/full queues, foreign custody and incomplete native cleanup.
pub(super) async fn submit(
    owner: &NativeMetadataOwner,
    resource: &Arc<Mutex<PublicationJob>>,
) -> io::Result<NativeSourceCleanupReport> {
    let (response, receive) = oneshot::channel();
    owner
        .commands
        .as_ref()
        .ok_or_else(|| invalid("source cleanup owner stopped"))?
        .try_send(Command::FinishPublicationSources {
            resource: Arc::clone(resource),
            response,
        })
        .map_err(|error| match error {
            mpsc::TrySendError::Full(_) => {
                io::Error::new(io::ErrorKind::WouldBlock, "source cleanup queue full")
            }
            mpsc::TrySendError::Disconnected(_) => {
                io::Error::new(io::ErrorKind::BrokenPipe, "source cleanup owner stopped")
            }
        })?;
    receive
        .await
        .map_err(|_| invalid("source cleanup worker terminated"))?
}

/// Finishes native pending sources without releasing pins or inferring free space.
///
/// # Errors
/// Refuses foreign/unready resources, active publisher grace, uncertain commands
/// and changed native funding. Accepted failures preserve resources for recovery.
pub(in crate::host_cache::owner) fn execute(
    executor: &mut NativeOwnerExecutor,
    resource: &Arc<Mutex<PublicationJob>>,
) -> io::Result<NativeSourceCleanupReport> {
    // A foreign caller must not fault or mutate this owner's valid policy.
    require_registration(executor, resource)?;
    let context = executor.admission_context()?;
    let result = complete(executor, resource, &context);
    if result.is_err() {
        let mut owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("cleanup custody poisoned"))?;
        owner.faulted = true;
        owner.recovery_required = true;
        owner.recovery_id = None;
    }
    result
}

fn complete(
    executor: &mut NativeOwnerExecutor,
    resource: &Arc<Mutex<PublicationJob>>,
    context: &PublisherRunningContext,
) -> io::Result<NativeSourceCleanupReport> {
    let (count, body, project, publisher_uid) = {
        let job = resource
            .lock()
            .map_err(|_| invalid("cleanup publication poisoned"))?;
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("cleanup custody poisoned"))?;
        let body = Arc::clone(residence::registered_body(&owner, &job)?);
        let count = job
            .manifest
            .as_ref()
            .map_or(usize::from(job.transfer.is_some()), |manifest| {
                manifest.transfers.len()
            });
        (
            count,
            body,
            owner.preparation.config.project_id,
            owner.preparation.config.publisher.identities.publish_uid,
        )
    };
    for index in 0..count {
        let funding = CleanupFunding::capture(executor, resource, index)?;
        funding.check(executor)?;
        if !funding.acknowledged()? {
            let session = Arc::clone(&funding.session);
            let observation = Arc::clone(&funding.observation);
            let completed = {
                let mut turn = executor.cleanup_turn(&funding)?;
                session
                    .finish_source_retirement(context, &mut turn)
                    .map_err(io::Error::other)?
            };
            // Keep the actual successful native result before subsequent
            // fallible checks or closure. Cancellation cannot discard it.
            completed.check(&session, &observation)?;
            funding.retain_acknowledgement(completed)?;
        }
        funding.check(executor)?;
        funding.close_descriptors(executor)?;
        funding.check(executor)?;
    }
    {
        let mut job = resource
            .lock()
            .map_err(|_| invalid("cleanup publication poisoned"))?;
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("cleanup custody poisoned"))?;
        let actual = residence::registered_body(&owner, &job)?;
        if !Arc::ptr_eq(actual, &body) {
            return Err(invalid("source closure changed completed sealed backing"));
        }
        if let Some(manifest) = &mut job.manifest {
            // The completed private reassembly plan also owns original chunk
            // descriptions, including repeated inputs. Drop them only after
            // every native final-removal acknowledgement and descriptor check.
            // Reconstruction metadata and durable pins remain independently held.
            drop(manifest.plan.take());
        }
    }
    let allocated = residence::synchronize_body(&body, project, publisher_uid)?;
    context.check_current().map_err(io::Error::other)?;
    let mut owner = executor
        .custody()
        .lock()
        .map_err(|_| invalid("cleanup custody poisoned"))?;
    residence::check_snapshot(&owner)?;
    owner.preparation.recheck()?;
    // Independently retained descriptions may still be charged after our own
    // closes. This is fresh kernel accounting, never a logical subtraction.
    let future = state::check_charge(&owner)?;
    Ok(NativeSourceCleanupReport {
        completed_sources: count,
        synchronized_sealed_inode_bytes: allocated,
        charged_reserved_bytes: owner
            .preparation
            .quota()
            .observation()
            .charged_reserved_bytes,
        future_hold_bytes: future,
    })
}
