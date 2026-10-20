//! Runs original consumer grant, renewal and release operations on the physical worker.
//!
//! Actual source, context and attempted effects enter the finite registry before
//! writes. Neither a cancelled reply nor a late failure frees uncertain custody.

use super::{
    ConsumerJob, NativeConsumerLease, NativeLeaseAccounting, Phase,
    clock::{self, Deadline},
    invalid,
    source::{Allocation, ConsumerSource},
    state,
    view::ReadView,
};
use crate::host_cache::owner::{publication, retention::NativeOwnerExecutor, snapshot};
use std::{
    io,
    sync::{Arc, Mutex},
};
use terrane_format::identity::Identity;
use terrane_sdk::host::cache::{LeaseRecord, PinRecord, ReservationRecord};

/// Retains and synchronizes one actual bounded resident consumer grant.
///
/// # Errors
/// Refuses elapsed deadlines, absent source/Resume, exhausted resources and IO.
pub(in crate::host_cache::owner) async fn acquire(
    executor: &mut NativeOwnerExecutor,
    identity: Identity,
    expires: u64,
) -> io::Result<NativeConsumerLease> {
    let deadline = Deadline::new(expires)?;
    publication::eviction::restore_for(executor, &identity).await?;
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let source = Arc::new(ConsumerSource::prepare(executor, identity).await?);
    let custody = Arc::clone(executor.custody());
    let (token, hold) = {
        let owner = custody
            .lock()
            .map_err(|_| invalid("consumer custody poisoned"))?;
        state::check_ready(executor, &owner)?;
        source.check_protected(&owner)?;
        deadline.check_live()?;
        clock::grace_end(Some(expires), owner.preparation.config.policy.release_grace)?;
        (
            state::fresh_token(&owner)?,
            owner.preparation.config.metadata_sync_hold_bytes,
        )
    };
    let view = Arc::new(ReadView::pending(
        Arc::clone(&source),
        format!("consumer:{token}"),
        executor.consumer_read_budget(),
    ));
    let job = executor.register_consumer_job(ConsumerJob {
        custody,
        running,
        source,
        view: Arc::clone(&view),
        token,
        hold,
        generation: 0,
        started: false,
        phase: Phase::Pending,
        accounting: None,
    })?;
    let result = pin(executor, &job, deadline).await;
    if result.is_err() {
        executor.reclaim_consumer_job(&job)?;
    }
    result.map(|initial_accounting| NativeConsumerLease {
        view,
        initial_accounting,
    })
}

async fn pin(
    executor: &NativeOwnerExecutor,
    resource: &Arc<Mutex<ConsumerJob>>,
    deadline: Deadline,
) -> io::Result<NativeLeaseAccounting> {
    let (custody, running, source, owner_name) = {
        let job = resource
            .lock()
            .map_err(|_| invalid("consumer job poisoned"))?;
        (
            Arc::clone(&job.custody),
            Arc::clone(&job.running),
            Arc::clone(&job.source),
            job.view.owner.clone(),
        )
    };
    running.check_current().map_err(io::Error::other)?;
    let write = {
        let mut job = resource
            .lock()
            .map_err(|_| invalid("consumer job poisoned"))?;
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("consumer custody poisoned"))?;
        state::check_ready(executor, &owner)?;
        source.check_protected(&owner)?;
        deadline.check_live()?;
        job.view.check_publish_slot()?;
        let mut next = owner.state.clone();
        next.reservations.push(ReservationRecord {
            id: job.token.clone(),
            owner: owner.preparation.config.quota_owner.clone(),
            bytes: job.hold,
        });
        next.leases.push(LeaseRecord {
            owner: owner_name.clone(),
            expires: deadline.expires,
        });
        for hash in source.protected_hashes() {
            next.pins.push(PinRecord {
                owner: owner_name.clone(),
                hash: hash.clone(),
                expires: deadline.expires,
            });
        }
        let hold = job.hold;
        let write = state::begin(
            executor,
            &mut owner,
            &running,
            next,
            hold,
            Some(&mut job.started),
        )?;
        job.generation = owner.generation;
        write
    };
    snapshot::persist(executor, write).await?;
    let allocated = source.synchronize_pin_backing()?;
    running.check_current().map_err(io::Error::other)?;
    let mut job = resource
        .lock()
        .map_err(|_| invalid("consumer job poisoned"))?;
    let mut owner = custody
        .lock()
        .map_err(|_| invalid("consumer custody poisoned"))?;
    state::check_job(&owner, &job, &owner_name, deadline.expires)?;
    let observation = state::finish(&mut owner, job.generation)?;
    let accounting = accounting(allocated, observation);
    job.accounting = Some(accounting);
    job.phase = Phase::Live(deadline);
    // Expiry after real IO withholds the handle but does not pretend that the
    // durable physical pin disappeared. Periodic expiry owns its cleanup.
    if let Err(error) = job.view.publish(deadline) {
        job.view.close();
        return Err(error);
    }
    Ok(accounting)
}

/// Renews only this executor's actual original live view and resource job.
///
/// # Errors
/// Refuses a foreign/revoked/expired handle, invalid expiry or failed native IO.
pub(in crate::host_cache::owner) async fn renew(
    executor: &mut NativeOwnerExecutor,
    view: Arc<ReadView>,
    expires: u64,
) -> io::Result<NativeLeaseAccounting> {
    let resource = executor.consumer_job_for_view(&view)?;
    let (custody, running, source, previous, next_deadline) = {
        let job = resource
            .lock()
            .map_err(|_| invalid("consumer job poisoned"))?;
        let Phase::Live(previous) = job.phase else {
            return Err(invalid("consumer lease is not live"));
        };
        view.live_deadline()?;
        view.check_publish_slot()?;
        (
            Arc::clone(&job.custody),
            Arc::clone(&job.running),
            Arc::clone(&job.source),
            previous,
            previous.renew(expires)?,
        )
    };
    running.check_current().map_err(io::Error::other)?;
    let write = {
        let mut job = resource
            .lock()
            .map_err(|_| invalid("consumer job poisoned"))?;
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("consumer custody poisoned"))?;
        state::check_ready(executor, &owner)?;
        state::check_job(&owner, &job, &view.owner, previous.expires)?;
        previous.check_live()?;
        clock::grace_end(Some(expires), owner.preparation.config.policy.release_grace)?;
        let mut next = owner.state.clone();
        for lease in next.leases.iter_mut().filter(|row| row.owner == view.owner) {
            lease.expires = expires;
        }
        for pin in next.pins.iter_mut().filter(|row| row.owner == view.owner) {
            pin.expires = expires;
        }
        let write = state::begin(
            executor,
            &mut owner,
            &running,
            next,
            0,
            Some(&mut job.started),
        )?;
        job.generation = owner.generation;
        write
    };
    // The old read epoch stays active throughout all actual IO.
    snapshot::persist(executor, write).await?;
    let allocated = source.synchronize_pin_backing()?;
    running.check_current().map_err(io::Error::other)?;
    let accounting = {
        let mut job = resource
            .lock()
            .map_err(|_| invalid("consumer job poisoned"))?;
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("consumer custody poisoned"))?;
        state::check_job(&owner, &job, &view.owner, expires)?;
        let observation = state::finish(&mut owner, job.generation)?;
        let accounting = accounting(allocated, observation);
        job.phase = Phase::Live(next_deadline);
        job.accounting = Some(accounting);
        accounting
    };
    if let Err(error) = previous.check_live() {
        view.close();
        release_at(executor, &resource, Some(previous.expires)).await?;
        return Err(error);
    }
    if let Err(error) = view.publish(next_deadline) {
        view.close();
        release_at(executor, &resource, Some(previous.expires)).await?;
        return Err(error);
    }
    Ok(accounting)
}

/// Revokes an original view and durably moves its pin into bounded release grace.
///
/// # Errors
/// Refuses foreign views, changed original registrations and failed native IO.
pub(in crate::host_cache::owner) async fn release(
    executor: &mut NativeOwnerExecutor,
    view: Arc<ReadView>,
) -> io::Result<NativeLeaseAccounting> {
    let resource = executor.consumer_job_for_view(&view)?;
    release_at(executor, &resource, None).await
}

async fn release_at(
    executor: &NativeOwnerExecutor,
    resource: &Arc<Mutex<ConsumerJob>>,
    expired_at: Option<u64>,
) -> io::Result<NativeLeaseAccounting> {
    let (custody, running, source, expires) = {
        let job = resource
            .lock()
            .map_err(|_| invalid("consumer job poisoned"))?;
        match job.phase {
            Phase::Grace { .. } | Phase::Removed => {
                return job
                    .accounting
                    .ok_or_else(|| invalid("consumer release has no completed accounting"));
            }
            Phase::Pending => return Err(invalid("consumer pin never completed")),
            Phase::Live(deadline) => (
                Arc::clone(&job.custody),
                Arc::clone(&job.running),
                Arc::clone(&job.source),
                deadline.expires,
            ),
        }
    };
    running.check_current().map_err(io::Error::other)?;
    let (write, grace_owner, end) = {
        let mut job = resource
            .lock()
            .map_err(|_| invalid("consumer job poisoned"))?;
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("consumer custody poisoned"))?;
        state::check_ready(executor, &owner)?;
        state::check_job(&owner, &job, &job.view.owner, expires)?;
        let now = clock::now_seconds()?;
        let origin = expired_at.or_else(|| (now >= expires).then_some(expires));
        let end = clock::grace_end(origin, owner.preparation.config.policy.release_grace)?;
        let grace_owner = format!("consumer-grace:{}", job.token);
        if owner
            .state
            .leases
            .iter()
            .any(|row| row.owner == grace_owner)
        {
            return Err(invalid("consumer grace owner already exists"));
        }
        let mut next = owner.state.clone();
        for lease in next
            .leases
            .iter_mut()
            .filter(|row| row.owner == job.view.owner)
        {
            lease.owner = grace_owner.clone();
            lease.expires = end;
        }
        for pin in next
            .pins
            .iter_mut()
            .filter(|row| row.owner == job.view.owner)
        {
            pin.owner = grace_owner.clone();
            pin.expires = end;
        }
        job.view.close();
        let write = state::begin(
            executor,
            &mut owner,
            &running,
            next,
            0,
            Some(&mut job.started),
        )?;
        job.generation = owner.generation;
        (write, grace_owner, end)
    };
    snapshot::persist(executor, write).await?;
    let allocated = source.synchronize_pin_backing()?;
    running.check_current().map_err(io::Error::other)?;
    let mut job = resource
        .lock()
        .map_err(|_| invalid("consumer job poisoned"))?;
    let mut owner = custody
        .lock()
        .map_err(|_| invalid("consumer custody poisoned"))?;
    state::check_job(&owner, &job, &grace_owner, end)?;
    let observation = state::finish(&mut owner, job.generation)?;
    let accounting = accounting(allocated, observation);
    job.phase = Phase::Grace {
        owner: grace_owner,
        end,
    };
    job.accounting = Some(accounting);
    job.view.record_release(accounting);
    Ok(accounting)
}

/// Combines measured sealed allocation with distinct full-owner policy observations.
pub(super) fn accounting(
    allocated: Allocation,
    observation: state::PolicyObservation,
) -> NativeLeaseAccounting {
    NativeLeaseAccounting {
        synchronized_sealed_inode_bytes: allocated.sealed,
        synchronized_backing_inode_bytes: allocated.backing,
        charged_reserved_bytes: observation.charged,
        future_hold_bytes: observation.future,
    }
}
