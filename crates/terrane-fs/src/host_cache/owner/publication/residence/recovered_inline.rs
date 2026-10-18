//! Pins actual recovered inline backing before issuing an immutable range source.
//!
//! A genuine adopted descriptor alone supplies no durable pin. The physical
//! worker registers its actual body and acknowledged recovery context first,
//! writes a distinct operation lease, pin and future hold, synchronizes the
//! native filesystem, and reconciles fresh quota before acknowledging a source.
//! This is retained producer custody, not a consumer lease or NativeReady.

use super::*;
use crate::{
    host_quota::synchronized_allocated_bytes, publisher_local::client::PublisherRunningContext,
};
use std::{fs::File, io::Read};
use terrane::host::cache::{LeaseRecord, PinRecord, ReservationRecord};

/// Retains actual adopted backing and every attempted source-pin effect.
pub(in crate::host_cache::owner) struct RecoveredInlineJob {
    custody: Arc<Mutex<Custody>>,
    running: Arc<PublisherRunningContext>,
    body: Arc<PeerPublishedObject<HostDomainLocation>>,
    row: ResidenceRecord,
    generation: u64,
    token: String,
    hold: u64,
    project: u32,
    publisher_uid: u32,
    started: bool,
    completion: Option<CompletedPin>,
}

/// Exists only after the actual snapshot, native synchronization and fresh Q.
struct CompletedPin {
    allocated_inode_bytes: u64,
    charged_reserved_bytes: u64,
    future_hold_bytes: u64,
}

impl RecoveredInlineJob {
    /// Recognizes absence of any attempted durable pin mutation for cleanup only.
    pub(in crate::host_cache::owner) fn is_effect_free(&self) -> bool {
        !self.started
    }

    /// Checks the original synchronized operation pin without issuing new authority.
    ///
    /// # Errors
    /// Refuses incomplete effects, foreign backing, changed rows or funding,
    /// stale snapshot provenance and changed synchronized inode allocation.
    pub(super) fn check_registration(
        &self,
        owner: &Custody,
        source: &Source,
        identity: &Identity,
    ) -> io::Result<NativeChunkSpan> {
        check_snapshot(owner)?;
        self.check_resources(owner)?;
        self.check_funding(owner)?;
        let completed = self
            .completion
            .as_ref()
            .ok_or_else(|| invalid("inline source pin incomplete"))?;
        if !Arc::ptr_eq(&self.body, &source.body)
            || completed.allocated_inode_bytes != synchronized_allocated_bytes(self.body.handle())?
            || completed
                .charged_reserved_bytes
                .checked_add(completed.future_hold_bytes)
                .is_none_or(|bytes| bytes > owner.preparation.config.policy.capacity)
        {
            return Err(invalid("inline source lost original reconciled backing"));
        }
        claim_span(owner, self.body.claim(), identity, &source.row)
    }

    fn check_resources(&self, owner: &Custody) -> io::Result<()> {
        owner.check_current()?;
        if owner.recovery_required
            || !Arc::ptr_eq(
                self.running.publisher_session(),
                &owner.preparation.publisher_session(),
            )
            || !Arc::ptr_eq(self.body.layout(), owner.preparation.layout())
            || self.body.claim().manifest().is_some()
            || self.row.chunk != self.row.object
            || self.row.object != state::hex(self.body.claim().descriptor().digest())
            || self.project != owner.preparation.config.project_id
            || self.publisher_uid != owner.preparation.config.publisher.identities.publish_uid
            || !owner
                .state
                .residences
                .iter()
                .any(|row| same_row(row, &self.row))
            || !owner.state.reservations.iter().any(|hold| {
                hold.id == state::hex(self.running.retained_bootstrap_id())
                    && hold.owner == owner.preparation.config.quota_owner
                    && hold.bytes == owner.preparation.config.metadata_sync_hold_bytes
            })
        {
            return Err(invalid(
                "inline source differs from original recovery custody",
            ));
        }
        Ok(())
    }

    fn check_funding(&self, owner: &Custody) -> io::Result<()> {
        let lease = format!("source:{}", self.token);
        if !self.started
            || self.token.is_empty()
            || self.hold != owner.preparation.config.metadata_sync_hold_bytes
            || !owner.state.reservations.iter().any(|row| {
                row.id == self.token
                    && row.owner == owner.preparation.config.quota_owner
                    && row.bytes == self.hold
            })
            || !owner
                .state
                .leases
                .iter()
                .any(|row| row.owner == lease && row.expires == RETAINED_LEASE_DEADLINE)
            || !owner.state.pins.iter().any(|row| {
                row.owner == lease
                    && row.hash == self.row.object
                    && row.expires == RETAINED_LEASE_DEADLINE
            })
        {
            return Err(invalid(
                "inline source lost its original pin, lease or hold",
            ));
        }
        Ok(())
    }
}

/// Funds a source only from this worker's actual completed inline recovery registry.
///
/// Other resident sources retain their existing complete publication or metadata
/// pins. Missing residences remain ordinary misses. A dropped caller never
/// cancels this physical command or releases an uncertain pin attempt.
///
/// # Errors
/// Refuses absent Resume, changed custody, missing capacity, failed native state
/// synchronization or quota reconciliation, retaining every started operation.
pub(in crate::host_cache::owner) async fn prepare(
    executor: &mut NativeOwnerExecutor,
    identity: &Identity,
) -> io::Result<()> {
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let candidate = {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("inline source custody poisoned"))?;
        match select_locked(executor, &owner, identity) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let Some(row) = owner
            .state
            .residences
            .iter()
            .find(|row| row.chunk == state::hex(identity.digest()))
        else {
            return Ok(());
        };
        let Some(body) = executor
            .inline_registry()
            .iter()
            .find(|body| state::hex(body.claim().descriptor().digest()) == row.object)
        else {
            return Ok(());
        };
        RecoveredInlineJob {
            custody: Arc::clone(executor.custody()),
            running,
            body: Arc::clone(body),
            row: row.clone(),
            generation: owner.generation,
            token: String::new(),
            hold: owner.preparation.config.metadata_sync_hold_bytes,
            project: owner.preparation.config.project_id,
            publisher_uid: owner.preparation.config.publisher.identities.publish_uid,
            started: false,
            completion: None,
        }
    };
    let resource = executor.register_inline_source(candidate)?;
    let result = pin(executor, &resource, identity).await;
    if result.is_err() {
        executor.reclaim_inline_source(&resource)?;
    }
    result
}

/// Completes one original physical pin through actual snapshot, inode and quota barriers.
async fn pin(
    executor: &NativeOwnerExecutor,
    resource: &Arc<Mutex<RecoveredInlineJob>>,
    identity: &Identity,
) -> io::Result<()> {
    let (running, body, project, publisher_uid) = {
        let job = resource
            .lock()
            .map_err(|_| invalid("inline source job poisoned"))?;
        (
            Arc::clone(&job.running),
            Arc::clone(&job.body),
            job.project,
            job.publisher_uid,
        )
    };
    running.check_current().map_err(io::Error::other)?;
    check_native_body(&body, project, publisher_uid)?;
    let custody = Arc::clone(executor.custody());
    let write = {
        let mut job = resource
            .lock()
            .map_err(|_| invalid("inline source job poisoned"))?;
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("inline source custody poisoned"))?;
        job.check_resources(&owner)?;
        check_snapshot(&owner)?;
        if owner.faulted || job.started || owner.generation != job.generation {
            return Err(invalid(
                "inline pin requires a fresh physical source command",
            ));
        }
        claim_span(&owner, body.claim(), identity, &job.row)?;
        owner.preparation.recheck()?;
        let future = state::check_charge(&owner)?
            .checked_add(job.hold)
            .ok_or_else(|| invalid("inline future holds overflow"))?;
        state::check_total(&owner, future)?;
        let mut random = [0; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let token = state::hex(&random);
        if owner.state.reservations.iter().any(|row| row.id == token) {
            return Err(invalid("inline source token collision"));
        }
        let lease = format!("source:{token}");
        let mut next = owner.state.clone();
        next.reservations.push(ReservationRecord {
            id: token.clone(),
            owner: owner.preparation.config.quota_owner.clone(),
            bytes: job.hold,
        });
        next.leases.push(LeaseRecord {
            owner: lease.clone(),
            expires: RETAINED_LEASE_DEADLINE,
        });
        next.pins.push(PinRecord {
            owner: lease,
            hash: job.row.object.clone(),
            expires: RETAINED_LEASE_DEADLINE,
        });
        next.encoded_len(owner.preparation.config.state)
            .map_err(io::Error::other)?;
        job.token = token;
        job.started = true;
        owner.faulted = true;
        owner.begin_mutation()?;
        job.generation = owner.generation;
        owner.state = next;
        super::super::super::snapshot::prepare(executor, &mut owner)?
    };
    super::super::super::snapshot::persist(executor, write).await?;
    // Only owned actual descriptors cross these filesystem operations. Neither
    // embedded custody nor the publisher RPC mutex is held during native IO.
    let allocated_inode_bytes = synchronize_body(&body, project, publisher_uid)?;
    running.check_current().map_err(io::Error::other)?;
    {
        let mut job = resource
            .lock()
            .map_err(|_| invalid("inline source job poisoned"))?;
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("inline source custody poisoned"))?;
        check_snapshot(&owner)?;
        job.check_resources(&owner)?;
        job.check_funding(&owner)?;
        if !owner.faulted || owner.generation != job.generation {
            return Err(invalid(
                "inline source lost its exclusive physical pin phase",
            ));
        }
        owner.snapshot_allocated_bytes = owner
            .snapshot
            .as_ref()
            .ok_or_else(|| invalid("inline source snapshot absent"))
            .and_then(|(file, _)| synchronized_allocated_bytes(file))?;
        owner.directory_allocated_bytes = synchronized_allocated_bytes(&owner.directory)?;
        owner.preparation.recheck()?;
        let future_hold_bytes = state::check_charge(&owner)?;
        let charged_reserved_bytes = owner
            .preparation
            .quota()
            .observation()
            .charged_reserved_bytes;
        job.completion = Some(CompletedPin {
            allocated_inode_bytes,
            charged_reserved_bytes,
            future_hold_bytes,
        });
        owner.faulted = false;
    }
    Ok(())
}

/// Resolves only original registered and reconciled inline source jobs.
///
/// # Errors
/// Refuses foreign, incomplete or changed physical resources and policy rows.
pub(super) fn select(
    executor: &NativeOwnerExecutor,
    owner: &Custody,
    identity: &Identity,
    row: &ResidenceRecord,
) -> io::Result<Option<Source>> {
    for resource in executor.inline_source_jobs() {
        let job = resource
            .lock()
            .map_err(|_| invalid("inline source job poisoned"))?;
        if job.row.object != row.object {
            continue;
        }
        if !Arc::ptr_eq(&job.custody, executor.custody()) {
            return Err(invalid("inline source belongs to another physical owner"));
        }
        let span = claim_span(owner, job.body.claim(), identity, row)?;
        let source = Source {
            origin: Origin::RecoveredInline(Arc::clone(resource)),
            body: Arc::clone(&job.body),
            span,
            row: row.clone(),
            generation: owner.generation,
            project: owner.preparation.config.project_id,
            publisher_uid: owner.preparation.config.publisher.identities.publish_uid,
            allocation_limit: owner.preparation.config.reads.max_allocation_bytes,
        };
        job.check_registration(owner, &source, identity)?;
        return Ok(Some(source));
    }
    Ok(None)
}
