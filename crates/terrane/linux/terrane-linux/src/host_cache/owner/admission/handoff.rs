//! Transfers actual completed encoded admissions into retained cache ownership.
//!
//! Producer future holds retire only after the original inode inventory is
//! checked and a replacement policy snapshot is synchronized. The worker keeps
//! every native resource. Durable release grace and dictionary dependency pins
//! are policy promises; neither their names nor their absence create custody.

use super::{Input, NativeAdmissionHandoffError, backing::AdmissionJob, reconcile, state};
use crate::{
    host_cache::owner::{
        RETAINED_LEASE_DEADLINE,
        consumer::{clock, state as policy},
        publication::residence::check_snapshot,
        retention::{Command, Custody, NativeMetadataOwner, NativeOwnerExecutor},
        snapshot,
    },
    host_quota::synchronized_allocated_bytes,
    publisher_local::client::{EncodedReadObservation, PublisherRunningContext},
};
use std::{
    collections::BTreeMap,
    io,
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex, mpsc},
};
use terrane_sdk::host::cache::{CacheState, LeaseRecord, PinRecord};
use tokio::sync::oneshot;

/// Reports actual cache ownership separately from allocation and future holds.
#[derive(Clone, Copy, Debug)]
pub struct NativeAdmissionHandoffReport {
    /// Synchronized allocated blocks of the original chunk or metadata pair.
    pub synchronized_member_bytes: u64,
    /// Fresh complete-project kernel charged-and-reserved usage.
    pub charged_reserved_bytes: u64,
    /// Distinct future allocation holds after producer funding retires.
    pub future_hold_bytes: u64,
    /// Original producer hold removed by the synchronized handoff.
    pub released_future_hold_bytes: u64,
    /// Durable deadline protecting the original admitted identities after release.
    pub release_grace_ends_at: u64,
}

/// Retains the original worker's completed admission through producer release.
#[derive(Clone)]
pub(super) struct CachedAdmission {
    custody: Arc<Mutex<Custody>>,
    running: Arc<PublisherRunningContext>,
    original: Arc<EncodedReadObservation>,
    token: String,
    hashes: Vec<String>,
    dependencies: Vec<String>,
    original_hold: u64,
    generation: u64,
    expires: u64,
}

impl CachedAdmission {
    fn prepare(
        executor: &NativeOwnerExecutor,
        owner: &Custody,
        job: &AdmissionJob,
        running: Arc<PublisherRunningContext>,
        original: Arc<EncodedReadObservation>,
    ) -> io::Result<Self> {
        if !job.complete || job.cached.is_some() || !Arc::ptr_eq(&job.custody, executor.custody()) {
            return Err(invalid(
                "cache handoff requires original completed producer custody",
            ));
        }
        state::check_registration(owner, job)?;
        original.check_original(&running, &super::eviction::key_for_input(&job.input)?)?;
        // A dictionary can have the same plaintext identity as its dependent
        // chunk while using another actual encoding/inode. Hash subtraction
        // would lose that dependency; the original retained jobs establish it.
        if matches!(&job.input, Input::Metadata { .. }) && !job.dependencies.is_empty() {
            return Err(invalid(
                "metadata admission unexpectedly retains a dictionary",
            ));
        }
        let mut dependencies = Vec::new();
        dependencies
            .try_reserve_exact(job.dependencies.len())
            .map_err(io::Error::other)?;
        for resource in &job.dependencies {
            let dependency = super::backing::lock(resource)?;
            let Input::Chunk { descriptor, .. } = &dependency.input else {
                return Err(invalid("cache dictionary changed its actual input class"));
            };
            dependencies.push(state::hex(descriptor.digest()));
        }
        dependencies.sort();
        dependencies.dedup();
        Ok(Self {
            custody: Arc::clone(executor.custody()),
            running,
            original,
            token: job.token.clone(),
            hashes: job.hashes.clone(),
            dependencies,
            original_hold: job.hold,
            generation: owner.generation,
            expires: clock::grace_end(None, owner.preparation.config.policy.release_grace)?,
        })
    }

    fn grace_owner(&self) -> String {
        format!("admission-grace:{}", self.token)
    }

    fn dependency_owner(&self) -> String {
        format!("cache-dependency:{}", self.token)
    }

    /// Checks original native custody and the complete synchronized promises.
    ///
    /// # Errors
    /// Refuses changed registration, bootstrap, funding, grace or dependencies.
    pub(super) fn check(&self, owner: &Custody, job: &AdmissionJob) -> io::Result<()> {
        check_snapshot(owner)?;
        policy::check_bootstrap(owner, &self.running)?;
        self.original
            .check_original(&self.running, &super::eviction::key_for_input(&job.input)?)?;
        let producer = format!("admission:{}", self.token);
        if !job
            .read_observation
            .as_ref()
            .is_some_and(|actual| Arc::ptr_eq(actual, &self.original))
            || !job.complete
            || !Arc::ptr_eq(&job.custody, &self.custody)
            || job.token != self.token
            || job.hashes != self.hashes
            || job.hold != self.original_hold
            || owner.generation < self.generation
            || owner
                .state
                .reservations
                .iter()
                .any(|hold| hold.id == self.token)
            || owner
                .state
                .leases
                .iter()
                .any(|lease| lease.owner == producer)
            || owner.state.pins.iter().any(|pin| pin.owner == producer)
        {
            return Err(invalid(
                "cached admission changed its original physical funding",
            ));
        }
        let grace = self.grace_owner();
        let present = owner.state.leases.iter().any(|lease| lease.owner == grace)
            || owner.state.pins.iter().any(|pin| pin.owner == grace);
        if present {
            check_promise(&owner.state, &grace, self.expires, &self.hashes)?;
        } else if owner.generation <= self.generation || clock::now_seconds()? < self.expires {
            return Err(invalid("cached admission lost unexpired producer grace"));
        }
        check_promise(
            &owner.state,
            &self.dependency_owner(),
            RETAINED_LEASE_DEADLINE,
            &self.dependencies,
        )
    }

    /// Removes this actual source's remaining promises after acknowledged transfer.
    ///
    /// # Errors
    /// Refuses changed original custody or altered synchronized promises.
    pub(super) fn remove_transferred(
        &self,
        owner: &Custody,
        job: &AdmissionJob,
        next: &mut CacheState,
    ) -> io::Result<()> {
        self.check(owner, job)?;
        let grace = self.grace_owner();
        let dependency = self.dependency_owner();
        next.pins
            .retain(|pin| pin.owner != grace && pin.owner != dependency);
        next.leases
            .retain(|lease| lease.owner != grace && lease.owner != dependency);
        Ok(())
    }

    /// Checks synchronized removal before relinquishing the original source job.
    ///
    /// # Errors
    /// Refuses another cache handoff or any remaining original promise/funding.
    pub(super) fn check_released(&self, owner: &Custody, job: &AdmissionJob) -> io::Result<()> {
        let actual = job
            .cached
            .as_ref()
            .ok_or_else(|| invalid("cached source custody absent"))?;
        if !Arc::ptr_eq(&self.custody, &actual.custody)
            || !Arc::ptr_eq(&self.running, &actual.running)
            || !Arc::ptr_eq(&self.original, &actual.original)
            || self.token != actual.token
            || self.generation != actual.generation
            || self.hashes != actual.hashes
            || self.dependencies != actual.dependencies
            || self.original_hold != actual.original_hold
            || self.expires != actual.expires
            || owner
                .state
                .reservations
                .iter()
                .any(|row| row.id == self.token)
        {
            return Err(invalid("released cached source changed original custody"));
        }
        for purpose in [
            self.grace_owner(),
            self.dependency_owner(),
            format!("admission:{}", self.token),
        ] {
            check_promise(&owner.state, &purpose, 0, &[])?;
        }
        Ok(())
    }
}

fn check_promise(
    state: &CacheState,
    owner: &str,
    expires: u64,
    hashes: &[String],
) -> io::Result<()> {
    let leases = state.leases.iter().filter(|row| row.owner == owner).count();
    let pins = state.pins.iter().filter(|row| row.owner == owner).count();
    if hashes.is_empty() {
        if leases != 0 || pins != 0 {
            return Err(invalid("unexpected cached admission promise"));
        }
    } else if leases != 1
        || !state
            .leases
            .iter()
            .any(|row| row.owner == owner && row.expires == expires)
        || pins != hashes.len()
        || hashes.iter().any(|hash| {
            !state
                .pins
                .iter()
                .any(|pin| pin.owner == owner && pin.hash == *hash && pin.expires == expires)
        })
    {
        return Err(invalid("cached admission promise changed"));
    }
    Ok(())
}

/// Submits a genuine admission without discarding it on actual queue refusal.
///
/// # Errors
/// Returns the original admission on local refusal; accepted failures retain
/// physical resources independently of the reply waiter.
pub(super) async fn submit<A>(
    owner: &NativeMetadataOwner,
    resource: Arc<Mutex<AdmissionJob>>,
    admission: A,
) -> Result<NativeAdmissionHandoffReport, NativeAdmissionHandoffError<A>> {
    let (response, receive) = oneshot::channel();
    let Some(commands) = owner.commands.as_ref() else {
        return Err(NativeAdmissionHandoffError::Unsubmitted {
            error: io::Error::new(io::ErrorKind::BrokenPipe, "admission cache owner stopped"),
            admission: Box::new(admission),
        });
    };
    if let Err(error) = commands.try_send(Command::CacheAdmission { resource, response }) {
        let error = match error {
            mpsc::TrySendError::Full(_) => {
                io::Error::new(io::ErrorKind::WouldBlock, "admission cache queue full")
            }
            mpsc::TrySendError::Disconnected(_) => {
                io::Error::new(io::ErrorKind::BrokenPipe, "admission cache owner stopped")
            }
        };
        return Err(NativeAdmissionHandoffError::Unsubmitted {
            error,
            admission: Box::new(admission),
        });
    }
    drop(admission);
    receive
        .await
        .map_err(|_| {
            NativeAdmissionHandoffError::Accepted(invalid("admission cache worker terminated"))
        })?
        .map_err(NativeAdmissionHandoffError::Accepted)
}

/// Synchronizes producer release while retaining actual chunk or pair custody.
///
/// # Errors
/// Refuses foreign/incomplete admissions, changed bytes, stale funding or
/// failed physical synchronization. Started effects keep faulted custody.
pub(in crate::host_cache::owner) async fn execute(
    executor: &mut NativeOwnerExecutor,
    resource: &Arc<Mutex<AdmissionJob>>,
) -> io::Result<NativeAdmissionHandoffReport> {
    executor.check_physical_worker()?;
    if !executor
        .admission_jobs()
        .iter()
        .any(|job| Arc::ptr_eq(job, resource))
    {
        return Err(invalid(
            "admission cache handoff belongs to another physical owner",
        ));
    }
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let dependencies = {
        let job = super::backing::lock(resource)?;
        let mut dependencies = Vec::new();
        dependencies
            .try_reserve_exact(job.dependencies.len())
            .map_err(io::Error::other)?;
        dependencies.extend(job.dependencies.iter().cloned());
        dependencies
    };
    for dependency in dependencies {
        super::read_custody::observe(executor, &dependency)?;
    }
    let original = super::read_custody::observe(executor, resource)?;
    let (mut cached, files) = {
        let job = super::backing::lock(resource)?;
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("admission cache custody poisoned"))?;
        reconcile::verify(&owner, &job)?;
        let cached =
            CachedAdmission::prepare(executor, &owner, &job, Arc::clone(&running), original)?;
        let files = job
            .files
            .iter()
            .map(|member| {
                member
                    .readonly
                    .as_ref()
                    .ok_or_else(|| invalid("admission cache member absent"))?
                    .try_clone()
            })
            .collect::<io::Result<Vec<_>>>()?;
        (cached, files)
    };
    policy::synchronize_policy(executor)?;
    let mut allocated = BTreeMap::new();
    for file in &files {
        let metadata = file.metadata()?;
        allocated.insert(
            (metadata.dev(), metadata.ino()),
            synchronized_allocated_bytes(file)?,
        );
    }
    let member_bytes = allocated.values().try_fold(0u64, |sum, bytes| {
        sum.checked_add(*bytes)
            .ok_or_else(|| invalid("cached admission allocation overflows"))
    })?;
    drop(files);
    let write = {
        let job = super::backing::lock(resource)?;
        let mut owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("admission cache custody poisoned"))?;
        reconcile::verify(&owner, &job)?;
        state::check_registration(&owner, &job)?;
        let mut next = owner.state.clone();
        let producer = format!("admission:{}", job.token);
        check_promise(&next, &producer, RETAINED_LEASE_DEADLINE, &job.hashes)?;
        next.pins.retain(|row| row.owner != producer);
        next.leases.retain(|row| row.owner != producer);
        next.reservations.retain(|row| row.id != job.token);
        for (purpose, expires, hashes) in [
            (cached.grace_owner(), cached.expires, &cached.hashes),
            (
                cached.dependency_owner(),
                RETAINED_LEASE_DEADLINE,
                &cached.dependencies,
            ),
        ] {
            check_promise(&next, &purpose, 0, &[])?;
            if !hashes.is_empty() {
                next.leases.push(LeaseRecord {
                    owner: purpose.clone(),
                    expires,
                });
                for hash in hashes {
                    next.pins.push(PinRecord {
                        owner: purpose.clone(),
                        hash: hash.clone(),
                        expires,
                    });
                }
            }
        }
        let write = policy::begin(executor, &mut owner, &running, next, 0, None)?;
        cached.generation = owner.generation;
        write
    };
    snapshot::persist(executor, write).await?;
    let generation = cached.generation;
    let released = cached.original_hold;
    let expires = cached.expires;
    {
        let mut job = super::backing::lock(resource)?;
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("admission cache custody poisoned"))?;
        cached.check(&owner, &job)?;
        if job.cached.is_some() {
            return Err(invalid("admission cache custody already transferred"));
        }
        job.cached = Some(cached);
    }
    policy::synchronize_policy(executor)?;
    running.check_current().map_err(io::Error::other)?;
    let mut owner = executor
        .custody()
        .lock()
        .map_err(|_| invalid("admission cache custody poisoned"))?;
    let observed = policy::finish(&mut owner, generation)?;
    Ok(NativeAdmissionHandoffReport {
        synchronized_member_bytes: member_bytes,
        charged_reserved_bytes: observed.charged,
        future_hold_bytes: observed.future,
        released_future_hold_bytes: released,
        release_grace_ends_at: expires,
    })
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
