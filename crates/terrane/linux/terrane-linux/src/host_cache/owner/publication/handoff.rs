//! Transfers a completed publication into native cache ownership.
//!
//! Original body, reconstruction metadata and acknowledged source cleanup stay
//! physically owned through the synchronized producer-funding decrement. A
//! durable grace pin replaces the producer promise. Consumer pins are separate.

use super::{PublicationJob, invalid, producer_reads, residence, retirement};
use crate::{
    host_cache::{
        RetainedManifest,
        owner::{
            consumer::{clock, state as policy},
            retention::{Command, Custody, NativeMetadataOwner, NativeOwnerExecutor},
            snapshot,
        },
    },
    publisher_local::client::{PeerPublishedObject, PublisherRunningContext},
};
use std::{
    io,
    sync::{Arc, Mutex, mpsc},
};
use terrane_sdk::host::cache::{HostDomainLocation, LeaseRecord, PinRecord};
use tokio::sync::oneshot;

/// Distinguishes an unsubmitted handoff from a failure after worker acceptance.
///
/// Only a queue refusal returns the original publication for retry. An accepted
/// command remains physically owned even when its waiter receives an error.
pub enum NativeCacheHandoffError<P> {
    /// Returns the original publication because no command was accepted.
    Unsubmitted {
        /// Explains why the owner could not accept the command.
        error: io::Error,
        /// Retains the original completed publication for retry.
        publication: P,
    },
    /// Reports an accepted command's failure without claiming effects rolled back.
    Accepted(io::Error),
}

impl<P> std::fmt::Debug for NativeCacheHandoffError<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsubmitted { error, .. } => formatter
                .debug_struct("Unsubmitted")
                .field("error", error)
                .finish_non_exhaustive(),
            Self::Accepted(error) => formatter.debug_tuple("Accepted").field(error).finish(),
        }
    }
}

impl<P> std::fmt::Display for NativeCacheHandoffError<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsubmitted { error, .. } | Self::Accepted(error) => error.fmt(formatter),
        }
    }
}

impl<P> std::error::Error for NativeCacheHandoffError<P> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unsubmitted { error, .. } | Self::Accepted(error) => Some(error),
        }
    }
}

/// Reports completed cache ownership separately from measured physical usage.
///
/// This report supplies no raw handle, consumer grant or eviction authority.
#[derive(Clone, Copy, Debug)]
pub struct NativeCacheHandoffReport {
    /// Synchronized allocated blocks of the original sealed inode alone.
    pub synchronized_sealed_inode_bytes: u64,
    /// Fresh charged-and-reserved usage of the complete native project.
    pub charged_reserved_bytes: u64,
    /// Distinct future policy holds after releasing obsolete producer funding.
    pub future_hold_bytes: u64,
    /// Original durable deadline protecting the object after producer release.
    pub release_grace_ends_at: u64,
    /// Number of acknowledged standalone source admissions released.
    pub released_source_admissions: usize,
}

/// Retains genuine completed cache custody, never reconstructed from a row or ID.
pub(super) struct CachedPublication {
    custody: Arc<Mutex<Custody>>,
    body: Arc<PeerPublishedObject<HostDomainLocation>>,
    metadata: Option<Arc<RetainedManifest>>,
    running: Arc<PublisherRunningContext>,
    generation: u64,
    grace: Grace,
}

struct Grace {
    owner: String,
    expires: u64,
    hashes: Vec<String>,
}

impl CachedPublication {
    /// Borrows actual reconstruction custody through dependent sealed retirement.
    pub(super) fn reconstruction(&self) -> Option<&Arc<RetainedManifest>> {
        self.metadata.as_ref()
    }

    /// Names only this actual retained manifest's reconstruction pin purpose.
    pub(super) fn reconstruction_pin_owner(&self) -> Option<String> {
        self.metadata
            .as_ref()
            .map(|metadata| format!("metadata:{}", super::state::hex(metadata.retention_id())))
    }

    /// Checks retained native ownership against current synchronized policy.
    ///
    /// # Errors
    /// Refuses changed body/layout, original bootstrap custody or metadata,
    /// stale generations, and a missing or altered durable grace promise.
    pub(super) fn check(
        &self,
        owner: &Custody,
        custody: &Arc<Mutex<Custody>>,
        body: &Arc<PeerPublishedObject<HostDomainLocation>>,
    ) -> io::Result<()> {
        residence::check_snapshot(owner)?;
        policy::check_bootstrap(owner, &self.running)?;
        if !Arc::ptr_eq(custody, &self.custody)
            || !Arc::ptr_eq(body, &self.body)
            || !Arc::ptr_eq(body.layout(), owner.preparation.layout())
            || owner.generation < self.generation
        {
            return Err(invalid(
                "cached publication changed original native custody",
            ));
        }
        if let Some(metadata) = &self.metadata {
            metadata.check_registration(owner)?;
            if metadata.claim().descriptor() != body.claim().descriptor() {
                return Err(invalid(
                    "cached reconstruction metadata differs from sealed body",
                ));
            }
        }
        let grace = &self.grace;
        let present = owner
            .state
            .leases
            .iter()
            .any(|lease| lease.owner == grace.owner)
            || owner.state.pins.iter().any(|pin| pin.owner == grace.owner);
        if !present {
            // The original native cache capability survives the actual
            // owner's later synchronized expiry sweep. Row absence never
            // constructs a cache capability or a backing descriptor.
            if owner.generation <= self.generation || clock::now_seconds()? < grace.expires {
                return Err(invalid("cached publication lost unexpired release grace"));
            }
        } else if owner
            .state
            .leases
            .iter()
            .filter(|lease| lease.owner == grace.owner)
            .count()
            != 1
            || !owner
                .state
                .leases
                .iter()
                .any(|lease| lease.owner == grace.owner && lease.expires == grace.expires)
            || owner
                .state
                .pins
                .iter()
                .filter(|pin| pin.owner == grace.owner)
                .count()
                != grace.hashes.len()
            || grace.hashes.iter().any(|hash| {
                !owner.state.pins.iter().any(|pin| {
                    pin.owner == grace.owner && &pin.hash == hash && pin.expires == grace.expires
                })
            })
        {
            return Err(invalid("cached publication changed durable release grace"));
        }
        Ok(())
    }
}

/// Submits only the original completed publication, retaining physical ownership.
///
/// # Errors
/// Refuses stopped/full queues or an unavailable physical worker response.
pub(super) async fn submit<P>(
    owner: &NativeMetadataOwner,
    resource: Arc<Mutex<PublicationJob>>,
    publication: P,
) -> Result<NativeCacheHandoffReport, NativeCacheHandoffError<P>> {
    let (response, receive) = oneshot::channel();
    let Some(commands) = owner.commands.as_ref() else {
        return Err(NativeCacheHandoffError::Unsubmitted {
            error: io::Error::new(io::ErrorKind::BrokenPipe, "cache handoff owner stopped"),
            publication,
        });
    };
    if let Err(error) = commands.try_send(Command::CachePublication { resource, response }) {
        let error = match error {
            mpsc::TrySendError::Full(_) => {
                io::Error::new(io::ErrorKind::WouldBlock, "cache handoff queue full")
            }
            mpsc::TrySendError::Disconnected(_) => {
                io::Error::new(io::ErrorKind::BrokenPipe, "cache handoff owner stopped")
            }
        };
        return Err(NativeCacheHandoffError::Unsubmitted { error, publication });
    }
    drop(publication);
    receive
        .await
        .map_err(|_| NativeCacheHandoffError::Accepted(invalid("cache handoff worker terminated")))?
        .map_err(NativeCacheHandoffError::Accepted)
}

/// Synchronizes actual cache custody before acknowledging producer-funding release.
///
/// # Errors
/// Refuses foreign/incomplete publication, active producer reads, missing final
/// source acknowledgments, changed metadata or native backing, and snapshot or
/// quota failure. Started effects retain faulted physical custody on failure.
pub(in crate::host_cache::owner) async fn execute(
    executor: &mut NativeOwnerExecutor,
    resource: &Arc<Mutex<PublicationJob>>,
) -> io::Result<NativeCacheHandoffReport> {
    let closed = producer_reads::execute(executor, resource)?;
    if closed.active_views != 0 {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "producer reads have not quiesced",
        ));
    }
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let custody = Arc::clone(executor.custody());
    let (body, metadata, sources, grace, project, publisher_uid) = {
        let job = resource
            .lock()
            .map_err(|_| invalid("handoff publication poisoned"))?;
        let owner = custody
            .lock()
            .map_err(|_| invalid("handoff custody poisoned"))?;
        if job.cached.is_some() {
            return Err(invalid("publication already belongs to cache custody"));
        }
        let body = Arc::clone(residence::registered_body(&owner, &job)?);
        let sources = retirement::closed_funding(executor, &owner, &job)?;
        let mut hashes = job
            .manifest
            .as_ref()
            .map(|input| input.backing_hashes(&owner))
            .transpose()?
            .unwrap_or_default();
        hashes.push(super::state::hex(job.claim.descriptor().digest()));
        hashes.sort();
        hashes.dedup();
        let grace = Grace {
            owner: format!("publication-grace:{}", job.token),
            expires: clock::grace_end(None, owner.preparation.config.policy.release_grace)?,
            hashes,
        };
        if owner
            .state
            .leases
            .iter()
            .any(|row| row.owner == grace.owner)
            || owner.state.pins.iter().any(|row| row.owner == grace.owner)
        {
            return Err(invalid("cache release grace identifier occupied"));
        }
        (
            body,
            job.manifest
                .as_ref()
                .map(|input| Arc::clone(&input.retained)),
            sources,
            grace,
            owner.preparation.config.project_id,
            owner.preparation.config.publisher.identities.publish_uid,
        )
    };
    let allocated = residence::synchronize_body(&body, project, publisher_uid)?;
    running.check_current().map_err(io::Error::other)?;
    let (write, generation) = {
        let job = resource
            .lock()
            .map_err(|_| invalid("handoff publication poisoned"))?;
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("handoff custody poisoned"))?;
        let original = residence::registered_body(&owner, &job)?;
        if !Arc::ptr_eq(original, &body) || !Arc::ptr_eq(&job.custody, &custody) {
            return Err(invalid("handoff changed original body or writer"));
        }
        let mut next = owner.state.clone();
        for source in &sources {
            source.remove_from(&owner, &mut next)?;
        }
        let producer = format!("publication:{}", job.token);
        next.pins.retain(|pin| pin.owner != producer);
        next.leases.retain(|lease| lease.owner != producer);
        next.reservations.retain(|hold| hold.id != job.token);
        next.leases.push(LeaseRecord {
            owner: grace.owner.clone(),
            expires: grace.expires,
        });
        if owner
            .state
            .pins
            .iter()
            .filter(|pin| pin.owner == producer)
            .count()
            != grace.hashes.len()
            || grace.hashes.iter().any(|hash| {
                !owner.state.pins.iter().any(|pin| {
                    pin.owner == producer
                        && &pin.hash == hash
                        && pin.expires == super::super::RETAINED_LEASE_DEADLINE
                })
            })
        {
            return Err(invalid("handoff producer dependency pins changed"));
        }
        for hash in &grace.hashes {
            next.pins.push(PinRecord {
                owner: grace.owner.clone(),
                expires: grace.expires,
                hash: hash.clone(),
            });
        }
        let write = policy::begin(executor, &mut owner, &running, next, 0, None)?;
        (write, owner.generation)
    };
    snapshot::persist(executor, write).await?;
    running.check_current().map_err(io::Error::other)?;
    let expires = grace.expires;
    {
        let mut job = resource
            .lock()
            .map_err(|_| invalid("handoff publication poisoned"))?;
        let owner = custody
            .lock()
            .map_err(|_| invalid("handoff custody poisoned"))?;
        residence::check_snapshot(&owner)?;
        let cached = CachedPublication {
            custody: Arc::clone(&custody),
            body: Arc::clone(&body),
            metadata,
            running: Arc::clone(&running),
            generation,
            grace,
        };
        cached.check(&owner, &custody, &body)?;
        job.cached = Some(cached);
        job.encoded.clear();
        job.encoded.shrink_to_fit();
        job.dictionary = None;
    }
    // Actual descriptor and input release precedes the fresh complete-project
    // query. No logical funding decrement is presented as measured reclamation.
    executor.release_transferred_admissions(&sources)?;
    policy::synchronize_policy(executor)?;
    let mut owner = custody
        .lock()
        .map_err(|_| invalid("handoff custody poisoned"))?;
    let observed = policy::finish(&mut owner, generation)?;
    Ok(NativeCacheHandoffReport {
        synchronized_sealed_inode_bytes: allocated,
        charged_reserved_bytes: observed.charged,
        future_hold_bytes: observed.future,
        release_grace_ends_at: expires,
        released_source_admissions: sources.len(),
    })
}
