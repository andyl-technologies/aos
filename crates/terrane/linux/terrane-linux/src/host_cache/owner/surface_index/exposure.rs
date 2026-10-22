//! Synchronizes root exposure obligations through the original physical queue.
//!
//! A lease protects an already verified sealed index. It is not a FUSE worker,
//! authenticated transport credential or continuing Read authorization. Dropping
//! its receipt, deadline expiry and explicit drain never discharge kernel custody.

use super::{NativeMetadataOwner, NativeRootIndex, NativeSurfaceIndex, invalid};
use crate::host_cache::NativeSealedObjectLease;
use crate::host_cache::owner::{
    consumer::{clock, state},
    retention::{Command, NativeOwnerExecutor},
    snapshot,
};
use crate::structural_index::IndexKey;
use std::{
    io,
    sync::{Arc, mpsc},
};
use terrane_format::identity::Digest;
use terrane_sdk::host::cache::{ExposurePhase, ExposureRecord, PinRecord};
use tokio::sync::oneshot;

/// Retains the original index and identity of an acknowledged durable exposure.
///
/// Cloning or dropping this receipt does not renew or release the durable lease.
/// It supplies physical context only; a worker must separately authenticate every
/// backing request and perform its fresh scoped authorization.
#[derive(Clone)]
pub struct NativeExposureLease {
    id: String,
    generation: u64,
    commit: Digest,
    index: NativeSurfaceIndex,
}

impl NativeExposureLease {
    /// Returns the immutable signed commit selected for this exposure.
    pub const fn commit(&self) -> Digest {
        self.commit
    }

    /// Returns the canonical index key retained by this exposure.
    pub fn key(&self) -> IndexKey {
        self.index.key()
    }

    /// Returns the durable exposure identifier, which is not a credential.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the generation accepted by this original exposure context.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

pub(in crate::host_cache::owner) enum Operation {
    Check,
    ProtectObject { source: NativeSealedObjectLease },
    Retain { domain: String, expires: u64 },
    Renew { expires: u64 },
    Drain,
}

pub(in crate::host_cache::owner) struct Request {
    lease: NativeExposureLease,
    operation: Operation,
    response: oneshot::Sender<io::Result<NativeExposureLease>>,
}

impl NativeMetadataOwner {
    /// Durably retains an already checked mapped root before acknowledging a lease.
    ///
    /// This initial lease protects the index only. It grants no file descriptor
    /// and contains no object pins until a checked file preparation attaches
    /// actual backing. Cancellation after enqueue retains the physical obligation.
    /// No release API is provided: final kernel closure must first be established.
    ///
    /// # Errors
    /// Refuses disabled admission, a foreign original index or domain, elapsed
    /// deadlines, exhausted bounds, stale owner custody and native IO failures.
    pub async fn retain_surface_exposure(
        &self,
        served: &NativeRootIndex,
        expires: u64,
    ) -> io::Result<NativeExposureLease> {
        let lease = NativeExposureLease {
            id: String::new(),
            generation: 1,
            commit: served.commit,
            index: served.admission.clone(),
        };
        self.exposure_request(
            lease,
            Operation::Retain {
                domain: served.domain.clone(),
                expires,
            },
        )
        .await
    }

    /// Extends a still-live original exposure without changing its served root.
    ///
    /// Renewal cannot resurrect a draining or expired worker generation. Success
    /// acknowledges only physical lease state, not renewed Read authorization.
    ///
    /// # Errors
    /// Refuses foreign or expired leases, shortened deadlines, queue exhaustion,
    /// changed native custody, capacity and synchronization failures.
    pub async fn renew_surface_exposure(
        &self,
        lease: &NativeExposureLease,
        expires: u64,
    ) -> io::Result<()> {
        self.exposure_request(lease.clone(), Operation::Renew { expires })
            .await?;
        Ok(())
    }

    /// Durably starts draining an exposure without releasing its physical pins.
    ///
    /// This is idempotent for the same original context. The connection owner
    /// must separately stop opens, bound in-flight work and abort the connection.
    ///
    /// # Errors
    /// Refuses foreign context, queue exhaustion, changed native custody and IO.
    pub async fn drain_surface_exposure(&self, lease: &NativeExposureLease) -> io::Result<()> {
        self.exposure_request(lease.clone(), Operation::Drain)
            .await?;
        Ok(())
    }

    async fn exposure_request(
        &self,
        lease: NativeExposureLease,
        operation: Operation,
    ) -> io::Result<NativeExposureLease> {
        if self.surface_policy.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "surface admission disabled",
            ));
        }
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| invalid("native owner stopped"))?
            .try_send(Command::SurfaceExposure(Request {
                lease,
                operation,
                response,
            }))
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "native owner queue full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "native owner stopped")
                }
            })?;
        receive
            .await
            .map_err(|_| invalid("exposure worker stopped before acknowledgment"))?
    }

    /// Checks live original exposure context before accepting file pin effects.
    ///
    /// # Errors
    /// Refuses foreign, draining or expired context and native queue failures.
    pub(in crate::host_cache::owner) async fn check_surface_exposure(
        &self,
        lease: &NativeExposureLease,
    ) -> io::Result<()> {
        self.exposure_request(lease.clone(), Operation::Check)
            .await?;
        Ok(())
    }

    /// Copies actual whole-object protection into this exposure's durable pins.
    ///
    /// # Errors
    /// Refuses foreign original jobs, elapsed or draining context, a consumer
    /// deadline beyond the exposure, exhausted bounds and synchronization errors.
    pub(in crate::host_cache::owner) async fn protect_surface_object(
        &self,
        lease: &NativeExposureLease,
        source: &NativeSealedObjectLease,
    ) -> io::Result<()> {
        self.exposure_request(
            lease.clone(),
            Operation::ProtectObject {
                source: source.clone(),
            },
        )
        .await?;
        Ok(())
    }
}

pub(in crate::host_cache::owner) async fn execute(
    executor: &NativeOwnerExecutor,
    request: Request,
) {
    let result = transition(executor, request.lease, request.operation).await;
    let _ = request.response.send(result);
}

async fn transition(
    executor: &NativeOwnerExecutor,
    mut lease: NativeExposureLease,
    operation: Operation,
) -> io::Result<NativeExposureLease> {
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let source = match &operation {
        Operation::ProtectObject { source } => Some(source.clone()),
        _ => None,
    };
    let source_context = source
        .as_ref()
        .map(|source| source.exposure_context(executor))
        .transpose()?;
    if let Some(context) = &source_context {
        context.check_current().map_err(io::Error::other)?;
    }
    let custody = executor.custody();
    let now = clock::now_seconds()?;
    let (write, generation) = {
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("exposure custody poisoned"))?;
        state::check_ready(executor, &owner)?;
        state::check_bootstrap(&owner, &running)?;
        let job = owner
            .surface_indexes
            .get(&lease.index.key())
            .ok_or_else(|| invalid("exposure index is absent from original owner"))?;
        let backing = job
            .backing
            .as_ref()
            .ok_or_else(|| invalid("exposure index is unresolved"))?;
        if !Arc::ptr_eq(backing, &lease.index.backing) {
            return Err(invalid("exposure index belongs to another native owner"));
        }
        if let Err(error) = backing.check() {
            owner.faulted = true;
            return Err(error);
        }
        let mut next = owner.state.clone();
        match operation {
            Operation::Retain { domain, expires } => {
                if domain != owner.preparation.config.location.domain() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "exposure belongs to another domain",
                    ));
                }
                lease.id = state::fresh_token(&owner)?;
                next.retain_exposure(
                    ExposureRecord {
                        id: lease.id.clone(),
                        generation: lease.generation,
                        commit: state::hex(&lease.commit),
                        root: state::hex(&lease.index.key().root()),
                        index_version: lease.index.key().version(),
                        deadline: expires,
                        phase: ExposurePhase::Active,
                    },
                    &[],
                    now,
                    owner.preparation.config.state,
                )
                .map_err(io::Error::other)?;
            }
            operation => {
                let row = next
                    .exposures
                    .iter_mut()
                    .find(|row| {
                        row.id == lease.id
                            && row.generation == lease.generation
                            && row.commit == state::hex(&lease.commit)
                            && row.root == state::hex(&lease.index.key().root())
                            && row.index_version == lease.index.key().version()
                    })
                    .ok_or_else(|| invalid("exposure lost its original durable context"))?;
                match operation {
                    Operation::Check | Operation::ProtectObject { .. }
                        if !row.accepts_work(lease.generation, now) =>
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "exposure is expired or draining",
                        ));
                    }
                    Operation::Check => return Ok(lease),
                    Operation::ProtectObject { source } => {
                        let (hashes, expires) = source.exposure_pins(executor, &owner)?;
                        if expires > row.deadline {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "file grant exceeds exposure deadline",
                            ));
                        }
                        let pin_owner = row.pin_owner();
                        for hash in hashes {
                            if !next
                                .pins
                                .iter()
                                .any(|pin| pin.owner == pin_owner && pin.hash == hash)
                            {
                                next.pins.push(PinRecord {
                                    owner: pin_owner.clone(),
                                    hash,
                                    expires: i64::MAX as u64,
                                });
                            }
                        }
                    }
                    Operation::Renew { expires } => {
                        if !row.accepts_work(lease.generation, now)
                            || expires < row.deadline
                            || expires <= now
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "exposure renewal is expired or draining",
                            ));
                        }
                        row.deadline = expires;
                    }
                    Operation::Drain => row.phase = ExposurePhase::Draining,
                    Operation::Retain { .. } => {
                        return Err(invalid("unexpected exposure transition"));
                    }
                }
            }
        }
        let write = state::begin(executor, &mut owner, &running, next, 0, None)?;
        (write, owner.generation)
    };
    snapshot::persist(executor, write).await?;
    state::synchronize_policy(executor)?;
    running.check_current().map_err(io::Error::other)?;
    if let Some(context) = &source_context {
        context.check_current().map_err(io::Error::other)?;
    }
    let mut owner = custody
        .lock()
        .map_err(|_| invalid("exposure completion custody poisoned"))?;
    lease.index.check_native_backing()?;
    if let Some(source) = &source {
        source.exposure_pins(executor, &owner)?;
    }
    state::finish(&mut owner, generation)?;
    Ok(lease)
}
