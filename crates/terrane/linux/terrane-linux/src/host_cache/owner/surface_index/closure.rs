//! Discharges draining exposure policy only after authenticated native closure.
//!
//! The original queue recorded these inode bindings before disclosure. A caller
//! supplies an identifier, never replacement native evidence. Names, receipt
//! drops and deadline expiry cannot establish closure. No backing descriptor is
//! retained by this reconciliation request.

mod cold;
pub(in crate::host_cache::owner) use cold::capture as cold_policy;

use super::{NativeMetadataOwner, invalid};
use crate::{
    host_cache::owner::{
        consumer::state,
        retention::{Command, NativeOwnerExecutor},
        snapshot,
    },
    host_quota::{MAX_CENSUS_EXCLUSIONS, ProjectInode},
};
use std::{io, sync::mpsc};
use terrane_sdk::host::cache::ExposurePhase;
use tokio::sync::oneshot;

/// Reports authenticated closure checks performed by the original physical owner.
///
/// Counts describe this completed request, not permission to release any other
/// custody. Every selected exposure is either completed or still blocked.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeExposureReconciliation {
    /// Number of original draining exposures checked in this request.
    pub checked: usize,
    /// Number removed durably after authenticated closure of all original inodes.
    pub completed: usize,
    /// Number retaining their original obligations because kernel custody remains.
    pub blocked: usize,
}

impl NativeMetadataOwner {
    /// Reconciles the owner's bounded inventory of draining exposures.
    ///
    /// The original physical queue selects its own durable records. Callers
    /// supply no identifiers or replacement closure evidence. Active exposures
    /// remain untouched; named backings, descriptors and mappings retain their
    /// obligations. This operation does not stop workers or retire names.
    /// Cancellation after enqueue does not cancel the retained physical work.
    ///
    /// # Errors
    /// Refuses disabled admission, a full or stopped queue, stale native custody,
    /// unavailable census, invalid or excessive records, lost funding and
    /// synchronization failures. Earlier successful closures remain committed
    /// if a later check fails; every unresolved obligation remains retained.
    pub async fn reconcile_draining_surface_exposures(
        &self,
    ) -> io::Result<NativeExposureReconciliation> {
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
            .try_send(Command::ReconcileDrainingSurfaceExposures { response })
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
            .map_err(|_| invalid("native owner stopped before exposure reconciliation"))?
    }

    /// Removes one draining exposure only after all its original inodes close.
    ///
    /// Returns `false` if the record is already absent or the authenticated
    /// census still observes unresolved kernel custody. A named backing, open
    /// descriptor or mapping keeps its obligation. Callers must separately stop
    /// worker operations and retire backing names; this operation does neither.
    /// Cancellation after enqueue leaves the serialized owner responsible for
    /// completing or retaining the funded transition.
    ///
    /// # Errors
    /// Refuses malformed identifiers, another generation, active or legacy
    /// records, disabled admission, unavailable census, exhausted bounds,
    /// changed native partition custody and synchronization failures.
    pub async fn reconcile_surface_exposure(&self, id: &str, generation: u64) -> io::Result<bool> {
        if self.surface_policy.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "surface admission disabled",
            ));
        }
        if id.len() != 32
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || generation == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid exposure context",
            ));
        }
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| invalid("native owner stopped"))?
            .try_send(Command::ReconcileSurfaceExposure {
                id: id.to_owned(),
                generation,
                response,
            })
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
            .map_err(|_| invalid("native owner stopped before exposure reconciliation"))?
    }
}

/// Selects only the finite original inventory, without accepting public row data.
pub(in crate::host_cache::owner) async fn reconcile_draining(
    executor: &NativeOwnerExecutor,
) -> io::Result<NativeExposureReconciliation> {
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let exposures = {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("exposure reconciliation custody poisoned"))?;
        state::check_ready(executor, &owner)?;
        state::check_bootstrap(&owner, &running)?;
        if owner.state.exposures.len() > owner.preparation.config.state.records {
            return Err(invalid(
                "exposure reconciliation inventory exceeds record bound",
            ));
        }

        // Scan the whole validated finite inventory so retained early rows
        // cannot starve later closures. No custody lock crosses persistence.
        owner
            .state
            .exposures
            .iter()
            .filter(|record| record.phase == ExposurePhase::Draining)
            .map(|record| (record.id.clone(), record.generation))
            .collect::<Vec<_>>()
    };

    let mut report = NativeExposureReconciliation::default();
    for (id, generation) in exposures {
        let completed = reconcile(executor, &id, generation).await?;
        report.checked += 1;
        if completed {
            report.completed += 1;
        } else {
            report.blocked += 1;
        }
    }
    Ok(report)
}

/// Keeps the original durable obligations through the actual closure comparison.
pub(in crate::host_cache::owner) async fn reconcile(
    executor: &NativeOwnerExecutor,
    id: &str,
    generation: u64,
) -> io::Result<bool> {
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let custody = executor.custody();
    let Some((write, mutation_generation)) = prepare(executor, &running, id, generation)? else {
        return Ok(false);
    };
    snapshot::persist(executor, write).await?;
    state::synchronize_policy(executor)?;
    running.check_current().map_err(io::Error::other)?;
    let mut owner = custody
        .lock()
        .map_err(|_| invalid("exposure closure completion poisoned"))?;
    state::finish(&mut owner, mutation_generation)?;
    Ok(true)
}

/// Keeps validation, native observation and funding in one serialized state lock.
fn prepare(
    executor: &NativeOwnerExecutor,
    running: &std::sync::Arc<crate::publisher_local::client::PublisherRunningContext>,
    id: &str,
    generation: u64,
) -> io::Result<Option<(snapshot::PreparedSnapshotWrite, u64)>> {
    let custody = executor.custody();
    let mut owner = custody
        .lock()
        .map_err(|_| invalid("exposure closure custody poisoned"))?;
    state::check_ready(executor, &owner)?;
    state::check_bootstrap(&owner, running)?;
    let Some(record) = owner
        .state
        .exposures
        .iter()
        .find(|row| row.id == id)
        .cloned()
    else {
        return Ok(None);
    };
    if record.generation != generation || record.phase != ExposurePhase::Draining {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "exposure is not the requested draining generation",
        ));
    }
    if record.backings.is_empty() || record.backings.len() > MAX_CENSUS_EXCLUSIONS {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "exposure has no bounded original closure bindings",
        ));
    }
    let filesystem = state::hex(&owner.preparation.config.filesystem_uuid);
    let project = owner.preparation.config.project_id;
    if record
        .backings
        .iter()
        .any(|backing| backing.filesystem_uuid != filesystem || backing.project_id != project)
    {
        return Err(invalid(
            "exposure closure belongs to another native partition",
        ));
    }
    let excluded: Vec<_> = record
        .backings
        .iter()
        .map(|backing| ProjectInode {
            device: backing.device,
            inode: backing.inode,
        })
        .collect();
    if !owner.preparation.exposure_inodes_closed(&excluded)? {
        return Ok(None);
    }
    // Named inodes and the original probe were held through the query. Equality
    // proves every excluded original inode is gone, independently of names
    // and holders. A closed inode cannot acquire a new original reference.
    let mut next = owner.state.clone();
    let pin_owner = record.pin_owner();
    next.exposures.retain(|row| row.id != record.id);
    next.pins.retain(|row| row.owner != pin_owner);
    next.leases.retain(|row| row.owner != pin_owner);
    let write = state::begin(executor, &mut owner, running, next, 0, None)?;
    Ok(Some((write, owner.generation)))
}
