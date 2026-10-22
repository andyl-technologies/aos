//! Discharges draining exposure policy only after authenticated native closure.
//!
//! The original queue recorded these inode bindings before disclosure. A caller
//! supplies an identifier, never replacement native evidence. Names, receipt
//! drops and deadline expiry cannot establish closure. No backing descriptor is
//! retained by this reconciliation request.

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

impl NativeMetadataOwner {
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
    let observed = owner.preparation.project_census(&excluded)?;
    if !observed.all_excluded_closed() {
        return Ok(None);
    }
    // Counted inodes were held through the helper's quota query. Equality
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
