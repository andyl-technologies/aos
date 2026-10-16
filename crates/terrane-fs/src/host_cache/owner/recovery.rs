//! Runs serialized actual recovery without conflating it with tier readiness.
//!
//! The first complete case is an actually empty content namespace and empty
//! cold policy. Unknown names, private publication state, temporary files,
//! pending bodies and every unhandled candidate remain non-ready. A receipt
//! requires real shared/private scans, durable state, synchronized allocation,
//! fresh authenticated quota charges and the original successful drain epoch.
//! No Resume or file-bucket readiness is granted by this module.

use super::{
    recovery_accounting::{self, SynchronizedAllocation},
    recovery_namespace::SharedNamespaceObservation,
    recovery_state,
    recovery_state_parent::StateParentObservation,
    retention::{Command, Custody, NativeMetadataOwner},
};
use crate::{
    host_cache::NativeRecoveryInspection,
    host_quota::synchronized_allocated_bytes,
    publisher_local::client::{Client, PublisherRecoveryContext},
};
use std::{
    io,
    sync::{Arc, Mutex, mpsc},
};
use terrane::host::cache::HostDomainLocation;
use tokio::sync::oneshot;

/// Retains genuine completion of the currently implemented empty recovery case.
///
/// Only the physical owner constructs this after exhaustive actual observations
/// and durable reconciliation. It cannot be constructed from a boolean, caller
/// epoch or file. It does not prove BKT-15 bucket validity, grant service handles,
/// resume exposures or authorize native admission. No Resume consumer is enabled.
pub struct CompletedRecovery {
    custody: Arc<Mutex<Custody>>,
    session: Arc<Client<HostDomainLocation>>,
    context: PublisherRecoveryContext<HostDomainLocation>,
    shared: SharedNamespaceObservation,
    state_parent: StateParentObservation,
    inventory: NativeRecoveryInspection,
    generation: u64,
    recovery_id: [u8; 16],
    allocation: SynchronizedAllocation,
    charged_reserved_bytes: u64,
    future_hold_bytes: u64,
}

impl CompletedRecovery {
    /// Compares actual producer custody without accepting an external authority token.
    pub(super) fn matches_custody(&self, custody: &Arc<Mutex<Custody>>) -> bool {
        Arc::ptr_eq(&self.custody, custody)
    }

    /// Borrows the actual producer session without acquiring its RPC mutex.
    pub(crate) fn publisher_session(&self) -> Arc<Client<HostDomainLocation>> {
        Arc::clone(&self.session)
    }

    /// Borrows the actual successful drain context; it contains no caller epoch.
    pub(crate) fn publisher_context(&self) -> &PublisherRecoveryContext<HostDomainLocation> {
        &self.context
    }

    /// Returns synchronized allocation of the explicitly retained native inodes.
    ///
    /// This deduplicated st_blocks sum excludes unobserved filesystem metadata
    /// and private descendant inodes. It is not full project charge or a hold.
    pub fn synchronized_retained_inode_bytes(&self) -> u64 {
        self.allocation.retained_inode_bytes
    }

    /// Returns the number of distinct inodes in that synchronized observation.
    pub fn synchronized_retained_inodes(&self) -> usize {
        self.allocation.retained_inodes
    }

    /// Returns authenticated charged-and-reserved project usage at completion.
    ///
    /// This kernel observation is distinct from synchronized inode blocks and
    /// policy holds. It is a boundary snapshot, not a promise of unchanged usage.
    pub fn charged_reserved_bytes(&self) -> u64 {
        self.charged_reserved_bytes
    }

    /// Returns the durable logical future hold retained by this recovery owner.
    pub fn future_hold_bytes(&self) -> u64 {
        self.future_hold_bytes
    }

    /// Rechecks actual owner generation, namespaces, state and native custody.
    ///
    /// This may lock embedded state and must precede a consumer's RPC lock. It
    /// is never called on an already-sealed read. The consumer must separately
    /// check the opaque publisher context atomically under its actual RPC lock.
    ///
    /// # Errors
    /// Refuses changed generations/roots/names, faulted custody, missing durable
    /// state, another actual session or changed bootstrap policy records.
    pub fn check_current(&self) -> io::Result<()> {
        let owner = self
            .custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.check_current()?;
        if owner.faulted
            || owner.recovery_required
            || owner.snapshot.is_none()
            || owner.generation != self.generation
            || owner.recovery_id != Some(self.recovery_id)
            || !Arc::ptr_eq(&self.session, &owner.preparation.publisher_session())
        {
            return Err(invalid(
                "recovery completion no longer matches actual owner custody",
            ));
        }
        recovery_state::check_bootstrap(
            &owner.preparation.config,
            &owner.state,
            &self.recovery_id,
        )?;
        self.shared.check_current()?;
        self.state_parent.check_current()?;
        self.inventory.check_current()?;
        require_empty_inventory(&self.inventory)
    }
}

impl NativeMetadataOwner {
    /// Runs bounded actual recovery in the retained physical command queue.
    ///
    /// The currently complete case requires empty cold policy and an exhaustive
    /// empty content namespace. Every other case remains explicitly unresolved;
    /// no record is auto-cleared and no exposure is resumed. Request cancellation
    /// never cancels accepted physical work or releases its durable future hold.
    ///
    /// # Errors
    /// Refuses a full/stopped queue, unresolved records/names/candidates, failed
    /// native synchronization, uncertain transport, quota excess and a changed
    /// publisher barrier. Late failure retains faulted custody and its hold.
    pub async fn recover(&self) -> io::Result<CompletedRecovery> {
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::other("native recovery owner stopped"))?
            .try_send(Command::Recover { response })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "native recovery queue is full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::other("native recovery owner stopped")
                }
            })?;
        receive
            .await
            .map_err(|_| io::Error::other("native recovery owner terminated before completion"))?
    }
}

/// Completes the actual empty case on the sole physical command executor.
///
/// # Errors
/// Refuses every unresolved record/name/candidate, stale native or publisher
/// custody, failed durability, unknown quota or excessive actual charge. After
/// the first snapshot attempt, failures retain the owner's hold and fault state.
pub(super) async fn run(custody: &Arc<Mutex<Custody>>) -> io::Result<CompletedRecovery> {
    let (session, inspector, shared, state_parent) = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.check_current()?;
        if owner.faulted {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "failed physical work requires native reconciliation",
            ));
        }
        owner.recovery_required = true;
        owner.recovery_id = None;
        recovery_state::require_empty(&owner.state)?;
        let state_parent = StateParentObservation::inspect(&owner.preparation)?;
        let shared = SharedNamespaceObservation::inspect(&owner.preparation)?;
        if !shared.only_empty_scaffolds() {
            return Err(unresolved(
                "shared body, temporary or unknown namespace entry requires reconciliation",
            ));
        }
        (
            owner.preparation.publisher_session(),
            owner.preparation.recovery_inspector()?,
            shared,
            state_parent,
        )
    };
    // No embedded guard is held while acquiring the actual client RPC mutex.
    let context = session.recovery_context().map_err(io::Error::other)?;
    let (id, generation) = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.check_current()?;
        shared.check_current()?;
        state_parent.check_current()?;
        owner.preparation.recheck()?;
        let bootstrap = recovery_state::bootstrap(&owner.preparation.config, &owner.state)?;
        check_charge(&owner)?;
        owner.begin_mutation()?;
        owner.state = bootstrap.snapshot;
        owner.faulted = true;
        owner.persist().await?;
        (bootstrap.id, owner.generation)
    };
    let inventory = inspector.inspect()?;
    require_empty_inventory(&inventory)?;
    session
        .check_recovery_context(&context)
        .map_err(io::Error::other)?;
    let (allocation, charged_reserved_bytes, future_hold_bytes) = {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        shared.check_current()?;
        state_parent.check_current()?;
        inventory.check_current()?;
        recovery_state::check_bootstrap(&owner.preparation.config, &owner.state, &id)?;
        owner.persist().await?;
        let allocation = recovery_accounting::observe(&owner, &shared, &state_parent)?;
        owner.snapshot_allocated_bytes = owner
            .snapshot
            .as_ref()
            .ok_or_else(|| invalid("recovery snapshot is absent"))
            .and_then(|(file, _)| synchronized_allocated_bytes(file))?;
        owner.directory_allocated_bytes = synchronized_allocated_bytes(&owner.directory)?;
        owner.preparation.recheck()?;
        check_charge(&owner)?;
        shared.check_current()?;
        state_parent.check_current()?;
        owner.check_current()?;
        owner.recovery_id = Some(id);
        owner.recovery_required = false;
        owner.faulted = false;
        (
            allocation,
            owner
                .preparation
                .quota()
                .observation()
                .charged_reserved_bytes,
            owner.preparation.config.metadata_sync_hold_bytes,
        )
    };
    // Any uncertainty after filesystem work withholds the receipt and restores
    // the faulted state. The durable reservation is never dropped with a waiter.
    if let Err(error) = session.check_recovery_context(&context) {
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("recovery custody poisoned"))?;
        owner.faulted = true;
        owner.recovery_required = true;
        owner.recovery_id = None;
        return Err(io::Error::other(error));
    }
    Ok(CompletedRecovery {
        custody: Arc::clone(custody),
        session,
        context,
        shared,
        state_parent,
        inventory,
        generation,
        recovery_id: id,
        allocation,
        charged_reserved_bytes,
        future_hold_bytes,
    })
}

fn require_empty_inventory(inventory: &NativeRecoveryInspection) -> io::Result<()> {
    if inventory.inventory_failure().is_some()
        || inventory.namespace_failure().is_some()
        || !inventory.candidates().is_empty()
    {
        return Err(unresolved(
            "actual publisher inventory has unresolved names, bodies or failures",
        ));
    }
    Ok(())
}

fn check_charge(owner: &Custody) -> io::Result<()> {
    if owner
        .preparation
        .quota()
        .observation()
        .charged_reserved_bytes
        .checked_add(owner.preparation.config.metadata_sync_hold_bytes)
        .is_none_or(|total| total > owner.preparation.config.policy.capacity)
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "recovery charge and future hold exceed policy",
        ));
    }
    Ok(())
}

fn unresolved(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
