//! Requires genuine native parent/Target actor custody at fork boundaries.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

/// Quiesces and joins the actual native parent actor before registry freeze.
///
/// # Errors
/// Preserves native refusal when the same parent's Original is absent or its
/// actual dispatch/join is unresolved. No local operation replaces that loan.
pub(crate) fn prepare_fork() -> Result<(), RamError> {
    let Some(controller) = controller()? else {
        return Ok(());
    };
    let owner = controller
        .state
        .lock()
        .map_err(|_| RamError::Invariant("RAM controller poisoned"))?
        .owner
        .clone()
        .ok_or("RAM owner not admitted")?;
    if owner.has_cold_authority()? && !super::super::fork::has_prepared_cold()? {
        return Err(RamError::Invariant(
            "cold fork requires staged fault custody",
        ));
    }
    actor::prepare_fork(&controller)?;
    let mut state = controller
        .state
        .lock()
        .map_err(|_| RamError::Invariant("RAM fork admission poisoned"))?;
    if state.fork_preparing
        || state.checkpoint_producer_held(&controller.state, &controller.operations)
        || state.policy_applying
        || state.requested_revision != state.applied_revision
    {
        return Err(RamError::Invariant("RAM fork admission already closed"));
    }
    state.fork_preparing = true;
    drop(state);
    owner.cancel_scheduled_reclaim()
}

/// Observes the actual same-owner native healthy join before final sealing.
///
/// # Errors
/// Refuses an unresolved native actor, retained record or failed physical join.
pub(crate) fn final_seal() -> Result<(), RamError> {
    let Some(controller) = controller()? else {
        return Ok(());
    };
    actor::final_seal(&controller)
}

/// Requires the genuine later native parent Original before worker rearm.
///
/// # Errors
/// Refuses while the matching native Original issuer is unavailable. A new
/// local deadline or a completed installing purpose cannot supply that custody.
pub(crate) fn resume_parent() -> Result<(), RamError> {
    let Some(controller) = controller()? else {
        return Ok(());
    };
    final_seal()?;
    let _retained = controller;
    Err(RamError::Invariant(
        "native parent Original is not available for RAM actor rearm",
    ))
}

/// Names child control custody, issued only by a future genuine Target owner.
pub(crate) struct PreparedChildControl {
    _private: (),
}

impl PreparedChildControl {
    /// Requires the same Target's actual independently admitted controller.
    ///
    /// # Errors
    /// Refuses absent native Target constructor and allocator custody.
    pub(crate) fn operations(&self) -> Result<Arc<dyn SourceOperationFactory>, RamError> {
        Err(RamError::Invariant(
            "native Target RAM controller is not installed",
        ))
    }

    /// Requires an actual native Target endpoint loan rather than a numeric role.
    ///
    /// # Errors
    /// Refuses absent Target endpoint custody; Parent cannot donate its borrow.
    pub(crate) fn descriptor(&self) -> Result<std::os::fd::RawFd, RamError> {
        Err(RamError::Invariant(
            "native Target RAM endpoint loan is absent",
        ))
    }
}

/// Refuses unissued Target control before descriptor duplication or worker birth.
///
/// # Errors
/// Requires a separately issued native Target Source and actor constructor. The
/// Parent's purpose, callback context and endpoint never create a Target owner.
pub(crate) fn prepare_child(
    _descriptor: i32,
    _session: [u8; 32],
    _target: RamControlTarget,
    _resources: RamControlResources,
    _policy: RamControlPolicy,
    _spill_quota: u64,
    _outer: RamControlOuterCap,
) -> Result<PreparedChildControl, RamError> {
    Err(RamError::Invariant(
        "native Target RAM actor Source is not installed",
    ))
}

/// Requires real Target worker birth before publishing independent child state.
///
/// # Errors
/// Refuses absent native Target actor custody before controller replacement.
pub(crate) fn rebind_child(
    _prepared: PreparedChildControl,
    _owner: Arc<PausedPagingOwner>,
) -> Result<(), RamError> {
    Err(RamError::Invariant(
        "native Target RAM actor is not admitted",
    ))
}

/// Requires actual inherited close custody from the native endpoint owner.
///
/// # Errors
/// Refuses transfer of the borrowed Parent descriptor without its native loan.
pub(crate) fn disarm_parent_control() -> Result<std::os::fd::RawFd, RamError> {
    final_seal()?;
    Err(RamError::Invariant(
        "native inherited RAM endpoint close loan is absent",
    ))
}
