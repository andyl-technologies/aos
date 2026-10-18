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
    prepare_with_admission(&controller, || {
        // An Apply cannot activate cold RAM after this handoff check.
        if owner.has_cold_authority()? && !super::super::fork::has_prepared_cold()? {
            return Err(RamError::Invariant(
                "cold fork requires staged fault custody",
            ));
        }
        owner.cancel_scheduled_reclaim()?;
        actor::prepare_fork(&controller)
    })
}

// Close policy admission before cancellation or actor quiescence can take effect.
// A later refusal retains this gate until genuine parent rearm resolves custody.
fn prepare_with_admission(
    controller: &LivePagerController,
    prepare: impl FnOnce() -> Result<(), RamError>,
) -> Result<(), RamError> {
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
    prepare()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn unsettled_policy_refuses_before_external_fork_preparation() {
        for busy in 0..3 {
            let controller = super::super::tests::controller();
            {
                let mut state = controller.state.lock().unwrap();
                match busy {
                    0 => state.fork_preparing = true,
                    1 => state.policy_applying = true,
                    _ => state.requested_revision = 1,
                }
            }
            let entered = Cell::new(false);

            let result = prepare_with_admission(&controller, || {
                entered.set(true);
                Ok(())
            });

            assert!(result.is_err());
            assert!(
                !entered.get(),
                "busy controller reached external preparation"
            );
        }
    }

    #[test]
    fn admission_stays_closed_after_external_preparation_refusal() {
        let controller = super::super::tests::controller();
        let first = RamError::from(io::Error::from_raw_os_error(libc::EIO));
        let entered = Cell::new(false);
        let reentered = Cell::new(false);

        let result = prepare_with_admission(&controller, || {
            entered.set(true);
            let state = controller
                .state
                .try_lock()
                .expect("admission lock released");
            assert!(state.fork_preparing);
            drop(state);

            let nested = prepare_with_admission(&controller, || {
                reentered.set(true);
                Ok(())
            });
            assert!(nested.is_err());
            Err(first.clone())
        });

        assert_eq!(result, Err(first));
        assert!(entered.get());
        assert!(!reentered.get());
        assert!(controller.state.lock().unwrap().fork_preparing);
        assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
    }
}
