//! Quiesces parent control and establishes fresh child operational authority.
//!
//! SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

/// Quiesces independent control at a complete frame before native registry freeze.
///
/// # Errors
/// Refuses cold custody without staged handoff, uncertain worker ownership or
/// an expired original quiescence budget. A timed-out join handle stays retained.
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
            "cold fork requires independently staged fault custody",
        ));
    }
    let operation = controller.begin(SourceOperationClass::Quiescence)?;
    {
        let mut state = controller
            .state
            .lock()
            .map_err(|_| RamError::Invariant("RAM fork admission poisoned"))?;
        if state.fork_preparing || state.policy_applying {
            return Err(RamError::Invariant("RAM fork admission already closed"));
        }
        state.fork_preparing = true;
    }
    // Closing policy admission first prevents a racing accepted Apply from
    // queuing new mainloop work after the existing request has been canceled.
    if let Err(error) = owner.cancel_scheduled_reclaim() {
        controller
            .state
            .lock()
            .map_err(|_| RamError::Invariant("RAM fork admission poisoned"))?
            .fork_preparing = false;
        return Err(error);
    }
    {
        let mut joining = controller
            .joining
            .lock()
            .map_err(|_| RamError::Invariant("RAM join ownership poisoned"))?;
        if joining.is_some() {
            return Err(RamError::Invariant("RAM control join already retained"));
        }
        let worker = controller
            .worker
            .lock()
            .map_err(|_| RamError::Invariant("RAM worker ownership poisoned"))?
            .take()
            .ok_or("RAM control worker absent")?;
        *joining = Some(worker.stop()?);
    }
    loop {
        let slice = operation.wait_slice()?;
        let ready = controller
            .joining
            .lock()
            .map_err(|_| RamError::Invariant("RAM join ownership poisoned"))?
            .as_ref()
            .is_some_and(JoinHandle::is_finished);
        if ready {
            break;
        }
        std::thread::sleep(slice.min(Duration::from_millis(10)));
    }
    let handle = controller
        .joining
        .lock()
        .map_err(|_| RamError::Invariant("RAM join ownership poisoned"))?
        .take()
        .ok_or("RAM control join missing")?;
    let paused = handle
        .join()
        .map_err(|_| RamError::Invariant("RAM control worker panicked"))??;
    *controller
        .paused
        .lock()
        .map_err(|_| RamError::Invariant("RAM paused ownership poisoned"))? = Some(paused);
    operation.complete()?;
    Ok(())
}

/// Verifies a closed independent parent endpoint before the final native seal.
///
/// # Errors
/// Refuses a live/joining worker or missing complete-record custody.
pub(crate) fn final_seal() -> Result<(), RamError> {
    let Some(controller) = controller()? else {
        return Ok(());
    };
    if controller
        .worker
        .lock()
        .map_err(|_| RamError::Invariant("RAM worker ownership poisoned"))?
        .is_some()
        || controller
            .joining
            .lock()
            .map_err(|_| RamError::Invariant("RAM join ownership poisoned"))?
            .is_some()
        || controller
            .paused
            .lock()
            .map_err(|_| RamError::Invariant("RAM paused ownership poisoned"))?
            .is_none()
    {
        return Err(RamError::Invariant(
            "RAM control final seal lacks quiescence",
        ));
    }
    Ok(())
}

/// Resumes exactly the parent's retained endpoint and sequence after disposition.
///
/// # Errors
/// Refuses absent paused custody or failed actual native worker admission.
pub(crate) fn resume_parent() -> Result<(), RamError> {
    let Some(controller) = controller()? else {
        return Ok(());
    };
    final_seal()?;
    let state = controller
        .paused
        .lock()
        .map_err(|_| RamError::Invariant("RAM paused ownership poisoned"))?
        .take()
        .ok_or("RAM control paused custody missing")?;
    let worker = PagerControlWorker::resume(state, controller.clone())?;
    *controller
        .worker
        .lock()
        .map_err(|_| RamError::Invariant("RAM worker ownership poisoned"))? = Some(worker);
    controller.await_worker_ready(SourceOperationClass::ForkRearm)?;
    controller
        .state
        .lock()
        .map_err(|_| RamError::Invariant("RAM fork admission poisoned"))?
        .fork_preparing = false;
    Ok(())
}

/// Holds a fresh, prevalidated child control endpoint without starting a thread.
pub(crate) struct PreparedChildControl {
    controller: Arc<LivePagerController>,
    stream: UnixStream,
}

impl PreparedChildControl {
    /// Returns only the new child's independent operation-budget authority.
    pub(crate) fn operations(&self) -> Arc<dyn SourceOperationFactory> {
        self.controller.clone()
    }
}

/// Preallocates private child control custody from a checked sealed fork plan.
///
/// # Errors
/// Refuses inherited sessions/incarnations, incomplete resources, unbounded
/// infrastructure timing or invalid connected stream ownership.
pub(crate) fn prepare_child(
    descriptor: i32,
    session: [u8; 32],
    target: RamControlTarget,
    resources: RamControlResources,
    policy: RamControlPolicy,
    spill_quota: u64,
    outer: RamControlOuterCap,
) -> Result<PreparedChildControl, RamError> {
    let parent = controller()?.ok_or("RAM parent controller absent")?;
    if descriptor < 0
        || session == [0; 32]
        || session == parent.session
        || target.owner_generation == parent.target.owner_generation
        || target.daemon_epoch == [0; 32]
        || target.owner_id == [0; 32]
        || target.node_id == [0; 32]
        || target.owner_generation == 0
        || target.arena_generation == 0
        || resources.metadata_bytes == 0
    {
        return Err(RamError::Invariant("child RAM control namespace invalid"));
    }
    outer.validate()?;
    validate_infrastructure(&policy.budgets, Some(outer))?;
    // SAFETY: native stage custody lends this checked imported role for duplication.
    let fd = unsafe { BorrowedFd::borrow_raw(descriptor) }.try_clone_to_owned()?;
    let stream = UnixStream::from(fd);
    validate_stream(&stream)?;
    let controller = Arc::new(LivePagerController {
        target,
        session,
        state: Arc::new(Mutex::new(State {
            resources,
            budgets: policy.budgets,
            outer: Some(outer),
            outer_expired: false,
            aliases: [None; 3],
            inventory: None,
            owner: None,
            requested_revision: 0,
            applied_revision: 0,
            reservation_revision: 0,
            observation_sequence: 0,
            policy: None,
            failed: false,
            fork_preparing: false,
            policy_applying: false,
        })),
        canceled: Arc::new(AtomicBool::new(false)),
        operations: Arc::new(AtomicUsize::new(0)),
        native_worker: parent.native_worker,
        native_grant: parent.native_grant,
        spill: Mutex::new(None),
        spill_quota,
        worker: Mutex::new(None),
        paused: Mutex::new(None),
        joining: Mutex::new(None),
    });
    Ok(PreparedChildControl { controller, stream })
}

/// Publishes a fresh child controller after actual child arena custody is ready.
///
/// The native stage owner has already authenticated the plan and the engine has
/// installed independent child fault authority. No inherited source socket or
/// controller sequence becomes child authority.
///
/// # Errors
/// Refuses missing geometry, failed native worker admission or uncertain parent
/// quiescence. A failed publication retains resource authority for containment.
pub(crate) fn rebind_child(
    prepared: PreparedChildControl,
    owner: Arc<PausedPagingOwner>,
) -> Result<(), RamError> {
    let parent = controller()?.ok_or("RAM parent controller absent")?;
    if parent
        .worker
        .lock()
        .map_err(|_| RamError::Invariant("RAM parent worker poisoned"))?
        .is_some()
        || parent
            .joining
            .lock()
            .map_err(|_| RamError::Invariant("RAM parent join poisoned"))?
            .is_some()
    {
        return Err(RamError::Invariant(
            "child RAM controller lacks joined parent custody",
        ));
    }
    let snapshot = owner.authority_snapshot()?;
    if snapshot.logical_bytes == 0 || snapshot.topology_generation == 0 || snapshot.failed {
        return Err(RamError::Invariant("child RAM arena authority not ready"));
    }
    let report = parent
        .state
        .lock()
        .map_err(|_| RamError::Invariant("RAM parent controller poisoned"))?
        .inventory
        .as_ref()
        .map(|inventory| inventory.report)
        .ok_or("RAM parent inventory missing")?;
    let PreparedChildControl { controller, stream } = prepared;
    {
        let mut state = controller
            .state
            .lock()
            .map_err(|_| RamError::Invariant("RAM child controller poisoned"))?;
        state.owner = Some(owner.clone());
        state.inventory = Some(Inventory {
            report: RamControlInventoryReport {
                topology_generation: snapshot.topology_generation,
                logical_bytes: snapshot.logical_bytes,
                granted: true,
                ..report
            },
            regions: Vec::new(),
            grant: Some((state.resources, controller.spill_quota)),
            operation: None,
        });
    }
    super::super::restore::rebind_resident(owner.clone())?;
    {
        let mut state = parent
            .state
            .lock()
            .map_err(|_| RamError::Invariant("inherited controller retirement poisoned"))?;
        if state.aliases.iter().any(Option::is_some) {
            return Err(RamError::Invariant(
                "inherited controller retains descriptor aliases",
            ));
        }
        // Old sources, spill wrappers and paused control have transferred native
        // close custody. Breaking this copied cycle releases only retired
        // metadata; the fresh owner already retains every active child lease.
        state.owner.take();
    }
    {
        let mut current = CONTROLLER
            .lock()
            .map_err(|_| RamError::Invariant("RAM controller publication poisoned"))?;
        if !current
            .as_ref()
            .is_some_and(|candidate| Arc::ptr_eq(candidate, &parent))
        {
            return Err(RamError::Invariant(
                "child RAM controller publication changed",
            ));
        }
        *current = Some(controller.clone());
    }
    let worker = PagerControlWorker::start(
        stream,
        controller.session,
        controller.target,
        controller.clone(),
    )?;
    *controller
        .worker
        .lock()
        .map_err(|_| RamError::Invariant("RAM child worker ownership poisoned"))? = Some(worker);
    controller.await_worker_ready(SourceOperationClass::ForkRearm)?;
    Ok(())
}

/// Transfers joined parent socket-close custody before native child FD disposition.
///
/// # Errors
/// Refuses an active parent actor or absent complete-frame handoff.
pub(crate) fn disarm_parent_control() -> Result<std::os::fd::RawFd, RamError> {
    let parent = controller()?.ok_or("RAM parent controller absent")?;
    final_seal()?;
    let paused = parent
        .paused
        .lock()
        .map_err(|_| RamError::Invariant("RAM paused ownership poisoned"))?
        .take()
        .ok_or("RAM paused endpoint absent")?;
    Ok(paused.into_inherited_descriptor())
}

impl PreparedChildControl {
    /// Reports the uniquely retained new child socket role without transferring it.
    pub(crate) fn descriptor(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.stream.as_raw_fd()
    }
}
