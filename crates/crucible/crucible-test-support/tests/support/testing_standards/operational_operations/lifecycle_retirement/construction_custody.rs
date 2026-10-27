//! Binds construction cleanup to its actual retained phase and physical owners.
//!
//! Refused phases and generation leases stay in their original carrier. Actual
//! body destruction remains the canonical queue's separate responsibility.

use super::super::Contract;

pub(super) const BODY: &[(&str, usize)] = &[
    (
        r###"fn finish_pending_reaped(
    partial: &mut Partial,
) -> Result<(), ProductionVmConstructionCleanupError> {
    if let Some(reaped) = partial.pending_reaped.as_mut() {
        if !reaped.channels_closed {
            return Err(ProductionVmConstructionCleanupError::Retained(
                "pending node destruction remains uncertain",
            ));
        }
        reaped
            .lease
            .finish()
            .map_err(ProductionVmConstructionCleanupError::Authority)?;
        partial.pending_reaped = None;
    }
    Ok(())
}"###,
        1,
    ),
    (
        r###"pub(super) enum Phase {
    Partial(Partial),
    Complete(ProductionVmLifecycleLoop),
    #[cfg(target_os = "linux")]
    Source(ProductionVmHotForkSourceWorld),
    #[cfg(target_os = "linux")]
    SharedSource(crate::vm_lifecycle::hot_fork::shared_source::SharedSourceBody),
    #[cfg(target_os = "linux")]
    SourceRearmFailure(crate::vm_lifecycle::hot_fork::rearm_return::SourceRearmBody),
    #[cfg(target_os = "linux")]
    SourcePreparation(crate::vm_lifecycle::SourceWorldPreparation),
    Empty,
}"###,
        1,
    ),
    (
        r###"pub fn retry_cleanup(&self) -> Result<(), ProductionVmConstructionCleanupError> {
        let mut phase = self.phase.try_lock().map_err(phase_lock_error)?;
        if self.physically_closed.load(Ordering::Acquire) {
            return Ok(());
        }
        match &mut *phase {
            Phase::Partial(partial) => retire_partial(partial)?,
            Phase::Complete(lifecycle) => retire_complete(lifecycle)?,
            #[cfg(target_os = "linux")]
            Phase::Source(source) => source.retry_source_retirement_body()?,
            #[cfg(target_os = "linux")]
            Phase::SharedSource(source) => source.retry_body()?,
            #[cfg(target_os = "linux")]
            Phase::SourceRearmFailure(source) => source.retry_body()?,
            #[cfg(target_os = "linux")]
            Phase::SourcePreparation(preparation) => preparation.retry_body()?,
            Phase::Empty => return Ok(()),
        }
        // Keep the actual phase in this carrier. The canonical queue destroys
        // it outside the cell mutex, then returns the containing-body lease.
        // A later factual retry observes closure without repeating effects.
        self.physically_closed.store(true, Ordering::Release);
        Ok(())
    }"###,
        1,
    ),
    (
        r###"pub fn retry_cleanup(&self) -> Result<(), ProductionVmConstructionCleanupError> {
        match &self.storage {
            FailureStorage::Preallocated(custody) => custody.retry_cleanup(),
            FailureStorage::Missing(missing) => {
                let first = missing
                    .partial
                    .try_lock()
                    .map_err(phase_lock_error)
                    .and_then(|mut partial| retire_partial(&mut partial));
                let existing = match missing.existing.as_ref() {
                    Some(custody) => custody.retry_cleanup(),
                    None => Ok(()),
                };
                match (first, existing) {
                    (Ok(()), Ok(())) => Ok(()),
                    (Err(first), Ok(())) | (Ok(()), Err(first)) => Err(first),
                    (Err(first), Err(existing)) => Err(first.with_later_failure(existing)),
                }
            }
            #[cfg(target_os = "linux")]
            FailureStorage::Rejected { returned, .. } => {
                // Keep the exact returned token even after owner cleanup. Only
                // its real cell can later authenticate reservation completion.
                let mut returned = returned.try_lock().map_err(phase_lock_error)?;
                match returned.as_mut() {
                    Some((_, owner)) => owner.retry_cleanup(),
                    None => Ok(()),
                }
            }
        }
    }"###,
        1,
    ),
    (
        r###"fn retire_partial(partial: &mut Partial) -> Result<(), ProductionVmConstructionCleanupError> {
    if partial.cleanup_complete {
        return Ok(());
    }
    retire_launch(partial)?;
    retire_adoption(partial)?;
    while let Some(adoption) = partial.hot_fork_adoptions.pop() {
        partial.pending_adoption = Some(adoption);
        retire_adoption(partial)?;
    }
    while let Some(restore) = partial.hot_fork_restore.as_mut() {
        let Some((_, adoption)) = restore.adoptions.pop_first() else {
            break;
        };
        partial.pending_adoption = Some(adoption);
        // Retry keeps a refused adoption or its reaped lease in this same body.
        retire_adoption(partial)?;
    }
    if let Some(inner) = partial.inner.as_mut() {
        inner
            .backend_mut()
            .shutdown()
            .map_err(ProductionVmConstructionCleanupError::Backend)?;
    }
    if let Some(backends) = partial.backends.as_mut() {
        backends
            .shutdown()
            .map_err(ProductionVmConstructionCleanupError::Backend)?;
    }
    partial.block_device_map.clear();
    if let Some(devices) = partial.block_devices.as_ref() {
        clear_devices(devices)?;
    }
    finish_retained_node_leases(&partial.node_generations, &mut partial.node_leases)?;
    partial.retained_hot_fork_disk_files.clear();
    partial.pending_exact = None;
    partial.pending_launch_config = None;
    partial.launch_configs.clear();
    partial.repository_restore = None;
    partial.restore_checkpoint = None;
    partial.hot_fork_restore = None;
    partial.hot_fork_continuation = None;
    partial.exact_ram_parents.clear();
    if let Some(launcher) = partial.node_launcher.as_mut() {
        launcher.finish()?;
    }
    partial.cleanup_complete = true;
    Ok(())
}"###,
        1,
    ),
    (
        r###"fn retire_complete(
    lifecycle: &mut ProductionVmLifecycleLoop,
) -> Result<(), ProductionVmConstructionCleanupError> {
    if let Some(first) = lifecycle.retained_cleanup_failure.take() {
        return Err(first);
    }
    lifecycle.retry_retained_debug_construction()?;
    if lifecycle.debug_gateway.is_some() || lifecycle.indeterminate_debug_candidate.is_some() {
        return Err(ProductionVmConstructionCleanupError::Retained(
            "construction contains a live external debugger owner",
        ));
    }
    lifecycle
        .retire_terminal_replacement_transaction()
        .map_err(ProductionVmConstructionCleanupError::Scheduler)?;
    lifecycle
        .inner
        .backend_mut()
        .shutdown()
        .map_err(ProductionVmConstructionCleanupError::Backend)?;
    clear_devices(&lifecycle.block_devices)?;
    finish_retained_node_leases(&lifecycle.node_generations, &mut lifecycle.node_leases)?;
    lifecycle.retained_hot_fork_disk_owners.clear();
    lifecycle.launch_configs.clear();
    lifecycle.exact_ram_parents.clear();
    // This private failed-construction route preserves the ordinary Loop's
    // sticky latch as history, while proving actual map retirement directly.
    lifecycle.node_launcher.finish()
}"###,
        1,
    ),
    (
        r###"fn finish_retained_node_leases(
    generations: &BTreeMap<NodeId, u64>,
    leases: &mut BTreeMap<NodeId, Box<dyn ProductionVmNodeLease>>,
) -> Result<(), ProductionVmConstructionCleanupError> {
    let mut first = None;
    leases.retain(|node, lease| {
        let result = match generations.get(node) {
            Some(generation)
                if lease.identity().node() == node
                    && lease.identity().generation() == *generation =>
            {
                lease
                    .finish()
                    .map_err(ProductionVmConstructionCleanupError::Authority)
            }
            _ => Err(ProductionVmConstructionCleanupError::Retained(
                "reaped construction node retains an unmatched generation lease",
            )),
        };
        match result {
            Ok(()) => false,
            Err(error) => {
                if first.is_none() {
                    first = Some(error);
                }
                true
            }
        }
    });
    first.map_or(Ok(()), Err)
}"###,
        1,
    ),
    (
        r###"fn retire_launch(partial: &mut Partial) -> Result<(), ProductionVmConstructionCleanupError> {
    finish_pending_reaped(partial)?;
    if let Some(launch) = partial.pending_launch.as_mut() {
        launch
            .node
            .force_quarantine_and_reap()
            .map_err(ProductionVmConstructionCleanupError::Node)?;
    }
    if let Some(ProductionVmNodeLaunch { node, lease, .. }) = partial.pending_launch.take() {
        partial.pending_reaped = Some(ReapedLease {
            lease,
            channels_closed: false,
        });
        drop(node);
        if let Some(reaped) = partial.pending_reaped.as_mut() {
            reaped.channels_closed = true;
        }
    }
    finish_pending_reaped(partial)
}"###,
        1,
    ),
    (
        r###"fn retire_adoption(partial: &mut Partial) -> Result<(), ProductionVmConstructionCleanupError> {
    if let Some(adoption) = partial.pending_adoption.as_mut() {
        adoption
            .node
            .force_quarantine_and_reap()
            .map_err(ProductionVmConstructionCleanupError::Node)?;
        if adoption.lease.identity() != &adoption.identity {
            return Err(ProductionVmConstructionCleanupError::Retained(
                "adopted node retains a mismatched generation lease",
            ));
        }
    }
    if let Some(adoption) = partial.pending_adoption.take() {
        partial.pending_launch = Some(ProductionVmNodeLaunch {
            node: adoption.node,
            lease: adoption.lease,
            run_directory: adoption.run_directory,
        });
        retire_launch(partial)?;
    }
    Ok(())
}"###,
        1,
    ),
];

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/vm_lifecycle/construction/custody",
    required: BODY,
    expressions: &[
        ("custody.retry_cleanup()", 2),
        ("owner.retry_cleanup()", 1),
        ("source.retry_source_retirement_body()", 1),
        ("source.retry_body()", 2),
        ("preparation.retry_body()", 1),
        ("lifecycle.retry_retained_debug_construction()", 1),
    ],
    identifiers: &[
        ("retry_cleanup", 5),
        ("retry_source_retirement_body", 1),
        ("retry_body", 3),
        ("retry_retained_debug_construction", 1),
    ],
    companions: &[
        super::ORIGINAL,
        super::BACKEND,
        super::SOURCE,
        super::super::hot_fork_retirement::CONSTRUCTOR_BODY,
        super::super::production_publication::CONSTRUCTOR_RESERVATION,
        super::super::production_publication::CONSTRUCTOR_QUEUE,
        super::super::production_publication::CONSTRUCTOR_DRIVER,
        super::super::production_publication::CONSTRUCTOR_QUEUED_OWNER,
        super::super::production_publication::ROLE_REPORTS,
        super::super::hot_fork_retirement::SHARED_BODY,
        super::super::hot_fork_retirement::REARM_BODY,
        super::super::hot_fork_retirement::PREPARATION_BODY,
    ],
};
