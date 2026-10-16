//! Retains the actual partial or complete World across constructor refusal.
//!
//! Storage is admitted before construction. Every transfer moves existing
//! owners; neither this carrier nor its failure supplies operational authority.

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, TryLockError};

use super::*;

#[cfg(test)]
mod tests;

/// Owns the exact construction resources until publication or physical return.
pub struct ProductionVmConstructionCustody {
    // Error::source borrows this stable field without borrowing the phase lock.
    pub(super) first: Option<LifecycleApiError>,
    pub(super) phase: Mutex<Phase>,
    physically_closed: AtomicBool,
    #[cfg(target_os = "linux")]
    pub(super) reservation: Option<
        Box<dyn crucible_api::ProductionVmCleanupReservation<Failure = crucible::SchedulerError>>,
    >,
}

pub(super) enum Phase {
    Partial(Partial),
    Complete(ProductionVmLifecycleLoop),
    Empty,
}

/// Contains each resource once while the constructor assembles its model frame.
pub(in crate::vm_lifecycle) struct Partial {
    pub(in crate::vm_lifecycle) restore_checkpoint: Option<ProductionVmExactCheckpointSet>,
    pub(in crate::vm_lifecycle) hot_fork_restore: Option<ProductionVmHotForkRestore>,
    pub(in crate::vm_lifecycle) hot_fork_continuation: Option<ProductionVmHotForkWorldContinuation>,
    pub(in crate::vm_lifecycle) hot_fork_adoptions: Vec<ProductionVmHotForkNodeAdoption>,
    pub(in crate::vm_lifecycle) node_launcher: Option<Box<dyn ProductionVmNodeLauncher>>,
    pub(in crate::vm_lifecycle) retained_config: Option<Arc<ProductionVmLifecycleConfig>>,
    pub(in crate::vm_lifecycle) run_directory: Option<ProductionRunDirectory>,
    pub(in crate::vm_lifecycle) backends: Option<QemuNodeSet>,
    pub(in crate::vm_lifecycle) launch_configs: BTreeMap<NodeId, QemuLiveNodeStepGateConfig>,
    pub(in crate::vm_lifecycle) node_generations: BTreeMap<NodeId, u64>,
    pub(in crate::vm_lifecycle) node_leases: BTreeMap<NodeId, Box<dyn ProductionVmNodeLease>>,
    pub(in crate::vm_lifecycle) retained_hot_fork_disk_files: Vec<File>,
    pub(in crate::vm_lifecycle) repository_restore: Option<RepositoryExactRestoreAuthority>,
    pub(in crate::vm_lifecycle) pending_adoption: Option<ProductionVmHotForkNodeAdoption>,
    pub(in crate::vm_lifecycle) pending_launch: Option<ProductionVmNodeLaunch>,
    pub(in crate::vm_lifecycle) pending_exact: Option<ProductionVmExactNodeRestoreAdmission>,
    pub(in crate::vm_lifecycle) pending_launch_config: Option<QemuLiveNodeStepGateConfig>,
    pub(in crate::vm_lifecycle) block_device_map:
        BTreeMap<ContentHash, crucible_qemu::QemuSharedBlockDevice>,
    pub(in crate::vm_lifecycle) block_devices: Option<storage_faults::ProductionBlockDevices>,
    pub(in crate::vm_lifecycle) exact_ram_parents:
        BTreeMap<ContentHash, ProductionExactRamPublishedParent>,
    pub(in crate::vm_lifecycle) inner:
        Option<BackendQuantumLoop<SingleScheduler, QemuNodeSet, ProductionFaultNetworkInterceptor>>,
    pub(in crate::vm_lifecycle) input_decode_custody: Option<crucible::owned_decode::DecodeCustody>,
    pending_reaped: Option<ReapedLease>,
    cleanup_complete: bool,
}

struct ReapedLease {
    lease: Box<dyn ProductionVmNodeLease>,
    // A node destructor must finish before its external lease may finish.
    channels_closed: bool,
}

impl Partial {
    pub(in crate::vm_lifecycle) fn is_empty(&self) -> bool {
        self.restore_checkpoint.is_none()
            && self.hot_fork_restore.is_none()
            && self.hot_fork_continuation.is_none()
            && self.hot_fork_adoptions.is_empty()
            && self.node_launcher.is_none()
            && self.retained_config.is_none()
            && self.run_directory.is_none()
            && self.backends.is_none()
            && self.launch_configs.is_empty()
            && self.node_generations.is_empty()
            && self.node_leases.is_empty()
            && self.retained_hot_fork_disk_files.is_empty()
            && self.repository_restore.is_none()
            && self.pending_adoption.is_none()
            && self.pending_launch.is_none()
            && self.pending_exact.is_none()
            && self.pending_launch_config.is_none()
            && self.block_device_map.is_empty()
            && self.block_devices.is_none()
            && self.exact_ram_parents.is_empty()
            && self.inner.is_none()
            && self.input_decode_custody.is_none()
            && self.pending_reaped.is_none()
            && !self.cleanup_complete
    }

    fn new() -> Self {
        Self {
            restore_checkpoint: None,
            hot_fork_restore: None,
            hot_fork_continuation: None,
            hot_fork_adoptions: Vec::new(),
            node_launcher: None,
            retained_config: None,
            run_directory: None,
            backends: None,
            launch_configs: BTreeMap::new(),
            node_generations: BTreeMap::new(),
            node_leases: BTreeMap::new(),
            retained_hot_fork_disk_files: Vec::new(),
            repository_restore: None,
            pending_adoption: None,
            pending_launch: None,
            pending_exact: None,
            pending_launch_config: None,
            block_device_map: BTreeMap::new(),
            block_devices: None,
            exact_ram_parents: BTreeMap::new(),
            inner: None,
            input_decode_custody: None,
            pending_reaped: None,
            cleanup_complete: false,
        }
    }
}

/// Retains every incoming owner before inspecting the launcher's storage slot.
pub(in crate::vm_lifecycle) fn with_inputs(
    launcher: Box<dyn ProductionVmNodeLauncher>,
    checkpoint: Option<ProductionVmExactCheckpointSet>,
    restore: Option<ProductionVmHotForkRestore>,
    continuation: Option<ProductionVmHotForkWorldContinuation>,
    adoptions: Vec<ProductionVmHotForkNodeAdoption>,
) -> Result<Box<ProductionVmConstructionCustody>, ProductionVmConstructionFailure> {
    let mut incoming = Partial::new();
    incoming.node_launcher = Some(launcher);
    incoming.restore_checkpoint = checkpoint;
    incoming.hot_fork_restore = restore;
    incoming.hot_fork_continuation = continuation;
    incoming.hot_fork_adoptions = adoptions;
    let existing = incoming
        .node_launcher
        .as_mut()
        .and_then(|launcher| launcher.take_construction_custody());
    if let Some(mut custody) = existing {
        let pristine = custody.first.is_none();
        #[cfg(target_os = "linux")]
        let pristine = pristine && custody.reservation.is_none();
        if pristine {
            if let Ok(partial) = custody.partial_mut() {
                if partial.is_empty() {
                    *partial = incoming;
                    return Ok(custody);
                }
            }
        }
        return Err(ProductionVmConstructionFailure {
            storage: FailureStorage::Missing(MissingStorage {
                first: LifecycleApiError::ConstructionCustodyUnavailable,
                partial: Mutex::new(incoming),
                existing: Some(custody),
            }),
            additional: None,
        });
    }
    Err(ProductionVmConstructionFailure {
        storage: FailureStorage::Missing(MissingStorage {
            first: LifecycleApiError::ConstructionCustodyUnavailable,
            partial: Mutex::new(incoming),
            existing: None,
        }),
        additional: None,
    })
}

impl ProductionVmConstructionCustody {
    /// Creates empty storage without issuing a resource or starting a clock.
    pub fn new() -> Self {
        Self {
            first: None,
            phase: Mutex::new(Phase::Partial(Partial::new())),
            physically_closed: AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            reservation: None,
        }
    }

    /// Returns the actual carrier body extent required before its allocation.
    pub const fn allocation_bytes() -> u64 {
        std::mem::size_of::<Self>() as u64
    }

    pub(in crate::vm_lifecycle) fn partial_mut(
        &mut self,
    ) -> Result<&mut Partial, LifecycleApiError> {
        match self.phase.get_mut() {
            Ok(Phase::Partial(partial)) => Ok(partial),
            Ok(_) => Err(loop_factory_error("construction partial phase is absent")),
            Err(_) => Err(loop_factory_error("construction custody is poisoned")),
        }
    }

    /// Transfers the whole partial body through the constructor's move-only cut.
    /// The assembly closure performs no callbacks or fallible physical work.
    pub(super) fn complete_with(
        &mut self,
        assemble: impl FnOnce(Partial) -> Result<ProductionVmLifecycleLoop, Partial>,
    ) -> Result<(), LifecycleApiError> {
        let phase = self
            .phase
            .get_mut()
            .map_err(|_| loop_factory_error("construction custody is poisoned"))?;
        let partial = match std::mem::replace(phase, Phase::Empty) {
            Phase::Partial(partial) => partial,
            other => {
                *phase = other;
                return Err(loop_factory_error("construction partial phase is absent"));
            }
        };
        if partial.pending_reaped.is_some() || partial.cleanup_complete {
            *phase = Phase::Partial(partial);
            return Err(loop_factory_error(
                "construction retains a reaped pending lease",
            ));
        }
        match assemble(partial) {
            Ok(lifecycle) => {
                *phase = Phase::Complete(lifecycle);
                Ok(())
            }
            Err(partial) => {
                *phase = Phase::Partial(partial);
                Err(loop_factory_error(
                    "construction assembly retained an incomplete frame",
                ))
            }
        }
    }

    pub(super) fn complete_mut(
        &mut self,
    ) -> Result<&mut ProductionVmLifecycleLoop, LifecycleApiError> {
        match self.phase.get_mut() {
            Ok(Phase::Complete(lifecycle)) => Ok(lifecycle),
            Ok(_) => Err(loop_factory_error("complete construction phase is absent")),
            Err(_) => Err(loop_factory_error("construction custody is poisoned")),
        }
    }

    pub(in crate::vm_lifecycle) fn into_failure(
        mut self: Box<Self>,
        first: LifecycleApiError,
    ) -> ProductionVmConstructionFailure {
        let additional = if self.first.is_none() {
            self.first = Some(first);
            None
        } else {
            // Preserve a repeated caller error without replacing the stable source.
            Some(first)
        };
        ProductionVmConstructionFailure {
            storage: FailureStorage::Preallocated(self),
            additional,
        }
    }

    pub(super) fn into_loop(mut self: Box<Self>) -> Result<ProductionVmLifecycleLoop, Box<Self>> {
        if self.first.is_some() || self.physically_closed.load(Ordering::Acquire) {
            return Err(self);
        }
        #[cfg(target_os = "linux")]
        if self.reservation.is_some() {
            return Err(self);
        }
        let lifecycle = match self.phase.get_mut() {
            Ok(phase) => match std::mem::replace(phase, Phase::Empty) {
                Phase::Complete(lifecycle) => Some(lifecycle),
                other => {
                    *phase = other;
                    None
                }
            },
            Err(_) => None,
        };
        match lifecycle {
            Some(mut lifecycle) => {
                // Its successful return keeps this original paid carrier. No
                // runtime failure will need a new Box to preserve the Loop.
                lifecycle.construction_custody = Some(self);
                Ok(lifecycle)
            }
            None => Err(self),
        }
    }

    /// Retries physical retirement using the same retained owners.
    ///
    /// # Errors
    /// Retains the complete phase on physical refusal or uncertain ownership.
    pub fn retry_cleanup(&self) -> Result<(), ProductionVmConstructionCleanupError> {
        let mut phase = self.phase.try_lock().map_err(phase_lock_error)?;
        if self.physically_closed.load(Ordering::Acquire) {
            return Ok(());
        }
        match &mut *phase {
            Phase::Partial(partial) => retire_partial(partial)?,
            Phase::Complete(lifecycle) => retire_complete(lifecycle)?,
            Phase::Empty => return Ok(()),
        }
        // Keep the actual phase in this carrier. The canonical queue destroys
        // it outside the cell mutex, then returns the containing-body lease.
        // A later factual retry observes closure without repeating effects.
        self.physically_closed.store(true, Ordering::Release);
        Ok(())
    }
}

impl Default for ProductionVmConstructionCustody {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ProductionVmConstructionCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionVmConstructionCustody")
            .field("first", &self.first)
            .finish_non_exhaustive()
    }
}

/// Returns construction refusal together with its actual cleanup owner.
#[must_use = "retain the construction failure until physical cleanup succeeds"]
pub struct ProductionVmConstructionFailure {
    pub(super) storage: FailureStorage,
    pub(super) additional: Option<LifecycleApiError>,
}

pub(super) enum FailureStorage {
    Preallocated(Box<ProductionVmConstructionCustody>),
    Missing(MissingStorage),
    #[cfg(target_os = "linux")]
    Rejected {
        first: LifecycleApiError,
        returned: Mutex<
            Option<(
                Box<
                    dyn crucible_api::ProductionVmCleanupReservation<
                            Failure = crucible::SchedulerError,
                        >,
                >,
                Box<dyn crucible_api::ProductionVmCleanupOwner<Failure = crucible::SchedulerError>>,
            )>,
        >,
    },
}

// The fallback cannot contain a Complete phase: the Loop itself retains a
// fixed failure slot, so putting another inline Loop here would be recursive.
pub(super) struct MissingStorage {
    pub(super) first: LifecycleApiError,
    pub(super) partial: Mutex<Partial>,
    pub(super) existing: Option<Box<ProductionVmConstructionCustody>>,
}

impl ProductionVmConstructionFailure {
    fn first(&self) -> Option<&LifecycleApiError> {
        match &self.storage {
            FailureStorage::Preallocated(custody) => custody.first.as_ref(),
            FailureStorage::Missing(missing) => Some(&missing.first),
            #[cfg(target_os = "linux")]
            FailureStorage::Rejected { first, .. } => Some(first),
        }
    }

    /// Borrows the original typed cause without consuming retained custody.
    #[must_use]
    pub fn first_error(&self) -> Option<&LifecycleApiError> {
        self.first()
    }

    /// Returns the fixed inline extent of one owning failure slot.
    ///
    /// This geometry is not allocation credit; the containing actual owner
    /// must include it in its authenticated before-birth extent.
    pub const fn retained_slot_bytes() -> u64 {
        std::mem::size_of::<Mutex<Option<Self>>>() as u64
    }

    /// Returns the same originally allocated carrier without another allocation.
    ///
    /// # Errors
    /// Returns this complete failure when it owns inline missing-carrier storage
    /// or an additional original error that must remain retained.
    pub fn into_custody(self) -> Result<Box<ProductionVmConstructionCustody>, Self> {
        match self {
            Self {
                storage: FailureStorage::Preallocated(custody),
                additional: None,
            } => Ok(custody),
            retained => Err(retained),
        }
    }

    /// Retries the same retained construction without creating an allowance.
    ///
    /// # Errors
    /// Preserves this failure and its phase whenever physical retirement refuses.
    pub fn retry_cleanup(&self) -> Result<(), ProductionVmConstructionCleanupError> {
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
                first.and(existing)
            }
            #[cfg(target_os = "linux")]
            FailureStorage::Rejected { returned, .. } => {
                // Keep the exact returned token even after owner cleanup. Only
                // its real cell can later authenticate reservation completion.
                let mut returned = returned.try_lock().map_err(phase_lock_error)?;
                match returned.as_mut() {
                    Some((_, owner)) => owner
                        .retry_cleanup()
                        .map_err(ProductionVmConstructionCleanupError::Leases),
                    None => Ok(()),
                }
            }
        }
    }
}

impl fmt::Debug for ProductionVmConstructionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionVmConstructionFailure")
            .field("first", &self.first())
            .field("additional", &self.additional)
            .finish()
    }
}

impl fmt::Display for ProductionVmConstructionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.first() {
            Some(first) => write!(formatter, "production construction refused: {first}"),
            None => formatter.write_str("production construction retains cleanup custody"),
        }
    }
}

impl Error for ProductionVmConstructionFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.first().map(|first| first as &dyn Error)
    }
}

/// Preserves the typed refusal from an actual construction cleanup stage.
#[derive(Debug)]
pub enum ProductionVmConstructionCleanupError {
    /// A prior unwind made the retained phase uncertain.
    Poisoned,
    /// Another invocation still borrows the same owning phase.
    Pending,
    /// An owning internal phase is incomplete or ambiguous.
    Retained(&'static str),
    /// Actual node reap refused.
    Node(crucible_qemu::QemuNodeError),
    /// Actual backend shutdown refused.
    Backend(crucible::BackendError),
    /// Exact generation lease retirement refused.
    Leases(SchedulerError),
    /// Actual aggregate launcher or pending lease retirement refused.
    Authority(LifecycleApiError),
}

impl fmt::Display for ProductionVmConstructionCleanupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poisoned => formatter.write_str("construction custody is poisoned"),
            Self::Pending => formatter.write_str("construction cleanup is already borrowed"),
            Self::Retained(message) => formatter.write_str(message),
            Self::Node(source) => write!(formatter, "construction node reap: {source}"),
            Self::Backend(source) => write!(formatter, "construction backend retirement: {source}"),
            Self::Leases(source) => write!(formatter, "construction lease retirement: {source}"),
            Self::Authority(source) => {
                write!(formatter, "construction authority retirement: {source}")
            }
        }
    }
}

impl Error for ProductionVmConstructionCleanupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Node(source) => Some(source),
            Self::Backend(source) => Some(source),
            Self::Leases(source) => Some(source),
            Self::Authority(source) => Some(source),
            Self::Poisoned | Self::Pending | Self::Retained(_) => None,
        }
    }
}

fn phase_lock_error<T>(error: TryLockError<T>) -> ProductionVmConstructionCleanupError {
    match error {
        TryLockError::WouldBlock => ProductionVmConstructionCleanupError::Pending,
        TryLockError::Poisoned(_) => ProductionVmConstructionCleanupError::Poisoned,
    }
}

fn finish_pending_reaped(
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
}

fn retire_launch(partial: &mut Partial) -> Result<(), ProductionVmConstructionCleanupError> {
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
}

fn clear_devices(
    devices: &storage_faults::ProductionBlockDevices,
) -> Result<(), ProductionVmConstructionCleanupError> {
    devices
        .lock()
        .map_err(|_| ProductionVmConstructionCleanupError::Poisoned)?
        .clear();
    Ok(())
}

fn retire_adoption(partial: &mut Partial) -> Result<(), ProductionVmConstructionCleanupError> {
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
}

fn retire_partial(partial: &mut Partial) -> Result<(), ProductionVmConstructionCleanupError> {
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
        launcher
            .finish()
            .map_err(ProductionVmConstructionCleanupError::Authority)?;
    }
    partial.cleanup_complete = true;
    Ok(())
}

fn retire_complete(
    lifecycle: &mut ProductionVmLifecycleLoop,
) -> Result<(), ProductionVmConstructionCleanupError> {
    lifecycle
        .retry_retained_debug_construction()
        .map_err(ProductionVmConstructionCleanupError::Leases)?;
    if lifecycle.debug_gateway.is_some() || lifecycle.indeterminate_debug_candidate.is_some() {
        return Err(ProductionVmConstructionCleanupError::Retained(
            "construction contains a live external debugger owner",
        ));
    }
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
    lifecycle
        .node_launcher
        .finish()
        .map_err(ProductionVmConstructionCleanupError::Authority)
}

/// Visits the existing map without allocating a second node roster on refusal.
fn finish_retained_node_leases(
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
}

impl ProductionVmLifecycleLoop {
    /// Moves the whole lifecycle back into its original empty construction Box.
    ///
    /// This is custody publication preparation, never execution authority or
    /// evidence that a semantic shutdown result proved physical retirement.
    ///
    /// # Errors
    /// Returns the same complete lifecycle if its original carrier is missing,
    /// occupied, or poisoned. No replacement carrier is allocated.
    pub fn into_construction_custody(
        mut self,
    ) -> Result<Box<ProductionVmConstructionCustody>, Self> {
        let Some(mut custody) = self.construction_custody.take() else {
            return Err(self);
        };
        let reusable = custody.first.is_none()
            && !custody.physically_closed.load(Ordering::Acquire)
            && matches!(custody.phase.get_mut(), Ok(Phase::Empty));
        #[cfg(target_os = "linux")]
        let reusable = reusable && custody.reservation.is_none();
        if !reusable {
            self.construction_custody = Some(custody);
            return Err(self);
        }
        // This empty, exclusively owned mutex was validated above. No callback
        // runs between validation and the move into the existing carrier.
        let phase = match custody.phase.get_mut() {
            Ok(phase) => phase,
            Err(_) => {
                self.construction_custody = Some(custody);
                return Err(self);
            }
        };
        *phase = Phase::Complete(self);
        Ok(custody)
    }
}

impl crucible_api::ProductionVmCleanupOwner for ProductionVmConstructionCustody {
    type Failure = crucible::SchedulerError;

    fn retry_cleanup(&mut self) -> Result<(), SchedulerError> {
        ProductionVmConstructionCustody::retry_cleanup(self).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: error.to_string(),
            }
        })
    }
}
