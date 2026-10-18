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

mod inputs;
mod post_body;
mod return_body;
#[cfg(target_os = "linux")]
mod source_preparation;
pub(in crate::vm_lifecycle) use inputs::with_inputs;

#[cfg(test)]
mod tests;

/// Owns the exact construction resources until publication or physical return.
pub struct ProductionVmConstructionCustody {
    // Error::source borrows this stable field without borrowing the phase lock.
    pub(super) first: Option<LifecycleApiError>,
    pub(super) phase: Mutex<Phase>,
    physically_closed: AtomicBool,
    post_body: Option<crate::ProductionVmConstructionPostBody>,
    #[cfg(target_os = "linux")]
    pub(super) return_destination: Option<crate::lifecycle_cleanup::SourceBodyReturn>,
    #[cfg(target_os = "linux")]
    pub(super) reservation: Option<
        Box<
            dyn crucible_control_api::ProductionVmCleanupReservation<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                    ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
                >,
        >,
    >,
    // The component account remains alive until this actual carrier drops.
    #[cfg(test)]
    component_funding: Option<crucible_engine::owned_decode::DecodeCustody>,
}

pub(super) enum Phase {
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
        BTreeMap<ContentHash, crucible_qemu_host::QemuSharedBlockDevice>,
    pub(in crate::vm_lifecycle) block_devices: Option<storage_faults::ProductionBlockDevices>,
    pub(in crate::vm_lifecycle) exact_ram_parents:
        BTreeMap<ContentHash, ProductionExactRamPublishedParent>,
    pub(in crate::vm_lifecycle) inner:
        Option<BackendQuantumLoop<SingleScheduler, QemuNodeSet, ProductionFaultNetworkInterceptor>>,
    pub(in crate::vm_lifecycle) input_decode_custody: Option<crucible_engine::owned_decode::DecodeCustody>,
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

impl ProductionVmConstructionCustody {
    /// Creates empty storage without issuing a resource or starting a clock.
    pub fn new() -> Self {
        Self {
            first: None,
            phase: Mutex::new(Phase::Partial(Partial::new())),
            physically_closed: AtomicBool::new(false),
            post_body: None,
            #[cfg(target_os = "linux")]
            return_destination: None,
            #[cfg(target_os = "linux")]
            reservation: None,
            #[cfg(test)]
            component_funding: None,
        }
    }

    /// Allocates one component carrier under its already installed fixture account.
    ///
    /// This storage has no Main reservation or native launch authority. The
    /// shared constructor still validates it and retains all actual inputs.
    #[cfg(test)]
    pub(crate) fn prepare_component() -> Result<Box<Self>, LifecycleApiError> {
        let funding = crucible_engine::owned_decode::require_current_custody()
            .map_err(LifecycleApiError::ConfigurationCopy)?;
        crucible_engine::owned_decode::charge_array::<Self>(1)
            .map_err(LifecycleApiError::ConfigurationCopy)?;
        let mut custody = Self::new();
        custody.component_funding = Some(funding);
        Ok(Box::new(custody))
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

    /// Retains the initiating cause beside this same partial or complete owner.
    pub(crate) fn into_failure(
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

    /// Borrows only an original empty carrier for a completed Loop move.
    fn retirement_slot(&mut self) -> Option<&mut Phase> {
        if self.first.is_some() || self.physically_closed.load(Ordering::Acquire) {
            return None;
        }
        #[cfg(target_os = "linux")]
        if self.reservation.is_some() || self.return_destination.is_some() {
            return None;
        }
        match self.phase.get_mut() {
            Ok(phase @ Phase::Empty) => Some(phase),
            _ => None,
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
                    dyn crucible_control_api::ProductionVmCleanupReservation<
                            Failure = crate::ProductionVmConstructionCleanupError,
                            PostBody = crate::ProductionVmConstructionPostBody,
                            ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
                        >,
                >,
                Box<
                    dyn crucible_control_api::ProductionVmCleanupOwner<
                            Failure = crate::ProductionVmConstructionCleanupError,
                            PostBody = crate::ProductionVmConstructionPostBody,
                        >,
                >,
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

    /// Moves a component diagnostic while its actual body stays in the caller's slot.
    ///
    /// Only the explicitly fixture-funded carrier permits this extraction. It
    /// does not publish to Main or attest cleanup; native carriers keep their
    /// original error until the canonical reservation accepts the owner.
    #[cfg(test)]
    pub(crate) fn take_component_first_error(&mut self) -> Option<LifecycleApiError> {
        if self.additional.is_some() {
            return None;
        }
        match &mut self.storage {
            FailureStorage::Preallocated(custody) if custody.component_funding.is_some() => {
                custody.first.take()
            }
            _ => None,
        }
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
    /// The same shared Source allocation still has an actual strong or Weak alias.
    SharedAliasesPending,
    /// An owning internal phase is incomplete or ambiguous.
    Retained(&'static str),
    /// Actual node reap refused.
    Node(crucible_qemu_host::QemuNodeError),
    /// Actual backend shutdown refused.
    Backend(crucible_engine::BackendError),
    /// Exact generation lease retirement refused.
    Leases(SchedulerError),
    /// Actual aggregate launcher or pending lease retirement refused.
    Authority(LifecycleApiError),
    /// A guard retained its actual cleanup leaf and observed custody.
    Guard(crate::QemuAttemptResourceGuardCleanupFailure),
    /// Existing scheduler cleanup retained its typed cause.
    Scheduler(SchedulerError),
    /// The original counted observer protects a Main-held cleanup cause.
    Prepared(crate::lifecycle_cleanup::PreparedSourceFailure),
    /// The two independent bodies of a rejected carrier both refused cleanup.
    GuardPair {
        /// The earlier non-host-cleanup report, if it preceded both leaves.
        first: Option<ProductionVmCleanupEarlierFailure>,
        /// The first body's actual host cleanup leaf, in observation order.
        first_guard: crate::QemuAttemptResourceGuardCleanupFailure,
        /// The other body's independently owned host cleanup leaf.
        second_guard: crate::QemuAttemptResourceGuardCleanupFailure,
    },
    /// An earlier report and the independently retained first guard leaf.
    GuardHistory {
        /// The unchanged report that preceded the guard refusal.
        first: ProductionVmCleanupEarlierFailure,
        /// The first guard cleanup cause, with its actual custody observation.
        guard: crate::QemuAttemptResourceGuardCleanupFailure,
    },
}

impl fmt::Display for ProductionVmConstructionCleanupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poisoned => formatter.write_str("construction custody is poisoned"),
            Self::Pending => formatter.write_str("construction cleanup is already borrowed"),
            Self::SharedAliasesPending => {
                formatter.write_str("shared Source allocation aliases remain")
            }
            Self::Retained(message) => formatter.write_str(message),
            Self::Node(source) => write!(formatter, "construction node reap: {source}"),
            Self::Backend(source) => write!(formatter, "construction backend retirement: {source}"),
            Self::Leases(source) => write!(formatter, "construction lease retirement: {source}"),
            Self::Authority(source) => {
                write!(formatter, "construction authority retirement: {source}")
            }
            Self::Guard(source) => write!(formatter, "guard retirement: {source}"),
            Self::Scheduler(source) => std::fmt::Display::fmt(source, formatter),
            Self::Prepared(source) => std::fmt::Display::fmt(source, formatter),
            Self::GuardHistory { first, guard } => {
                write!(formatter, "{first}; guard cleanup: {guard}")
            }
            Self::GuardPair {
                first,
                first_guard,
                second_guard,
            } => {
                if let Some(first) = first {
                    write!(formatter, "{first}; ")?;
                }
                write!(
                    formatter,
                    "first body cleanup: {first_guard}; other body cleanup: {second_guard}"
                )
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
            Self::Guard(source) => Some(source),
            Self::Scheduler(source) => Some(source),
            Self::Prepared(source) => Some(source),
            Self::GuardHistory { first, .. } => Some(first),
            Self::GuardPair {
                first, first_guard, ..
            } => first
                .as_ref()
                .map(|first| first as &dyn Error)
                .or(Some(first_guard)),
            Self::Poisoned | Self::Pending | Self::SharedAliasesPending | Self::Retained(_) => None,
        }
    }
}

/// Retains the unchanged earlier diagnostic beside the first guard cleanup leaf.
///
/// This finite diagnostic union owns no new cleanup allowance or containing body.
#[derive(Debug, thiserror::Error)]
pub enum ProductionVmCleanupEarlierFailure {
    /// The same original Main report retained before local guard cleanup.
    #[error(transparent)]
    Prepared(crate::lifecycle_cleanup::PreparedSourceFailure),
    /// A prior unwind made the phase uncertain.
    #[error("construction custody is poisoned")]
    Poisoned,
    /// Another invocation still borrows the same phase.
    #[error("construction cleanup is already borrowed")]
    Pending,
    /// The earlier shared allocation still retained an actual alias.
    #[error("shared Source allocation aliases remain")]
    SharedAliasesPending,
    /// The earlier owning phase was incomplete.
    #[error("{0}")]
    Retained(&'static str),
    /// Actual node reap refused.
    #[error("construction node reap: {0}")]
    Node(#[source] crucible_qemu_host::QemuNodeError),
    /// Actual backend shutdown refused.
    #[error("construction backend retirement: {0}")]
    Backend(#[source] crucible_engine::BackendError),
    /// Exact lease retirement refused.
    #[error("construction lease retirement: {0}")]
    Leases(#[source] SchedulerError),
    /// An earlier launcher or lease check refused.
    #[error("construction authority retirement: {0}")]
    Authority(#[source] LifecycleApiError),
    /// Existing scheduler cleanup retained its typed cause.
    #[error(transparent)]
    Scheduler(SchedulerError),
    /// The earlier local-role report, retained beside aggregate cleanup.
    #[error(transparent)]
    Guard(crate::QemuAttemptResourceGuardCleanupFailure),
}

impl ProductionVmConstructionCleanupError {
    /// Borrows the independently retained first guard cleanup cause.
    #[must_use]
    pub fn guard_failure(&self) -> Option<&crate::QemuAttemptResourceGuardCleanupFailure> {
        match self {
            Self::Guard(guard) | Self::GuardHistory { guard, .. } => Some(guard),
            Self::GuardPair { first_guard, .. } => Some(first_guard),
            _ => None,
        }
    }

    pub(crate) fn retain_first(slot: &mut Option<Self>, source: Self) -> &Self {
        let first = match slot.take() {
            Some(first) => first.with_later_failure(source),
            None => source,
        };
        slot.insert(first)
    }

    pub(crate) fn with_later_failure(self, source: Self) -> Self {
        match source {
            Self::Guard(guard) | Self::GuardHistory { guard, .. } => self.with_guard_history(guard),
            Self::GuardPair {
                first_guard,
                second_guard,
                ..
            } => self
                .with_guard_history(first_guard)
                .with_guard_history(second_guard),
            _ => self,
        }
    }

    fn with_guard_history(self, guard: crate::QemuAttemptResourceGuardCleanupFailure) -> Self {
        let first = match self {
            Self::Poisoned => ProductionVmCleanupEarlierFailure::Poisoned,
            Self::Pending => ProductionVmCleanupEarlierFailure::Pending,
            Self::SharedAliasesPending => ProductionVmCleanupEarlierFailure::SharedAliasesPending,
            Self::Retained(message) => ProductionVmCleanupEarlierFailure::Retained(message),
            Self::Node(source) => ProductionVmCleanupEarlierFailure::Node(source),
            Self::Backend(source) => ProductionVmCleanupEarlierFailure::Backend(source),
            Self::Leases(source) => ProductionVmCleanupEarlierFailure::Leases(source),
            Self::Authority(source) => ProductionVmCleanupEarlierFailure::Authority(source),
            Self::Scheduler(source) => ProductionVmCleanupEarlierFailure::Scheduler(source),
            Self::Prepared(source) => ProductionVmCleanupEarlierFailure::Prepared(source),
            Self::Guard(first) => {
                if !guard.has_raw_cause() {
                    return Self::Guard(first);
                }
                if first.has_raw_cause() {
                    return Self::GuardPair {
                        first: None,
                        first_guard: first,
                        second_guard: guard,
                    };
                }
                ProductionVmCleanupEarlierFailure::Guard(first)
            }
            Self::GuardHistory {
                first,
                guard: retained,
            } => {
                if !guard.has_raw_cause() {
                    return Self::GuardHistory {
                        first,
                        guard: retained,
                    };
                }
                if retained.has_raw_cause() {
                    return Self::GuardPair {
                        first: Some(first),
                        first_guard: retained,
                        second_guard: guard,
                    };
                }
                return Self::GuardHistory { first, guard };
            }
            Self::GuardPair {
                first,
                first_guard,
                second_guard,
            } => {
                // The actual Missing carrier contains exactly two bodies. Each
                // aggregate close is one-shot; subsequent reports are local
                // status. No selected-node lease calls an aggregate close.
                return Self::GuardPair {
                    first,
                    first_guard,
                    second_guard,
                };
            }
        };
        Self::GuardHistory { first, guard }
    }
}

impl From<LifecycleApiError> for ProductionVmConstructionCleanupError {
    fn from(source: LifecycleApiError) -> Self {
        Self::Authority(source)
    }
}

impl From<SchedulerError> for ProductionVmConstructionCleanupError {
    fn from(source: SchedulerError) -> Self {
        Self::Scheduler(source)
    }
}

impl From<crate::QemuAttemptResourceGuardCleanupFailure> for ProductionVmConstructionCleanupError {
    fn from(source: crate::QemuAttemptResourceGuardCleanupFailure) -> Self {
        Self::Guard(source)
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
        launcher.finish()?;
    }
    partial.cleanup_complete = true;
    Ok(())
}

fn retire_complete(
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

#[cfg(target_os = "linux")]
pub(in crate::vm_lifecycle) struct SourceRetirementSlot<'a> {
    phase: &'a mut Phase,
}

#[cfg(target_os = "linux")]
impl SourceRetirementSlot<'_> {
    /// Moves the whole existing Source after exclusive carrier validation.
    pub(in crate::vm_lifecycle) fn install(self, source: ProductionVmHotForkSourceWorld) {
        *self.phase = Phase::Source(source);
    }
}

#[cfg(target_os = "linux")]
impl ProductionVmConstructionCustody {
    pub(in crate::vm_lifecycle) fn source_retirement_slot(
        &mut self,
    ) -> Option<SourceRetirementSlot<'_>> {
        self.retirement_slot()
            .map(|phase| SourceRetirementSlot { phase })
    }

    pub(in crate::vm_lifecycle) fn retire_complete_body(
        lifecycle: &mut ProductionVmLifecycleLoop,
    ) -> Result<(), ProductionVmConstructionCleanupError> {
        retire_complete(lifecycle)
    }
}
