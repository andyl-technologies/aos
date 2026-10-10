//! Retains the entered family Quiescence and its process cancellation event.
//!
//! CPU remains zero in the staged escrow. This owner authenticates the family
//! operation and preserves its original end; it supplies no native callback,
//! worker drain, Source, process birth or execution-phase permission.

use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, OnceLock};

use crucible_api::vm_lifecycle::HostRamProcessFamilyPartition;
use crucible_linux_resource::host_services::{
    HostServiceAllocator, HostServiceError, HostServiceLease,
};
use crucible_linux_resource::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor, HostSupervisionError,
};
use crucible_linux_resource::ram_policy::{HostRamTarget, HostResourceVector};
#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
use crucible_qemu::QemuProcessStageIdentityError;

use crucible_qemu::{QemuChildProcessContract, QemuProcessStageBinding, QemuSpawnError};

/// Noncopying assignment retained by the actual configured family.
pub(super) struct StagedProcessAssignment {
    state: Arc<StageState>,
    pending_subscription: Option<HostServiceLease>,
    // The shared body and its Arc header close before the final loan alias.
    _control_resources: HostServiceLease,
}

/// Move-only family operation retained through native relinquishment or containment.
///
/// Dropping it does not release the issuer's occupied record or entered Pause.
/// A copied basis describes this owner and never replaces its custody.
pub(crate) struct ConfiguredStageOperation {
    state: Arc<StageState>,
    _control_resources: HostServiceLease,
}

struct StageState {
    parent: HostRamTarget,
    stage: HostRamTarget,
    escrow: HostResourceVector,
    original: HostOperationSupervisor,
    process_binding: OnceLock<QemuProcessStageBinding>,
    quiescence: OnceLock<HostOperationGuard>,
    failure: OnceLock<StageFailure>,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(crate) enum StageEarlyRefusal {
    #[error("configured process park issuer is busy")]
    IssuerBusy,
    #[error("configured process park issuer is poisoned")]
    IssuerPoisoned,
    #[error("configured process stage invariant refused: {0}")]
    Invariant(&'static str),
    #[error(transparent)]
    Original(#[from] HostSupervisionError),
    #[error(transparent)]
    Account(#[from] HostServiceError),
}

#[derive(Debug, thiserror::Error)]
pub(super) enum StageFailureCause {
    #[error(transparent)]
    Original(#[from] HostSupervisionError),
    #[error(transparent)]
    ProcessContract(#[from] QemuSpawnError),
    #[error(transparent)]
    Assignment(#[from] StageEarlyRefusal),
}

#[derive(Debug, thiserror::Error)]
#[error(
    "family stage refused: {first}; entered Quiescence postcut: {quiescence_after:?}; independent original postcut: {original_after:?}"
)]
struct StageFailure {
    #[source]
    first: StageFailureCause,
    quiescence_after: Option<HostSupervisionError>,
    original_after: Option<HostSupervisionError>,
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
/// Preserves a typed refusal while revalidating the same retained phase.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StageReborrowRefusal {
    #[error(transparent)]
    Issuer(#[from] StageEarlyRefusal),
    #[error(transparent)]
    Parent(#[from] crucible_linux_resource::ram_policy::HostRamPolicyError),
    #[error(transparent)]
    Owner(#[from] crate::qemu_resource_guard::ProcessStageContractRefusal),
    #[error(transparent)]
    Identity(#[from] QemuProcessStageIdentityError),
}

/// Preserves an early refusal or the same prepaid entered failure owner.
pub(crate) enum StagePrepareError {
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    Reborrow {
        first: StageReborrowRefusal,
        quiescence_after: Option<HostSupervisionError>,
        original_after: Option<HostSupervisionError>,
    },
    Admission(super::super::park_drain_registration::PreparedStageAdmissionFailure),
    Before {
        source: StageEarlyRefusal,
        original_after: Option<HostSupervisionError>,
    },
    Entered {
        operation: ConfiguredStageOperation,
    },
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
impl StageEarlyRefusal {
    fn failure(&self) -> crucible_api::ProductionVmParentParkStageEarlyCause<'_> {
        use crucible_api::ProductionVmParentParkStageEarlyCause as Cause;
        match self {
            Self::IssuerBusy => Cause::IssuerBusy,
            Self::IssuerPoisoned => Cause::IssuerPoisoned,
            Self::Invariant(reason) => Cause::Invariant(reason),
            Self::Original(first) => Cause::Original(first),
            Self::Account(first) => Cause::Account(first),
        }
    }
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
impl StagePrepareError {
    pub(crate) fn failure(&self) -> crucible_api::ProductionVmParentParkStageFailure<'_> {
        use crucible_api::{
            ProductionVmParentParkStageEnteredCause as Entered,
            ProductionVmParentParkStageFailure as Failure,
            ProductionVmParentParkStageReborrowCause as Reborrow,
        };

        match self {
            Self::Before {
                source,
                original_after,
            } => Failure::Before {
                first: source.failure(),
                original_after: original_after.as_ref(),
            },
            Self::Admission(owner) => owner.failure(),
            Self::Entered { operation } => {
                let retained = operation.state.failure.get();
                let first = retained.map(|failure| match &failure.first {
                    StageFailureCause::Original(first) => Entered::Original(first),
                    StageFailureCause::ProcessContract(first) => Entered::ProcessContract(first),
                    StageFailureCause::Assignment(first) => Entered::Assignment(first.failure()),
                });
                Failure::Entered {
                    first,
                    quiescence_after: retained
                        .and_then(|failure| failure.quiescence_after.as_ref()),
                    original_after: retained.and_then(|failure| failure.original_after.as_ref()),
                }
            }
            Self::Reborrow {
                first,
                quiescence_after,
                original_after,
            } => Failure::Reborrow {
                first: match first {
                    StageReborrowRefusal::Issuer(first) => Reborrow::Issuer(first.failure()),
                    StageReborrowRefusal::Parent(first) => Reborrow::Parent(first),
                    StageReborrowRefusal::Owner(first) => Reborrow::Owner(first.failure()),
                    StageReborrowRefusal::Identity(first) => Reborrow::Identity(first),
                },
                quiescence_after: quiescence_after.as_ref(),
                original_after: original_after.as_ref(),
            },
        }
    }
}

impl std::fmt::Debug for StagePrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            Self::Reborrow {
                first,
                quiescence_after,
                original_after,
            } => formatter
                .debug_struct("StageReborrowError")
                .field("first", first)
                .field("quiescence_after", quiescence_after)
                .field("original_after", original_after)
                .finish(),
            Self::Admission(failure) => std::fmt::Debug::fmt(failure, formatter),
            Self::Before {
                source,
                original_after,
            } => formatter
                .debug_struct("StagePrepareError")
                .field("source", source)
                .field("original_after", original_after)
                .finish(),
            Self::Entered { operation } => formatter
                .debug_struct("StagePrepareError")
                .field("failure", &operation.state.failure.get())
                .finish(),
        }
    }
}

impl std::fmt::Display for StagePrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            Self::Reborrow {
                first,
                quiescence_after,
                original_after,
            } => write!(
                formatter,
                "family stage reborrow refused: {first}; phase postcut: {quiescence_after:?}; family postcut: {original_after:?}"
            ),
            Self::Admission(failure) => std::fmt::Display::fmt(failure, formatter),
            Self::Before {
                source,
                original_after,
            } => write!(
                formatter,
                "family stage admission refused: {source}; independent original postcut: {original_after:?}"
            ),
            Self::Entered { operation } => match operation.state.failure.get() {
                Some(failure) => std::fmt::Display::fmt(failure, formatter),
                None => formatter
                    .write_str("family stage remains contained after incomplete publication"),
            },
        }
    }
}

impl std::error::Error for StagePrepareError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            Self::Reborrow { first, .. } => Some(first),
            Self::Admission(failure) => std::error::Error::source(failure),
            Self::Before { source, .. } => Some(source),
            Self::Entered { operation } => match operation.state.failure.get() {
                Some(failure) => Some(failure),
                None => None,
            },
        }
    }
}

impl StagedProcessAssignment {
    pub(super) fn prepare(
        partition: HostRamProcessFamilyPartition,
        initial: HostRamTarget,
        parent: HostRamTarget,
        arena_generation: u64,
        original: &HostOperationSupervisor,
        services: &HostServiceAllocator,
    ) -> Result<(Self, ConfiguredStageOperation), StageEarlyRefusal> {
        original.verify_original_live()?;
        let escrow = partition
            .staged_escrow()
            .ok_or(StageEarlyRefusal::Invariant(
                "configured family has no reserved process stage",
            ))?;
        if parent != initial || arena_generation == 0 || arena_generation == parent.arena_generation
        {
            return Err(StageEarlyRefusal::Invariant(
                "stage differs from its exact configured parent",
            ));
        }
        let owner_generation =
            parent
                .owner_generation
                .checked_add(1)
                .ok_or(StageEarlyRefusal::Invariant(
                    "process stage generation exhausted",
                ))?;
        let stage = HostRamTarget {
            owner_generation,
            arena_generation,
            retained_template: false,
            ..parent
        };
        let (layout, _) = std::alloc::Layout::new::<(AtomicUsize, AtomicUsize)>()
            .extend(std::alloc::Layout::new::<StageState>())
            .map_err(|_| StageEarlyRefusal::Invariant("stage Arc extent overflow"))?;
        let bytes = layout
            .pad_to_align()
            .size()
            .checked_add(std::mem::size_of::<StageState>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ConfiguredStageOperation>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<StagePrepareError>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| bytes.checked_add(HostServiceLease::metadata_bytes()))
            .and_then(|bytes| bytes.checked_add(QemuProcessStageBinding::retained_control_bytes()?))
            .ok_or(StageEarlyRefusal::Invariant(
                "process stage control extent overflow",
            ))?;
        // The weak process identity can retain its original Arc header after
        // the last contract closes. Its distinct header custody is included
        // above and remains with this body until the final external loan.
        // The world already retains the finite supervisor roster. This distinct
        // loan pays the Arc, typed failure, returned holder and construction
        // overlap. Subscriber FD/control is independently paid before begin/dup.
        let control_resources = services.reserve_resources(0, 0, bytes)?;
        let subscription = services.reserve_resources(
            0,
            1,
            HostOperationGuard::original_quiescence_cancellation_bytes(),
        )?;
        original.verify_original_live()?;
        let state = Arc::new(StageState {
            parent,
            stage,
            escrow,
            original: original.clone(),
            process_binding: OnceLock::new(),
            quiescence: OnceLock::new(),
            failure: OnceLock::new(),
        });
        let operation = ConfiguredStageOperation {
            state: Arc::clone(&state),
            _control_resources: control_resources.clone(),
        };
        Ok((
            Self {
                state,
                pending_subscription: Some(subscription),
                _control_resources: control_resources,
            },
            operation,
        ))
    }

    pub(super) fn enter(
        &mut self,
        contract: &QemuChildProcessContract,
    ) -> Result<(), StageFailureCause> {
        self.state.original.verify_original_live()?;
        self.state
            .process_binding
            .set(contract.retain_process_stage_binding())
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        let credit = self
            .pending_subscription
            .take()
            .ok_or(HostSupervisionError::InvalidBudget)?;
        let quiescence = self.state.original.begin(HostOperationClass::Quiescence)?;
        self.state
            .quiescence
            .set(quiescence)
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        let quiescence = self
            .state
            .quiescence
            .get()
            .ok_or(HostSupervisionError::Unavailable)?;
        let descriptor = contract.try_clone_cancellation_event()?;
        quiescence.retain_original_quiescence_cancellation(descriptor, credit)?;
        quiescence.check_original_quiescence_cancellation()?;
        Ok(())
    }

    pub(super) fn finish_entry(
        &self,
        entered: Result<(), StageFailureCause>,
        operation: ConfiguredStageOperation,
    ) -> Result<ConfiguredStageOperation, StagePrepareError> {
        // Sample the actual entered guard and its retained event at the final
        // publication boundary. The family cap alone cannot certify this phase.
        let quiescence_after = self.state.quiescence.get().and_then(|guard| {
            (|| {
                guard.check_original_quiescence_cancellation()?;
                guard.wait_slice()?;
                guard.check_original_quiescence_cancellation()
            })()
            .err()
        });
        let original_after = self.state.original.verify_original_live().err();
        let (first, quiescence_after, original_after) = match entered {
            Err(first) => (first, quiescence_after, original_after),
            Ok(()) => match (quiescence_after, original_after) {
                (None, None) => return Ok(operation),
                (Some(source), original_after) => {
                    (StageFailureCause::Original(source), None, original_after)
                }
                (None, Some(source)) => (StageFailureCause::Original(source), None, None),
            },
        };
        // Both slots and the whole first-cause storage were born before begin.
        // Publishing a refusal only moves the real error into that same body.
        let _ = self.state.failure.set(StageFailure {
            first,
            quiescence_after,
            original_after,
        });
        Err(StagePrepareError::Entered { operation })
    }

    pub(super) fn verify(
        &self,
        operation: &ConfiguredStageOperation,
    ) -> Result<(), StageEarlyRefusal> {
        if !Arc::ptr_eq(&self.state, &operation.state) {
            return Err(StageEarlyRefusal::Invariant(
                "stage differs from retained issuer state",
            ));
        }
        operation.verify_parent(&self.state.parent)?;
        Ok(())
    }
}

impl ConfiguredStageOperation {
    /// Verifies the current contract against the actual stage-entry allocation.
    ///
    /// # Errors
    /// Refuses missing entry custody or a separately created process attempt.
    #[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
    pub(crate) fn verify_process_contract(
        &self,
        contract: &QemuChildProcessContract,
    ) -> Result<(), QemuProcessStageIdentityError> {
        let binding = self
            .state
            .process_binding
            .get()
            .ok_or(QemuProcessStageIdentityError)?;
        contract.verify_process_stage_binding(binding)
    }

    /// Preserves revalidation's typed first cause and both actual postcuts.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn reborrow_refusal(&self, first: StageReborrowRefusal) -> StagePrepareError {
        let (quiescence_after, original_after) = self.observe_original_cuts();
        StagePrepareError::Reborrow {
            first,
            quiescence_after,
            original_after,
        }
    }

    /// Observes phase/subscriber and outer family refusal independently.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn observe_original_cuts(
        &self,
    ) -> (Option<HostSupervisionError>, Option<HostSupervisionError>) {
        let phase = if self.state.failure.get().is_some() {
            Some(HostSupervisionError::Unavailable)
        } else {
            match self.state.quiescence.get() {
                Some(guard) => guard.check_original_quiescence_cancellation().err(),
                None => Some(HostSupervisionError::Unavailable),
            }
        };
        let outer = self.state.original.verify_original_live().err();
        (phase, outer)
    }

    /// Rechecks the retained issuer parent against the installed source loan.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn verify_source_parent(
        &self,
        source: &crucible_qemu::QemuNodeSetPreparedHotForkSource<'_>,
    ) -> Result<(), crucible_linux_resource::ram_policy::HostRamPolicyError> {
        source.verify_original_park_parent(&self.state.parent)
    }

    pub(crate) fn verify_original(&self) -> Result<(), HostSupervisionError> {
        self.state.original.verify_original_live()?;
        if self.state.failure.get().is_some() || self.state.process_binding.get().is_none() {
            return Err(HostSupervisionError::Unavailable);
        }
        self.state
            .quiescence
            .get()
            .ok_or(HostSupervisionError::Unavailable)?
            .check_original_quiescence_cancellation()
    }

    pub(crate) fn verify_parent(&self, parent: &HostRamTarget) -> Result<(), HostSupervisionError> {
        self.verify_original()?;
        if self.state.parent != *parent
            || self.state.stage.owner_generation
                != parent
                    .owner_generation
                    .checked_add(1)
                    .ok_or(HostSupervisionError::IdentityExhausted)?
            || self.state.escrow.cpu_slots != 0
        {
            return Err(HostSupervisionError::InvalidBudget);
        }
        Ok(())
    }

    // The callback's result cannot borrow the retained guard. The fixed phase
    // provider must preserve both actual guards at every wait/effect cut and
    // independently retain each postcause when the callback itself refuses.
    pub(crate) fn with_quiescence<T>(
        &self,
        invoke: impl for<'guard> FnOnce(&'guard HostOperationGuard) -> T,
    ) -> Result<(T, Option<HostSupervisionError>), HostSupervisionError> {
        self.verify_original()?;
        let guard = self
            .state
            .quiescence
            .get()
            .ok_or(HostSupervisionError::Unavailable)?;
        let outcome = invoke(guard);
        let original_after = self.verify_original().err();
        Ok((outcome, original_after))
    }
}

#[cfg(all(test, target_os = "linux", feature = "private-measurement-domain"))]
mod failure_tests {
    use super::*;
    use crucible_api::{
        ProductionVmParentParkStageEarlyCause as Early,
        ProductionVmParentParkStageFailure as Failure,
    };

    #[test]
    fn typed_stage_view_preserves_first_and_independent_post_references() {
        let retained = StagePrepareError::Before {
            source: StageEarlyRefusal::Original(HostSupervisionError::Unavailable),
            original_after: Some(HostSupervisionError::InvalidBudget),
        };
        let StagePrepareError::Before {
            source,
            original_after,
        } = &retained
        else {
            unreachable!()
        };
        let Failure::Before {
            first: Early::Original(borrowed),
            original_after: Some(post),
        } = retained.failure()
        else {
            panic!("stage carrier or typed first/post cause changed");
        };
        let StageEarlyRefusal::Original(first) = source else {
            unreachable!()
        };
        assert!(std::ptr::eq(first, borrowed));
        assert!(std::ptr::eq(original_after.as_ref().unwrap(), post));
        assert!(matches!(borrowed, HostSupervisionError::Unavailable));
        assert!(matches!(post, HostSupervisionError::InvalidBudget));
    }
}
