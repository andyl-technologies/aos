//! Binds later stage admission to the same configured world and launcher.
//!
//! The private park provider retains the existing registration allocation used by setup.
//! Its private constructor authenticates the admitted context before launcher
//! erasure; no caller supplies a service allocator or process contract.

use std::sync::Arc;

use crucible_api::vm_lifecycle::HostRamAdmissionError;
#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
use crucible_linux_resource::host_services::{
    HostServiceAllocator, HostServiceError, HostServiceLease,
};
#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
use crucible_linux_resource::host_supervision::HostSupervisionError;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
use crucible_linux_resource::ram_policy::HostRamPolicyError;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
use crucible_qemu::QemuNodeSetPreparedHotForkSource;

use super::AdmittedRamRegistrationFactory;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
use super::NEXT_ARENA_GENERATION;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
use super::process_family::ConfiguredStageOperation;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
use super::process_family::StageReborrowRefusal;
#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
use super::process_family::{StageEarlyRefusal, StagePrepareError};
use crate::AttemptExecutionContext;
#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
use crate::qemu_resource_guard::ProcessStageContractRefusal;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
use crate::{
    ExecutionCancellation, QemuAttemptGenerationResourceOwner, QemuAttemptProcessResourceGuard,
};

/// Validates the configured family issuer paired with the admitted launcher.
///
/// The Linux private provider retains the registration and cancellation owner
/// for its later fixed stage operation.
pub(crate) struct ConfiguredParkDrainRegistration {
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    registration: Arc<AdmittedRamRegistrationFactory>,
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    cancellation: ExecutionCancellation,
}

/// Retains a preadmitted body for the typed admission cause and original post.
///
/// The body exists before the Node or containing host is checked. Refusal only
/// moves its causes into that body; body free precedes the external loan refund.
#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
pub(crate) struct PreparedStageAdmissionFailure {
    body: Box<Option<StageAdmissionFailureData>>,
    // Physical body free precedes the external same-service control refund.
    _resources: HostServiceLease,
}

#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
#[derive(Debug, thiserror::Error)]
enum StageAdmissionCause {
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    #[error(transparent)]
    Node(HostRamPolicyError),
    #[error(transparent)]
    Owner(ProcessStageContractRefusal),
}

#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
#[derive(Debug, thiserror::Error)]
#[error(
    "configured stage admission refused: {first}; independent family postcut: {original_after:?}"
)]
struct StageAdmissionFailureData {
    #[source]
    first: StageAdmissionCause,
    original_after: Option<HostSupervisionError>,
}

#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
impl PreparedStageAdmissionFailure {
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn failure(&self) -> crucible_api::ProductionVmParentParkStageFailure<'_> {
        use crucible_api::{
            ProductionVmParentParkStageAdmissionCause as Cause,
            ProductionVmParentParkStageFailure as Failure,
        };
        let retained = self.body.as_ref();
        Failure::Admission {
            first: retained.as_ref().map(|failure| match &failure.first {
                StageAdmissionCause::Node(first) => Cause::Node(first),
                StageAdmissionCause::Owner(first) => Cause::Owner(first.failure()),
            }),
            original_after: retained
                .as_ref()
                .and_then(|failure| failure.original_after.as_ref()),
        }
    }

    fn allocation_bytes() -> Result<u64, HostServiceError> {
        let bytes = std::mem::size_of::<Option<StageAdmissionFailureData>>()
            .checked_add(std::mem::size_of::<StageAdmissionFailureData>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| bytes.checked_add(HostServiceLease::metadata_bytes()))
            .ok_or(HostServiceError::InvalidContract)?;
        Ok(bytes)
    }

    fn prepare(services: &HostServiceAllocator) -> Result<Self, HostServiceError> {
        let resources = services.reserve_resources(0, 0, Self::allocation_bytes()?)?;
        let body = Box::new(None);
        Ok(Self {
            body,
            _resources: resources,
        })
    }

    fn refuse(
        mut self,
        first: StageAdmissionCause,
        original_after: Option<HostSupervisionError>,
    ) -> StagePrepareError {
        *self.body = Some(StageAdmissionFailureData {
            first,
            original_after,
        });
        StagePrepareError::Admission(self)
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
impl std::fmt::Debug for PreparedStageAdmissionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.body, formatter)
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
impl std::fmt::Display for PreparedStageAdmissionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.body.as_ref() {
            Some(failure) => std::fmt::Display::fmt(failure, formatter),
            None => formatter.write_str("configured stage admission is incomplete"),
        }
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
impl std::error::Error for PreparedStageAdmissionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.body.as_ref() {
            Some(failure) => Some(&failure.first),
            None => None,
        }
    }
}

impl ConfiguredParkDrainRegistration {
    /// Pairs the existing registration with its authenticated attempt context.
    ///
    /// # Errors
    /// Refuses a terminal original or a different daemon epoch, owner or
    /// operation supervisor before publishing the companion.
    pub(super) fn from_assignment(
        registration: Arc<AdmittedRamRegistrationFactory>,
        context: &AttemptExecutionContext,
    ) -> Result<Self, HostRamAdmissionError> {
        registration.supervisor.verify_original_live()?;
        if context.host_daemon_epoch() != registration.daemon_epoch
            || context.host_ram_owner_id() != Some(registration.owner_id)
            || context.host_operation_supervisor() != Some(&registration.supervisor)
        {
            return Err(HostRamAdmissionError::contract(
                "park issuer differs from the admitted assignment",
            ));
        }
        Ok(Self {
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            registration,
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            cancellation: context.cancellation().clone(),
        })
    }

    /// Issues the retained family stage for the installed prepared source and process owner.
    ///
    /// # Errors
    /// Refuses a missing or occupied family, stale parent or containing owner,
    /// exhausted control admission, or terminal original or Quiescence. Typed
    /// admission causes and independent postcuts remain in their prepaid owners.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn prepare_stage_for_source<G>(
        &self,
        node_name: &str,
        node: &QemuNodeSetPreparedHotForkSource<'_>,
        owner: &mut QemuAttemptGenerationResourceOwner<G>,
    ) -> Result<ConfiguredStageOperation, StagePrepareError>
    where
        G: QemuAttemptProcessResourceGuard,
    {
        let mut prepare = || -> Result<_, StageEarlyRefusal> {
            self.registration.supervisor.verify_original_live()?;
            let mut world = try_issuer_world(&self.registration.world)?;
            let world = world.as_mut().ok_or(StageEarlyRefusal::Invariant(
                "park issuer world is unconfigured",
            ))?;
            let index = world
                .shapes
                .iter()
                .position(|shape| shape.node == node_name)
                .ok_or(StageEarlyRefusal::Invariant(
                    "park node is absent from its world",
                ))?;
            let family = world
                .families
                .get_mut(index)
                .ok_or(StageEarlyRefusal::Invariant("park family is absent"))?;
            let parent = family.initial_target().ok_or(StageEarlyRefusal::Invariant(
                "park family has no issued parent",
            ))?;
            let services = world
                .services
                .get(node_name)
                .ok_or(StageEarlyRefusal::Invariant(
                    "park family service owner is absent",
                ))?;
            let failure = PreparedStageAdmissionFailure::prepare(services)?;
            if let Err(source) = node.verify_original_park_parent(&parent) {
                return Ok(Err(failure.refuse(
                    StageAdmissionCause::Node(source),
                    self.registration.supervisor.verify_original_live().err(),
                )));
            }
            let arena = NEXT_ARENA_GENERATION
                .fetch_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |value| value.checked_add(1),
                )
                .map_err(|_| StageEarlyRefusal::Invariant("park arena generation exhausted"))?;
            match owner.with_process_stage_contract(&self.cancellation, |contract| {
                family.prepare_staged(parent, arena, services, contract)
            }) {
                Ok(result) => {
                    drop(failure);
                    Ok(result)
                }
                Err(source) => Ok(Err(failure.refuse(
                    StageAdmissionCause::Owner(source),
                    self.registration.supervisor.verify_original_live().err(),
                ))),
            }
        };
        prepare().map_err(|source| StagePrepareError::Before {
            source,
            original_after: self.registration.supervisor.verify_original_live().err(),
        })?
    }

    /// Revalidates the same retained stage through an owning relinquishment disposition.
    ///
    /// # Errors
    /// Returns the owning disposition on stale issuer, parent, process contract,
    /// contention, or either actual original refusal. Its typed first cause and
    /// independent phase and family postcuts stay in the same prepaid phase body.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn reborrow_stage_for_source<G>(
        &self,
        node_name: &str,
        source: &QemuNodeSetPreparedHotForkSource<'_>,
        owner: &mut QemuAttemptGenerationResourceOwner<G>,
        disposition: crate::qemu_lifecycle_launcher::OriginalParkDrainDisposition,
    ) -> Result<
        crate::qemu_lifecycle_launcher::OriginalParkDrainDisposition,
        crate::qemu_lifecycle_launcher::OriginalParkDrainDisposition,
    >
    where
        G: QemuAttemptProcessResourceGuard,
    {
        disposition
            .handoff_stage(|stage| {
                let mut verify = || -> Result<(), StageReborrowRefusal> {
                    self.registration
                        .supervisor
                        .verify_original_live()
                        .map_err(StageEarlyRefusal::Original)?;
                    let world = try_issuer_world(&self.registration.world)?;
                    let world = world.as_ref().ok_or(StageEarlyRefusal::Invariant(
                        "park issuer world is unconfigured",
                    ))?;
                    let index = world
                        .shapes
                        .iter()
                        .position(|shape| shape.node == node_name)
                        .ok_or(StageEarlyRefusal::Invariant(
                            "park node is absent from its world",
                        ))?;
                    let family = world
                        .families
                        .get(index)
                        .ok_or(StageEarlyRefusal::Invariant("park family is absent"))?;
                    family.verify_staged(&stage)?;
                    stage.verify_source_parent(source)?;
                    owner.with_process_stage_contract(&self.cancellation, |contract| {
                        stage.verify_process_contract(contract)
                    })??;
                    Ok(())
                };
                let outcome = verify().map_err(|first| stage.reborrow_refusal(first));
                (stage, outcome)
            })
            .map(|(disposition, ())| disposition)
    }
}

// A live original cannot wait for another registry owner. This borrow ends
// before any Pause, native command or callback-runtime lock is entered.
#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
fn try_issuer_world<T>(
    world: &std::sync::Mutex<T>,
) -> Result<std::sync::MutexGuard<'_, T>, StageEarlyRefusal> {
    world.try_lock().map_err(|error| match error {
        std::sync::TryLockError::WouldBlock => StageEarlyRefusal::IssuerBusy,
        std::sync::TryLockError::Poisoned(_) => StageEarlyRefusal::IssuerPoisoned,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_park_issuer_contention_refuses_without_waiting_or_changing_record() {
        let world = std::sync::Mutex::new(17_u64);
        let held = world.lock().unwrap();

        let refused = try_issuer_world(&world);

        assert!(matches!(refused, Err(StageEarlyRefusal::IssuerBusy)));
        assert_eq!(*held, 17);
        drop(refused);
        drop(held);
        assert_eq!(*try_issuer_world(&world).unwrap(), 17);
    }

    #[test]
    fn parent_park_issuer_poison_preserves_the_uncertain_record() {
        let world = std::sync::Mutex::new(23_u64);
        let panic = std::panic::catch_unwind(|| {
            let _held = world.lock().unwrap();
            panic!("fixture poisons actual issuer lock");
        });
        assert!(panic.is_err());

        let refused = try_issuer_world(&world);

        assert!(matches!(refused, Err(StageEarlyRefusal::IssuerPoisoned)));
        drop(refused);
        assert!(world.is_poisoned());
        assert_eq!(*world.lock().unwrap_err().into_inner(), 23);
    }

    #[test]
    fn prepared_stage_admission_keeps_selected_body_credit_through_error_drop() {
        let bytes = PreparedStageAdmissionFailure::allocation_bytes().expect("body geometry");
        let services = HostServiceAllocator::new(1, 1, bytes).expect("selected body capacity");
        let prepared = PreparedStageAdmissionFailure::prepare(&services).expect("prepaid body");

        let failure = prepared.refuse(
            StageAdmissionCause::Owner(ProcessStageContractRefusal::NotCurrent),
            Some(HostSupervisionError::Unavailable),
        );

        assert!(matches!(
            services.reserve_resources(0, 0, 1),
            Err(HostServiceError::CapacityExhausted)
        ));
        let StagePrepareError::Admission(owner) = &failure else {
            panic!("same prepared owner");
        };
        let data = owner.body.as_ref().as_ref().expect("typed failure data");
        assert!(matches!(
            data.first,
            StageAdmissionCause::Owner(ProcessStageContractRefusal::NotCurrent)
        ));
        assert_eq!(data.original_after, Some(HostSupervisionError::Unavailable));
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        {
            use crucible_api::{
                ProductionVmParentParkStageAdmissionCause as Cause,
                ProductionVmParentParkStageFailure as Failure,
                ProductionVmParentParkStageOwnerCause as Owner,
            };
            let Failure::Admission {
                first: Some(Cause::Owner(Owner::NotCurrent)),
                original_after: Some(post),
            } = owner.failure()
            else {
                panic!("prepaid admission first and post lost their typed carrier");
            };
            assert!(std::ptr::eq(post, data.original_after.as_ref().unwrap()));
            assert!(matches!(
                services.reserve_resources(0, 0, 1),
                Err(HostServiceError::CapacityExhausted)
            ));
        }
        drop(failure);
        assert!(services.reserve_resources(0, 0, bytes).is_ok());
    }
}
