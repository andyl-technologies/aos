//! Requests a real isolated actor return while an authenticated page is pending.

use super::*;
use crucible_protocol::ram_control::{
    RamControlDisposition, RamControlFaultActorAction, RamControlFaultActorFailure,
    RamControlFaultActorReport,
};
use crucible_qemu::ram_control::RamControlRegistrar;

pub(super) const ENTITLEMENT: [u8; 32] = [0xe1; 32];

pub(super) struct ActorExitProbe {
    registry: crate::HostOperationalRegistry,
    target: HostRamTarget,
    generation: u64,
}

impl ActorExitProbe {
    pub(super) fn new(registry: crate::HostOperationalRegistry, target: HostRamTarget) -> Self {
        let report = registry
            .fault_actor_status(target)
            .expect("independent authenticated fault actor observation")
            .expect("actual admitted fault actor");
        assert!(report.failure.is_none());
        assert!(!report.exit_requested);
        assert!(!report.membership_released);
        Self {
            registry,
            target,
            generation: report.worker_generation,
        }
    }

    pub(super) fn request_before_response(&self) -> Result<(), QemuRamSourceError> {
        let wrong_entitlement = self
            .registry
            .test_fault_actor(
                self.target,
                [0xe2; 32],
                self.generation,
                RamControlFaultActorAction::RequestExit,
            )
            .map_err(control_failure)?;
        assert_eq!(
            wrong_entitlement.disposition,
            RamControlDisposition::Unsupported
        );
        let unchanged = wrong_entitlement
            .fault_actor
            .expect("actual unchanged actor");
        assert!(!unchanged.exit_requested);
        assert!(unchanged.failure.is_none());
        let wrong_generation = self
            .registry
            .test_fault_actor(
                self.target,
                ENTITLEMENT,
                self.generation
                    .checked_add(1)
                    .expect("actual generation has a stale successor"),
                RamControlFaultActorAction::RequestExit,
            )
            .map_err(control_failure)?;
        assert_eq!(
            wrong_generation.disposition,
            RamControlDisposition::NotCurrent
        );
        assert_eq!(wrong_generation.fault_actor, Some(unchanged));
        let accepted = self
            .registry
            .test_fault_actor(
                self.target,
                ENTITLEMENT,
                self.generation,
                RamControlFaultActorAction::RequestExit,
            )
            .map_err(control_failure)?;
        assert_eq!(accepted.disposition, RamControlDisposition::Accepted);
        let queued = accepted.fault_actor.expect("actual request observation");
        assert!(queued.exit_requested);
        // The request handler does not synthesize a terminal or release receipt.
        assert!(queued.failure.is_none());
        assert!(!queued.membership_released);
        Ok(())
    }

    pub(super) fn verify_actual_return(
        &self,
        supervisor: &crucible_linux_resource::host_supervision::HostOperationSupervisor,
    ) -> RamControlFaultActorReport {
        let guard = supervisor
            .begin(crucible_linux_resource::host_supervision::HostOperationClass::Cleanup)
            .expect("same original Service cap bounds role observation");
        let report = loop {
            let remaining = guard
                .wait_slice()
                .expect("original bounded actor disposition wait");
            let report = self
                .registry
                .fault_actor_status(self.target)
                .expect("role2 controller remains alive after isolated role1 failure")
                .expect("retained original actor lifetime");
            assert_eq!(report.worker_generation, self.generation);
            if report.membership_released {
                break report;
            }
            std::thread::sleep(remaining.min(Duration::from_millis(1)));
        };
        assert!(report.exit_requested);
        assert_eq!(
            report.failure,
            Some(RamControlFaultActorFailure::RequestedExit)
        );
        guard
            .complete()
            .expect("original cap did not expire during disposition");
        report
    }
}

pub(super) fn original_actor_cause(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(cause) = error.downcast_ref::<crucible_qemu::QemuNativeFaultActorFailure>() {
            return cause.report.failure == Some(RamControlFaultActorFailure::RequestedExit);
        }
        current = error.source();
    }
    false
}

fn control_failure(source: crucible_protocol::ram_control::RamControlError) -> QemuRamSourceError {
    QemuRamSourceError::BackingFailure {
        kind: crucible::BackendOperationalFailureKind::Unavailable,
        source: crucible::BackendOperationalCause::new(source),
    }
}
