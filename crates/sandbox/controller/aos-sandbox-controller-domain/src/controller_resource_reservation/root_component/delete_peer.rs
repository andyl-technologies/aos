//! Pays one purpose-bound Controller comparison and its four Root service posts.
//!
//! This resident capsule belongs to one actual accepted flight. It never uses
//! the InitialController startup slot, refunds traffic, or establishes Delete
//! admission. All four native post destinations are armed before primary work.

mod stages;
pub(crate) use aos_sandbox_policy::native::RootExecutionNoApplyReadPhaseV2;

pub(crate) use stages::{RootStopCleanupStageV1, RootMaintenanceStorageStageV2, RootContinuationDemandV1, RootContinuationStageV1, RootContinuationStagesV1};

use std::error::Error as StdError;

pub(crate) use aos_sandbox_broker::receiving::RootPurposePeerPostV1;
use aos_sandbox_broker::receiving::{RootPurposePeerPostsOriginalV1, RootPurposePostErrorV1};
use aos_sandbox_model::{
    ResourceVector,
    component_receiving::{operation_traffic_demand_v1, without_operation_traffic_v1},
};

use super::{ResourceReservationErrorV1, RootReceivingOriginalV1};
use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};

mod sealed {
    pub trait Sealed {}
}

/// Supplies only a selected purpose's internal continuation DATA custody.
pub(crate) trait RootPeerStageStateV1: Default {
    fn failure(&self) -> Option<&(dyn StdError + 'static)>;
}

impl RootPeerStageStateV1 for () {
    fn failure(&self) -> Option<&(dyn StdError + 'static)> { None }
}

/// Seals the finite internal purpose set for the shared native DATA engine.
pub(crate) trait RootPeerPurposeV1: sealed::Sealed + Default {
    type Stages: RootPeerStageStateV1;
    const APPLY_INPUT_REQUIRED: bool;
    const HOST_INPUT_REQUIRED: bool = false;
    const MAINTENANCE_STORAGE_REQUIRED: bool = false;
    const FINALITY_RECOVER_ONLY: bool = false;
    const START_ASSIGNMENT_INPUTS_ONLY: bool = false;
    const DELETE_INPUT_REQUIRED: bool = false;
    const EXECUTION_NO_APPLY_ONLY: bool = false;
    const STOP_CLEANUP_ONLY: bool = false;
}

macro_rules! root_peer_purpose {
    ($name:ident, $stages:ty, $apply:expr) => {
        root_peer_purpose!($name, $stages, $apply, false);
    };
    ($name:ident, $stages:ty, $apply:expr, $host:expr) => {
        #[derive(Default)]
        pub(crate) struct $name;

        impl sealed::Sealed for $name {}
        impl RootPeerPurposeV1 for $name {
            type Stages = $stages;
            const APPLY_INPUT_REQUIRED: bool = $apply;
            const HOST_INPUT_REQUIRED: bool = $host;
        }
    };
}

#[derive(Default)]
pub(crate) struct DeleteRootPeerPurposeV1;

impl sealed::Sealed for DeleteRootPeerPurposeV1 {}

impl RootPeerPurposeV1 for DeleteRootPeerPurposeV1 {
    type Stages = RootContinuationStagesV1;
    const APPLY_INPUT_REQUIRED: bool = false;
    const DELETE_INPUT_REQUIRED: bool = true;
}

root_peer_purpose!(EnvironmentRootPeerPurposeV1, RootContinuationStagesV1, false);
root_peer_purpose!(ApplyRootPeerPurposeV1, RootContinuationStagesV1, true);
root_peer_purpose!(HostLaunchRootPeerPurposeV1, RootContinuationStagesV1, false, true);

/// Binds only the actual current Recover/Source/Host Stop cleanup programme.
#[derive(Default)]
pub(crate) struct StopCleanupRootPeerPurposeV1;

impl sealed::Sealed for StopCleanupRootPeerPurposeV1 {}

impl RootPeerPurposeV1 for StopCleanupRootPeerPurposeV1 {
    type Stages = RootContinuationStagesV1;
    const APPLY_INPUT_REQUIRED: bool = false;
    const STOP_CLEANUP_ONLY: bool = true;
}

/// Owns only current Maintenance Storage31 and its full final proof.
#[derive(Default)]
pub(crate) struct MaintenanceStorageRootPeerPurposeV2;

impl sealed::Sealed for MaintenanceStorageRootPeerPurposeV2 {}

impl RootPeerPurposeV1 for MaintenanceStorageRootPeerPurposeV2 {
    type Stages = RootContinuationStagesV1;
    const APPLY_INPUT_REQUIRED: bool = false;
    const MAINTENANCE_STORAGE_REQUIRED: bool = true;
}

#[derive(Default)]
pub(crate) struct FinalityRecoverRootPeerPurposeV1;

impl sealed::Sealed for FinalityRecoverRootPeerPurposeV1 {}

impl RootPeerPurposeV1 for FinalityRecoverRootPeerPurposeV1 {
    type Stages = RootContinuationStagesV1;
    const APPLY_INPUT_REQUIRED: bool = false;
    const FINALITY_RECOVER_ONLY: bool = true;
}

#[derive(Default)]
pub(crate) struct StartAssignmentInputsRootPeerPurposeV2;

impl sealed::Sealed for StartAssignmentInputsRootPeerPurposeV2 {}

impl RootPeerPurposeV1 for StartAssignmentInputsRootPeerPurposeV2 {
    type Stages = RootContinuationStagesV1;
    const APPLY_INPUT_REQUIRED: bool = false;
    const START_ASSIGNMENT_INPUTS_ONLY: bool = true;
}

/// Binds only Execution NoApply native reads to its own actual Root peer.
#[derive(Default)]
pub(crate) struct ExecutionNoApplyRootPeerPurposeV2;

impl sealed::Sealed for ExecutionNoApplyRootPeerPurposeV2 {}

impl RootPeerPurposeV1 for ExecutionNoApplyRootPeerPurposeV2 {
    type Stages = RootContinuationStagesV1;
    const APPLY_INPUT_REQUIRED: bool = false;
    const EXECUTION_NO_APPLY_ONLY: bool = true;
}

#[derive(Default)]
pub(crate) struct RootPurposePeerAdmissionV1<K: RootPeerPurposeV1> {
    entered: bool,
    permit: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    traffic: Option<Result<(), ResourceReservationErrorV1>>,
    posts: RootPurposePeerPostsOriginalV1<Error>,
    kind: std::marker::PhantomData<K>,
    stages: K::Stages,
}

impl RootPurposePostErrorV1 for Error {
    fn closed() -> Self {
        Self::Service
    }

    fn from_observation(error: aos_sandbox_broker::receiving::RootObservationErrorV1) -> Self {
        error.into()
    }
}

impl<K: RootPeerPurposeV1> RootPurposePeerAdmissionV1<K> {
    pub(crate) fn continuation_failure_v1(&self) -> Option<&(dyn StdError + 'static)> {
        self.stages.failure()
    }

    pub(crate) fn require_armed_v1(&self) -> Result<(), Error> {
        if matches!(self.permit, Some(Ok(_)))
            && matches!(self.traffic, Some(Ok(())))
            && self.posts.require_armed_v1().is_ok()
        {
            Ok(())
        } else {
            Err(Error::Service)
        }
    }

    pub(crate) fn is_positive_v1(&self, purpose: RootPurposePeerPostV1) -> bool {
        self.posts.is_positive_v1(purpose)
    }

    pub(crate) fn admission_failure_v1(&self) -> Option<&(dyn StdError + 'static)> {
        self.permit
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.traffic
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.posts.arming_failure_v1().map(|cause| cause as _))
    }

    pub(crate) fn post_failure_v1(
        &self,
        purpose: RootPurposePeerPostV1,
    ) -> Option<&(dyn StdError + 'static)> {
        self.posts.post_failure_v1(purpose)
    }

    pub(crate) fn settle_admission_positive_v1(&mut self) -> Result<(), Error> {
        self.posts.settle_admission_positive_once_v1()
    }

    pub(crate) fn settle_final_positive_v1(&mut self) -> Result<(), Error> {
        self.posts.settle_final_positive_once_v1()
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn arm_purpose_peer_once_v1<K: RootPeerPurposeV1>(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        admission: &mut RootPurposePeerAdmissionV1<K>,
    ) -> Result<(), Error> {
        if K::EXECUTION_NO_APPLY_ONLY || admission.entered {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        admission.entered = true;
        let returned = (|| {
            self.require_active_policy_flight_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let base = self
                .policy_listener_prefix()
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let demand =
                crate::normal_root::RootPurposeControllerPeerReceivingV1::<K>::fixed_demand_v1()?;
            let complete = base.checked_add(without_operation_traffic_v1(demand))?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(&mut admission.permit, returned);
        if !matches!(admission.permit, Some(Ok(_))) {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let returned = crate::normal_root::RootPurposeControllerPeerReceivingV1::<K>::fixed_demand_v1()
            .and_then(|demand| self.debit_observer_traffic_v1(operation_traffic_demand_v1(demand)));
        self.native_refusal_original_v1().park_empty_result_v1(&mut admission.traffic, returned);
        if !matches!(admission.traffic, Some(Ok(()))) {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        // Arm all four once-only debts before any primary comparison. A later
        // arm refusal leaves each earlier actual destination resident.
        admission.posts.arm_once_v1(
            &self.activation,
            startup.native_startup_original_v1(),
        )?;
        admission.require_armed_v1()
    }

    pub(crate) fn observe_purpose_peer_post_once_v1<K: RootPeerPurposeV1>(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        admission: &mut RootPurposePeerAdmissionV1<K>,
        purpose: RootPurposePeerPostV1,
    ) -> Result<(), Error> {
        admission.posts.observe_once_v1(
            &mut self.activation,
            startup.native_startup_original_v1(),
            purpose,
        )
    }
}
