//! Selects genuine Start or Maintenance R stages for shared fixed Root inputs.
//!
//! Both variants retain their own actual financial/native purpose. The common
//! credential and verifier engine accepts neither callbacks nor a supplied
//! role, payer or accepted-Start surrogate.

use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::normal_root::{NormalRootStartupErrorV1, RootHostLaunchStageReceivingV1,
    RootMaintenanceStorageStageReceivingV2};
use crate::policy_compiler::provisioning_current::ownership_trust::RootOwnershipTrustReceivingV2;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ResourceInputsPurposeV2 { Start, MaintenanceStorage }

pub(super) enum ResourceInputsReceivingV2<'held, 'flight, 'startup> {
    Start(&'held mut RootHostLaunchStageReceivingV1<'flight, 'startup>),
    MaintenanceStorage(&'held mut RootMaintenanceStorageStageReceivingV2<'flight, 'startup>),
}

impl ResourceInputsReceivingV2<'_, '_, '_> {
    pub(super) fn purpose_v2(&self) -> ResourceInputsPurposeV2 {
        match self {
            Self::Start(_) => ResourceInputsPurposeV2::Start,
            Self::MaintenanceStorage(_) => ResourceInputsPurposeV2::MaintenanceStorage,
        }
    }

    pub(super) fn enrolled_node_v2(&self) -> Result<[u8; 16], NormalRootStartupErrorV1> {
        match self {
            Self::Start(stage) => stage.enrolled_node_v1(),
            Self::MaintenanceStorage(stage) => stage.enrolled_node_v1(),
        }
    }

    pub(super) fn admit_fixed_once_v2(&mut self, demand: RootContinuationDemandV1)
        -> Result<(), NormalRootStartupErrorV1>
    {
        match self {
            Self::Start(stage) => stage.admit_host_trust_fixed_once_v1(demand),
            Self::MaintenanceStorage(stage) => stage.admit_maintenance_trust_fixed_once_v2(demand),
        }
    }

    pub(super) fn admit_request_typed_once_v2(&mut self, demand: RootContinuationDemandV1)
        -> Result<(), NormalRootStartupErrorV1>
    {
        match self {
            Self::Start(stage) => stage.admit_host_request_typed_once_v1(demand),
            Self::MaintenanceStorage(stage) => stage.admit_maintenance_request_typed_once_v2(demand),
        }
    }
}

impl<'flight, 'startup> ResourceInputsReceivingV2<'_, 'flight, 'startup> {
    pub(super) fn ownership_trust_v2(&mut self)
        -> RootOwnershipTrustReceivingV2<'_, 'flight, 'startup>
    {
        match self {
            Self::Start(stage) => RootOwnershipTrustReceivingV2::Host(&mut **stage),
            Self::MaintenanceStorage(stage) => RootOwnershipTrustReceivingV2::MaintenanceStorage(&mut **stage),
        }
    }
}
