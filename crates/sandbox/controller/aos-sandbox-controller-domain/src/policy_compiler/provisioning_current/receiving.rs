//! Selects only actual opaque Environment, Apply or HostLaunch R borrowers.

use aos_sandbox_model::ResourceVector;
use aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1;
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::normal_root::{RootMaintenanceStorageStageReceivingV2, RootDeleteCacheStageReceivingV2, RootApplyStageReceivingV1, RootHostLaunchStageReceivingV1, RootEnvironmentStageReceivingV1,
    NormalRootStartupErrorV1 as Error};

pub(super) enum ReceivingV1<'flight, 'startup> {
    Delete(RootDeleteCacheStageReceivingV2<'flight, 'startup>),
    Environment(RootEnvironmentStageReceivingV1<'flight, 'startup>),
    Apply(RootApplyStageReceivingV1<'flight, 'startup>),
    HostLaunch(RootHostLaunchStageReceivingV1<'flight, 'startup>),
    MaintenanceStorage(RootMaintenanceStorageStageReceivingV2<'flight, 'startup>),
}

macro_rules! stage {
    ($method:ident) => {
        pub(super) fn $method(&mut self, demand: ResourceVector) -> Result<(), Error> {
            match self {
                Self::Delete(actual) => actual.$method(RootContinuationDemandV1::from_demand_v1(demand)),
                Self::Environment(actual) => actual.$method(RootContinuationDemandV1::from_demand_v1(demand)),
                Self::Apply(actual) => actual.$method(RootContinuationDemandV1::from_demand_v1(demand)),
                Self::HostLaunch(actual) => actual.$method(RootContinuationDemandV1::from_demand_v1(demand)),
                Self::MaintenanceStorage(actual) => actual.$method(RootContinuationDemandV1::from_demand_v1(demand)),
            }
        }
    };
}
macro_rules! cache_stage {
    ($method:ident) => {
        pub(super) fn $method(&mut self, role: CacheJournalRecipeRoleV1, demand: ResourceVector) -> Result<(), Error> {
            match self {
                Self::Delete(actual) => actual.$method(role, RootContinuationDemandV1::from_demand_v1(demand)),
                Self::Environment(actual) => actual.$method(role, RootContinuationDemandV1::from_demand_v1(demand)),
                Self::Apply(actual) => actual.$method(role, RootContinuationDemandV1::from_demand_v1(demand)),
                Self::HostLaunch(actual) => actual.$method(role, RootContinuationDemandV1::from_demand_v1(demand)),
                Self::MaintenanceStorage(actual) => actual.$method(role, RootContinuationDemandV1::from_demand_v1(demand)),
            }
        }
    };
}

impl ReceivingV1<'_, '_> {
    pub(super) fn controller_identity_v1(&self) -> (u32, u32) {
        match self { Self::Delete(actual) => actual.controller_identity_v1(), Self::Environment(actual) => actual.controller_identity_v1(), Self::Apply(actual) => actual.controller_identity_v1(), Self::HostLaunch(actual) => actual.controller_identity_v1(), Self::MaintenanceStorage(actual) => actual.controller_identity_v1() }
    }

    stage!(admit_source_fixed_once_v1);
    stage!(admit_source_native_once_v1);
    stage!(admit_source_semantic_once_v1);
    stage!(admit_source_tree_models_once_v1);
    stage!(admit_cache_models_once_v1);
    stage!(admit_cache_objects_fixed_once_v1);
    stage!(admit_cache_objects_native_once_v1);
    cache_stage!(admit_cache_fixed_once_v1);
    cache_stage!(admit_cache_native_once_v1);
    cache_stage!(admit_cache_semantic_once_v1);
}
