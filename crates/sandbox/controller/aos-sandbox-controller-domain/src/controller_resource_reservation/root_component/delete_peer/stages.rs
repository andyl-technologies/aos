//! Admits finite continuation stages against the same active Root flight.
//!
//! Stage demands are derived by concrete retained readers before their work.
//! Resident requirements accumulate conservatively; consumable traffic is
//! charged once for each reached stage and never reset by positive disposal.

use std::error::Error as StdError;

use aos_sandbox_model::{
    ResourceVector,
    component_receiving::{operation_traffic_demand_v1, without_operation_traffic_v1},
};
use aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1;

use super::{RootPeerPurposeV1, RootPurposePeerAdmissionV1, RootReceivingOriginalV1};
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::normal_root::NormalRootStartupErrorV1 as Error;

// Host61..81 is the coordinated finite Host provider; Recover starts82.
const STAGES: usize = 307;

/// Names the actual current Stop recovery issuer's finite paid programme.
#[derive(Clone, Copy)]
pub(crate) enum RootStopCleanupStageV1 {
    Trust,
    ControllerFixed,
    ControllerNative,
    ControllerSemantic,
    HostFixed,
    HostNative,
    HostSemantic,
    SourceFixed,
    SourceNative,
    SourceSemantic,
    Models,
    Plan,
    UnsignedReply,
    ChildDecision,
    FinalHostFixed,
    FinalHostNative,
    FinalHostSemantic,
    FinalModels,
    Receipt,
}

impl RootStopCleanupStageV1 {
    fn index_v1(self) -> usize {
        288 + match self {
            Self::Trust => 0,
            Self::ControllerFixed => 1,
            Self::ControllerNative => 2,
            Self::ControllerSemantic => 3,
            Self::HostFixed => 4,
            Self::HostNative => 5,
            Self::HostSemantic => 6,
            Self::SourceFixed => 7,
            Self::SourceNative => 8,
            Self::SourceSemantic => 9,
            Self::Models => 10,
            Self::Plan => 11,
            Self::UnsignedReply => 12,
            Self::ChildDecision => 13,
            Self::FinalHostFixed => 14,
            Self::FinalHostNative => 15,
            Self::FinalHostSemantic => 16,
            Self::FinalModels => 17,
            Self::Receipt => 18,
        }
    }

    fn prerequisites_positive_v1(self, stages: &RootContinuationStagesV1) -> bool {
        match self {
            Self::Trust => true,
            _ => stages.positive(self.index_v1() - 1),
        }
    }
}

#[cfg(test)]
mod stop_cleanup_stage_tests {
    use super::*;

    #[test]
    fn receipt_is_last_and_requires_every_actual_final_host_frontier() {
        use RootStopCleanupStageV1 as P;
        let programme = [P::Trust, P::ControllerFixed, P::ControllerNative, P::ControllerSemantic,
            P::HostFixed, P::HostNative, P::HostSemantic, P::SourceFixed, P::SourceNative,
            P::SourceSemantic, P::Models, P::Plan, P::UnsignedReply, P::ChildDecision,
            P::FinalHostFixed, P::FinalHostNative, P::FinalHostSemantic, P::FinalModels, P::Receipt];
        let mut stages = RootContinuationStagesV1::default();
        assert_eq!(programme.map(P::index_v1), std::array::from_fn::<_, 19, _>(|i| 288 + i));

        for phase in programme {
            if !matches!(phase, P::Receipt) { assert!(!P::Receipt.prerequisites_positive_v1(&stages)); }
            assert!(phase.prerequisites_positive_v1(&stages));
            stages.requirements[phase.index_v1()] = Some(Ok(ResourceVector::ZERO));
            stages.traffic[phase.index_v1()] = Some(Ok(()));
        }

        assert_eq!(P::Receipt.index_v1() + 1, STAGES);
        stages.traffic[P::FinalModels.index_v1()] = Some(Err(ResourceReservationErrorV1::Conflict));
        assert!(!P::Receipt.prerequisites_positive_v1(&stages));
    }
}

/// Carries a concrete reader's bounded representation and native schedule DATA.
///
/// Construction is internal to Root semantic readers; this value does not
/// construct a receiver, establish acceptance, or grant an effect.
pub(crate) struct RootContinuationDemandV1(ResourceVector, ResourceVector);

impl RootContinuationDemandV1 {
    pub(crate) fn from_demand_v1(demand: ResourceVector) -> Self {
        Self(demand, ResourceVector::ZERO)
    }

    /// Moves both existing comparison-only demand components without admission.
    pub(crate) fn into_parts_data_v1(self) -> (ResourceVector, ResourceVector) {
        (self.0, self.1)
    }

    // The concrete D receiver derives this baseline from its genuine still-held
    // owners. Arithmetic stays inside the sole actual retained stage engine.
    pub(crate) fn with_resident_baseline_v2(mut self, baseline: ResourceVector) -> Self {
        self.1 = baseline;
        self
    }
}

/// Names only the reached finite current Maintenance Storage31 programme.
///
/// The indices belong to its distinct actual R purpose; shared C/Source/Cache
/// readers continue to use the existing common destinations 0..29.
#[derive(Clone, Copy)]
pub(crate) enum RootMaintenanceStorageStageV2 {
    Query,
    Subject,
    TrustFixed,
    TrustTyped,
    CurrentAssignment,
    CurrentInventory,
    LiveOwnership,
    RequestTyped,
    Plan,
    FinalProof,
    FinalControllerFixed,
    FinalControllerNative,
    FinalControllerSemantic,
    FinalSessionFixed,
    FinalSessionNative,
    FinalSessionSemantic,
    FinalSourceFixed,
    FinalSourceNative,
    FinalSourceSemantic,
    FinalModels,
    FinalResponse,
}

impl RootMaintenanceStorageStageV2 {
    fn index_v2(self) -> usize {
        match self {
            Self::Query => 197,
            Self::Subject => 198,
            Self::TrustFixed => 199,
            Self::TrustTyped => 200,
            Self::CurrentAssignment => 201,
            Self::CurrentInventory => 202,
            Self::LiveOwnership => 203,
            Self::RequestTyped => 204,
            Self::Plan => 205,
            Self::FinalProof => 206,
            Self::FinalControllerFixed => 207,
            Self::FinalControllerNative => 208,
            Self::FinalControllerSemantic => 209,
            Self::FinalSessionFixed => 210,
            Self::FinalSessionNative => 211,
            Self::FinalSessionSemantic => 212,
            Self::FinalSourceFixed => 213,
            Self::FinalSourceNative => 214,
            Self::FinalSourceSemantic => 215,
            Self::FinalModels => 216,
            Self::FinalResponse => 217,
        }
    }

    fn prerequisites_positive_v2(self, stages: &RootContinuationStagesV1) -> bool {
        match self {
            Self::Query => true,
            Self::Subject => stages.positive(197),
            Self::TrustFixed => stages.positive(198),
            Self::TrustTyped => stages.positive(199),
            Self::CurrentAssignment => [200, 2, 8].into_iter().all(|index| stages.positive(index)),
            Self::CurrentInventory => stages.positive(201) && stages.positive(5),
            Self::LiveOwnership => stages.positive(201) && stages.positive(200),
            Self::RequestTyped => stages.positive(202) && stages.positive(203),
            Self::Plan => stages.positive(204) && stages.positive(28),
            Self::FinalProof => stages.positive(205) && stages.positive(29),
            Self::FinalControllerFixed | Self::FinalSessionFixed | Self::FinalSourceFixed => stages.positive(206),
            Self::FinalControllerNative | Self::FinalControllerSemantic
                | Self::FinalSessionNative | Self::FinalSessionSemantic
                | Self::FinalSourceNative | Self::FinalSourceSemantic => stages.positive(self.index_v2() - 1),
            Self::FinalModels => [209, 212, 215].into_iter().all(|index| stages.positive(index)),
            Self::FinalResponse => stages.positive(216),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum RootContinuationStageV1 {
    StopCleanup(RootStopCleanupStageV1),
    MaintenanceStorage(RootMaintenanceStorageStageV2),
    ControllerFixed,
    ControllerNative,
    ControllerSemantic,
    StorageFixed,
    StorageNative,
    StorageSemantic,
    SourceFixed,
    SourceNative,
    SourceSemantic,
    CacheFixed(CacheJournalRecipeRoleV1),
    CacheNative(CacheJournalRecipeRoleV1),
    CacheSemantic(CacheJournalRecipeRoleV1),
    SourceTreeModels,
    CacheModels,
    CacheObjectsFixed,
    CacheObjectsNative,
    Compiler,
    FinalResponse,
    EnvironmentArtifactFixed,
    EnvironmentArtifactNative,
    EnvironmentClosureFixed,
    EnvironmentClosureNative,
    EnvironmentEvidenceFixed,
    EnvironmentEvidenceNative,
    EnvironmentEvidencePublish,
    EnvironmentResponse,
    EnvironmentCompiler,
    EnvironmentAccepted,
    ApplyFinalProof,
    ApplyFinalControllerFixed,
    ApplyFinalControllerNative,
    ApplyFinalControllerSemantic,
    ApplyFinalStorageFixed,
    ApplyFinalStorageNative,
    ApplyFinalStorageSemantic,
    ApplyFinalSourceFixed,
    ApplyFinalSourceNative,
    ApplyFinalSourceSemantic,
    ApplyFinalResponse,
    ApplyQuery,
    ApplySubject,
    EnvironmentRequest,
    EnvironmentPolicy,
    ApplyTrustFixed,
    ApplyTrustTyped,
    ApplyBundleTyped,
    ApplyStorageInputs,
    DeleteCacheActionable,
    DeleteInitialInventory,
    DeleteGraphFixed,
    DeleteGraphObjects,
    DeleteGraphModels,
    DeleteGraphComparison,
    DeleteResourcePolicy,
    DeleteResourceTrust,
    DeleteResourceAssignment,
    DeleteResourcePreparation,
    DeleteResourceDraft,
    DeleteResourceSignature,
    DeleteResourcePolicyConfirmation,
    DeletePreparatoryApproval,
    DeletePreparationCurrent(crate::policy_compiler::delete_root::RootDeletePreparationCurrentPhaseV3),
    DeleteApplyIssuer(crate::policy_compiler::delete_root::RootDeleteApplyIssuerPhaseV3),
    DeleteNetworkIssuer(crate::policy_compiler::delete_root::RootDeleteApplyIssuerPhaseV3),
    DeleteMountIssuer(crate::policy_compiler::delete_root::RootDeleteApplyIssuerPhaseV3),
    DeleteMountSpec(crate::policy_compiler::delete_root::RootDeleteMountSpecPhaseV4),
    DeleteCleanupCurrent(crate::policy_compiler::delete_root::RootDeleteCleanupCurrentPhaseV4),
    DeleteCompletion(crate::policy_compiler::delete_root::RootDeleteCompletionPhaseV4),
    DeleteFreshFloor,
    DeleteFreshTransfer,
    DeleteFreshTransferTrust,
    DeleteFreshTransferObservation,
    DeleteFreshFrame,
    DeleteFreshSourceFixed,
    DeleteFreshSourceNative,
    DeleteFreshSourceSemantic,
    DeleteFreshCacheOverlay,
    DeleteFreshCacheFixed(CacheJournalRecipeRoleV1),
    DeleteFreshCacheNative(CacheJournalRecipeRoleV1),
    DeleteFreshCacheSemantic(CacheJournalRecipeRoleV1),
    DeleteFreshCacheModels,
    DeleteFreshCacheObjectsFixed,
    DeleteFreshCacheObjectsNative,
    DeleteFreshCacheActionable,
    DeleteFreshController(crate::policy_compiler::delete_root::RootDeleteControllerAdmissionPhaseV1),
    HostQuery,
    HostSubject,
    HostTrustFixed,
    HostTrustTyped,
    HostAcceptedStart,
    HostHistoricalCreate,
    HostFreshOwnership,
    HostRequestTyped,
    HostPlan,
    HostFinalProof,
    HostFinalControllerFixed,
    HostFinalControllerNative,
    HostFinalControllerSemantic,
    HostFinalSessionFixed,
    HostFinalSessionNative,
    HostFinalSessionSemantic,
    HostFinalSourceFixed,
    HostFinalSourceNative,
    HostFinalSourceSemantic,
    HostFinalModels,
    HostFinalResponse,
    FinalityRecoverQuery,
    FinalityRecoverTrustFixed,
    FinalityRecoverTrustTyped,
    FinalityRecoverControllerFixed,
    FinalityRecoverControllerNative,
    FinalityRecoverControllerSemantic,
    FinalityRecoverSourceFixed,
    FinalityRecoverSourceNative,
    FinalityRecoverSourceSemantic,
    FinalityRecoverSessionFixed,
    FinalityRecoverSessionNative,
    FinalityRecoverSessionSemantic,
    FinalityRecoverModels,
    FinalityRecoverResponse,
    StartAssignmentInputsQuery,
    StartAssignmentInputsSubject,
    StartAssignmentInputsPolicyFixed,
    StartAssignmentInputsPolicyTyped,
    StartAssignmentInputsControllerFixed,
    StartAssignmentInputsControllerNative,
    StartAssignmentInputsControllerSemantic,
    StartAssignmentInputsSourceFixed,
    StartAssignmentInputsSourceNative,
    StartAssignmentInputsSourceSemantic,
    StartAssignmentInputsModels,
    StartAssignmentInputsResponse,
    HostCatalogNetworkFixed,
    HostCatalogNetworkNative,
    HostCatalogNetworkSemantic,
    HostCatalogMountFixed,
    HostCatalogMountNative,
    HostCatalogMountSemantic,
    HostCatalogModels,
    MountBefore62Fixed,
    MountBefore62Native,
    MountBefore62Semantic,
}

fn cache_index(role: CacheJournalRecipeRoleV1) -> usize {
    match role {
        CacheJournalRecipeRoleV1::Bootstrap => 0,
        CacheJournalRecipeRoleV1::Hold => 1,
        CacheJournalRecipeRoleV1::State => 2,
        CacheJournalRecipeRoleV1::Authority => 3,
        CacheJournalRecipeRoleV1::Clock => 4,
    }
}

impl RootContinuationStageV1 {
    fn index(self) -> usize {
        match self {
            Self::StopCleanup(phase) => phase.index_v1(),
            Self::MaintenanceStorage(phase) => phase.index_v2(),
            Self::ControllerFixed => 0,
            Self::ControllerNative => 1,
            Self::ControllerSemantic => 2,
            Self::StorageFixed => 3,
            Self::StorageNative => 4,
            Self::StorageSemantic => 5,
            Self::SourceFixed => 6,
            Self::SourceNative => 7,
            Self::SourceSemantic => 8,
            Self::CacheFixed(role) => 9 + 3 * cache_index(role),
            Self::CacheNative(role) => 10 + 3 * cache_index(role),
            Self::CacheSemantic(role) => 11 + 3 * cache_index(role),
            Self::SourceTreeModels => 24,
            Self::CacheModels => 25,
            Self::CacheObjectsFixed => 26,
            Self::CacheObjectsNative => 27,
            Self::Compiler => 28,
            Self::FinalResponse => 29,
            Self::EnvironmentArtifactFixed => 30,
            Self::EnvironmentArtifactNative => 31,
            Self::EnvironmentClosureFixed => 32,
            Self::EnvironmentClosureNative => 33,
            Self::EnvironmentEvidenceFixed => 34,
            Self::EnvironmentEvidenceNative => 35,
            Self::EnvironmentEvidencePublish => 36,
            Self::EnvironmentResponse => 37,
            Self::EnvironmentCompiler => 38,
            Self::EnvironmentAccepted => 39,
            Self::ApplyFinalProof => 40,
            Self::ApplyFinalControllerFixed => 41,
            Self::ApplyFinalControllerNative => 42,
            Self::ApplyFinalControllerSemantic => 43,
            Self::ApplyFinalStorageFixed => 44,
            Self::ApplyFinalStorageNative => 45,
            Self::ApplyFinalStorageSemantic => 46,
            Self::ApplyFinalSourceFixed => 47,
            Self::ApplyFinalSourceNative => 48,
            Self::ApplyFinalSourceSemantic => 49,
            Self::ApplyFinalResponse => 50,
            Self::ApplyQuery => 51,
            Self::ApplySubject => 52,
            Self::EnvironmentRequest => 53,
            Self::EnvironmentPolicy => 54,
            Self::ApplyTrustFixed => 55,
            Self::ApplyTrustTyped => 56,
            Self::ApplyBundleTyped => 57,
            Self::ApplyStorageInputs => 58,
            Self::DeleteCacheActionable => 59,
            Self::DeleteInitialInventory => 60,
            Self::DeleteGraphFixed => 96,
            Self::DeleteGraphObjects => 97,
            Self::DeleteGraphModels => 98,
            Self::DeleteGraphComparison => 99,
            Self::HostQuery => 61,
            Self::HostSubject => 62,
            Self::HostTrustFixed => 63,
            Self::HostTrustTyped => 64,
            Self::HostAcceptedStart => 65,
            Self::HostHistoricalCreate => 66,
            Self::HostFreshOwnership => 67,
            Self::HostRequestTyped => 68,
            Self::HostPlan => 69,
            Self::HostFinalProof => 70,
            Self::HostFinalControllerFixed => 71,
            Self::HostFinalControllerNative => 72,
            Self::HostFinalControllerSemantic => 73,
            Self::HostFinalSessionFixed => 74,
            Self::HostFinalSessionNative => 75,
            Self::HostFinalSessionSemantic => 76,
            Self::HostFinalSourceFixed => 77,
            Self::HostFinalSourceNative => 78,
            Self::HostFinalSourceSemantic => 79,
            Self::HostFinalModels => 80,
            Self::HostFinalResponse => 81,

            Self::DeleteResourcePolicy => 159,
            Self::DeleteResourceTrust => 160,
            Self::DeleteResourceAssignment => 161,
            Self::DeleteResourcePreparation => 162,
            Self::DeleteResourceDraft => 163,
            Self::DeleteResourceSignature => 164,
            Self::DeleteResourcePolicyConfirmation => 165,
            Self::DeletePreparatoryApproval => 176,
            Self::DeletePreparationCurrent(phase) => 177 + phase.index_v3(),
            Self::DeleteApplyIssuer(phase) => 189 + phase.index_v3(),
            Self::DeleteNetworkIssuer(phase) => 227 + phase.index_v3(),
            Self::DeleteMountIssuer(phase) => 236 + phase.index_v3(),
            Self::DeleteMountSpec(phase) => 255 + phase.index_v4(),
            Self::DeleteCleanupCurrent(phase) => 244 + phase.index_v4(),
            Self::DeleteCompletion(phase) => 258 + phase.index_v4(),
            Self::DeleteFreshFloor => 146,
            Self::DeleteFreshTransfer => 143,
            Self::DeleteFreshTransferTrust => 144,
            Self::DeleteFreshTransferObservation => 145,
            Self::DeleteFreshFrame => 100,
            Self::DeleteFreshSourceFixed => 120,
            Self::DeleteFreshSourceNative => 121,
            Self::DeleteFreshSourceSemantic => 122,
            Self::DeleteFreshCacheOverlay => 123,
            Self::DeleteFreshCacheFixed(role) => 124 + 3 * cache_index(role),
            Self::DeleteFreshCacheNative(role) => 125 + 3 * cache_index(role),
            Self::DeleteFreshCacheSemantic(role) => 126 + 3 * cache_index(role),
            Self::DeleteFreshCacheModels => 139,
            Self::DeleteFreshCacheObjectsFixed => 140,
            Self::DeleteFreshCacheObjectsNative => 141,
            Self::DeleteFreshCacheActionable => 142,
            Self::DeleteFreshController(phase) => 101 + phase as usize,
            Self::FinalityRecoverQuery => 82,
            Self::FinalityRecoverTrustFixed => 83,
            Self::FinalityRecoverTrustTyped => 84,
            Self::FinalityRecoverControllerFixed => 85,
            Self::FinalityRecoverControllerNative => 86,
            Self::FinalityRecoverControllerSemantic => 87,
            Self::FinalityRecoverSourceFixed => 88,
            Self::FinalityRecoverSourceNative => 89,
            Self::FinalityRecoverSourceSemantic => 90,
            Self::FinalityRecoverSessionFixed => 91,
            Self::FinalityRecoverSessionNative => 92,
            Self::FinalityRecoverSessionSemantic => 93,
            Self::FinalityRecoverModels => 94,
            Self::FinalityRecoverResponse => 95,
            Self::StartAssignmentInputsQuery => 147,
            Self::StartAssignmentInputsSubject => 148,
            Self::StartAssignmentInputsPolicyFixed => 149,
            Self::StartAssignmentInputsPolicyTyped => 150,
            Self::StartAssignmentInputsControllerFixed => 151,
            Self::StartAssignmentInputsControllerNative => 152,
            Self::StartAssignmentInputsControllerSemantic => 153,
            Self::StartAssignmentInputsSourceFixed => 154,
            Self::StartAssignmentInputsSourceNative => 155,
            Self::StartAssignmentInputsSourceSemantic => 156,
            Self::StartAssignmentInputsModels => 157,
            Self::StartAssignmentInputsResponse => 158,
            Self::HostCatalogNetworkFixed => 166,
            Self::HostCatalogNetworkNative => 167,
            Self::HostCatalogNetworkSemantic => 168,
            Self::HostCatalogMountFixed => 169,
            Self::HostCatalogMountNative => 170,
            Self::HostCatalogMountSemantic => 171,
            Self::HostCatalogModels => 172,
            Self::MountBefore62Fixed => 173,
            Self::MountBefore62Native => 174,
            Self::MountBefore62Semantic => 175,
        }
    }

    pub(crate) fn final_delete_cache_stage_v2(self) -> Option<Self> {
        Some(match self {
            Self::SourceFixed => Self::DeleteFreshCacheOverlay,
            Self::CacheFixed(role) => Self::DeleteFreshCacheFixed(role),
            Self::CacheNative(role) => Self::DeleteFreshCacheNative(role),
            Self::CacheSemantic(role) => Self::DeleteFreshCacheSemantic(role),
            Self::CacheModels => Self::DeleteFreshCacheModels,
            Self::CacheObjectsFixed => Self::DeleteFreshCacheObjectsFixed,
            Self::CacheObjectsNative => Self::DeleteFreshCacheObjectsNative,
            Self::DeleteCacheActionable => Self::DeleteFreshCacheActionable,
            _ => return None,
        })
    }

    fn is_host_preparation_v2(self) -> bool {
        matches!(self,
            Self::HostCatalogNetworkFixed
                | Self::HostCatalogNetworkNative
                | Self::HostCatalogNetworkSemantic
                | Self::HostCatalogMountFixed
                | Self::HostCatalogMountNative
                | Self::HostCatalogMountSemantic
                | Self::HostCatalogModels
                | Self::MountBefore62Fixed
                | Self::MountBefore62Native
                | Self::MountBefore62Semantic
        )
    }

    fn is_start_assignment_inputs_v2(self) -> bool {
        matches!(self,
            Self::StartAssignmentInputsQuery
                | Self::StartAssignmentInputsSubject
                | Self::StartAssignmentInputsPolicyFixed
                | Self::StartAssignmentInputsPolicyTyped
                | Self::StartAssignmentInputsControllerFixed
                | Self::StartAssignmentInputsControllerNative
                | Self::StartAssignmentInputsControllerSemantic
                | Self::StartAssignmentInputsSourceFixed
                | Self::StartAssignmentInputsSourceNative
                | Self::StartAssignmentInputsSourceSemantic
                | Self::StartAssignmentInputsModels
                | Self::StartAssignmentInputsResponse
        )
    }

    fn is_finality_recover_v1(self) -> bool {
        matches!(self,
            Self::FinalityRecoverQuery
                |             Self::FinalityRecoverTrustFixed
                |             Self::FinalityRecoverTrustTyped
                |             Self::FinalityRecoverControllerFixed
                |             Self::FinalityRecoverControllerNative
                |             Self::FinalityRecoverControllerSemantic
                |             Self::FinalityRecoverSourceFixed
                |             Self::FinalityRecoverSourceNative
                |             Self::FinalityRecoverSourceSemantic
                |             Self::FinalityRecoverSessionFixed
                |             Self::FinalityRecoverSessionNative
                |             Self::FinalityRecoverSessionSemantic
                |             Self::FinalityRecoverModels
                |             Self::FinalityRecoverResponse
        )
    }

    // Pure compilation follows actual accepted Start/current native inputs.
    // Historical Create and fresh lease/request comparisons consume that DATA
    // later; only HostPlan may issue their full conjunction as an unsigned plan.
    fn host_input_prerequisites_positive_v2(self, stages: &RootContinuationStagesV1) -> bool {
        match self {
            Self::ControllerFixed | Self::StorageFixed | Self::SourceFixed => stages.positive(62),
            Self::Compiler => stages.positive(62) && stages.positive(65),
            Self::FinalResponse => stages.positive(69),
            _ => true,
        }
    }

    fn prerequisites_positive(self, stages: &RootContinuationStagesV1) -> bool {
        match self {
            Self::StopCleanup(phase) => phase.prerequisites_positive_v1(stages),
            Self::MaintenanceStorage(phase) => phase.prerequisites_positive_v2(stages),
            Self::ControllerFixed | Self::StorageFixed | Self::SourceFixed
                | Self::CacheFixed(_) => true,
            Self::ControllerNative | Self::ControllerSemantic
                | Self::StorageNative | Self::StorageSemantic
                | Self::SourceNative | Self::SourceSemantic
                | Self::CacheNative(_) | Self::CacheSemantic(_) => {
                stages.positive(self.index() - 1)
            }
            Self::SourceTreeModels => stages.positive(8),
            Self::CacheModels => [11, 14, 17, 20, 23].into_iter().all(|index| stages.positive(index)),
            Self::CacheObjectsFixed => stages.positive(25),
            Self::CacheObjectsNative => stages.positive(26),
            Self::Compiler => [2, 5, 24, 27].into_iter().all(|index| stages.positive(index)),
            Self::FinalResponse => stages.positive(28),
            Self::EnvironmentArtifactFixed => stages.positive(2) && stages.positive(8),
            Self::EnvironmentArtifactNative => stages.positive(30),
            Self::EnvironmentClosureFixed => stages.positive(31),
            Self::EnvironmentClosureNative => stages.positive(32),
            Self::EnvironmentEvidenceFixed => stages.positive(33),
            Self::EnvironmentEvidenceNative => stages.positive(34),
            Self::EnvironmentEvidencePublish => stages.positive(35) && stages.positive(38),
            Self::EnvironmentResponse => stages.positive(36),
            Self::EnvironmentCompiler => [2, 24, 27, 39].into_iter().all(|index| stages.positive(index)),
            Self::EnvironmentAccepted => stages.positive(2) && stages.positive(8),
            // The unsigned reply belongs to the initial completed compiler.
            // Final proof and all three native cuts have fresh paid destinations;
            // none can reuse or overwrite an initial read's positive stage.
            Self::ApplyTrustFixed => stages.positive(52),
            Self::ApplyTrustTyped => stages.positive(55),
            Self::ApplyBundleTyped => stages.positive(56),
            Self::ApplyStorageInputs => stages.positive(56),
            Self::DeleteCacheActionable => stages.positive(25) && stages.positive(27),
            Self::DeleteInitialInventory => stages.positive(59)
                && matches!(stages.cache_retirement[0], Some(Ok(_))),
            Self::DeleteGraphFixed => stages.positive(146)
                && matches!(stages.cache_retirement[1], Some(Ok(_))),
            Self::DeleteGraphObjects => stages.positive(96),
            Self::DeleteGraphModels => stages.positive(97),
            Self::DeleteGraphComparison => stages.positive(98),
            Self::DeleteResourcePolicy => stages.positive(99),
            Self::DeleteResourceTrust => stages.positive(159),
            Self::DeleteResourceAssignment => stages.positive(160),
            Self::DeleteResourcePreparation => stages.positive(161),
            Self::DeleteResourceDraft => stages.positive(162),
            Self::DeleteResourceSignature => stages.positive(163),
            Self::DeleteResourcePolicyConfirmation => stages.positive(164),
            Self::DeletePreparatoryApproval => stages.positive(165),
            Self::DeletePreparationCurrent(phase) => stages.positive(176 + phase.index_v3()),
            Self::DeleteApplyIssuer(phase) => stages.positive(188 + phase.index_v3()),
            Self::DeleteNetworkIssuer(phase) => match phase.index_v3() {
                0 => stages.positive(196),
                index => stages.positive(226 + index),
            },
            Self::DeleteMountIssuer(phase) => match phase.index_v3() {
                0 => stages.positive(251),
                3 => stages.positive(238) && stages.positive(257),
                index => stages.positive(235 + index),
            },
            Self::DeleteMountSpec(phase) => match phase.index_v4() {
                0 => stages.positive(238),
                index => stages.positive(254 + index),
            },
            Self::DeleteCompletion(phase) => {
                [196, 234, 243, 251, 257].into_iter().all(|index| stages.positive(index))
                    && (258..258 + phase.index_v4()).all(|index| stages.positive(index))
            },
            Self::DeleteCleanupCurrent(phase) => {
                use crate::policy_compiler::delete_root::RootDeleteCleanupCurrentPhaseV4 as P;
                match phase {
                    P::Frame => stages.positive(234),
                    P::NetworkFixed => stages.positive(250),
                    P::NetworkNative => stages.positive(244),
                    P::NetworkModels => stages.positive(245),
                    P::HostFixed => stages.positive(246),
                    P::HostNative => stages.positive(247),
                    P::HostModels => stages.positive(248),
                    P::Comparison => (244..=250).all(|index| stages.positive(index)),
                }
            },
            Self::DeleteFreshFloor => stages.positive(142),
            Self::DeleteFreshTransfer => stages.positive(100),
            Self::DeleteFreshTransferTrust => stages.positive(143),
            Self::DeleteFreshTransferObservation => stages.positive(144),
            Self::DeleteFreshFrame => stages.positive(60),
            Self::DeleteFreshSourceFixed => stages.positive(118),
            Self::DeleteFreshSourceNative | Self::DeleteFreshSourceSemantic => stages.positive(self.index() - 1),
            Self::DeleteFreshCacheOverlay => stages.positive(122),
            Self::DeleteFreshCacheFixed(_) => stages.positive(123),
            Self::DeleteFreshCacheNative(_) | Self::DeleteFreshCacheSemantic(_) => stages.positive(self.index() - 1),
            Self::DeleteFreshCacheModels => [126, 129, 132, 135, 138].into_iter().all(|index| stages.positive(index)),
            Self::DeleteFreshCacheObjectsFixed => stages.positive(139),
            Self::DeleteFreshCacheObjectsNative => stages.positive(140),
            Self::DeleteFreshCacheActionable => stages.positive(139) && stages.positive(141),
            Self::DeleteFreshController(phase) => {
                use crate::policy_compiler::delete_root::RootDeleteControllerAdmissionPhaseV1 as Phase;
                match phase {
                    Phase::Fixed => stages.positive(145),
                    Phase::Native | Phase::Semantic => stages.positive(self.index() - 1),
                    Phase::CapabilityCensus => stages.positive(103),
                    Phase::SessionFixed => stages.positive(119),
                    Phase::MountSessionFixed | Phase::StorageSessionFixed
                        | Phase::NetworkSessionFixed => stages.positive(self.index() - 1),
                    Phase::SessionNative | Phase::SessionModels
                        | Phase::MountSessionNative | Phase::MountSessionModels
                        | Phase::StorageSessionNative | Phase::StorageSessionModels
                        | Phase::NetworkSessionNative | Phase::NetworkSessionModels =>
                        stages.positive(self.index() - 1),
                    // Fresh C must be byte-identical to the already verified
                    // original. Its held authorization/manifests stay resident;
                    // this route cannot replace them or open another witness.
                    Phase::AuthorizationHeader | Phase::AuthorizationBody | Phase::BrokerTrust => false,
                }
            },
            Self::EnvironmentRequest => true,
            Self::EnvironmentPolicy => stages.positive(34),
            Self::ApplyQuery => true,
            Self::ApplySubject => stages.positive(51),
            Self::ApplyFinalProof => stages.positive(28) && stages.positive(29),
            Self::ApplyFinalControllerFixed | Self::ApplyFinalStorageFixed
                | Self::ApplyFinalSourceFixed => stages.positive(40),
            Self::ApplyFinalControllerNative | Self::ApplyFinalControllerSemantic
                | Self::ApplyFinalStorageNative | Self::ApplyFinalStorageSemantic
                | Self::ApplyFinalSourceNative | Self::ApplyFinalSourceSemantic => {
                stages.positive(self.index() - 1)
            }
            Self::ApplyFinalResponse => [43, 46, 49].into_iter().all(|index| stages.positive(index)),
            Self::HostQuery => true,
            Self::HostSubject => stages.positive(61),
            Self::HostTrustFixed => stages.positive(62),
            Self::HostTrustTyped => stages.positive(63),
            Self::HostAcceptedStart => stages.positive(64) && stages.positive(2) && stages.positive(8),
            Self::HostHistoricalCreate => stages.positive(65) && stages.positive(5),
            Self::HostFreshOwnership => stages.positive(65) && stages.positive(64),
            Self::HostRequestTyped => stages.positive(66) && stages.positive(67),
            Self::HostPlan => [65, 66, 67, 68, 28].into_iter().all(|index| stages.positive(index)),
            Self::HostFinalProof => stages.positive(69) && stages.positive(29),
            Self::HostFinalControllerFixed | Self::HostFinalSessionFixed | Self::HostFinalSourceFixed => stages.positive(70),
            Self::HostFinalControllerNative | Self::HostFinalControllerSemantic
                | Self::HostFinalSessionNative | Self::HostFinalSessionSemantic
                | Self::HostFinalSourceNative | Self::HostFinalSourceSemantic => stages.positive(self.index() - 1),
            Self::HostFinalModels => [73, 76, 79].into_iter().all(|index| stages.positive(index)),
            Self::HostFinalResponse => stages.positive(80),
            Self::FinalityRecoverQuery => true,
            Self::FinalityRecoverTrustFixed | Self::FinalityRecoverControllerFixed => stages.positive(82),
            Self::FinalityRecoverTrustTyped => stages.positive(83),
            Self::FinalityRecoverSourceFixed => stages.positive(87),
            Self::FinalityRecoverSessionFixed => stages.positive(87) && stages.positive(84),
            Self::FinalityRecoverControllerNative | Self::FinalityRecoverControllerSemantic
                | Self::FinalityRecoverSourceNative | Self::FinalityRecoverSourceSemantic
                | Self::FinalityRecoverSessionNative | Self::FinalityRecoverSessionSemantic => stages.positive(self.index() - 1),
            Self::FinalityRecoverModels => [84,87,90,93].into_iter().all(|index| stages.positive(index)),
            Self::FinalityRecoverResponse => stages.positive(94),
            Self::StartAssignmentInputsQuery => true,
            Self::StartAssignmentInputsSubject => stages.positive(147),
            Self::StartAssignmentInputsPolicyFixed => stages.positive(148),
            Self::StartAssignmentInputsPolicyTyped => stages.positive(149),
            Self::StartAssignmentInputsControllerFixed => stages.positive(148),
            Self::StartAssignmentInputsControllerNative => stages.positive(151),
            Self::StartAssignmentInputsControllerSemantic => stages.positive(152),
            Self::StartAssignmentInputsSourceFixed => stages.positive(153),
            Self::StartAssignmentInputsSourceNative => stages.positive(154),
            Self::StartAssignmentInputsSourceSemantic => stages.positive(155),
            Self::StartAssignmentInputsModels => [150, 153, 156].into_iter().all(|index| stages.positive(index)),
            Self::StartAssignmentInputsResponse => stages.positive(157),
            Self::HostCatalogNetworkFixed | Self::MountBefore62Fixed => stages.positive(68),
            Self::HostCatalogMountFixed => stages.positive(168),
            Self::HostCatalogNetworkNative | Self::HostCatalogNetworkSemantic
                | Self::HostCatalogMountNative | Self::HostCatalogMountSemantic
                | Self::MountBefore62Native | Self::MountBefore62Semantic =>
                    stages.positive(self.index() - 1),
            Self::HostCatalogModels => stages.positive(168) && stages.positive(171),
        }
    }
}

pub(crate) struct RootContinuationStagesV1 {
    complete: Option<ResourceVector>,
    requirements: [Option<Result<ResourceVector, ResourceReservationErrorV1>>; STAGES],
    traffic: [Option<Result<(), ResourceReservationErrorV1>>; STAGES],
    first: Option<usize>,
    closed: Option<ResourceReservationErrorV1>,
    traffic_cause: Option<std::sync::Arc<ResourceReservationErrorV1>>,
    cache_retirement: [Option<Result<ResourceVector, ResourceReservationErrorV1>>; 2],
}

impl Default for RootContinuationStagesV1 {
    fn default() -> Self {
        Self {
            complete: None,
            requirements: std::array::from_fn(|_| None),
            traffic: std::array::from_fn(|_| None),
            first: None,
            closed: None,
            traffic_cause: None,
            cache_retirement: std::array::from_fn(|_| None),
        }
    }
}

impl RootContinuationStagesV1 {
    fn positive(&self, index: usize) -> bool {
        matches!(self.requirements[index], Some(Ok(_)))
            && matches!(self.traffic[index], Some(Ok(())))
    }

    fn first_failure(&self) -> Option<&(dyn StdError + 'static)> {
        let Some(index) = self.first else {
            return self.cache_retirement.iter().filter_map(Option::as_ref)
                .find_map(|value| value.as_ref().err())
                .map(|cause| cause as _).or_else(|| self.closed.as_ref().map(|cause| cause as _));
        };
        self.requirements[index].as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.traffic_cause.as_deref().map(|cause| cause as _))
            .or_else(|| self.traffic[index].as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

impl super::RootPeerStageStateV1 for RootContinuationStagesV1 {
    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.first_failure()
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn admit_purpose_stage_once_v1<K: RootPeerPurposeV1<Stages = RootContinuationStagesV1>>(
        &mut self,
        admission: &mut RootPurposePeerAdmissionV1<K>,
        stage: RootContinuationStageV1,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        let index = stage.index();
        // A repeated offer never overwrites the first reached original. The
        // enclosing native Root refusal is sticky, including ordering errors.
        if admission.stages.first_failure().is_some() || admission.stages.requirements[index].is_some() {
            admission.stages.closed.get_or_insert(ResourceReservationErrorV1::Conflict);
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let returned = (|| {
            self.require_active_policy_flight_v1()
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            admission.require_armed_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            // NoApply now has its own actual native ledger. The remaining
            // legacy Root purposes retain their distinct old stage subsets.
            if K::STOP_CLEANUP_ONLY != matches!(stage, RootContinuationStageV1::StopCleanup(_)) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if K::EXECUTION_NO_APPLY_ONLY {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if matches!(stage, RootContinuationStageV1::DeletePreparationCurrent(_)
                | RootContinuationStageV1::DeleteApplyIssuer(_)
                | RootContinuationStageV1::DeleteNetworkIssuer(_)
                | RootContinuationStageV1::DeleteMountIssuer(_)
                | RootContinuationStageV1::DeleteMountSpec(_)) && !K::DELETE_INPUT_REQUIRED {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if matches!(stage, RootContinuationStageV1::DeleteCompletion(_)) && !K::DELETE_INPUT_REQUIRED {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if matches!(stage, RootContinuationStageV1::DeleteCleanupCurrent(_)) && !K::DELETE_INPUT_REQUIRED {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if matches!(stage, RootContinuationStageV1::MaintenanceStorage(_))
                && !K::MAINTENANCE_STORAGE_REQUIRED {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            // This current effect purpose cannot borrow a Start, Apply,
            // Environment or Delete resource stage. Only the actual shared
            // C/Source/Storage/Cache/compiler programme is common.
            if K::MAINTENANCE_STORAGE_REQUIRED
                && !matches!(stage, RootContinuationStageV1::MaintenanceStorage(_))
                && stage.index() >= 30 {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if K::MAINTENANCE_STORAGE_REQUIRED
                && matches!(stage, RootContinuationStageV1::ControllerFixed
                    | RootContinuationStageV1::StorageFixed | RootContinuationStageV1::SourceFixed
                    | RootContinuationStageV1::Compiler)
                && !admission.stages.positive(198) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if K::MAINTENANCE_STORAGE_REQUIRED && matches!(stage, RootContinuationStageV1::Compiler)
                && ![201, 202, 203, 204].into_iter().all(|index| admission.stages.positive(index)) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if K::MAINTENANCE_STORAGE_REQUIRED && matches!(stage, RootContinuationStageV1::FinalResponse)
                && !admission.stages.positive(205) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            // A genuine Recover purpose can consume only its finite metadata
            // observation stages; sibling provisioning/compiler stages cannot
            // turn it into an Apply, Host, Environment or Cache borrower.
            if K::FINALITY_RECOVER_ONLY != stage.is_finality_recover_v1() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            // The read-only input purpose cannot borrow resource, compiler,
            // cache or sibling finality stages from the shared native ledger.
            if K::START_ASSIGNMENT_INPUTS_ONLY != stage.is_start_assignment_inputs_v2() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            // Only the same actual Host-purpose recipient can enter these
            // preparatory resource readers and the catalog comparison.
            if stage.is_host_preparation_v2() && !K::HOST_INPUT_REQUIRED {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if !stage.prerequisites_positive(&admission.stages) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            // The sealed Apply marker alone selects this input ordering. The
            // query/subject bytes remain comparison DATA; they grant no sibling
            // purpose and never rearm an already-paid reader destination.
            if K::APPLY_INPUT_REQUIRED
                && matches!(stage, RootContinuationStageV1::ControllerFixed
                    | RootContinuationStageV1::StorageFixed
                    | RootContinuationStageV1::Compiler)
                && !admission.stages.positive(52)
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if K::APPLY_INPUT_REQUIRED
                && matches!(stage, RootContinuationStageV1::Compiler)
                && (!admission.stages.positive(57) || !admission.stages.positive(58))
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            // The actual Start purpose keeps its accepted operation/gen0 and
            // common native-read gates. Pure compiler DATA precedes the later
            // historical/ownership/request checks; HostPlan requires all of them.
            if K::HOST_INPUT_REQUIRED
                && !stage.host_input_prerequisites_positive_v2(&admission.stages) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let base = admission.stages.complete.or_else(|| {
                admission.permit.as_ref().and_then(|result| result.as_ref().ok()).copied()
            }).ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let complete = base.checked_add(without_operation_traffic_v1(demand.0))?
                .checked_add(without_operation_traffic_v1(demand.1))?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(&mut admission.stages.requirements[index], returned);
        if let Some(Ok(complete)) = admission.stages.requirements[index].as_ref() {
            admission.stages.complete = Some(*complete);
        } else {
            admission.stages.first = Some(index);
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let returned = self.debit_observer_traffic_v1(operation_traffic_demand_v1(demand.0));
        self.native_refusal_original_v1().park_empty_result_v1(&mut admission.stages.traffic[index], returned);
        if !matches!(admission.stages.traffic[index], Some(Ok(()))) {
            // Share the actual error allocation already retained by SAME R.
            // A coarse returned projection cannot hide its native financial cause.
            admission.stages.traffic_cause = self.native_receiving_refusal.clone();
            admission.stages.first = Some(index);
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        Ok(())
    }
}

impl RootReceivingOriginalV1 {
    // This closed D projection derives its amount from the actual completed
    // Cache owner after physical consumption, never from caller counts/DATA.
    pub(crate) fn retire_delete_cache_resident_once_v2(&mut self,
        admission: &mut RootPurposePeerAdmissionV1<super::DeleteRootPeerPurposeV1>,
        owner: &crate::policy_compiler::delete_root::RootDeleteCacheCurrentOriginalV2,
    ) -> Result<(), Error> {
        let slot = usize::from(owner.is_final_read_v2());
        if admission.stages.first_failure().is_some() || admission.stages.cache_retirement[slot].is_some() {
            admission.stages.closed.get_or_insert(ResourceReservationErrorV1::Conflict);
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let returned = (|| {
            self.require_active_policy_flight_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            admission.require_armed_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let (completed, next) = if slot == 0 { (59, 60) } else { (142, 96) };
            if !admission.stages.positive(completed) || admission.stages.requirements[next].is_some() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let files = owner.retired_cache_files_v2()?;
            let complete = admission.stages.complete.ok_or(ResourceReservationErrorV1::Conflict)?;
            let remaining = complete.get(aos_sandbox_model::ResourceDimension::OpenFiles)
                .checked_sub(files).ok_or(ResourceReservationErrorV1::Conflict)?;
            Ok(complete.with(aos_sandbox_model::ResourceDimension::OpenFiles, remaining))
        })();
        self.native_refusal_original_v1().park_empty_result_v1(&mut admission.stages.cache_retirement[slot], returned);
        match admission.stages.cache_retirement[slot].as_ref().and_then(|value| value.as_ref().ok()) {
            Some(remaining) => {
                // Only current continuation residency changes. Every original
                // requirement, the R highwater and spent traffic stay owned.
                admission.stages.complete = Some(*remaining);
                Ok(())
            }
            None => { self.activation.latch_root_refusal_v1(); Err(Error::Service) }
        }
    }
}

impl RootPurposePeerAdmissionV1<super::DeleteRootPeerPurposeV1> {
    pub(crate) fn delete_cache_retirement_failure_v2(&self) -> Option<&(dyn StdError + 'static)> {
        self.stages.cache_retirement.iter().filter_map(Option::as_ref)
            .find_map(|value| value.as_ref().err()).map(|cause| cause as _)
    }
}

#[cfg(test)]
mod retirement_tests {
    use super::*;

    #[test]
    fn later_closure_keeps_the_same_original_cache_retirement_cause() {
        let mut stages = RootContinuationStagesV1::default();
        stages.cache_retirement[0] = Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable));
        let first = stages.first_failure().unwrap() as *const dyn StdError;

        stages.closed = Some(ResourceReservationErrorV1::Conflict);

        assert!(std::ptr::eq(first, stages.first_failure().unwrap() as *const dyn StdError));
        assert!(matches!(stages.cache_retirement[0],
            Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable))));
    }
}

#[cfg(test)]
mod host_stage_tests {
    use super::*;

    fn paid(stages: &mut RootContinuationStagesV1, index: usize) {
        stages.requirements[index] = Some(Ok(ResourceVector::ZERO));
        stages.traffic[index] = Some(Ok(()));
    }

    fn enter(stages: &mut RootContinuationStagesV1, stage: RootContinuationStageV1) {
        assert!(stage.prerequisites_positive(stages));
        assert!(stage.host_input_prerequisites_positive_v2(stages));
        paid(stages, stage.index());
    }

    fn initial_start_inputs() -> RootContinuationStagesV1 {
        use RootContinuationStageV1 as S;
        let mut stages = RootContinuationStagesV1::default();
        for stage in [S::HostQuery, S::HostSubject, S::HostTrustFixed, S::HostTrustTyped,
            S::ControllerFixed, S::ControllerNative, S::ControllerSemantic,
            S::StorageFixed, S::StorageNative, S::StorageSemantic,
            S::SourceFixed, S::SourceNative, S::SourceSemantic, S::SourceTreeModels] {
            enter(&mut stages, stage);
        }
        for role in [CacheJournalRecipeRoleV1::Bootstrap, CacheJournalRecipeRoleV1::Hold,
            CacheJournalRecipeRoleV1::State, CacheJournalRecipeRoleV1::Authority,
            CacheJournalRecipeRoleV1::Clock] {
            for stage in [S::CacheFixed(role), S::CacheNative(role), S::CacheSemantic(role)] {
                enter(&mut stages, stage);
            }
        }
        for stage in [S::CacheModels, S::CacheObjectsFixed, S::CacheObjectsNative] {
            enter(&mut stages, stage);
        }
        stages
    }

    #[test]
    fn pure_start_compilation_precedes_the_later_plan_conjunction() {
        use RootContinuationStageV1 as S;
        let mut stages = initial_start_inputs();
        assert!(!S::Compiler.host_input_prerequisites_positive_v2(&stages));

        enter(&mut stages, S::HostAcceptedStart);
        enter(&mut stages, S::Compiler);

        // The exact production ordering now reaches compiled DATA without a
        // cycle. No plan or reply can precede the independently paid later joins.
        assert!(!S::HostPlan.prerequisites_positive(&stages));
        assert!(!S::FinalResponse.host_input_prerequisites_positive_v2(&stages));
        enter(&mut stages, S::HostHistoricalCreate);
        assert!(!S::HostPlan.prerequisites_positive(&stages));
        enter(&mut stages, S::HostFreshOwnership);
        assert!(!S::HostPlan.prerequisites_positive(&stages));
        enter(&mut stages, S::HostRequestTyped);
        enter(&mut stages, S::HostPlan);
        enter(&mut stages, S::FinalResponse);
    }

    #[test]
    fn pure_compiler_requires_actual_start_and_every_common_native_input() {
        use RootContinuationStageV1 as S;
        for missing in [2, 5, 24, 27, 62, 65] {
            let mut stages = initial_start_inputs();
            enter(&mut stages, S::HostAcceptedStart);
            stages.traffic[missing] = Some(Err(ResourceReservationErrorV1::Conflict));

            assert!(!S::Compiler.prerequisites_positive(&stages)
                || !S::Compiler.host_input_prerequisites_positive_v2(&stages),
                "compiler admitted without actual prerequisite {missing}");
        }
    }

    #[test]
    fn plan_refuses_each_missing_or_failed_later_comparison() {
        use RootContinuationStageV1 as S;
        for missing in [65, 66, 67, 68, 28] {
            let mut stages = initial_start_inputs();
            for stage in [S::HostAcceptedStart, S::Compiler, S::HostHistoricalCreate,
                S::HostFreshOwnership, S::HostRequestTyped] {
                enter(&mut stages, stage);
            }
            stages.traffic[missing] = None;
            assert!(!S::HostPlan.prerequisites_positive(&stages),
                "plan admitted without prerequisite {missing}");

            stages.traffic[missing] = Some(Err(ResourceReservationErrorV1::Conflict));
            assert!(!S::HostPlan.prerequisites_positive(&stages),
                "plan admitted with failed prerequisite {missing}");
        }
    }

    #[test]
    fn initial_host_model_order_cannot_reuse_old_apply_input_slots() {
        let mut stages = RootContinuationStagesV1::default();
        for index in [2, 5, 8, 28, 29, 51, 52, 55, 56, 57, 58] {
            paid(&mut stages, index);
        }
        assert!(!RootContinuationStageV1::HostAcceptedStart.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::HostRequestTyped.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::HostFinalProof.prerequisites_positive(&stages));

        for index in 61..=69 { paid(&mut stages, index); }

        assert!(RootContinuationStageV1::HostAcceptedStart.prerequisites_positive(&stages));
        assert!(RootContinuationStageV1::HostRequestTyped.prerequisites_positive(&stages));
        assert!(RootContinuationStageV1::HostFinalProof.prerequisites_positive(&stages));
    }

    #[test]
    fn final_host_models_require_all_three_distinct_fresh_read_invoices() {
        let mut stages = RootContinuationStagesV1::default();
        for index in [43, 46, 49, 50, 70, 73, 76] { paid(&mut stages, index); }
        assert!(!RootContinuationStageV1::HostFinalModels.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::HostFinalResponse.prerequisites_positive(&stages));

        paid(&mut stages, 79);
        assert!(RootContinuationStageV1::HostFinalModels.prerequisites_positive(&stages));
        paid(&mut stages, 80);
        assert!(RootContinuationStageV1::HostFinalResponse.prerequisites_positive(&stages));
    }
}


#[cfg(test)]
mod delete_continuation_stage_tests {
    use super::*;
    use crate::policy_compiler::delete_root::RootDeleteControllerAdmissionPhaseV1 as Phase;

    fn paid(stages: &mut RootContinuationStagesV1, stage: RootContinuationStageV1) {
        stages.requirements[stage.index()] = Some(Ok(ResourceVector::ZERO));
        stages.traffic[stage.index()] = Some(Ok(()));
    }



    #[test]
    fn apply_issuer_requires_each_distinct_post26_successor_debit() {
        use crate::policy_compiler::delete_root::RootDeleteApplyIssuerPhaseV3 as P;
        let phases = [P::Policy, P::Trust, P::Assignment, P::Preparation,
            P::Draft, P::Signature, P::Confirmation, P::Approval];
        let mut stages = RootContinuationStagesV1::default();
        assert_eq!(phases.map(|phase| RootContinuationStageV1::DeleteApplyIssuer(phase).index()),
            [189, 190, 191, 192, 193, 194, 195, 196]);
        assert!(!RootContinuationStageV1::DeleteApplyIssuer(P::Policy).prerequisites_positive(&stages));

        stages.requirements[188] = Some(Ok(ResourceVector::ZERO));
        stages.traffic[188] = Some(Ok(()));
        for phase in phases {
            let selected = RootContinuationStageV1::DeleteApplyIssuer(phase);
            assert!(selected.prerequisites_positive(&stages));
            paid(&mut stages, selected);
        }

        stages.traffic[194] = Some(Err(ResourceReservationErrorV1::Conflict));
        assert!(!RootContinuationStageV1::DeleteApplyIssuer(P::Confirmation).prerequisites_positive(&stages));
        assert_eq!(stages.requirements.len(), STAGES);
        assert_eq!(stages.traffic.len(), STAGES);
    }

    #[test]
    fn network_issuer_requires_actual7_and_every_independent_successor_debit() {
        use crate::policy_compiler::delete_root::RootDeleteApplyIssuerPhaseV3 as P;
        let phases = [P::Policy, P::Trust, P::Assignment, P::Preparation,
            P::Draft, P::Signature, P::Confirmation, P::Approval];
        let mut stages = RootContinuationStagesV1::default();
        assert_eq!(phases.map(|phase| RootContinuationStageV1::DeleteNetworkIssuer(phase).index()),
            [227, 228, 229, 230, 231, 232, 233, 234]);
        assert!(!RootContinuationStageV1::DeleteNetworkIssuer(P::Policy).prerequisites_positive(&stages));
        // PublicExecution's unrelated last reader cannot substitute for7.
        stages.requirements[226] = Some(Ok(ResourceVector::ZERO));
        stages.traffic[226] = Some(Ok(()));
        assert!(!RootContinuationStageV1::DeleteNetworkIssuer(P::Policy).prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::DeleteApplyIssuer(P::Approval));
        for phase in phases {
            let stage = RootContinuationStageV1::DeleteNetworkIssuer(phase);
            assert!(stage.prerequisites_positive(&stages));
            paid(&mut stages, stage);
        }
        stages.traffic[232] = Some(Err(ResourceReservationErrorV1::Conflict));
        assert!(!RootContinuationStageV1::DeleteNetworkIssuer(P::Confirmation).prerequisites_positive(&stages));
    }

    #[test]
    fn cleanup_native_models_cannot_precede_their_own_funded_receipt_and_reads() {
        use crate::policy_compiler::delete_root::RootDeleteCleanupCurrentPhaseV4 as P;
        let mut stages = RootContinuationStagesV1::default();
        let stage = RootContinuationStageV1::DeleteCleanupCurrent;
        assert!(!stage(P::Frame).prerequisites_positive(&stages));
        assert!(!stage(P::NetworkFixed).prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::DeleteNetworkIssuer(
            crate::policy_compiler::delete_root::RootDeleteApplyIssuerPhaseV3::Approval));
        assert!(stage(P::Frame).prerequisites_positive(&stages));
        assert!(!stage(P::NetworkFixed).prerequisites_positive(&stages));
        paid(&mut stages, stage(P::Frame));
        for phase in [P::NetworkFixed, P::NetworkNative, P::NetworkModels,
            P::HostFixed, P::HostNative, P::HostModels, P::Comparison] {
            assert!(stage(phase).prerequisites_positive(&stages));
            paid(&mut stages, stage(phase));
        }
        stages.traffic[248] = Some(Err(ResourceReservationErrorV1::Conflict));
        assert!(!stage(P::Comparison).prerequisites_positive(&stages));
    }

    #[test]
    fn delete_completion_requires_each_actual_native_semantic_and_model_frontier() {
        use crate::policy_compiler::delete_root::RootDeleteCompletionPhaseV4 as P;
        let mut stages = RootContinuationStagesV1::default();
        let stage = RootContinuationStageV1::DeleteCompletion;
        assert!(STAGES >= 266);
        assert!(!stage(P::Fixed).prerequisites_positive(&stages));
        for index in [196, 234, 243, 251, 257] {
            stages.requirements[index] = Some(Ok(ResourceVector::ZERO));
            stages.traffic[index] = Some(Ok(()));
        }
        for phase in [P::Fixed, P::MountNative, P::MountModels, P::StorageNative,
            P::StorageModels, P::SourceNative, P::SourceSemantic, P::SourceModels] {
            assert!(stage(phase).prerequisites_positive(&stages));
            paid(&mut stages, stage(phase));
        }
        stages.traffic[263] = Some(Err(ResourceReservationErrorV1::Conflict));
        assert!(!stage(P::SourceModels).prerequisites_positive(&stages));
        stages.traffic[263] = Some(Ok(()));
        stages.traffic[243] = None;
        assert!(!stage(P::SourceModels).prerequisites_positive(&stages));
    }

    #[test]
    fn initial_ack_only_permits_a_new_fresh_interval_not_the_graph_or_final_floor() {
        let mut stages = RootContinuationStagesV1::default();
        stages.requirements[59] = Some(Ok(ResourceVector::ZERO));
        stages.traffic[59] = Some(Ok(()));
        stages.cache_retirement[0] = Some(Ok(ResourceVector::ZERO));
        assert!(RootContinuationStageV1::DeleteInitialInventory.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::DeleteGraphFixed.prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::DeleteInitialInventory);
        assert!(RootContinuationStageV1::DeleteFreshFrame.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::DeleteFreshFloor.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::DeleteFreshController(Phase::Fixed).prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::DeleteFreshFrame);
        assert!(RootContinuationStageV1::DeleteFreshTransfer.prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::DeleteFreshTransfer);
        assert!(RootContinuationStageV1::DeleteFreshTransferTrust.prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::DeleteFreshTransferTrust);
        assert!(RootContinuationStageV1::DeleteFreshTransferObservation.prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::DeleteFreshTransferObservation);
        assert!(RootContinuationStageV1::DeleteFreshController(Phase::Fixed).prerequisites_positive(&stages));
        for forbidden in [Phase::AuthorizationHeader, Phase::AuthorizationBody, Phase::BrokerTrust] {
            assert!(!RootContinuationStageV1::DeleteFreshController(forbidden).prerequisites_positive(&stages));
        }
    }

    #[test]
    fn sole_graph_requires_late_cache_disposal_and_distinct_current_serving_floor() {
        let mut stages = RootContinuationStagesV1::default();
        for index in 0..=145 {
            stages.requirements[index] = Some(Ok(ResourceVector::ZERO));
            stages.traffic[index] = Some(Ok(()));
        }
        stages.cache_retirement[0] = Some(Ok(ResourceVector::ZERO));
        assert!(!RootContinuationStageV1::DeleteGraphFixed.prerequisites_positive(&stages));
        assert!(RootContinuationStageV1::DeleteFreshFloor.prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::DeleteFreshFloor);
        assert!(!RootContinuationStageV1::DeleteGraphFixed.prerequisites_positive(&stages));
        stages.cache_retirement[1] = Some(Ok(ResourceVector::ZERO));
        assert!(RootContinuationStageV1::DeleteGraphFixed.prerequisites_positive(&stages));
        stages.traffic[146] = Some(Err(ResourceReservationErrorV1::Conflict));
        assert!(!RootContinuationStageV1::DeleteGraphFixed.prerequisites_positive(&stages));
    }

    #[test]
    fn resource_preparation_requires_its_own_current_policy_trust_and_assignment_fees() {
        let mut stages = RootContinuationStagesV1::default();
        paid(&mut stages, RootContinuationStageV1::DeleteGraphComparison);
        assert!(RootContinuationStageV1::DeleteResourcePolicy.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::DeleteResourcePreparation.prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::DeleteResourcePolicy);
        assert!(RootContinuationStageV1::DeleteResourceTrust.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::DeleteResourceAssignment.prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::DeleteResourceTrust);
        assert!(RootContinuationStageV1::DeleteResourceAssignment.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::DeleteResourcePreparation.prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::DeleteResourceAssignment);
        assert!(RootContinuationStageV1::DeleteResourcePreparation.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::DeleteResourceDraft.prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::DeleteResourcePreparation);
        assert!(RootContinuationStageV1::DeleteResourceDraft.prerequisites_positive(&stages));
        stages.traffic[162] = Some(Err(ResourceReservationErrorV1::Conflict));
        assert!(!RootContinuationStageV1::DeleteResourceDraft.prerequisites_positive(&stages));
        stages.traffic[161] = Some(Err(ResourceReservationErrorV1::Conflict));
        assert!(!RootContinuationStageV1::DeleteResourcePreparation.prerequisites_positive(&stages));
    }

    #[test]
    fn coordinated_graph_fresh_and_assignment_inputs_have_disjoint_bounded_storage() {
        let stages = RootContinuationStagesV1::default();
        let groups = [
            (RootContinuationStageV1::FinalityRecoverQuery.index(), RootContinuationStageV1::FinalityRecoverResponse.index()),
            (RootContinuationStageV1::DeleteGraphFixed.index(), RootContinuationStageV1::DeleteGraphComparison.index()),
            (RootContinuationStageV1::DeleteFreshFrame.index(), RootContinuationStageV1::DeleteFreshFloor.index()),
            (RootContinuationStageV1::StartAssignmentInputsQuery.index(), RootContinuationStageV1::StartAssignmentInputsResponse.index()),
            (RootContinuationStageV1::DeleteResourcePolicy.index(), RootContinuationStageV1::DeleteResourcePolicyConfirmation.index()),
            (RootContinuationStageV1::HostCatalogNetworkFixed.index(), RootContinuationStageV1::HostCatalogModels.index()),
            (RootContinuationStageV1::MountBefore62Fixed.index(), RootContinuationStageV1::MountBefore62Semantic.index()),
            (RootContinuationStageV1::DeletePreparatoryApproval.index(), RootContinuationStageV1::DeletePreparatoryApproval.index()),
        ];
        assert_eq!(groups, [(82, 95), (96, 99), (100, 146), (147, 158), (159, 165), (166, 172), (173, 175), (176, 176)]);
        for pair in groups.windows(2) { assert!(pair[0].1 < pair[1].0); }
        use crate::policy_compiler::delete_root::RootDeletePreparationCurrentPhaseV3 as P;
        let post26 = [P::ControllerFixed, P::ControllerNative, P::ControllerSemantic,
            P::SourceFixed, P::SourceNative, P::SourceSemantic, P::SourceModels,
            P::SourceSignature, P::StorageFixed, P::StorageNative, P::StorageModels, P::Comparison];
        assert_eq!(post26.map(|phase| RootContinuationStageV1::DeletePreparationCurrent(phase).index()),
            std::array::from_fn::<_, 12, _>(|index| 177 + index));
        assert_eq!(stages.requirements.len(), STAGES);
        assert_eq!(stages.traffic.len(), STAGES);
        assert!(groups.iter().all(|(_, end)| *end < STAGES));
    }

    #[test]
    fn host_catalog_cannot_replace_either_native_session_with_other_stage_success() {
        let mut stages = RootContinuationStagesV1::default();
        for index in 0..166 {
            stages.requirements[index] = Some(Ok(ResourceVector::ZERO));
            stages.traffic[index] = Some(Ok(()));
        }

        assert!(RootContinuationStageV1::HostCatalogNetworkFixed.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::HostCatalogMountFixed.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::HostCatalogModels.prerequisites_positive(&stages));
        for stage in [RootContinuationStageV1::HostCatalogNetworkFixed,
            RootContinuationStageV1::HostCatalogNetworkNative,
            RootContinuationStageV1::HostCatalogNetworkSemantic,
            RootContinuationStageV1::HostCatalogMountFixed,
            RootContinuationStageV1::HostCatalogMountNative,
            RootContinuationStageV1::HostCatalogMountSemantic]
        {
            assert!(stage.prerequisites_positive(&stages));
            paid(&mut stages, stage);
        }
        assert!(RootContinuationStageV1::HostCatalogModels.prerequisites_positive(&stages));

        stages.traffic[168] = Some(Err(ResourceReservationErrorV1::Conflict));
        assert!(!RootContinuationStageV1::HostCatalogModels.prerequisites_positive(&stages));
    }

    #[test]
    fn mount_preparation_requires_its_actual_assignment_and_all_three_spec_frontiers() {
        use crate::policy_compiler::delete_root::{RootDeleteApplyIssuerPhaseV3 as P,
            RootDeleteCleanupCurrentPhaseV4 as C, RootDeleteMountSpecPhaseV4 as S};
        let mut stages = RootContinuationStagesV1::default();
        let issuer = RootContinuationStageV1::DeleteMountIssuer;
        let spec = RootContinuationStageV1::DeleteMountSpec;
        assert_eq!([P::Policy, P::Trust, P::Assignment, P::Preparation, P::Draft,
            P::Signature, P::Confirmation, P::Approval].map(|phase| issuer(phase).index()),
            std::array::from_fn::<_, 8, _>(|index| 236 + index));
        assert_eq!([S::Fixed, S::Object, S::Model].map(|phase| spec(phase).index()), [255, 256, 257]);
        assert!(!issuer(P::Policy).prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::DeleteCleanupCurrent(C::Comparison));
        for phase in [P::Policy, P::Trust, P::Assignment] {
            assert!(issuer(phase).prerequisites_positive(&stages));
            paid(&mut stages, issuer(phase));
        }
        assert!(!issuer(P::Preparation).prerequisites_positive(&stages));
        assert!(!spec(S::Model).prerequisites_positive(&stages));
        for phase in [S::Fixed, S::Object, S::Model] {
            assert!(spec(phase).prerequisites_positive(&stages));
            paid(&mut stages, spec(phase));
        }
        assert!(issuer(P::Preparation).prerequisites_positive(&stages));
        stages.traffic[256] = Some(Err(ResourceReservationErrorV1::Conflict));
        assert!(!spec(S::Model).prerequisites_positive(&stages));
        assert!(spec(S::Model).index() < STAGES);
    }

    #[test]
    fn mount_absence_read_has_distinct_once_slots_from_final_inventory_and_host_catalog() {
        let mut stages = RootContinuationStagesV1::default();
        for index in 0..173 {
            stages.requirements[index] = Some(Ok(ResourceVector::ZERO));
            stages.traffic[index] = Some(Ok(()));
        }

        assert!(RootContinuationStageV1::MountBefore62Fixed.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::MountBefore62Native.prerequisites_positive(&stages));
        assert!(!RootContinuationStageV1::MountBefore62Semantic.prerequisites_positive(&stages));
        paid(&mut stages, RootContinuationStageV1::MountBefore62Fixed);
        paid(&mut stages, RootContinuationStageV1::MountBefore62Native);
        assert!(RootContinuationStageV1::MountBefore62Semantic.prerequisites_positive(&stages));

        stages.traffic[174] = Some(Err(ResourceReservationErrorV1::Conflict));
        assert!(!RootContinuationStageV1::MountBefore62Semantic.prerequisites_positive(&stages));
        assert!(RootContinuationStageV1::MountBefore62Fixed.is_host_preparation_v2());
        assert!(RootContinuationStageV1::HostCatalogModels.is_host_preparation_v2());
        assert!(!RootContinuationStageV1::StartAssignmentInputsModels.is_host_preparation_v2());
    }

}
