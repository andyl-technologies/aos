//! Lends only the selected Root continuation's finite stage destinations.

use aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1;
use crate::controller_resource_reservation::{
    RootContinuationDemandV1, RootContinuationStageV1, RootContinuationStagesV1, RootPurposePeerAdmissionV1,
    RootPeerPurposeV1, StopCleanupRootPeerPurposeV1, MaintenanceStorageRootPeerPurposeV2, RootMaintenanceStorageStageV2, DeleteRootPeerPurposeV1, ApplyRootPeerPurposeV1, HostLaunchRootPeerPurposeV1, EnvironmentRootPeerPurposeV1, FinalityRecoverRootPeerPurposeV1,
};
use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};

// The finite provisioning purposes lend only their actual stage custody.
// Delete retains its separate semantic/financial consumer.
pub(crate) trait RootProvisioningPurposeV1: RootPeerPurposeV1<Stages = RootContinuationStagesV1> {}
impl RootProvisioningPurposeV1 for DeleteRootPeerPurposeV1 {}
impl RootProvisioningPurposeV1 for ApplyRootPeerPurposeV1 {}
impl RootProvisioningPurposeV1 for HostLaunchRootPeerPurposeV1 {}
impl RootProvisioningPurposeV1 for MaintenanceStorageRootPeerPurposeV2 {}
impl RootProvisioningPurposeV1 for EnvironmentRootPeerPurposeV1 {}
impl RootProvisioningPurposeV1 for StopCleanupRootPeerPurposeV1 {}

pub(crate) type RootStopCleanupStageReceivingV1<'flight, 'startup> =
    RootProvisioningStageReceivingV1<'flight, 'startup, StopCleanupRootPeerPurposeV1>;

impl RootStopCleanupStageReceivingV1<'_, '_> {
    pub(crate) fn admit_stop_cleanup_once_v1(&mut self,
        phase: crate::controller_resource_reservation::RootStopCleanupStageV1,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::StopCleanup(phase), demand)
    }

    pub(crate) fn require_stop_cleanup_transport_prepaid_v1(&self,
        required: aos_sandbox_model::ResourceVector) -> Result<(), Error> {
        self.admission.require_armed_v1()?;
        let paid = crate::policy_compiler::stop_cleanup_root::transport::fixed_receiving_demand_v1()
            .map_err(|_| Error::Service)?;
        if paid.componentwise_max(required) != paid { return Err(Error::Service); }
        Ok(())
    }
}

/// Borrows selected stage custody without borrowing the whole accepted flight.
pub(crate) struct RootProvisioningStageReceivingV1<'flight, 'startup, K: RootProvisioningPurposeV1> {
    pub(super) startup: &'startup ProductionNormalRootStartupV1,
    pub(super) admission: &'flight mut RootPurposePeerAdmissionV1<K>,
    pub(super) resident_baseline: aos_sandbox_model::ResourceVector,
    pub(super) delete_final_cache: bool,
}

pub(crate) type RootDeleteCacheStageReceivingV2<'flight, 'startup> =
    RootProvisioningStageReceivingV1<'flight, 'startup, DeleteRootPeerPurposeV1>;

pub(crate) type RootEnvironmentStageReceivingV1<'flight, 'startup> =
    RootProvisioningStageReceivingV1<'flight, 'startup, EnvironmentRootPeerPurposeV1>;

pub(crate) type RootApplyStageReceivingV1<'flight, 'startup> =
    RootProvisioningStageReceivingV1<'flight, 'startup, ApplyRootPeerPurposeV1>;
pub(crate) type RootHostLaunchStageReceivingV1<'flight, 'startup> =
    RootProvisioningStageReceivingV1<'flight, 'startup, HostLaunchRootPeerPurposeV1>;

pub(crate) type RootMaintenanceStorageStageReceivingV2<'flight, 'startup> =
    RootProvisioningStageReceivingV1<'flight, 'startup, MaintenanceStorageRootPeerPurposeV2>;

macro_rules! stage_method {
    ($method:ident, $stage:ident) => {
        pub(crate) fn $method(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
            self.admit_once(RootContinuationStageV1::$stage, demand)
        }
    };
}

macro_rules! cache_stage_method {
    ($method:ident, $stage:ident) => {
        pub(crate) fn $method(&mut self, role: CacheJournalRecipeRoleV1, demand: RootContinuationDemandV1) -> Result<(), Error> {
            self.admit_once(RootContinuationStageV1::$stage(role), demand)
        }
    };
}

impl<'startup, K: RootProvisioningPurposeV1> RootProvisioningStageReceivingV1<'_, 'startup, K> {
    pub(crate) fn startup_v1(&self) -> &'startup ProductionNormalRootStartupV1 {
        self.startup
    }

    /// Borrows enrolled-node comparison DATA from the same delivered Root original.
    pub(crate) fn enrolled_node_v1(&self) -> Result<[u8; 16], Error> {
        self.admission.require_armed_v1().map_err(|_| Error::Service)?;
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().current_enrolled_node_data_v1();
        receiving.finish_returned_v1(returned)
    }

    /// Borrows B/N/R DATA from this same armed purpose's original Root image.
    pub(crate) fn controller_baseline_partition_v1(&self)
        -> Result<(aos_sandbox_model::ResourceVector, aos_sandbox_model::ResourceVector,
            aos_sandbox_model::ResourceVector), Error>
    {
        self.admission.require_armed_v1().map_err(|_| Error::Service)?;
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().current_controller_baseline_partition_data_v1();
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn controller_identity_v1(&self) -> (u32, u32) {
        let identities = self.startup.native.fields().profile.identities;
        (identities[0], identities[1])
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.admission.continuation_failure_v1()
    }

    stage_method!(admit_controller_fixed_once_v1, ControllerFixed);
    stage_method!(admit_controller_native_once_v1, ControllerNative);
    stage_method!(admit_controller_semantic_once_v1, ControllerSemantic);
    stage_method!(admit_storage_fixed_once_v1, StorageFixed);
    stage_method!(admit_storage_native_once_v1, StorageNative);
    stage_method!(admit_storage_semantic_once_v1, StorageSemantic);
    stage_method!(admit_source_fixed_once_v1, SourceFixed);
    stage_method!(admit_source_native_once_v1, SourceNative);
    stage_method!(admit_source_semantic_once_v1, SourceSemantic);
    cache_stage_method!(admit_cache_fixed_once_v1, CacheFixed);
    cache_stage_method!(admit_cache_native_once_v1, CacheNative);
    cache_stage_method!(admit_cache_semantic_once_v1, CacheSemantic);
    stage_method!(admit_source_tree_models_once_v1, SourceTreeModels);
    stage_method!(admit_cache_models_once_v1, CacheModels);
    stage_method!(admit_cache_objects_fixed_once_v1, CacheObjectsFixed);
    stage_method!(admit_cache_objects_native_once_v1, CacheObjectsNative);
    stage_method!(admit_compiler_once_v1, Compiler);
    stage_method!(admit_final_response_once_v1, FinalResponse);

    fn admit_once(&mut self, stage: RootContinuationStageV1, demand: RootContinuationDemandV1) -> Result<(), Error> {
        let selected = if self.delete_final_cache {
            stage.final_delete_cache_stage_v2().ok_or(Error::Service)?
        } else { stage };
        let demand = if matches!(stage, RootContinuationStageV1::SourceFixed) {
            demand.with_resident_baseline_v2(self.resident_baseline)
        } else { demand };
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().admit_purpose_stage_once_v1(self.admission, selected, demand);
        receiving.finish_returned_v1(returned)
    }
}

impl<'startup> RootEnvironmentStageReceivingV1<'_, 'startup> {
    /// Borrows only the optional pin from the same actual Root profile.
    /// The pin is DATA and is not an artifact measurement or generation grant.
    pub(crate) fn environment_provision_data_v1(&self)
        -> Option<&'startup aos_sandbox_broker::profile_data::schema::EnvironmentProvisionPinV1>
    {
        let startup: &'startup ProductionNormalRootStartupV1 = self.startup;
        startup.native.fields().profile.environment_provision.as_ref()
    }

    stage_method!(admit_environment_request_once_v1, EnvironmentRequest);
    stage_method!(admit_environment_policy_once_v1, EnvironmentPolicy);
    stage_method!(admit_environment_artifact_fixed_once_v1, EnvironmentArtifactFixed);
    stage_method!(admit_environment_artifact_native_once_v1, EnvironmentArtifactNative);
    stage_method!(admit_environment_closure_fixed_once_v1, EnvironmentClosureFixed);
    stage_method!(admit_environment_closure_native_once_v1, EnvironmentClosureNative);
    stage_method!(admit_environment_evidence_fixed_once_v1, EnvironmentEvidenceFixed);
    stage_method!(admit_environment_evidence_native_once_v1, EnvironmentEvidenceNative);
    stage_method!(admit_environment_evidence_publish_once_v1, EnvironmentEvidencePublish);
    stage_method!(admit_environment_response_once_v1, EnvironmentResponse);
    stage_method!(admit_environment_compiler_once_v1, EnvironmentCompiler);
    stage_method!(admit_environment_accepted_once_v1, EnvironmentAccepted);
}

// Only the actual Apply purpose can pay the final proof and fresh read cuts.
// These named methods cannot turn the shared stage DATA into another purpose.
impl RootApplyStageReceivingV1<'_, '_> {
    stage_method!(admit_apply_trust_fixed_once_v1, ApplyTrustFixed);
    stage_method!(admit_apply_trust_typed_once_v1, ApplyTrustTyped);
    stage_method!(admit_apply_bundle_typed_once_v1, ApplyBundleTyped);
    stage_method!(admit_apply_storage_inputs_once_v1, ApplyStorageInputs);
    stage_method!(admit_apply_query_once_v1, ApplyQuery);
    stage_method!(admit_apply_subject_once_v1, ApplySubject);
    stage_method!(admit_apply_final_proof_once_v1, ApplyFinalProof);
    stage_method!(admit_apply_final_controller_fixed_once_v1, ApplyFinalControllerFixed);
    stage_method!(admit_apply_final_controller_native_once_v1, ApplyFinalControllerNative);
    stage_method!(admit_apply_final_controller_semantic_once_v1, ApplyFinalControllerSemantic);
    stage_method!(admit_apply_final_storage_fixed_once_v1, ApplyFinalStorageFixed);
    stage_method!(admit_apply_final_storage_native_once_v1, ApplyFinalStorageNative);
    stage_method!(admit_apply_final_storage_semantic_once_v1, ApplyFinalStorageSemantic);
    stage_method!(admit_apply_final_source_fixed_once_v1, ApplyFinalSourceFixed);
    stage_method!(admit_apply_final_source_native_once_v1, ApplyFinalSourceNative);
    stage_method!(admit_apply_final_source_semantic_once_v1, ApplyFinalSourceSemantic);
    stage_method!(admit_apply_final_response_once_v1, ApplyFinalResponse);
}

impl RootDeleteCacheStageReceivingV2<'_, '_> {
    stage_method!(admit_delete_resource_policy_once_v2, DeleteResourcePolicy);
    stage_method!(admit_delete_resource_trust_once_v2, DeleteResourceTrust);
    stage_method!(admit_delete_resource_assignment_once_v2, DeleteResourceAssignment);
    stage_method!(admit_delete_resource_preparation_once_v2, DeleteResourcePreparation);
    stage_method!(admit_delete_resource_draft_once_v2, DeleteResourceDraft);
    stage_method!(admit_delete_resource_signature_once_v2, DeleteResourceSignature);
    stage_method!(admit_delete_resource_policy_confirmation_once_v2, DeleteResourcePolicyConfirmation);
    stage_method!(admit_delete_preparatory_approval_once_v3, DeletePreparatoryApproval);
    stage_method!(admit_delete_fresh_floor_once_v2, DeleteFreshFloor);
    stage_method!(admit_delete_fresh_transfer_once_v2, DeleteFreshTransfer);
    stage_method!(admit_delete_fresh_transfer_trust_once_v2, DeleteFreshTransferTrust);
    stage_method!(admit_delete_fresh_transfer_observation_once_v2, DeleteFreshTransferObservation);
    stage_method!(admit_delete_fresh_frame_once_v2, DeleteFreshFrame);
    stage_method!(admit_delete_fresh_source_fixed_once_v2, DeleteFreshSourceFixed);
    stage_method!(admit_delete_fresh_source_native_once_v2, DeleteFreshSourceNative);
    stage_method!(admit_delete_fresh_source_semantic_once_v2, DeleteFreshSourceSemantic);

    pub(crate) fn admit_delete_fresh_controller_once_v2(
        &mut self,
        phase: crate::policy_compiler::delete_root::RootDeleteControllerAdmissionPhaseV1,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::DeleteFreshController(phase), demand)
    }

    stage_method!(admit_delete_cache_actionable_once_v2, DeleteCacheActionable);
    stage_method!(admit_delete_initial_inventory_once_v2, DeleteInitialInventory);
    stage_method!(admit_delete_graph_fixed_once_v2, DeleteGraphFixed);
    stage_method!(admit_delete_graph_objects_once_v2, DeleteGraphObjects);
    stage_method!(admit_delete_graph_models_once_v2, DeleteGraphModels);
    stage_method!(admit_delete_graph_comparison_once_v2, DeleteGraphComparison);
}

impl super::RootPurposeControllerPeerReceivingV1<'_, DeleteRootPeerPurposeV1> {
    pub(in crate::normal_root) fn retire_delete_cache_resident_once_v2(&mut self,
        owner: &crate::policy_compiler::delete_root::RootDeleteCacheCurrentOriginalV2,
    ) -> Result<(), Error> {
        self.require_initial_v1()?;
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().retire_delete_cache_resident_once_v2(&mut self.admission, owner);
        receiving.finish_returned_v1(returned)
    }
}

impl super::RootPurposeControllerPeerReceivingV1<'_, DeleteRootPeerPurposeV1> {
    pub(in crate::normal_root) fn delete_cache_retirement_failure_v2(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.admission.delete_cache_retirement_failure_v2()
    }
}

// Only the genuine fresh Start Host/resource purpose receives these named
// destinations; a typed input or another Root marker cannot call this adapter.
impl RootHostLaunchStageReceivingV1<'_, '_> {
    stage_method!(admit_host_catalog_network_fixed_once_v2, HostCatalogNetworkFixed);
    stage_method!(admit_host_catalog_network_native_once_v2, HostCatalogNetworkNative);
    stage_method!(admit_host_catalog_network_semantic_once_v2, HostCatalogNetworkSemantic);
    stage_method!(admit_host_catalog_mount_fixed_once_v2, HostCatalogMountFixed);
    stage_method!(admit_host_catalog_mount_native_once_v2, HostCatalogMountNative);
    stage_method!(admit_host_catalog_mount_semantic_once_v2, HostCatalogMountSemantic);
    stage_method!(admit_host_catalog_models_once_v2, HostCatalogModels);
    stage_method!(admit_mount_before62_fixed_once_v2, MountBefore62Fixed);
    stage_method!(admit_mount_before62_native_once_v2, MountBefore62Native);
    stage_method!(admit_mount_before62_semantic_once_v2, MountBefore62Semantic);

    stage_method!(admit_host_query_once_v1, HostQuery);
    stage_method!(admit_host_subject_once_v1, HostSubject);
    stage_method!(admit_host_trust_fixed_once_v1, HostTrustFixed);
    stage_method!(admit_host_trust_typed_once_v1, HostTrustTyped);
    stage_method!(admit_host_accepted_start_once_v1, HostAcceptedStart);
    stage_method!(admit_host_historical_create_once_v1, HostHistoricalCreate);
    stage_method!(admit_host_fresh_ownership_once_v1, HostFreshOwnership);
    stage_method!(admit_host_request_typed_once_v1, HostRequestTyped);
    stage_method!(admit_host_plan_once_v1, HostPlan);
    stage_method!(admit_host_final_proof_once_v1, HostFinalProof);
    stage_method!(admit_host_final_controller_fixed_once_v1, HostFinalControllerFixed);
    stage_method!(admit_host_final_controller_native_once_v1, HostFinalControllerNative);
    stage_method!(admit_host_final_controller_semantic_once_v1, HostFinalControllerSemantic);
    stage_method!(admit_host_final_session_fixed_once_v1, HostFinalSessionFixed);
    stage_method!(admit_host_final_session_native_once_v1, HostFinalSessionNative);
    stage_method!(admit_host_final_session_semantic_once_v1, HostFinalSessionSemantic);
    stage_method!(admit_host_final_source_fixed_once_v1, HostFinalSourceFixed);
    stage_method!(admit_host_final_source_native_once_v1, HostFinalSourceNative);
    stage_method!(admit_host_final_source_semantic_once_v1, HostFinalSourceSemantic);
    stage_method!(admit_host_final_models_once_v1, HostFinalModels);
    stage_method!(admit_host_final_response_once_v1, HostFinalResponse);
}

/// Lends only a genuine Recover purpose's closed metadata observation stages.
pub(crate) struct RootFinalityRecoverStageReceivingV1<'flight, 'startup> {
    startup: &'startup ProductionNormalRootStartupV1,
    admission: &'flight mut RootPurposePeerAdmissionV1<FinalityRecoverRootPeerPurposeV1>,
}

impl<'flight, 'startup> RootFinalityRecoverStageReceivingV1<'flight, 'startup> {
    pub(super) fn new_v1(startup: &'startup ProductionNormalRootStartupV1,
        admission: &'flight mut RootPurposePeerAdmissionV1<FinalityRecoverRootPeerPurposeV1>,
    ) -> Self {
        Self { startup, admission }
    }

    pub(crate) fn controller_identity_v1(&self) -> (u32, u32) {
        let identities = self.startup.native.fields().profile.identities;
        (identities[0], identities[1])
    }

    pub(crate) fn enrolled_node_v1(&self) -> Result<[u8; 16], Error> {
        self.admission.require_armed_v1().map_err(|_|Error::Service)?;
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().current_enrolled_node_data_v1();
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn controller_baseline_partition_v1(&self)
        -> Result<(aos_sandbox_model::ResourceVector, aos_sandbox_model::ResourceVector,
            aos_sandbox_model::ResourceVector), Error> {
        self.admission.require_armed_v1().map_err(|_|Error::Service)?;
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().current_controller_baseline_partition_data_v1();
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.admission.continuation_failure_v1()
    }

    stage_method!(admit_finality_recover_query_once_v1, FinalityRecoverQuery);
    stage_method!(admit_finality_recover_trust_fixed_once_v1, FinalityRecoverTrustFixed);
    stage_method!(admit_finality_recover_trust_typed_once_v1, FinalityRecoverTrustTyped);
    stage_method!(admit_finality_recover_controller_fixed_once_v1, FinalityRecoverControllerFixed);
    stage_method!(admit_finality_recover_controller_native_once_v1, FinalityRecoverControllerNative);
    stage_method!(admit_finality_recover_controller_semantic_once_v1, FinalityRecoverControllerSemantic);
    stage_method!(admit_finality_recover_source_fixed_once_v1, FinalityRecoverSourceFixed);
    stage_method!(admit_finality_recover_source_native_once_v1, FinalityRecoverSourceNative);
    stage_method!(admit_finality_recover_source_semantic_once_v1, FinalityRecoverSourceSemantic);
    stage_method!(admit_finality_recover_session_fixed_once_v1, FinalityRecoverSessionFixed);
    stage_method!(admit_finality_recover_session_native_once_v1, FinalityRecoverSessionNative);
    stage_method!(admit_finality_recover_session_semantic_once_v1, FinalityRecoverSessionSemantic);
    stage_method!(admit_finality_recover_models_once_v1, FinalityRecoverModels);
    stage_method!(admit_finality_recover_response_once_v1, FinalityRecoverResponse);

    fn admit_once(&mut self, stage: RootContinuationStageV1, demand: RootContinuationDemandV1)
        -> Result<(), Error> {
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().admit_purpose_stage_once_v1(self.admission, stage, demand);
        receiving.finish_returned_v1(returned)
    }
}

/// Borrows only the read-only accepted Start input flight's finite stages.
pub(crate) struct RootStartAssignmentInputsStageReceivingV2<'flight, 'startup> {
    startup: &'startup ProductionNormalRootStartupV1,
    admission: &'flight mut RootPurposePeerAdmissionV1<
        crate::controller_resource_reservation::StartAssignmentInputsRootPeerPurposeV2,
    >,
}

impl<'flight, 'startup> RootStartAssignmentInputsStageReceivingV2<'flight, 'startup> {
    pub(super) fn new_v2(
        startup: &'startup ProductionNormalRootStartupV1,
        admission: &'flight mut RootPurposePeerAdmissionV1<
            crate::controller_resource_reservation::StartAssignmentInputsRootPeerPurposeV2,
        >,
    ) -> Self {
        Self { startup, admission }
    }

    pub(crate) fn controller_identity_v1(&self) -> (u32, u32) {
        let identities = self.startup.native.fields().profile.identities;
        (identities[0], identities[1])
    }

    pub(crate) fn enrolled_node_v1(&self) -> Result<[u8; 16], Error> {
        self.admission.require_armed_v1().map_err(|_| Error::Service)?;
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().current_enrolled_node_data_v1();
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn controller_baseline_partition_v1(&self)
        -> Result<(aos_sandbox_model::ResourceVector, aos_sandbox_model::ResourceVector,
            aos_sandbox_model::ResourceVector), Error>
    {
        self.admission.require_armed_v1().map_err(|_| Error::Service)?;
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().current_controller_baseline_partition_data_v1();
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.admission.continuation_failure_v1()
    }

    stage_method!(admit_start_assignment_inputs_query_once_v2, StartAssignmentInputsQuery);
    stage_method!(admit_start_assignment_inputs_subject_once_v2, StartAssignmentInputsSubject);
    stage_method!(admit_start_assignment_inputs_policy_fixed_once_v2, StartAssignmentInputsPolicyFixed);
    stage_method!(admit_start_assignment_inputs_policy_typed_once_v2, StartAssignmentInputsPolicyTyped);
    stage_method!(admit_start_assignment_inputs_controller_fixed_once_v2, StartAssignmentInputsControllerFixed);
    stage_method!(admit_start_assignment_inputs_controller_native_once_v2, StartAssignmentInputsControllerNative);
    stage_method!(admit_start_assignment_inputs_controller_semantic_once_v2, StartAssignmentInputsControllerSemantic);
    stage_method!(admit_start_assignment_inputs_source_fixed_once_v2, StartAssignmentInputsSourceFixed);
    stage_method!(admit_start_assignment_inputs_source_native_once_v2, StartAssignmentInputsSourceNative);
    stage_method!(admit_start_assignment_inputs_source_semantic_once_v2, StartAssignmentInputsSourceSemantic);
    stage_method!(admit_start_assignment_inputs_models_once_v2, StartAssignmentInputsModels);
    stage_method!(admit_start_assignment_inputs_response_once_v2, StartAssignmentInputsResponse);

    fn admit_once(&mut self, stage: RootContinuationStageV1, demand: RootContinuationDemandV1)
        -> Result<(), Error>
    {
        let mut receiving = self.startup.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().admit_purpose_stage_once_v1(self.admission, stage, demand);
        receiving.finish_returned_v1(returned)
    }
}

impl RootProvisioningStageReceivingV1<'_, '_, DeleteRootPeerPurposeV1> {
    pub(crate) fn admit_delete_preparation_current_once_v3(&mut self,
        phase: crate::policy_compiler::delete_root::RootDeletePreparationCurrentPhaseV3,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::DeletePreparationCurrent(phase), demand)
    }

    pub(crate) fn admit_delete_cleanup_current_once_v4(&mut self,
        phase: crate::policy_compiler::delete_root::RootDeleteCleanupCurrentPhaseV4,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::DeleteCleanupCurrent(phase), demand)
    }

    pub(crate) fn admit_delete_apply_issuer_once_v3(&mut self,
        phase: crate::policy_compiler::delete_root::RootDeleteApplyIssuerPhaseV3,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::DeleteApplyIssuer(phase), demand)
    }

    pub(crate) fn admit_delete_resource_continuation_once_v4(&mut self,
        purpose: aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3,
        phase: crate::policy_compiler::delete_root::RootDeleteApplyIssuerPhaseV3,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        use aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3 as P;
        let stage = match purpose {
            P::Preparation26 => return Err(Error::Service),
            P::Apply7 => RootContinuationStageV1::DeleteApplyIssuer(phase),
            P::Network9 => RootContinuationStageV1::DeleteNetworkIssuer(phase),
            P::MountReap62 => RootContinuationStageV1::DeleteMountIssuer(phase),
        };
        self.admit_once(stage, demand)
    }

    pub(crate) fn admit_delete_mount_spec_once_v4(&mut self,
        phase: crate::policy_compiler::delete_root::RootDeleteMountSpecPhaseV4,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::DeleteMountSpec(phase), demand)
    }

    pub(crate) fn admit_delete_completion_once_v4(&mut self,
        phase: crate::policy_compiler::delete_root::RootDeleteCompletionPhaseV4,
        demand: RootContinuationDemandV1,
    ) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::DeleteCompletion(phase), demand)
    }
}

// Only its actual sealed R purpose can borrow these current Storage31 stages.
impl RootMaintenanceStorageStageReceivingV2<'_, '_> {
    pub(crate) fn admit_maintenance_query_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::Query), demand)
    }

    pub(crate) fn admit_maintenance_subject_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::Subject), demand)
    }

    pub(crate) fn admit_maintenance_trust_fixed_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::TrustFixed), demand)
    }

    pub(crate) fn admit_maintenance_trust_typed_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::TrustTyped), demand)
    }

    pub(crate) fn admit_maintenance_current_assignment_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::CurrentAssignment), demand)
    }

    pub(crate) fn admit_maintenance_current_inventory_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::CurrentInventory), demand)
    }

    pub(crate) fn admit_maintenance_live_ownership_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::LiveOwnership), demand)
    }

    pub(crate) fn admit_maintenance_request_typed_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::RequestTyped), demand)
    }

    pub(crate) fn admit_maintenance_plan_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::Plan), demand)
    }

    pub(crate) fn admit_maintenance_final_proof_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::FinalProof), demand)
    }

    pub(crate) fn admit_maintenance_final_controller_fixed_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::FinalControllerFixed), demand)
    }

    pub(crate) fn admit_maintenance_final_controller_native_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::FinalControllerNative), demand)
    }

    pub(crate) fn admit_maintenance_final_controller_semantic_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::FinalControllerSemantic), demand)
    }

    pub(crate) fn admit_maintenance_final_session_fixed_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::FinalSessionFixed), demand)
    }

    pub(crate) fn admit_maintenance_final_session_native_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::FinalSessionNative), demand)
    }

    pub(crate) fn admit_maintenance_final_session_semantic_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::FinalSessionSemantic), demand)
    }

    pub(crate) fn admit_maintenance_final_source_fixed_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::FinalSourceFixed), demand)
    }

    pub(crate) fn admit_maintenance_final_source_native_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::FinalSourceNative), demand)
    }

    pub(crate) fn admit_maintenance_final_source_semantic_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::FinalSourceSemantic), demand)
    }

    pub(crate) fn admit_maintenance_final_models_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::FinalModels), demand)
    }

    pub(crate) fn admit_maintenance_final_response_once_v2(&mut self, demand: RootContinuationDemandV1) -> Result<(), Error> {
        self.admit_once(RootContinuationStageV1::MaintenanceStorage(RootMaintenanceStorageStageV2::FinalResponse), demand)
    }

}
