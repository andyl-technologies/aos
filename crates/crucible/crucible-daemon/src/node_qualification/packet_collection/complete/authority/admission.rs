//! Authenticates original preparation without admitting runtime effects.

use super::*;
use crucible_engine::{
    node_adapters::cnp::{
        CnpSemanticConformanceAuthority, CnpSemanticRealizationScope, CnpSemanticRegistrationPolicy,
    },
    node_admission::{
        AdmissionEvidence, ConformanceAdmissionAuthority, NodeCapabilityRequirement,
        QualificationClaim,
    },
};
use crucible_node_format::{ImplementationIdentity, NodeBinding, SchemaRef};

impl AdmissionEvidence for InstalledPacketCompleteCollectionAuthority {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        self.current().map_err(evidence_error)?;
        let answer = if let Some(body) = self.population.bodies.get(reference) {
            if body.len() > maximum {
                return Err(evidence_error(refused()));
            }
            reference
                .verify(body)
                .map_err(|error| evidence_error(error.into()))?;
            body.clone()
        } else {
            self.graph_policy.content(reference, maximum)?
        };
        self.current().map_err(evidence_error)?;
        Ok(answer)
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        self.graph_policy
            .authenticate_implementation(implementation)?;
        self.current().map_err(evidence_error)
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        self.graph_policy.authenticate_authority(binding)?;
        self.current().map_err(evidence_error)
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        self.graph_policy.authenticate_schema(schema)?;
        self.current().map_err(evidence_error)
    }

    fn qualify_capability(
        &self,
        world: &WorldBinding,
        binding: &NodeBinding,
        requirement: &NodeCapabilityRequirement,
    ) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        self.graph_policy
            .qualify_capability(world, binding, requirement)
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        self.current().map_err(evidence_error)?;
        self.graph_policy.qualify(claim)
    }
}

impl ConformanceAdmissionAuthority for InstalledPacketCompleteCollectionAuthority {
    fn authenticate_complete_archive_code_schema_roster(
        &self,
        plan: &crucible_engine::node_admission::InstalledConformancePlan,
        binding: &NodeBinding,
        schemas: &[SchemaRef],
    ) -> Option<Result<(), EvidenceError>> {
        // Only the separate never-enrolled historical code authority uses this
        // path. Ordinary/live callbacks keep their original per-schema checks.
        if self.capture_factory.get().is_some()
            || self.execution_scene.get().is_some()
            || self.report_startup_holder.get().is_some()
            || self.original_initial_callback_active.get()
            || self.original_runtime_callback_active.get()
        {
            return None;
        }
        Some((|| {
            plan.authenticate_authority(self)?;
            self.graph_policy
                .authenticate_schema_roster_data(binding, schemas)?;
            plan.authenticate_authority(self)
        })())
    }

    fn original_runtime_construction_policy(
        &self,
        _: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalRuntimeConstructionScope<'_>,
    ) -> Result<
        crucible_engine::node_admission::OriginalRuntimeConstructionPolicy,
        crucible_engine::node_contract::RuntimeError,
    > {
        self.original_runtime_construction_policy_data(scope)
    }

    fn authenticate_original_runtime_construction(
        &self,
        _: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalRuntimeConstructionScope<'_>,
        policy: &crucible_engine::node_admission::OriginalRuntimeConstructionPolicy,
    ) -> Result<
        crucible_engine::node_admission::OriginalRuntimeConstructionStorage,
        crucible_engine::node_contract::RuntimeError,
    > {
        self.authenticate_original_runtime_construction_data(scope, policy)
    }

    fn authenticate_original_runtime_construction_member(
        &self,
        _: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalRuntimeConstructionScope<'_>,
    ) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        self.authenticate_original_runtime_construction_member_data(scope)
    }

    fn original_restoration_construction_policy(
        &self,
        _evidence: &crucible_engine::node_admission::ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalRestorationConstructionScope<'_>,
    ) -> Result<
        crucible_engine::node_admission::OriginalRestorationConstructionPolicy,
        crucible_engine::node_contract::RuntimeError,
    > {
        self.original_restoration_construction_policy_data(scope)
    }

    fn authenticate_original_restoration_construction(
        &self,
        _evidence: &crucible_engine::node_admission::ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalRestorationConstructionScope<'_>,
        policy: &crucible_engine::node_admission::OriginalRestorationConstructionPolicy,
    ) -> Result<
        crucible_engine::node_admission::OriginalRestorationConstructionStorage,
        crucible_engine::node_contract::RuntimeError,
    > {
        self.authenticate_original_restoration_construction_data(scope, policy)
    }

    fn authenticate_original_restoration_construction_member(
        &self,
        _evidence: &crucible_engine::node_admission::ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalRestorationMemberScope<'_>,
    ) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        self.authenticate_original_restoration_construction_member_data(scope)
    }

    fn original_host_initial_lifecycle_policy(
        &self,
        _evidence: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalHostInitialLifecycleScope<'_>,
    ) -> Result<
        crucible_engine::node_admission::OriginalHostInitialLifecyclePolicy,
        crucible_engine::node_contract::RuntimeError,
    > {
        self.original_host_initial_lifecycle_policy_data(scope)
    }

    fn authenticate_original_host_initial_lifecycle(
        &self,
        _evidence: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalHostInitialLifecycleScope<'_>,
        policy: &crucible_engine::node_admission::OriginalHostInitialLifecyclePolicy,
    ) -> Result<
        crucible_engine::node_admission::OriginalHostInitialLifecycleStorage,
        crucible_engine::node_contract::RuntimeError,
    > {
        self.authenticate_original_host_initial_lifecycle_data(scope, policy)
    }

    fn authenticate_original_host_initial_lifecycle_member(
        &self,
        _evidence: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalHostInitialLifecycleMemberScope<'_>,
    ) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        self.authenticate_original_host_initial_lifecycle_member_data(scope)
    }

    fn original_native_host_startup_policy(
        &self,
        _plan: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalNativeHostStartupScope<'_>,
    ) -> Result<
        crucible_engine::node_admission::OriginalNativeHostStartupPolicy,
        crucible_engine::node_contract::RuntimeError,
    > {
        self.original_native_host_startup_policy_data(scope)
    }

    fn authenticate_original_native_host_startup(
        &self,
        _plan: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalNativeHostStartupScope<'_>,
        policy: &crucible_engine::node_admission::OriginalNativeHostStartupPolicy,
    ) -> Result<
        crucible_engine::node_admission::OriginalNativeHostStartupStorage,
        crucible_engine::node_contract::RuntimeError,
    > {
        self.authenticate_original_native_host_startup_data(scope, policy)
    }

    fn authenticate_original_native_host_startup_member(
        &self,
        _plan: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalNativeHostStartupMemberScope<'_>,
    ) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        self.authenticate_original_native_host_startup_member_data(scope)
    }

    fn original_native_startup_policy(
        &self,
        _plan: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalNativeStartupScope<'_>,
    ) -> Result<
        crucible_engine::node_admission::OriginalNativeStartupPolicy,
        crucible_engine::node_contract::RuntimeError,
    > {
        self.original_native_startup_policy_data(scope)
    }

    fn authenticate_original_native_startup(
        &self,
        _plan: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalNativeStartupScope<'_>,
        policy: &crucible_engine::node_admission::OriginalNativeStartupPolicy,
    ) -> Result<
        crucible_engine::node_admission::OriginalNativeStartupStorage,
        crucible_engine::node_contract::RuntimeError,
    > {
        self.authenticate_original_native_startup_data(scope, policy)
    }

    fn original_native_invocation_data(
        &self,
        _plan: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalNativeStartupScope<'_>,
    ) -> Result<[crucible_node_transport::reference_packet::service::native_startup::PacketNativeInvocationPurposeData; 3], crucible_engine::node_contract::RuntimeError>{
        self.original_native_invocation_data(scope)
    }

    fn original_restored_suffix_startup_data(
        &self,
        _plan: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalNativeStartupScope<'_>,
    ) -> Result<[
        crucible_node_transport::reference_packet::service::native_startup::PacketNativeRestoredSuffixStartupStorageData;
        3
    ], crucible_engine::node_contract::RuntimeError>{
        self.original_restored_suffix_startup_data(scope)
    }

    fn authenticate_original_native_startup_member(
        &self,
        _plan: &ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalNativeStartupMemberScope<'_>,
    ) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        self.authenticate_original_native_startup_member_data(scope)
    }

    fn authenticate_original_fresh_restore_host_member(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalFreshRestoreHostMemberScope<'_>,
    ) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        self.authenticate_original_fresh_restore_host_member_data(scope)
    }

    fn original_fresh_restore_host_policy(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalFreshRestoreHostScope<'_>,
    ) -> Result<
        crucible_engine::node_admission::OriginalFreshRestoreHostPolicy,
        crucible_engine::node_contract::RuntimeError,
    > {
        self.original_fresh_restore_host_policy_data(scope)
    }

    fn authenticate_original_fresh_restore_host(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalFreshRestoreHostScope<'_>,
        policy: &crucible_engine::node_admission::OriginalFreshRestoreHostPolicy,
    ) -> Result<
        crucible_engine::node_admission::OriginalFreshRestoreHostStorage,
        crucible_engine::node_contract::RuntimeError,
    > {
        self.authenticate_original_fresh_restore_host_data(scope, policy)
    }

    fn original_report_startup_policy(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalReportStartupScope<'_>,
    ) -> Result<crucible_engine::node_admission::OriginalReportStartupPolicy, EvidenceError> {
        self.original_report_startup_policy_data(scope)
    }

    fn authenticate_original_report_startup(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalReportStartupScope<'_>,
        policy: &crucible_engine::node_admission::OriginalReportStartupPolicy,
    ) -> Result<crucible_engine::node_admission::OriginalReportStartupStorage, EvidenceError> {
        self.original_report_startup_storage_data(scope, policy)
    }

    fn authenticate_original_report_startup_member(
        &self,
        _plan: ConformancePlanEvidence<'_>,
        scope: &crucible_engine::node_admission::OriginalReportStartupMemberScope<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_original_report_startup_member_data(scope)
    }

    fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, crucible_engine::node_contract::RuntimeError> {
        self.original_retained_requested_storage_precredit_data(maximum)
            .map(Some)
    }

    fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, EvidenceError> {
        self.original_retained_authority_backing(maximum)
            .map(Some)
            .map_err(evidence_error)
    }

    fn authenticate_collection_world(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: crucible_engine::node_admission::AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        self.original_execution_scene()
            .map_err(evidence_error)?
            .world_request(request)
            .map_err(evidence_error)
    }

    fn authenticate_collection_current_scope(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: crucible_engine::node_admission::AdmissionRequest<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        self.original_execution_scene()
            .map_err(evidence_error)?
            .world_request(request)
            .map_err(evidence_error)?;
        // This compiled source read follows every preceding host callback;
        // no vendor-provided callback is invoked after the terminal read.
        self.roster.current_native().map_err(|error| EvidenceError {
            message: error.reason,
        })
    }

    fn authenticate_collection_node(
        &self,
        plan: ConformancePlanEvidence<'_>,
        claim: QualificationClaim<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        let scene = self.original_execution_scene().map_err(evidence_error)?;
        scene.preparation().map_err(evidence_error)?;
        let QualificationClaim::Node {
            binding,
            binding_hash,
            qualification_refs,
        } = claim
        else {
            return Err(evidence_error(refused()));
        };
        let selected = self
            .roster
            .sources
            .iter()
            .map(|source| &source.installation().binding)
            .chain(std::iter::once(&self.host.selection().binding))
            .find(|selected| &selected.compatibility == binding)
            .ok_or_else(|| evidence_error(refused()))?;
        if binding_hash
            != &selected
                .compatibility
                .identity()
                .map_err(|error| evidence_error(error.into()))?
            || qualification_refs != selected.compatibility.qualification_refs
        {
            return Err(evidence_error(refused()));
        }
        scene.preparation().map_err(evidence_error)
    }

    fn authenticate_collection_exact_inputs(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: crucible_engine::node_admission::AdmissionRequest<'_>,
        source: &crucible_engine::node_contract::HostSchedulingSource,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        let scene = self.original_execution_scene().map_err(evidence_error)?;
        scene.world_request(request).map_err(evidence_error)?;
        scene.exact_source(source).map_err(evidence_error)
    }

    fn authenticate_collection_inputs(
        &self,
        plan: ConformancePlanEvidence<'_>,
        batch: &crucible_engine::node_scheduling::RuntimeInputBatch,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        self.original_execution_scene()
            .map_err(evidence_error)?
            .inputs(batch)
            .map_err(evidence_error)
    }

    fn authenticate_collection_operation(
        &self,
        plan: ConformancePlanEvidence<'_>,
        node: &crucible_node_format::Id,
        operation: &crucible_node_format::Id,
        request: &crucible_engine::node_contract::OperationRequest,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        self.original_execution_scene()
            .map_err(evidence_error)?
            .operation(node, operation, request)
            .map_err(evidence_error)
    }

    fn authenticate_collection_plan(
        &self,
        plan: ConformancePlanEvidence<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)
    }

    fn authenticate_collection_capture_profile(
        &self,
        plan: ConformancePlanEvidence<'_>,
        claim: QualificationClaim<'_>,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        self.original_capture_factory()?
            .authenticate_capture_profile(claim)
            .map_err(|error| EvidenceError {
                message: error.to_string(),
            })
    }

    fn authenticate_collection_capture(
        &self,
        plan: ConformancePlanEvidence<'_>,
        request: crucible_engine::node_admission::AdmissionRequest<'_>,
        source: &HostSchedulingSource,
        runtime: &crucible_engine::node_contract::OriginalLineageRuntimeRecord,
        scheduling: &crucible_engine::node_scheduling::SchedulingSnapshot,
        capture_id: &crucible_node_format::Id,
    ) -> Result<(), EvidenceError> {
        self.authenticate_plan_view(plan)?;
        crucible_node_format::Validate::validate(capture_id).map_err(|error| EvidenceError {
            message: error.to_string(),
        })?;
        self.original_capture_factory()?
            .authenticate_collecting_request(request, source, runtime, scheduling)
            .map_err(|error| EvidenceError {
                message: error.to_string(),
            })
    }
}

impl CnpSemanticRegistrationPolicy for InstalledPacketCompleteCollectionAuthority {
    fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, crucible_engine::node_contract::RuntimeError> {
        self.original_retained_requested_storage_precredit_data(maximum)
            .map(Some)
    }

    fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, OperationFailure> {
        InstalledPacketCompleteCollectionAuthority::original_retained_requested_storage_data(
            self, maximum,
        )
        .map(Some)
        .map_err(operation_error)
    }

    fn authenticate(&self, selected: &CnpSemanticInstallation) -> Result<(), OperationFailure> {
        self.current_for_original_initial_callback()
            .map_err(operation_error)?;
        self.index(selected).map_err(operation_error)?;
        self.current_for_original_initial_callback()
            .map_err(operation_error)
    }
}

impl CnpSemanticConformanceAuthority for InstalledPacketCompleteCollectionAuthority {
    fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, crucible_engine::node_contract::RuntimeError> {
        self.original_retained_requested_storage_precredit_data(maximum)
            .map(Some)
    }

    fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, OperationFailure> {
        InstalledPacketCompleteCollectionAuthority::original_retained_requested_storage_data(
            self, maximum,
        )
        .map(Some)
        .map_err(operation_error)
    }

    fn authenticate_graph(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        graph: &crucible_engine::node_admission::ConformanceGraph,
    ) -> Result<(), OperationFailure> {
        self.current_for_original_initial_callback()
            .map_err(operation_error)?;
        let member = self.index(scope.installation).map_err(operation_error)?;
        graph
            .plan()
            .authenticate_authority(self)
            .map_err(|error| operation_error(QualificationError::Evidence(error.to_string())))?;
        if graph.world() != &self.world {
            return Err(operation_error(refused()));
        }
        graph
            .reauthenticate()
            .map_err(|error| operation_error(QualificationError::Evidence(error.to_string())))?;
        self.original_execution_scene()
            .map_err(operation_error)?
            .observe_original(member, scope)
            .map_err(operation_error)
    }

    fn authenticate_native_dispatch(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        plan: &InstalledConformancePlan,
    ) -> Result<(), OperationFailure> {
        self.current_for_original_initial_callback()
            .map_err(operation_error)?;
        let member = self.index(scope.installation).map_err(operation_error)?;
        plan.authenticate_authority(self)
            .map_err(|error| operation_error(QualificationError::Evidence(error.to_string())))?;
        self.original_execution_scene()
            .map_err(operation_error)?
            .observe_original(member, scope)
            .map_err(operation_error)?;
        self.host.authenticate_dispatch_source()?;
        self.roster.current_native()?;
        self.current_for_original_initial_callback()
            .map_err(operation_error)
    }

    fn authenticate_installation(
        &self,
        selected: &CnpSemanticInstallation,
    ) -> Result<(), OperationFailure> {
        self.current_for_original_initial_callback()
            .map_err(operation_error)?;
        self.index(selected).map_err(operation_error)?;
        self.current_for_original_initial_callback()
            .map_err(operation_error)
    }

    fn authenticate_realization(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.current_for_original_initial_callback()
            .map_err(operation_error)?;
        let index = self.index(scope.installation).map_err(operation_error)?;
        let source = &self.roster.sources[index];
        source.authenticate_provider(scope.native)?;
        source.authenticate_realization(scope)?;
        source.authenticate_original_native_owner(scope.native)?;
        source.authenticate_realized_preconstruction(&scope)?;
        if source.selected_ack_emitter_selection()?.is_some() {
            self.original_ack_callback_started.set(true);
            let slot = self
                .original_ack_hello
                .try_borrow()
                .map_err(|_| operation_error(refused()))?[index]
                .as_ref()
                .cloned()
                .ok_or_else(|| operation_error(refused()))?;
            let mut original = slot
                .try_borrow_mut()
                .map_err(|_| operation_error(refused()))?;
            source.retain_original_canonical_ack_peer_association(&scope, &mut original)?;
        }
        self.current_for_original_initial_callback()
            .map_err(operation_error)
    }
}
