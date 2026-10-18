//! Common trait forwarding beneath current installed native and acceptance authority.

use std::task::{Context, Poll};

#[path = "implementation/facets.rs"]
mod facets;

pub(super) fn selected_facet_counter_scratch_data() -> usize {
    facets::counter_scratch_data()
}

use crucible_node_contract::{
    ContentRef, Extensions, Id, NodeBinding, NodeDescriptor, PreparedOwner, U64,
};
use crucible_node_provider::{bodies::*, envelope::Method};

use crate::{
    node_contract::*,
    node_scheduling::{
        InputCustodyCommit, InputPayload, NativeInputAcknowledgement, NativeSchedulingObservation,
        RuntimeInputBatch,
    },
};

use super::{CnpSemanticNode, refused, unknown};

impl FacetDescription for CnpSemanticNode {
    fn profile(&self) -> &Id {
        &self.exact_profile
    }
}

impl SimulationNode for CnpSemanticNode {
    fn inspect_original_initial_preparation_data(
        &self,
        ticket: &crate::node_admission::CompleteOriginalFreshRestoreHostWindow,
        source: &std::rc::Rc<super::PacketCompleteSemanticSource>,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        CnpSemanticNode::inspect_original_initial_preparation_data(self, ticket, source, plan)
    }

    fn retained_original_initial_requested_storage_precredit_data(
        &self,
        source: &std::rc::Rc<super::PacketCompleteSemanticSource>,
        maximum: usize,
    ) -> Result<Option<usize>, RuntimeError> {
        self.preparation
            .guard
            .preparation_storage_origin_precredit_data()?;
        let scratch = super::CnpPreparationStorageScratch::new(
            super::CnpPreparationStorageScratch::requested_bytes(),
        )?;
        let complete = CnpSemanticNode::retained_original_initial_requested_storage_precredit_data(
            self, source, &scratch, maximum,
        )?
        .complete_requested_bytes_precredit_data()?;
        let nested = complete
            .checked_sub(std::mem::size_of::<Self>())
            .ok_or(RuntimeError::ForeignAuthority)?;
        Ok(Some(nested))
    }

    fn retained_original_initial_requested_storage_precredit_scratch_data(
        &self,
    ) -> Result<Option<usize>, RuntimeError> {
        self.preparation
            .guard
            .preparation_storage_origin_precredit_data()?;
        if self.retained_registry.is_none()
            || self.retained_supervisor.is_none()
            || self.retained_operational.is_none()
        {
            return Ok(None);
        }
        super::CnpSemanticPreparation::original_initial_node_retained_counter_scratch_data()
            .map(Some)
    }

    fn quote_original_restored_capture_prequote(
        &self,
        launch: &crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        request: &crate::node_admission::OriginalRestoredCaptureRequestData<'_>,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        self.quote_installed_restored_capture_prequote_data(
            launch,
            canonical_launch5,
            request,
            maximum,
        )
    }

    fn reserve_original_restored_capture_counting_banks(
        &self,
        launch: &crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        request: &crate::node_admission::OriginalRestoredCaptureRequestData<'_>,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.reserve_installed_restored_capture_counting_banks_data(
            launch,
            canonical_launch5,
            request,
            maximum,
        )
    }

    fn quote_original_restored_capture_construction(
        &self,
        launch: &crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        request: &crate::node_admission::OriginalRestoredCaptureRequestData<'_>,
        maximum: usize,
    ) -> Result<
        crate::node_adapters::cnp::OriginalSourceRestoredCaptureConstructionData,
        RuntimeError,
    > {
        self.quote_installed_restored_capture_construction_data(
            launch,
            canonical_launch5,
            request,
            maximum,
        )
    }

    fn quote_original_restored_producer_execution(
        &self,
        grant: &crate::node_scheduling::ExecutionAdmission,
        launch: &crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch,
        raw5: &[u8],
        maximum: usize,
    ) -> Result<
        crate::node_admission::OriginalRestoredProducerExecutionConstructionData,
        RuntimeError,
    > {
        self.quote_installed_producer_execution_data(grant, launch, raw5, maximum)
    }

    fn begin_original_restored_producer_operation(
        &mut self,
        dispatch: &OriginalRuntimeOperationDispatch<'_>,
        claim: &crate::node_admission::OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Submission {
        match self.begin_installed_producer_execution_data(dispatch, claim) {
            Ok(()) => Submission::Accepted,
            Err(_) => Submission::Uncertain(EffectKnowledge::MayHaveProgressed),
        }
    }

    fn requires_original_restored_producer_claim_data(&self, token: &OperationToken) -> bool {
        self.requires_installed_producer_claim_data(token)
    }

    fn poll_original_restored_producer_operation(
        &mut self,
        token: &OperationToken,
        claim: &crate::node_admission::OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<OperationOutcome, OperationFailure> {
        self.poll_installed_producer_execution_data(token, claim)
    }

    fn with_original_restored_producer_report_data(
        &mut self,
        original: &OperationAdmission,
        claim: &crate::node_admission::OriginalRestoredProducerExecutionClaim<'_>,
        inspect: &mut dyn FnMut(
            &OriginalRestoredProducerReportReadScope<'_>,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.with_installed_producer_report_data(original, claim, inspect)
    }

    fn acknowledge_original_restored_producer_publication(
        &mut self,
        token: &OperationToken,
        outputs: &[Id],
        claim: &crate::node_admission::OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<(), OperationFailure> {
        self.retire_installed_producer_execution_data(token, outputs, claim)
    }

    fn observe_original_restored_producer_scheduling(
        &mut self,
        original: &OperationAdmission,
        claim: &crate::node_admission::OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        self.observe_installed_producer_checkpoint_data(original, claim)
    }

    fn original_restoration_construction_scratch_data(
        &self,
    ) -> Result<Option<usize>, RuntimeError> {
        self.original_restoration_construction_counter_scratch_data()
            .map(Some)
    }

    fn original_restoration_construction_data(
        &self,
        inputs: &crate::node_admission::OriginalRestorationNodeInputs<'_>,
    ) -> Result<Option<crate::node_admission::OriginalRestorationNodeConstructionData>, RuntimeError>
    {
        CnpSemanticNode::original_restoration_construction_data(self, inputs).map(Some)
    }

    fn execute_original_restoration_transaction(
        &mut self,
        dispatch: crate::node_admission::OriginalRestorationNodeDispatch<'_>,
    ) -> Result<(), RuntimeError> {
        self.execute_original_restoration_transaction_data(dispatch)
    }

    fn inspect_original_restoration_continuation(
        &self,
        inspection: crate::node_admission::OriginalRestorationNodeContinuationInspection<'_>,
    ) -> Result<(), RuntimeError> {
        self.inspect_original_restoration_continuation_data(inspection)
    }

    fn activate_original_installed_restoration_world(
        &mut self,
        world: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        if !self.has_installed_restoration_data() {
            return Err(RuntimeError::InvalidReceipt);
        }
        self.activate_installed_restoration(world)
            .map_err(|_| RuntimeError::InvalidReceipt)
    }

    fn retained_descriptor_views_precredit_data(&self) -> Result<Option<usize>, RuntimeError> {
        self.preparation
            .retained_descriptor_views_precredit_data()
            .map(Some)
    }

    fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, RuntimeError> {
        if self.retained_registry.is_none()
            || self.retained_supervisor.is_none()
            || self.retained_operational.is_none()
        {
            return Ok(None);
        }
        let scratch = super::CnpPreparationStorageScratch::new(
            super::CnpPreparationStorageScratch::requested_bytes(),
        )?;
        let complete = self
            .original_retained_node_precredit_data(&scratch, None, None, maximum)?
            .complete_requested_bytes_precredit_data()?;
        let nested = complete
            .checked_sub(std::mem::size_of::<Self>())
            .ok_or(RuntimeError::ForeignAuthority)?;
        Ok(Some(nested))
    }

    fn retained_requested_storage_precredit_scratch_data(
        &self,
    ) -> Result<Option<usize>, RuntimeError> {
        self.preparation
            .guard
            .preparation_storage_origin_precredit_data()?;
        if self.retained_registry.is_none()
            || self.retained_supervisor.is_none()
            || self.retained_operational.is_none()
        {
            return Ok(None);
        }
        super::CnpSemanticPreparation::original_conformance_node_retained_counter_scratch_data()
            .map(Some)
    }

    fn collection_scope(&self) -> Option<&crate::node_admission::InstalledConformancePlan> {
        self.preparation
            .guard
            .custody
            .as_ref()
            .and_then(|native| native.collection_plan.as_ref())
    }

    fn validate_collection_scope(
        &self,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<(), OperationFailure> {
        if !self
            .collection_scope()
            .is_some_and(|original| original.same_original(plan))
        {
            return Err(refused(
                "native collection belongs to another original plan",
            ));
        }
        self.current()
    }

    fn descriptor(&self) -> &NodeDescriptor {
        self.preparation.descriptor()
    }

    fn binding(&self) -> &NodeBinding {
        self.preparation.binding()
    }

    fn route(&self) -> &NodeRoute {
        &self.route
    }

    fn thread_affinity(&self) -> ThreadAffinity {
        self.affinity
    }

    fn facets(&self) -> &[FacetKind] {
        self.preparation
            .guard
            .custody
            .as_ref()
            .and_then(|native| native.source.as_ref())
            .map_or(&[], |source| source.installation().facets.as_slice())
    }

    fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<Option<usize>, OperationFailure> {
        // This is retained data observation, including after retirement. The
        // actual known registry alias needs only its original creator and Rc
        // association; no retired process or registrar authority is renewed.
        self.preparation.guard.storage_origin_data()?;
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or_else(|| refused("original node storage capsule is absent"))?;
        let registry = native
            .extension_handshake
            .as_ref()
            .map(|extension| extension.retain_original_registry_metadata_owner())
            .transpose()
            .map_err(unknown)?;
        let report = match registry.as_ref() {
            Some(registry) => {
                self.retained_requested_storage_with_registry_data(registry, maximum)?
            }
            None => CnpSemanticNode::retained_requested_storage_data(self, maximum)?,
        };
        let bytes = report.complete_requested_bytes()?;
        let nested = bytes
            .checked_sub(std::mem::size_of_val(self))
            .ok_or_else(|| refused("original node owning row omitted its concrete root"))?;
        self.preparation.guard.storage_origin_data()?;
        Ok(Some(nested))
    }

    fn preflight_complete_original_lineage_capture(
        &self,
        activation: &WorldActivation,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: crate::node_state::NativeArchiveLimits,
    ) -> Result<crate::node_state::CompleteOriginalOwnerCapturePreflight, OperationFailure> {
        // Refuse a copied process capsule before reading any inherited owner.
        self.preparation.guard.custody().map_err(unknown)?;
        self.current()?;
        // Observe the actual owning node/process/SDK loan before the Source
        // callback takes any mutable bank. Unknown owning roots refuse here;
        // a complete semantic serializer cannot replace those live owners.
        let maximum = limits
            .state
            .maximum_total_content_bytes
            .min(limits.native.maximum_total_record_bytes);
        <Self as SimulationNode>::retained_requested_storage_data(self, maximum)?
            .ok_or_else(|| refused("actual complete node owning row is unavailable"))?;
        self.current()?;
        let source = self.source()?;
        let active = self
            .state()?
            .active
            .as_ref()
            .ok_or_else(|| refused("complete capture has no original active world"))?;
        if !active.same_authority(activation) {
            return Err(refused("complete capture preflight has another activation"));
        }

        let result = source.preflight_complete_original_lineage_capture(
            self.scope()?,
            active,
            record,
            runtime_object,
            limits,
        );
        // A callback may return in a copied process. Authenticate origin before
        // reading cells or publishing a result from the original owner loan.
        self.preparation.guard.custody().map_err(unknown)?;
        self.current()?;
        result
    }

    fn capture_original_lineage_continuation_with_ticket(
        &mut self,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        activation: &WorldActivation,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: NativeCaptureLimits,
    ) -> Result<InstalledOriginalLineageCapture, OperationFailure> {
        self.capture_with_original_ticket(ticket, activation, record, runtime_object, limits)
    }

    fn capture_original_lineage_continuation_with_ticket_into(
        &mut self,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        activation: &WorldActivation,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: NativeCaptureLimits,
        completed: &mut Option<InstalledOriginalLineageCapture>,
    ) -> Result<(), OperationFailure> {
        self.capture_with_original_ticket_into(
            ticket,
            activation,
            record,
            runtime_object,
            limits,
            completed,
        )
    }

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        self.current()?;
        self.source()?.status(self.scope()?)
    }

    fn admit_original_lineage_restoration(
        &mut self,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), OperationFailure> {
        if !context.is_original_installed_restoration_data() {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "original lineage context admission is unsupported".into(),
            });
        }
        self.admit_installed_restoration(context)
    }

    fn install_original_lineage_restored_custody(
        &mut self,
        context: &OriginalLineageRestoration<'_>,
        activation: &WorldActivation,
        operations: &[OperationAdmission],
        inputs: &[std::rc::Rc<RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        if !context.is_original_installed_restoration_data() {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "complete original-lineage custody installation is unsupported".into(),
            });
        }
        self.install_installed_restoration(context, activation, operations, inputs)
    }

    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
        if self.has_installed_restoration_data() {
            return self.arm_installed_restoration(world);
        }
        self.arm_original(world)
    }

    fn validate_readiness(
        &self,
        world: &ActivationRecord,
        readiness: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.validate_ready(world, readiness)
    }

    fn prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<PreparedOwner>>, OperationFailure> {
        if self.has_installed_restoration_data() {
            self.validate_installed_ready(world, ready)?;
            let original = self
                .state()?
                .prepared_owner
                .as_ref()
                .ok_or_else(|| refused("selected prepared owner absent"))?;
            self.check_owner(original, ready)?;
            return Ok(Some(vec![original.clone()]));
        }
        self.validate_ready(world, ready)?;
        let original = self
            .state()?
            .prepared_owner
            .as_ref()
            .ok_or_else(|| refused("generic original public owner mapping is absent"))?;
        self.check_owner(original, ready)?;
        if self.source()?.prepared_owner(self.scope()?, world, ready)? != *original {
            return Err(refused(
                "generic public owner mapping changed actual native custody",
            ));
        }
        Ok(Some(vec![original.clone()]))
    }

    fn validate_prepared_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
        owners: &[PreparedOwner],
    ) -> Result<(), OperationFailure> {
        if self.prepared_owners(world, ready)?.as_deref() != Some(owners) {
            return Err(refused("generic complete owner preparation differs"));
        }
        Ok(())
    }

    fn validate_initial_preparation(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if self.has_installed_restoration_data() {
            self.validate_installed_ready(world, ready)?;
            if self.state()?.activation_attempt.is_some() {
                return Err(refused("selected initial preparation already activated"));
            }
            return Ok(());
        }
        self.validate_ready(world, ready)?;
        if self.state()?.activation_attempt.is_some()
            || !self.state()?.inputs.is_empty()
            || !self.state()?.operations.is_empty()
        {
            return Err(refused(
                "generic original native preparation has already been used",
            ));
        }
        self.source()?
            .validate_initial_preparation(self.scope()?, world, ready)
    }

    fn stage_inputs(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.current()?;
        if self.source()?.requires_original_input_lineage(batch) {
            return Err(refused(
                "generic selected input requires original producer lineage",
            ));
        }
        self.stage_original(batch)
    }

    fn requires_original_input_lineage(&self, batch: &RuntimeInputBatch) -> bool {
        if self.current().is_err() {
            return true;
        }
        let required = self
            .source()
            .is_ok_and(|source| source.requires_original_input_lineage(batch));
        self.current().is_err() || required
    }

    fn stage_inputs_with_original_lineage(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
        lineage: &OriginalInputLineage,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.current()?;
        self.source()?.validate_original_input_lineage(
            self.scope()?,
            batch,
            provenance,
            lineage,
        )?;
        self.current()?;
        let result = self.stage_original(batch);
        self.current()?;
        result
    }

    fn original_publication_lineage(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &crate::node_scheduling::NativePublication,
        limits: OriginalInputLineageLimits,
    ) -> Result<OriginalPublicationClaim, OperationFailure> {
        self.current()?;
        self.validate_outcome(original, outcome)?;
        let result = self.source()?.original_publication_lineage(
            self.scope()?,
            original,
            outcome,
            publication,
            limits,
        );
        self.current()?;
        result
    }

    fn validate_original_publication_lineage(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &crate::node_scheduling::NativePublication,
        claim: &OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        self.validate_outcome(original, outcome)?;
        let result = self.source()?.validate_original_publication_lineage(
            self.scope()?,
            original,
            outcome,
            publication,
            claim,
        );
        self.current()?;
        result
    }

    fn validate_exact_original_publication_lineage(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &crate::node_scheduling::NativePublication,
        claim: &OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        self.validate_outcome(original, outcome)?;
        let answer = self.source()?.validate_exact_original_publication_lineage(
            self.scope()?,
            original,
            outcome,
            publication,
            claim,
        );
        self.current()?;
        answer
    }

    fn validate_deferred_original_publication(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &crate::node_scheduling::NativePublication,
        prior: &OperationAdmission,
        prior_outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        if self.requires_installed_producer_claim_data(original.token())
            || self.requires_installed_producer_claim_data(prior.token())
        {
            return self.validate_installed_producer_deferred_data(
                original,
                outcome,
                publication,
                prior,
                prior_outcome,
            );
        }
        self.current()?;
        self.validate_outcome(original, outcome)?;
        self.validate_outcome(prior, prior_outcome)?;
        let retained = self.check_token(prior.token())?;
        if !retained.acknowledged || retained.retirement.is_none() {
            return Err(refused(
                "generic deferred prior grant lacks original retirement",
            ));
        }
        let answer = self.source()?.validate_deferred_original_publication(
            self.scope()?,
            original,
            outcome,
            publication,
            prior,
            prior_outcome,
        );
        self.current()?;
        answer
    }

    fn read_original_input_evidence(
        &self,
        original: &OperationAdmission,
        staged: &OriginalStagedInput<'_>,
        limits: OriginalInputLineageLimits,
    ) -> Result<OriginalInputEvidence, OperationFailure> {
        self.current()?;
        self.check_token(original.token())?;
        let result =
            self.source()?
                .read_original_input_evidence(self.scope()?, original, staged, limits);
        self.current()?;
        result
    }

    fn validate_original_input_evidence(
        &self,
        original: &OperationAdmission,
        staged: &OriginalStagedInput<'_>,
        evidence: &OriginalInputEvidence,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        self.check_token(original.token())?;
        let result = self.source()?.validate_original_input_evidence(
            self.scope()?,
            original,
            staged,
            evidence,
        );
        self.current()?;
        result
    }

    fn validate_input_acknowledgement(
        &self,
        batch: &RuntimeInputBatch,
        acknowledgement: &NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        if self.has_installed_restoration_data() {
            return self.validate_installed_restoration_ack(batch, acknowledgement);
        }
        self.check_ack(batch, acknowledgement)?;
        let original = self
            .state()?
            .inputs
            .get(batch.stage_operation())
            .ok_or_else(|| refused("generic original native staging is absent"))?;
        let response = original
            .response
            .as_ref()
            .ok_or_else(|| unknown("generic original native staging remains unresolved"))?;
        if original.watermark.get() == 0
            || original.watermark > self.state()?.watermark
            || original.acknowledgement.as_ref() != Some(acknowledgement)
            || self
                .source()?
                .input_acknowledgement(self.scope()?, batch, response)?
                != *acknowledgement
        {
            return Err(refused("generic original staging acknowledgement changed"));
        }
        Ok(())
    }

    fn commit_input_custody(
        &mut self,
        commit: &InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        self.commit_original_input(commit)
    }

    fn validate_input_custody_commit(
        &self,
        commit: &InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        self.validate_original_input_commit(commit)
    }

    fn begin_original_retained_operation(
        &mut self,
        dispatch: &crate::node_contract::OriginalRuntimeOperationDispatch<'_>,
    ) -> Submission {
        let admission = dispatch.admission_data();
        if dispatch
            .authenticate_original_data(admission, admission.activation(), &self.route)
            .is_err()
        {
            return Submission::Refused(Refusal {
                reason:
                    crate::node_contract::OriginalRuntimeOperationDispatch::NODE_IDENTITY_REFUSAL
                        .into(),
            });
        }
        if self.has_installed_restoration_data() {
            if self
                .authenticate_installed_suffix_dispatch_data(dispatch)
                .is_err()
            {
                return Submission::Refused(Refusal {
                    reason: crate::node_contract::OriginalRuntimeOperationDispatch::SUFFIX_IDENTITY_REFUSAL.into(),
                });
            }
            // Identity is necessary, never sufficient for a new native effect.
            // The paired current-proof row and Source/Core action issuer must
            // be retained/admitted before this branch can dispatch an Observe.
            return Submission::Refused(Refusal {
                reason: crate::node_contract::OriginalRuntimeOperationDispatch::SUFFIX_ACTION_ROW_REFUSAL.into(),
            });
        }
        self.begin_operation(admission)
    }

    fn begin_operation(&mut self, admission: &OperationAdmission) -> Submission {
        match self.begin_original(admission) {
            Ok(()) => Submission::Accepted,
            Err(error) => {
                let retained = self.state().is_ok_and(|state| {
                    state.operations.contains_key(admission.token().operation())
                });
                if retained {
                    Submission::Uncertain(EffectKnowledge::Unknown)
                } else if error.effects == EffectKnowledge::None {
                    Submission::Refused(Refusal {
                        reason: error.reason,
                    })
                } else {
                    Submission::Uncertain(error.effects)
                }
            }
        }
    }

    fn poll_operation(
        &mut self,
        operation: &OperationToken,
        context: &mut Context<'_>,
    ) -> Poll<Result<OperationOutcome, OperationFailure>> {
        match self.poll_original(operation) {
            Ok(Some(outcome)) => Poll::Ready(Ok(outcome)),
            Ok(None) => {
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn validate_outcome(
        &self,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        if self.has_installed_restoration_data() {
            return self.validate_installed_restoration_outcome(original, outcome);
        }
        self.current()?;
        let saved = self.check_token(original.token())?;
        if saved.admission.request() != original.request()
            || saved.outcome.as_ref() != Some(outcome)
        {
            return Err(refused("generic original outcome changed retained custody"));
        }
        self.source()?
            .validate_outcome(self.scope()?, original, outcome)
    }

    fn request_cancel(
        &mut self,
        operation: &OperationToken,
    ) -> Result<CancelStatus, OperationFailure> {
        self.cancel_original(operation)
    }

    fn close_quantum(&mut self, _original: &OperationAdmission) -> Submission {
        Submission::Refused(Refusal {
            reason: "generic exact source has no quantized closure".into(),
        })
    }

    fn acknowledge_publication(
        &mut self,
        operation: &OperationToken,
        outputs: &[Id],
    ) -> Result<(), OperationFailure> {
        self.acknowledge_original(operation, outputs)
    }

    fn seed_original_installed_restored_suffix(
        &self,
        world: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        self.seed_installed_restored_suffix_data(world)
    }

    fn quote_original_restored_scheduling_observation(
        &self,
        launch: &crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        ordinal: u64,
        maximum: usize,
    ) -> Result<
        crate::node_admission::OriginalRestoredSchedulingObservationConstructionData,
        RuntimeError,
    > {
        self.quote_installed_current_observation_data(launch, canonical_launch5, ordinal, maximum)
    }

    fn observe_original_restored_scheduling(
        &mut self,
        claim: &crate::node_admission::OriginalRestoredSchedulingObservationClaim<'_>,
    ) -> Result<crate::node_scheduling::NativeSchedulingObservation, OperationFailure> {
        self.observe_installed_current_data(claim)
    }

    fn observe_scheduling(
        &mut self,
        activation: &WorldActivation,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        if self.has_installed_restoration_data() {
            return self.observe_installed_restoration(activation);
        }
        self.current()?;
        self.source()?.preflight_transition(
            self.scope()?.native,
            super::CnpSemanticTransition::Observation,
        )?;
        self.activate_original(activation)?;
        let source = self.source()?;
        let install = source.installation();
        let sequence = U64::new(
            self.state()?
                .observe_sequence
                .get()
                .checked_add(1)
                .ok_or_else(|| refused("generic original observation identity exhausted"))?,
        );
        let id = Id::new(format!(
            "cnp-observe-{}-{sequence}",
            activation.record().activation_id
        ))
        .map_err(unknown)?;
        self.state_mut()?
            .credit
            .reserve_bytes(install.maximum_result_bytes, install.maximum_semantic_bytes)?;
        self.state_mut()?.observe_sequence = sequence;
        let response = self.call(
            id,
            None,
            Method::Observe,
            true,
            ObserveRequest {
                binding_hash: install.owner.identity().map_err(unknown)?,
                owner_generation: install.binding.authority.owner_generation,
                after_observation_sequence: U64::new(0),
                maximum_items: U64::new(install.maximum_operations as u64),
                extensions: Extensions::new(),
            },
        )?;
        let Some(MethodResult::Observe(result)) = response.result else {
            return Err(unknown(
                "generic original scheduling observation did not complete",
            ));
        };
        let observation = source.scheduling(self.scope()?, activation, &result)?;
        source.validate_scheduling(self.scope()?, activation, &observation)?;
        super::budget::serialized_size(&observation, install.maximum_result_bytes)?;
        self.state_mut()?.observation = Some((activation.clone(), observation.clone()));
        Ok(observation)
    }

    fn validate_scheduling_observation(
        &self,
        activation: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        if self.has_installed_restoration_data() {
            if self.has_installed_current_observation_data() {
                return self.validate_installed_current_observation_data(activation, observation);
            }
            return self.validate_installed_restoration_observation(activation, observation);
        }
        self.current()?;
        let (original, saved) = self
            .state()?
            .observation
            .as_ref()
            .ok_or_else(|| refused("generic original scheduling observation is absent"))?;
        if !original.same_authority(activation) || saved != observation {
            return Err(refused(
                "generic scheduling observation changed original custody",
            ));
        }
        self.source()?
            .validate_scheduling(self.scope()?, activation, observation)
    }

    fn read_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        self.current()?;
        self.check_token(original.token())?;
        self.source()?.evidence(
            self.scope()?,
            original.activation(),
            Some(original),
            references,
            self.maximum_bytes()?,
        )
    }

    fn validate_operation_evidence(
        &self,
        original: &OperationAdmission,
        references: &[ContentRef],
        objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        if self.read_operation_evidence(original, references)? != objects {
            return Err(refused("generic original operation evidence body changed"));
        }
        Ok(())
    }

    fn read_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        self.current()?;
        if self
            .state()?
            .active
            .as_ref()
            .is_none_or(|saved| !saved.same_authority(activation))
        {
            return Err(refused(
                "generic original boundary scope has foreign activation",
            ));
        }
        self.source()?.evidence(
            self.scope()?,
            activation,
            None,
            references,
            maximum_bytes.min(self.maximum_bytes()?),
        )
    }

    fn validate_boundary_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        if self.read_boundary_evidence(activation, references, self.maximum_bytes()?)? != objects {
            return Err(refused("generic original boundary evidence body changed"));
        }
        Ok(())
    }

    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, Refusal> {
        if kind == FacetKind::ExactExecution && self.facets().contains(&kind) {
            Ok(NodeFacet::ExactExecution(self))
        } else if kind == FacetKind::Preservation && self.facets().contains(&kind) {
            // The description borrows the admitted realized selection. It does
            // not grant generic Capture or replace the source-owned ticket.
            facets::preservation(
                &self
                    .preparation
                    .binding()
                    .compatibility
                    .operating_contract
                    .facets,
            )
            .map(|selected| NodeFacet::Preservation(selected))
            .ok_or_else(|| Refusal {
                reason: "generic native source has no selected qualified facet".into(),
            })
        } else {
            Err(Refusal {
                reason: "generic native source has no selected qualified facet".into(),
            })
        }
    }

    fn quarantine_resources(&mut self) {
        if let Ok(native) = self.preparation.guard.custody() {
            native.read_owner.revoke();
        }
        if let Ok(state) = self.state_mut() {
            state.quarantined = true;
        }
        if let Ok(controller) = self.controller_mut() {
            controller.fence();
        }
    }

    fn poll_reclamation(
        &mut self,
        owner: &OwnerIdentity,
        context: &mut Context<'_>,
    ) -> Poll<Result<NativeReclamationReceipt, OperationFailure>> {
        if self.route.owners.as_slice() != [owner.clone()] {
            return Poll::Ready(Err(refused(
                "generic native reclamation has foreign original owner",
            )));
        }
        self.quarantine_resources();
        let result = (|| {
            let native = self
                .preparation
                .guard
                .custody
                .as_mut()
                .ok_or_else(|| refused("generic original native custody is absent"))?;
            if !native.poll_reclamation().map_err(unknown)? {
                return Ok(None);
            }
            let source = native
                .source
                .as_ref()
                .cloned()
                .ok_or_else(|| refused("generic native reclamation source is absent"))?;
            if let Some(receipt) = native
                .runtime
                .as_ref()
                .and_then(|state| state.reclaimed.as_ref())
            {
                source.validate_reclamation(native, receipt)?;
                return Ok(Some(receipt.clone()));
            }
            let receipt = source.reclamation(native, owner)?;
            super::budget::serialized_size(
                &(&receipt.owner, &receipt.receipt),
                source.installation().maximum_result_bytes,
            )?;
            source.validate_reclamation(native, &receipt)?;
            if receipt.owner != *owner {
                return Err(unknown("generic reclamation source changed original owner"));
            }
            self.state_mut()?.reclaimed = Some(receipt.clone());
            Ok(Some(receipt))
        })();
        match result {
            Ok(Some(receipt)) => Poll::Ready(Ok(receipt)),
            Ok(None) => {
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn validate_reclamation(
        &self,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        if self.state()?.reclaimed.as_ref() != Some(receipt) {
            return Err(refused("generic original reclamation evidence is absent"));
        }
        let native = self.preparation.guard.custody().map_err(unknown)?;
        self.source()?.validate_reclamation(native, receipt)
    }
}
