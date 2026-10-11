//! Common trait forwarding beneath current installed native and acceptance authority.

use std::task::{Context, Poll};

use crucible_node_contract::{
    ContentRef, Extensions, Id, NodeBinding, NodeDescriptor, PreparedOwner, U64,
};
use crucible_node_provider::{bodies::*, envelope::Method};

use crate::{
    node_contract::*,
    node_scheduling::{
        InputPayload, NativeInputAcknowledgement, NativeSchedulingObservation, RuntimeInputBatch,
    },
};

use super::{CnpSemanticNode, refused, unknown};

impl FacetDescription for CnpSemanticNode {
    fn profile(&self) -> &Id {
        &self.exact_profile
    }
}

impl SimulationNode for CnpSemanticNode {
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

    fn status(&mut self) -> Result<NodeStatus, OperationFailure> {
        self.current()?;
        self.source()?.status(self.scope()?)
    }

    fn arm(&mut self, world: &ActivationRecord) -> Result<ReadyAttestation, OperationFailure> {
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
        self.stage_original(batch)
    }

    fn validate_input_acknowledgement(
        &self,
        batch: &RuntimeInputBatch,
        acknowledgement: &NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        self.current()?;
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

    fn observe_scheduling(
        &mut self,
        activation: &WorldActivation,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
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
