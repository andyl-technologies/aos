//! Independent source-program gate checks; all later unqualified facets refuse.

#![cfg(test)]

use super::*;

pub(super) struct Registration {
    pub original: HashRef,
    pub current: Cell<bool>,
}

impl CnpSemanticRegistrationPolicy for Registration {
    fn authenticate(&self, selection: &CnpSemanticInstallation) -> Result<(), OperationFailure> {
        if self.current.get() && registry::installation_identity(selection)? == self.original {
            Ok(())
        } else {
            Err(refused(
                "current independently installed packet source is absent or changed",
            ))
        }
    }
}

pub(super) struct Acceptance {
    pub allow: bool,
    pub calls: Cell<usize>,
    pub source: Rc<PacketSource>,
}

impl CnpSemanticAcceptance for Acceptance {
    fn authenticate(&self, scope: CnpSemanticRealizationScope<'_>) -> Result<(), OperationFailure> {
        self.calls.set(self.calls.get() + 1);
        if self.allow
            && self.source.gate_checks.get() > 0
            && scope.installation.binding == self.source.definition.installation.binding
            && scope.realization.realization_manifest.bindings
                == [scope.installation.binding.clone()]
        {
            // This controlled callback tests the obligatory ordering seam. It
            // does not produce a normative class certificate or native Ready.
            Ok(())
        } else {
            Err(refused(
                "packet mechanism fixture is not a vendor class acceptance",
            ))
        }
    }
}

pub(super) struct PacketSource {
    pub definition: Rc<Definition>,
    pub native_gate: Cell<bool>,
    pub gate_checks: Cell<usize>,
}

impl CnpSemanticSource for PacketSource {
    fn installation(&self) -> &CnpSemanticInstallation {
        &self.definition.installation
    }

    fn authenticate_provider(
        &self,
        native: &CnpSemanticProcessCustody,
    ) -> Result<(), OperationFailure> {
        native.authenticate_process().map_err(unknown)?;
        if native.controller().is_none_or(|controller| {
            controller.peer_executable()
                != &self.installation().provider.implementation.artifacts[0].content
        }) {
            return Err(refused("changed actual packet executable"));
        }
        Ok(())
    }

    fn preflight_transition(
        &self,
        native: &CnpSemanticProcessCustody,
        transition: CnpSemanticTransition,
    ) -> Result<(), OperationFailure> {
        self.authenticate_provider(native)?;
        if !matches!(transition, CnpSemanticTransition::Preparation) {
            return Err(refused(
                "ordering-only fixture has no qualified semantic transition",
            ));
        }
        native
            .controller()
            .ok_or_else(|| refused("original fixture controller absent"))?
            .preflight_source_reply(2, 18, 40 * FRAME, 1, FRAME)
            .map_err(|error| refused(error.to_string()))
    }

    fn authenticate_realization(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        if !self.native_gate.get() {
            return Err(refused("source-native packet gate is unqualified"));
        }
        self.authenticate_provider(scope.native)?;
        let expected = bytes(json!({
            "schema":"source-owned.packet-closed-gate.v1",
            "original_pid":scope.native.provider_pid(),
            "model":scope.installation.descriptor.model_ref,
            "realization":scope.installation.realize.realization_id,
            "native_callbacks":"0", "gate_closed":true,
            "input_inventory":[], "output_inventory":[],
            "pending_timers":[{"publication_ps":"5","microstep":"1","remaining":"1"}]
        }));
        if scope.realization.prepared_token != id("packet-original-prepared-token")
            || scope
                .controller
                .content(&scope.realization.closed_gate_receipt)
                .map_err(unknown)?
                != expected
            || scope.realization.closed_gate_receipt != reference(&expected)
        {
            return Err(refused(
                "actual packet source gate differs from original complete native program",
            ));
        }
        self.gate_checks.set(self.gate_checks.get() + 1);
        Ok(())
    }
    fn preflight_operation(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _original: &OperationAdmission,
    ) -> Result<(), OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common preflight_operation facet",
        ))
    }

    fn status(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<crate::node_contract::NodeStatus, OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common status facet",
        ))
    }

    fn prepared_owner(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _record: &ActivationRecord,
        _ready: &ReadyAttestation,
    ) -> Result<crucible_node_contract::PreparedOwner, OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common prepared_owner facet",
        ))
    }

    fn validate_initial_preparation(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _record: &ActivationRecord,
        _ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common validate_initial_preparation facet",
        ))
    }

    fn evidence(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _activation: &WorldActivation,
        _original: Option<&OperationAdmission>,
        _references: &[ContentRef],
        _maximum_bytes: usize,
    ) -> Result<Vec<crate::node_scheduling::InputPayload>, OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common evidence facet",
        ))
    }

    fn reclamation(
        &self,
        _native: &CnpSemanticProcessCustody,
        _owner: &crate::node_contract::OwnerIdentity,
    ) -> Result<crate::node_contract::NativeReclamationReceipt, OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common reclamation facet",
        ))
    }

    fn validate_reclamation(
        &self,
        _native: &CnpSemanticProcessCustody,
        _receipt: &crate::node_contract::NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common validate_reclamation facet",
        ))
    }

    fn readiness(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _record: &ActivationRecord,
        _response: &ActivateResult,
    ) -> Result<ReadyAttestation, OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common readiness facet",
        ))
    }

    fn validate_readiness(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _record: &ActivationRecord,
        _readiness: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common validate_readiness facet",
        ))
    }

    fn preflight_world_activation(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _activation: &WorldActivation,
    ) -> Result<(), OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common activation preflight",
        ))
    }

    fn validate_world_activation(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _activation: &WorldActivation,
        _response: &WorldActivateResult,
    ) -> Result<(), OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common validate_world_activation facet",
        ))
    }

    fn input_batch(
        &self,
        _batch: &RuntimeInputBatch,
        _sequence: crucible_node_contract::U64,
    ) -> Result<crucible_node_contract::InputBatch, OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common input_batch facet",
        ))
    }

    fn input_acknowledgement(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _batch: &RuntimeInputBatch,
        _response: &InputResult,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common input_acknowledgement facet",
        ))
    }

    fn boundary_policy(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _original: &OperationAdmission,
    ) -> Result<crucible_node_provider::bodies::BoundaryPolicy, OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common boundary_policy facet",
        ))
    }

    fn input_authorization(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _original: &OperationAdmission,
        _watermark: crucible_node_contract::U64,
    ) -> Result<crate::node_scheduling::InputPayload, OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common input_authorization facet",
        ))
    }

    fn outcome(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _original: &OperationAdmission,
        _response: &ResponseBody,
    ) -> Result<OperationOutcome, OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common outcome facet",
        ))
    }

    fn validate_outcome(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _original: &OperationAdmission,
        _outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common validate_outcome facet",
        ))
    }

    fn scheduling(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _activation: &WorldActivation,
        _response: &ObserveResult,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common scheduling facet",
        ))
    }

    fn validate_scheduling(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _activation: &WorldActivation,
        _observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common validate_scheduling facet",
        ))
    }

    fn validate_retirement(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _original: &OperationAdmission,
        _consumption: &crate::node_scheduling::InputPayload,
        _response: &RetireResult,
    ) -> Result<(), OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common validate_retirement facet",
        ))
    }

    fn consumption(
        &self,
        _scope: CnpSemanticRealizationScope<'_>,
        _original: &OperationAdmission,
        _outcome: &OperationOutcome,
        _outputs: &[Id],
    ) -> Result<crate::node_scheduling::InputPayload, OperationFailure> {
        Err(refused(
            "packet preparation fixture has no qualified common consumption facet",
        ))
    }
}
