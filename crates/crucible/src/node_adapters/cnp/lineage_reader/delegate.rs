//! Delegates selected effects while the whole original host capsule remains owned.

use super::LineageControlledReference;
use crate::node_adapters::reference_device::control::{ControlledReference, sealed};
use crate::{
    node_contract::{ActivationRecord, OperationAdmission, OperationFailure, ReadyAttestation},
    node_scheduling::{NativeInputAcknowledgement, RuntimeInputBatch},
};
use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    reference_device::{DeviceGrant, DeviceReceipt, DeviceStatus},
};

impl sealed::Sealed for LineageControlledReference {}

impl ControlledReference for LineageControlledReference {
    fn collection_scope(&self) -> Option<&crate::node_admission::InstalledConformancePlan> {
        self.state
            .as_ref()
            .and_then(|state| state.collection.as_ref())
    }

    fn validate_collection_scope(
        &self,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<(), OperationFailure> {
        let state = self.state().map_err(super::readiness::unknown)?;
        if !state
            .collection
            .as_ref()
            .is_some_and(|retained| retained.same_original(plan))
        {
            return Err(super::readiness::refused(
                "original collection capsule differs",
            ));
        }
        super::collection::authenticate(state, plan)
    }

    fn quantized_facet(&self) -> &str {
        "reference-device/quantized-lineage-reader-v1"
    }

    fn publication_causal_parents(
        &self,
        receipt: &DeviceReceipt,
    ) -> Result<Option<Vec<Position>>, OperationFailure> {
        ControlledReference::publication_causal_parents(
            self.state().map_err(super::readiness::unknown)?,
            receipt,
        )
    }

    fn completion_proof(
        &self,
        receipt: &DeviceReceipt,
    ) -> Result<Option<crate::node_scheduling::InputPayload>, OperationFailure> {
        ControlledReference::completion_proof(
            self.state().map_err(super::readiness::unknown)?,
            receipt,
        )
    }

    fn requires_original_input_lineage(&self, batch: &RuntimeInputBatch) -> bool {
        !batch.deliveries().is_empty()
    }

    fn original_publication_lineage(
        &self,
        original: &OperationAdmission,
        outcome: &crate::node_contract::OperationOutcome,
        publication: &crate::node_scheduling::NativePublication,
        limits: crate::node_contract::OriginalInputLineageLimits,
    ) -> Result<crate::node_contract::OriginalPublicationClaim, OperationFailure> {
        self.state()
            .map_err(super::readiness::unknown)?
            .publication_claim(original, outcome, publication, limits)
    }

    fn validate_original_publication_lineage(
        &self,
        original: &OperationAdmission,
        outcome: &crate::node_contract::OperationOutcome,
        publication: &crate::node_scheduling::NativePublication,
        claim: &crate::node_contract::OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        self.state()
            .map_err(super::readiness::unknown)?
            .validate_publication_claim(original, outcome, publication, claim)
    }

    fn stage_runtime_inputs_with_original_lineage(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: &crate::node_contract::InputProvenanceClosure,
        lineage: &crate::node_contract::OriginalInputLineage,
    ) -> Result<Option<NativeInputAcknowledgement>, OperationFailure> {
        self.state_mut()
            .map_err(super::readiness::unknown)?
            .stage_lineage_inputs(batch, provenance, lineage)
            .map(Some)
    }

    fn status(&self) -> DeviceStatus {
        self.state
            .as_ref()
            .map_or(DeviceStatus::Quarantined, |state| state.status)
    }

    fn child_pid(&self) -> u32 {
        self.native_pid
    }

    fn supervision_id(&self) -> U64 {
        self.supervision
    }

    fn owner_id(&self) -> &Id {
        &self.owner
    }

    fn incarnation_id(&self) -> &Id {
        &self.incarnation
    }

    fn generation(&self) -> U64 {
        self.generation
    }

    fn output_media_type(&self) -> &str {
        "application/octet-stream"
    }

    fn publication_identity(
        &self,
        receipt: &DeviceReceipt,
    ) -> Result<Option<(Id, U64)>, OperationFailure> {
        ControlledReference::publication_identity(
            self.state().map_err(super::readiness::unknown)?,
            receipt,
        )
    }

    fn stage(&mut self, grant: DeviceGrant, bytes: &[u8]) -> Result<(), ProviderError> {
        ControlledReference::stage(self.state_mut()?, grant, bytes)
    }

    fn activate(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        ControlledReference::activate(self.state_mut()?, grant)
    }

    fn close(&mut self, grant: &DeviceGrant) -> Result<DeviceReceipt, ProviderError> {
        ControlledReference::close(self.state_mut()?, grant)
    }

    fn validate_receipt(&self, receipt: &DeviceReceipt) -> Result<(), ProviderError> {
        ControlledReference::validate_receipt(self.state()?, receipt)
    }

    fn acknowledge_publication(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        ControlledReference::acknowledge_publication(self.state_mut()?, grant)
    }

    fn quarantine(&mut self) -> Result<bool, ProviderError> {
        ControlledReference::quarantine(self.state_mut()?)
    }

    fn prepare_activation(
        &mut self,
        record: &ActivationRecord,
    ) -> Result<Option<ReadyAttestation>, OperationFailure> {
        ControlledReference::prepare_activation(
            self.state_mut().map_err(super::readiness::unknown)?,
            record,
        )
    }

    fn validate_activation(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        ControlledReference::validate_activation(
            self.state().map_err(super::readiness::unknown)?,
            record,
            ready,
        )
    }

    fn stage_runtime_inputs(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<Option<NativeInputAcknowledgement>, OperationFailure> {
        ControlledReference::stage_runtime_inputs(
            self.state_mut().map_err(super::readiness::unknown)?,
            batch,
        )
    }

    fn read_boundary_evidence(
        &self,
        activation: &crate::node_contract::WorldActivation,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<crate::node_scheduling::InputPayload>, OperationFailure> {
        ControlledReference::read_boundary_evidence(
            self.state().map_err(super::readiness::unknown)?,
            activation,
            references,
            maximum_bytes,
        )
    }

    fn validate_boundary_evidence(
        &self,
        activation: &crate::node_contract::WorldActivation,
        references: &[ContentRef],
        objects: &[crate::node_scheduling::InputPayload],
    ) -> Result<(), OperationFailure> {
        ControlledReference::validate_boundary_evidence(
            self.state().map_err(super::readiness::unknown)?,
            activation,
            references,
            objects,
        )
    }

    fn read_original_input_evidence(
        &self,
        original: &OperationAdmission,
        staged: &crate::node_contract::OriginalStagedInput<'_>,
        limits: crate::node_contract::OriginalInputLineageLimits,
    ) -> Result<crate::node_contract::OriginalInputEvidence, OperationFailure> {
        ControlledReference::read_original_input_evidence(
            self.state().map_err(super::readiness::unknown)?,
            original,
            staged,
            limits,
        )
    }

    fn validate_original_input_evidence(
        &self,
        original: &OperationAdmission,
        staged: &crate::node_contract::OriginalStagedInput<'_>,
        evidence: &crate::node_contract::OriginalInputEvidence,
    ) -> Result<(), OperationFailure> {
        ControlledReference::validate_original_input_evidence(
            self.state().map_err(super::readiness::unknown)?,
            original,
            staged,
            evidence,
        )
    }

    fn input_provenance_dependencies(
        &self,
        activation: &crate::node_contract::WorldActivation,
        root: &ContentRef,
        limits: crate::node_contract::InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        ControlledReference::input_provenance_dependencies(
            self.state().map_err(super::readiness::unknown)?,
            activation,
            root,
            limits,
        )
    }

    fn validate_input_provenance_dependencies(
        &self,
        activation: &crate::node_contract::WorldActivation,
        root: &ContentRef,
        dependencies: &[ContentRef],
    ) -> Result<(), OperationFailure> {
        ControlledReference::validate_input_provenance_dependencies(
            self.state().map_err(super::readiness::unknown)?,
            activation,
            root,
            dependencies,
        )
    }

    fn requires_input_provenance(&self, batch: &RuntimeInputBatch) -> bool {
        !batch.deliveries().is_empty()
    }

    fn stage_runtime_inputs_with_provenance(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: &crate::node_contract::InputProvenanceClosure,
    ) -> Result<Option<NativeInputAcknowledgement>, OperationFailure> {
        ControlledReference::stage_runtime_inputs_with_provenance(
            self.state_mut().map_err(super::readiness::unknown)?,
            batch,
            provenance,
        )
    }

    fn prepared_owners(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<PreparedOwner>>, OperationFailure> {
        ControlledReference::prepared_owners(
            self.state().map_err(super::readiness::unknown)?,
            record,
            ready,
        )
    }

    fn validate_prepared_owners(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
        owners: &[PreparedOwner],
    ) -> Result<(), OperationFailure> {
        ControlledReference::validate_prepared_owners(
            self.state().map_err(super::readiness::unknown)?,
            record,
            ready,
            owners,
        )
    }

    fn validate_initial_preparation(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        ControlledReference::validate_initial_preparation(
            self.state().map_err(super::readiness::unknown)?,
            world,
            ready,
        )
    }

    fn retain_operation(&mut self, original: &OperationAdmission) -> Result<(), ProviderError> {
        ControlledReference::retain_operation(self.state_mut()?, original)
    }
}
