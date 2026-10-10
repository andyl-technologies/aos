//! Sealed public-provider implementation of the common quantized control path.

use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    reference_device::{DeviceGrant, DeviceReceipt, DeviceStatus},
};

use crate::{
    node_contract::{ActivationRecord, OperationAdmission, OperationFailure, ReadyAttestation},
    node_scheduling::{NativeInputAcknowledgement, RuntimeInputBatch},
};

use super::{control::ReaderState, readiness::refused};
use crate::node_adapters::reference_device::control::{ControlledReference, sealed};

impl sealed::Sealed for ReaderState {}

impl ControlledReference for ReaderState {
    fn quantized_facet(&self) -> &str {
        "reference-device/quantized-lineage-reader-v1"
    }

    fn publication_causal_parents(
        &self,
        receipt: &DeviceReceipt,
    ) -> Result<Option<Vec<Position>>, OperationFailure> {
        self.validate_receipt(receipt)
            .map_err(super::readiness::unknown)?;
        let event = self
            .windows
            .get(&receipt.grant.window_id)
            .and_then(|window| window.observations.as_ref())
            .and_then(|batch| batch.events.first())
            .ok_or_else(|| refused("original source publication missing"))?;
        if !event.causal_parent_ids.is_empty() {
            return Err(refused(
                "original public same-time parent scope is unsupported",
            ));
        }
        Ok(Some(Vec::new()))
    }

    fn completion_proof(
        &self,
        receipt: &DeviceReceipt,
    ) -> Result<Option<crate::node_scheduling::InputPayload>, OperationFailure> {
        self.validate_receipt(receipt)
            .map_err(super::readiness::unknown)?;
        let reference = self
            .windows
            .get(&receipt.grant.window_id)
            .and_then(|window| window.result.as_ref())
            .map(|result| result.physical_measurement_ref.clone())
            .ok_or_else(|| refused("original selected measurement is unavailable"))?;
        let bytes = self
            .guard
            .content(&reference)
            .map_err(super::readiness::unknown)?;
        Ok(Some(crate::node_scheduling::InputPayload {
            reference,
            bytes: bytes.to_vec(),
        }))
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
        self.publication_claim(original, outcome, publication, limits)
    }

    fn validate_original_publication_lineage(
        &self,
        original: &OperationAdmission,
        outcome: &crate::node_contract::OperationOutcome,
        publication: &crate::node_scheduling::NativePublication,
        claim: &crate::node_contract::OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        self.validate_publication_claim(original, outcome, publication, claim)
    }

    fn stage_runtime_inputs_with_original_lineage(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: &crate::node_contract::InputProvenanceClosure,
        lineage: &crate::node_contract::OriginalInputLineage,
    ) -> Result<Option<NativeInputAcknowledgement>, OperationFailure> {
        self.stage_lineage_inputs(batch, provenance, lineage)
            .map(Some)
    }

    fn status(&self) -> DeviceStatus {
        self.status
    }

    fn child_pid(&self) -> u32 {
        self.companion_pid
    }

    fn supervision_id(&self) -> U64 {
        self.supervision
    }

    fn owner_id(&self) -> &Id {
        &self.owner_binding.owner.id
    }

    fn incarnation_id(&self) -> &Id {
        &self.binding.authority.incarnation_id
    }

    fn generation(&self) -> U64 {
        self.binding.authority.owner_generation
    }

    fn output_media_type(&self) -> &str {
        "application/octet-stream"
    }

    fn publication_identity(
        &self,
        receipt: &DeviceReceipt,
    ) -> Result<Option<(Id, U64)>, OperationFailure> {
        self.validate_receipt(receipt)
            .map_err(super::readiness::unknown)?;
        let event = self
            .windows
            .get(&receipt.grant.window_id)
            .and_then(|window| window.observations.as_ref())
            .and_then(|batch| batch.events.first())
            .ok_or_else(|| refused("original public event identity is unavailable"))?;
        Ok(Some((event.id.clone(), event.source_sequence)))
    }

    fn stage(&mut self, grant: DeviceGrant, bytes: &[u8]) -> Result<(), ProviderError> {
        self.stage_window(grant, bytes)
    }

    fn activate(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        self.activate_window(grant)
    }

    fn close(&mut self, grant: &DeviceGrant) -> Result<DeviceReceipt, ProviderError> {
        self.close_window(grant)
    }

    fn validate_receipt(&self, receipt: &DeviceReceipt) -> Result<(), ProviderError> {
        self.verify_native_custody()?;
        if self
            .windows
            .get(&receipt.grant.window_id)
            .is_none_or(|window| window.receipt.as_ref() != Some(receipt))
        {
            return Err(ProviderError::Correlation(
                "public receipt lacks genuine original retained native result",
            ));
        }
        Ok(())
    }

    fn acknowledge_publication(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        self.acknowledge_window(grant)
    }

    fn quarantine(&mut self) -> Result<bool, ProviderError> {
        self.quarantine_public()
    }

    fn prepare_activation(
        &mut self,
        record: &ActivationRecord,
    ) -> Result<Option<ReadyAttestation>, OperationFailure> {
        ReaderState::prepare_activation(self, record).map(Some)
    }

    fn validate_activation(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        ReaderState::validate_activation(self, record, ready)
    }

    fn stage_runtime_inputs(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<Option<NativeInputAcknowledgement>, OperationFailure> {
        self.stage_inputs(batch, None).map(Some)
    }

    fn read_boundary_evidence(
        &self,
        activation: &crate::node_contract::WorldActivation,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<crate::node_scheduling::InputPayload>, OperationFailure> {
        self.read_public_boundary_evidence(activation, references, maximum_bytes)
    }

    fn validate_boundary_evidence(
        &self,
        activation: &crate::node_contract::WorldActivation,
        references: &[ContentRef],
        objects: &[crate::node_scheduling::InputPayload],
    ) -> Result<(), OperationFailure> {
        self.validate_public_boundary_evidence(activation, references, objects)
    }

    fn input_provenance_dependencies(
        &self,
        activation: &crate::node_contract::WorldActivation,
        root: &ContentRef,
        limits: crate::node_contract::InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        self.public_provenance_dependencies(activation, root, limits)
    }

    fn validate_input_provenance_dependencies(
        &self,
        activation: &crate::node_contract::WorldActivation,
        root: &ContentRef,
        dependencies: &[ContentRef],
    ) -> Result<(), OperationFailure> {
        let expected = self.public_provenance_dependencies(
            activation,
            root,
            crate::node_contract::InputProvenanceLimits::default(),
        )?;
        if expected != dependencies {
            return Err(refused("public provenance dependency inventory changed"));
        }
        Ok(())
    }

    fn requires_input_provenance(&self, batch: &RuntimeInputBatch) -> bool {
        !batch.deliveries().is_empty()
    }

    fn stage_runtime_inputs_with_provenance(
        &mut self,
        batch: &RuntimeInputBatch,
        provenance: &crate::node_contract::InputProvenanceClosure,
    ) -> Result<Option<NativeInputAcknowledgement>, OperationFailure> {
        self.stage_inputs(batch, Some(provenance)).map(Some)
    }

    fn prepared_owners(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<PreparedOwner>>, OperationFailure> {
        ReaderState::prepared_owners(self, record, ready)
    }

    fn validate_prepared_owners(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
        owners: &[PreparedOwner],
    ) -> Result<(), OperationFailure> {
        ReaderState::validate_prepared_owners(self, record, ready, owners)
    }

    fn validate_initial_preparation(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.validate_activation(world, ready)?;
        if self.active.is_some()
            || self.input.is_some()
            || !self.windows.is_empty()
            || self.pending.is_some()
            || self.next_input_sequence != U64::new(1)
            || self.checksum != 0
            || self.status != DeviceStatus::Parked
            || world.boundary != Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
        {
            return Err(refused(
                "public source is not its genuinely realized initial scope",
            ));
        }
        // This sealed adapter can only be constructed from actual fresh Realize
        // and source/ancestry verification. No restore constructor exists.
        self.verify_native_custody()
            .map_err(super::readiness::unknown)
    }

    fn retain_operation(&mut self, original: &OperationAdmission) -> Result<(), ProviderError> {
        self.verify_native_custody()?;
        if let Some(pending) = &self.pending {
            if pending.token().operation() != original.token().operation()
                || pending.request() != original.request()
                || pending.activation().record() != original.activation().record()
            {
                return Err(ProviderError::Conflict(
                    "public original opaque permission changed",
                ));
            }
            return Ok(());
        }
        if self
            .windows
            .values()
            .any(|window| window.original.token().operation() == original.token().operation())
        {
            return Err(ProviderError::Conflict(
                "public original operation already retained",
            ));
        }
        if self.pending.is_some() || self.windows.len() >= self.maximum_operations {
            return Err(ProviderError::ResourceExhausted(
                "public original operation custody",
            ));
        }
        self.pending = Some(original.clone());
        Ok(())
    }
}

impl ReaderState {
    pub(super) fn prepared_owners(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<PreparedOwner>>, OperationFailure> {
        self.validate_activation(record, ready)?;
        let owner = self
            .prepared
            .as_ref()
            .ok_or_else(|| refused("original public preparation unavailable"))?
            .owner
            .clone();
        Ok(Some(vec![owner]))
    }

    pub(super) fn validate_prepared_owners(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
        owners: &[PreparedOwner],
    ) -> Result<(), OperationFailure> {
        let expected = self
            .prepared_owners(record, ready)?
            .ok_or_else(|| refused("public preparation mapping unavailable"))?;
        if owners != expected {
            return Err(refused(
                "public preparation mapping changed original owner records",
            ));
        }
        Ok(())
    }
}
