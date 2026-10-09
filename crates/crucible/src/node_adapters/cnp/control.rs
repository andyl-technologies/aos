//! Retained public controls for the source-installed quantized checksum model.

use std::collections::BTreeMap;

use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    client::ReferenceController,
    reference_device::{DeviceGrant, DeviceReceipt, DeviceStatus},
};

use crate::{
    node_contract::{ActivationRecord, OperationAdmission, ReadyAttestation},
    node_scheduling::RuntimeInputBatch,
};

use super::{preparation::CnpReferencePreparation, process::CnpLaunchGuard};

pub(super) struct PreparedActivation {
    pub(super) record: ActivationRecord,
    pub(super) ready: ReadyAttestation,
    pub(super) registry_complete: bool,
    pub(super) owner: PreparedOwner,
}

pub(super) struct StagedInput {
    pub(super) original: RuntimeInputBatch,
    pub(super) public: InputBatch,
    pub(super) reference: ContentRef,
    pub(super) provenance: Option<crate::node_contract::InputProvenanceClosure>,
    pub(super) acknowledgement: Option<crate::node_scheduling::NativeInputAcknowledgement>,
    pub(super) bytes: Vec<u8>,
}

pub(super) struct PublicWindow {
    pub(super) original: OperationAdmission,
    pub(super) grant: DeviceGrant,
    pub(super) receipt: Option<DeviceReceipt>,
    pub(super) result: Option<crucible_node_provider::bodies::QuantumBeginResult>,
    pub(super) observations: Option<ObservationBatch>,
    pub(super) closed: bool,
    pub(super) consumed: bool,
}

pub(super) struct CnpRuntimeCustody {
    pub(super) binding: NodeBinding,
    pub(super) owner_binding: OwnerBinding,
    pub(super) gate: ControlReceipt,
    pub(super) companion_pid: u32,
    pub(super) status: DeviceStatus,
    pub(super) preparation_attempt: Option<ActivationRecord>,
    pub(super) prepared: Option<PreparedActivation>,
    pub(super) active: Option<ActivationRecord>,
    pub(super) input: Option<StagedInput>,
    pub(super) windows: BTreeMap<Id, PublicWindow>,
    pub(super) pending: Option<OperationAdmission>,
    pub(super) maximum_operations: usize,
    pub(super) next_input_sequence: U64,
    pub(super) checksum: u64,
    pub(super) boundary_evidence: BTreeMap<ContentRef, crate::node_scheduling::InputPayload>,
    pub(super) boundary_dependencies: BTreeMap<ContentRef, Vec<ContentRef>>,
}

impl CnpRuntimeCustody {
    pub(super) fn validate_retained(&self, companion: Option<u32>) -> Result<(), ProviderError> {
        let bytes = self
            .boundary_evidence
            .values()
            .try_fold(0usize, |total, object| {
                total.checked_add(object.bytes.len())
            });
        if self.boundary_evidence.len() > 4096
            || bytes.is_none_or(|total| total > 16 * 1024 * 1024)
            || self.boundary_evidence.iter().any(|(reference, object)| {
                reference != &object.reference || reference.verify(&object.bytes).is_err()
            })
            || self
                .boundary_dependencies
                .keys()
                .any(|reference| !self.boundary_evidence.contains_key(reference))
        {
            return Err(ProviderError::Correlation(
                "retained public proof registry changed original bytes",
            ));
        }
        self.binding.validate()?;
        self.owner_binding.validate()?;
        self.gate.validate()?;
        if companion != Some(self.companion_pid)
            || self.companion_pid == 0
            || self.maximum_operations == 0
            || self.maximum_operations > 65_536
            || self.windows.len() > self.maximum_operations
            || self.next_input_sequence.get() == 0
            || self.owner_binding.owner != self.binding.compatibility.execution_owner
            || self.gate.owner_ids != [self.owner_binding.owner.id.clone()]
            || self.gate.kind != ControlReceiptKind::ClosedGate
            || self.preparation_attempt.as_ref().is_some_and(|attempt| {
                attempt.generation.get() == 0
                    || attempt.world_binding_hash.validate().is_err()
                    || !attempt.owners.iter().any(|owner| {
                        owner.owner == self.owner_binding.owner.id
                            && owner.incarnation == self.binding.authority.incarnation_id
                            && owner.generation == self.binding.authority.owner_generation
                    })
                    || attempt.boundary
                        != Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
            })
            || self.prepared.as_ref().is_some_and(|prepared| {
                prepared.ready.ready_receipt != prepared.owner.ready_receipt
                    || prepared.owner.owner_id != self.owner_binding.owner.id
                    || self.preparation_attempt.as_ref() != Some(&prepared.record)
            })
            || self.active.as_ref().is_some_and(|active| {
                self.prepared
                    .as_ref()
                    .is_none_or(|prepared| prepared.record != *active)
            })
            || (matches!(
                self.status,
                DeviceStatus::Staged | DeviceStatus::Active | DeviceStatus::ClosedPending
            ) && self.active.is_none())
            || self.input.as_ref().is_some_and(|input| {
                input.original.batch() != &input.public.batch_id
                    || input
                        .acknowledgement
                        .as_ref()
                        .is_some_and(|ack| ack.batch != input.public.batch_id)
                    || input.public.batch_sequence >= self.next_input_sequence
            })
            || self.pending.as_ref().is_some_and(|pending| {
                pending.token().route().node != self.binding.compatibility.node_id
            })
            || self.windows.values().any(|window| {
                window.original.token().route().node != self.binding.compatibility.node_id
                    || window
                        .receipt
                        .as_ref()
                        .is_some_and(|receipt| receipt.grant != window.grant)
            })
            || self
                .windows
                .values()
                .filter_map(|window| window.receipt.as_ref())
                .max_by_key(|receipt| receipt.grant.quantum)
                .map_or(self.checksum != 0, |receipt| {
                    receipt.output.checksum.get() != self.checksum
                })
        {
            return Err(ProviderError::Correlation(
                "retained public runtime metadata changed original native custody",
            ));
        }
        Ok(())
    }
}

/// Owns a genuine installed public provider and its complete original controls.
///
/// Only the sealed host checksum adapter can use this control implementation.
/// It does not implement a generic native guarantee verifier: qualification is
/// supplied by the installation registry before graph admission. Unknown wire
/// outcomes retain the original process, operation and input journals.
pub struct CnpControlledReference {
    pub(super) guard: CnpLaunchGuard,
    pub(super) binding: NodeBinding,
    pub(super) owner_binding: OwnerBinding,
    pub(super) gate: ControlReceipt,
    pub(super) companion_pid: u32,
    pub(super) status: DeviceStatus,
    pub(super) preparation_attempt: Option<ActivationRecord>,
    pub(super) prepared: Option<PreparedActivation>,
    pub(super) active: Option<ActivationRecord>,
    pub(super) input: Option<StagedInput>,
    pub(super) windows: BTreeMap<Id, PublicWindow>,
    pub(super) pending: Option<OperationAdmission>,
    pub(super) maximum_operations: usize,
    pub(super) next_input_sequence: U64,
    pub(super) checksum: u64,
    pub(super) boundary_evidence: BTreeMap<ContentRef, crate::node_scheduling::InputPayload>,
    pub(super) boundary_dependencies: BTreeMap<ContentRef, Vec<ContentRef>>,
}

impl Drop for CnpControlledReference {
    fn drop(&mut self) {
        if let Some(custody) = self.guard.custody.as_mut() {
            // Dropping a borrower cannot erase opaque host admissions or turn
            // incomplete native windows into reusable operation identities.
            custody.runtime = Some(CnpRuntimeCustody {
                binding: self.binding.clone(),
                owner_binding: self.owner_binding.clone(),
                gate: self.gate.clone(),
                companion_pid: self.companion_pid,
                status: self.status,
                preparation_attempt: self.preparation_attempt.take(),
                prepared: self.prepared.take(),
                active: self.active.take(),
                input: self.input.take(),
                windows: std::mem::take(&mut self.windows),
                pending: self.pending.take(),
                maximum_operations: self.maximum_operations,
                next_input_sequence: self.next_input_sequence,
                checksum: self.checksum,
                boundary_evidence: std::mem::take(&mut self.boundary_evidence),
                boundary_dependencies: std::mem::take(&mut self.boundary_dependencies),
            });
        }
    }
}

impl CnpControlledReference {
    pub(super) fn new(preparation: CnpReferencePreparation, maximum_operations: usize) -> Self {
        Self {
            guard: preparation.guard,
            binding: preparation.binding,
            owner_binding: preparation.owner_binding,
            gate: preparation.gate,
            companion_pid: preparation.companion_pid,
            status: DeviceStatus::Parked,
            preparation_attempt: None,
            prepared: None,
            active: None,
            input: None,
            windows: BTreeMap::new(),
            pending: None,
            maximum_operations,
            next_input_sequence: U64::new(1),
            checksum: 0,
            boundary_evidence: BTreeMap::new(),
            boundary_dependencies: BTreeMap::new(),
        }
    }

    pub(super) fn controller(&self) -> Result<&ReferenceController, ProviderError> {
        self.guard
            .custody
            .as_ref()
            .and_then(|custody| custody.controller.as_ref())
            .ok_or(ProviderError::Correlation(
                "original CNP controller custody lost",
            ))
    }

    pub(super) fn controller_mut(&mut self) -> Result<&mut ReferenceController, ProviderError> {
        self.guard
            .custody
            .as_mut()
            .and_then(|custody| custody.controller.as_mut())
            .ok_or(ProviderError::Correlation(
                "original CNP controller custody lost",
            ))
    }

    pub(super) fn verify_native_custody(&self) -> Result<(), ProviderError> {
        self.guard.require_resolved_lifecycle_probes()?;
        let controller = self.controller()?;
        let provider = self.guard.provider_pid().ok_or(ProviderError::Correlation(
            "original CNP process custody lost",
        ))?;
        super::preparation::verify_companion(self.companion_pid, provider, &controller.profile)
            .map_err(|_| ProviderError::Correlation("actual CNP companion custody changed"))
    }
}

pub(super) fn original_id(kind: &str, original: &Id) -> Result<Id, ProviderError> {
    // Arbitrarily long admitted identities cannot overflow derived request IDs.
    // The domain-separated commitment preserves the exact original identity.
    let hash = canonical::hash(
        "cnp.installed-reference-request.v1",
        original.as_str().as_bytes(),
    )?;
    Ok(Id::new(format!("{kind}-{}", hash.digest))?)
}

pub(super) fn canonical_bytes(value: &impl serde::Serialize) -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(value).map_err(ContractError::from)?,
    )?)
}

pub(super) fn content(
    value: &impl serde::Serialize,
) -> Result<(ContentRef, Vec<u8>), ProviderError> {
    let bytes = canonical_bytes(value)?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    Ok((reference, bytes))
}
