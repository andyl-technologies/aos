//! Pure four-record Mount source-consumption correlation.

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{BrokerArgumentCommitment, ObjectDigest};

use super::{
    MountResourceStateV1, MountResourceV1, MountSourceConsistencyV1,
    MountSourceConsumptionStateError, NativeMutationV1, ObjectDescriptorV1, OwnedMountAttributeV1,
    SourcePinLifecycleV1, SourcePinRowV1, decode_mount_resource_key_v2,
    decode_mount_resource_value_v2, decode_source_pin_key_v1, decode_source_pin_value_v1,
    structurally_decode_mount_effect_v1,
};
use crate::MountSourceProofClassV1;
use crate::mount_source_acquisition_state::{
    MutationTagV2, RecordRefV2, SourceAcquisitionPhaseV2, SourceAcquisitionProofClassV2,
    StoredRecordV2, decode_mount_source_state_record_v2,
    mount_source_consumption_companion_digest_v2, transaction_id as mount_source_transaction_id,
};
use crate::semantics::{
    decode_canonical_mount_semantics_v1, project_final_mount_create_semantics_v1,
};

const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.journal.mount-source-consumption-preflight.v1\0";
/// Exact aggregate ceiling for the ordered four-record transaction.
pub const MAXIMUM_MOUNT_SOURCE_CONSUMPTION_TRANSACTION_BYTES_V2: usize = 52 * 1024 * 1024;
const _: () = assert!(MAXIMUM_MOUNT_SOURCE_CONSUMPTION_TRANSACTION_BYTES_V2 < 64 * 1024 * 1024);

/// Borrows one neutral record without importing a journal implementation.
#[derive(Clone, Copy, Debug)]
pub struct MountSourceConsumptionRecordV2<'a> {
    /// Stable numeric namespace code.
    pub namespace: u16,
    /// Exact record key.
    pub key: &'a [u8],
    /// Exact PUT value; the closed transaction rejects deletes.
    pub value: Option<&'a [u8]>,
}

/// Projects every identity and commitment of an exact consumption transaction.
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountSourceConsumptionProjectionV2 {
    transaction_id: [u8; 16],
    transaction_digest: [u8; 32],
    predecessor: RecordRefV2,
    successor: RecordRefV2,
    mount_acquisition_id: [u8; 32],
    provider_acquisition_id: [u8; 32],
    acquisition_sequence: u64,
    source_realization_handle: [u8; 32],
    descriptor_commitment: [u8; 32],
    operation_id: [u8; 16],
    transport_request_digest: [u8; 32],
    final_create_semantics: Vec<u8>,
    final_create_semantics_digest: [u8; 32],
    assignment_sandbox_id: [u8; 16],
    assignment_incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    prospective_mount_template_digest: [u8; 32],
    source_binding_digest: [u8; 32],
    mount_plan_digest: [u8; 32],
    ownership_lease_digest: [u8; 32],
    record_digests: [[u8; 32]; 4],
    source_pin_key_digest: [u8; 32],
    source_pin_value_digest: [u8; 32],
    effect_key_digest: [u8; 32],
    effect_value_digest: [u8; 32],
    mount_resource_key_digest: [u8; 32],
    mount_resource_value_digest: [u8; 32],
}

impl MountSourceConsumptionProjectionV2 {
    /// Returns the transaction identity and digest.
    #[must_use]
    pub const fn transaction(&self) -> ([u8; 16], [u8; 32]) {
        (self.transaction_id, self.transaction_digest)
    }

    /// Returns predecessor and successor acquisition references.
    #[must_use]
    pub fn acquisition_transition(&self) -> (&RecordRefV2, &RecordRefV2) {
        (&self.predecessor, &self.successor)
    }

    /// Returns Mount identity, provider identity, and provider sequence.
    #[must_use]
    pub const fn acquisition_identity(&self) -> ([u8; 32], [u8; 32], u64) {
        (
            self.mount_acquisition_id,
            self.provider_acquisition_id,
            self.acquisition_sequence,
        )
    }

    /// Returns realization and descriptor identities.
    #[must_use]
    pub const fn source_identity(&self) -> ([u8; 32], [u8; 32]) {
        (self.source_realization_handle, self.descriptor_commitment)
    }

    /// Returns the final Create operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the assignment identity and digest.
    #[must_use]
    pub const fn assignment(&self) -> ([u8; 16], [u8; 16], u64, u64, [u8; 32]) {
        (
            self.assignment_sandbox_id,
            self.assignment_incarnation_id,
            self.assignment_epoch,
            self.desired_generation,
            self.assignment_digest,
        )
    }

    /// Borrows the exact final Create semantics.
    #[must_use]
    pub fn final_create_semantics(&self) -> &[u8] {
        &self.final_create_semantics
    }

    /// Returns transport and final-semantics digests.
    #[must_use]
    pub const fn request_commitments(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.transport_request_digest,
            self.final_create_semantics_digest,
        )
    }

    /// Returns the final Create operation, request, semantic digest, and bytes.
    #[must_use]
    pub fn final_create(&self) -> ([u8; 16], [u8; 32], [u8; 32], &[u8]) {
        (
            self.operation_id,
            self.transport_request_digest,
            self.final_create_semantics_digest,
            &self.final_create_semantics,
        )
    }

    /// Returns semantic, source-binding, plan, and ownership commitments.
    #[must_use]
    pub const fn semantic_commitments(&self) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        (
            self.prospective_mount_template_digest,
            self.source_binding_digest,
            self.mount_plan_digest,
            self.ownership_lease_digest,
        )
    }

    /// Returns the exact ordered record commitments.
    #[must_use]
    pub const fn record_digests(&self) -> &[[u8; 32]; 4] {
        &self.record_digests
    }

    /// Returns exact key and value commitments for each companion record.
    #[must_use]
    pub const fn companion_key_value_digests(&self) -> [([u8; 32], [u8; 32]); 3] {
        [
            (self.source_pin_key_digest, self.source_pin_value_digest),
            (self.effect_key_digest, self.effect_value_digest),
            (
                self.mount_resource_key_digest,
                self.mount_resource_value_digest,
            ),
        ]
    }
}

/// Validates and projects one exact ordered four-record consumption transaction.
///
/// The effect wrapper is structurally decoded here. Its MAC authority must be
/// established independently by the broker key owner before these bytes enter
/// the protected purpose guard.
///
/// # Errors
///
/// Returns an error for wrong order, deletes, duplicate keys, pre-decode
/// bounds, malformed/noncanonical records, or any cross-record mismatch.
pub fn validate_mount_source_consumption_v2(
    transaction_id: [u8; 16],
    predecessor_value: &[u8],
    records: &[MountSourceConsumptionRecordV2<'_>],
) -> Result<MountSourceConsumptionProjectionV2, MountSourceConsumptionStateError> {
    if transaction_id == [0; 16] || records.len() != 4 {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }
    let expected_namespaces = [40_u16, 39, 3, 2];
    let mut aggregate = 0usize;
    for (record, expected_namespace) in records.iter().zip(expected_namespaces) {
        let value = record
            .value
            .ok_or(MountSourceConsumptionStateError::InvalidValue)?;
        aggregate = aggregate
            .checked_add(7)
            .and_then(|total| total.checked_add(record.key.len()))
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(MountSourceConsumptionStateError::InvalidSize)?;
        if record.namespace != expected_namespace
            || record.key.is_empty()
            || aggregate > MAXIMUM_MOUNT_SOURCE_CONSUMPTION_TRANSACTION_BYTES_V2
        {
            return Err(MountSourceConsumptionStateError::InvalidSize);
        }
    }
    for left in 0..records.len() {
        if records[left + 1..]
            .iter()
            .any(|right| right.key == records[left].key)
        {
            return Err(MountSourceConsumptionStateError::InvalidKey);
        }
    }

    let successor_value = records[0]
        .value
        .ok_or(MountSourceConsumptionStateError::InvalidValue)?;
    let StoredRecordV2::Acquisition { value: successor } =
        decode_mount_source_state_record_v2(records[0].key, successor_value)
            .map_err(|_| MountSourceConsumptionStateError::InvalidValue)?
    else {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    };
    let StoredRecordV2::Acquisition { value: predecessor } =
        decode_mount_source_state_record_v2(records[0].key, predecessor_value)
            .map_err(|_| MountSourceConsumptionStateError::InvalidValue)?
    else {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    };
    let evidence = successor
        .evidence
        .as_ref()
        .ok_or(MountSourceConsumptionStateError::InvalidValue)?;
    let consumption = successor
        .consumption
        .as_ref()
        .ok_or(MountSourceConsumptionStateError::InvalidValue)?;
    let expected_transaction_id = mount_source_transaction_id(
        MutationTagV2::Consumption,
        successor.scope.holder_authority_id,
        successor.scope.provider_authority_id,
        consumption.holder_sequence_revision,
        consumption.provider_head_revision,
        Some(successor.acquisition_id),
        Some(successor.revision),
        None,
        None,
        None,
    );
    if predecessor.phase != SourceAcquisitionPhaseV2::Active
        || successor.phase != SourceAcquisitionPhaseV2::Consumed
        || predecessor.revision.checked_add(1) != Some(successor.revision)
        || predecessor.consumption.is_some()
        || consumption.transaction_id != transaction_id
        || expected_transaction_id != transaction_id
        || !active_to_consumed_only(&predecessor, &successor)
    {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }

    let projected_template =
        project_final_mount_create_semantics_v1(&consumption.final_create_semantics)
            .map_err(|_| MountSourceConsumptionStateError::InvalidValue)?;
    let record_digests: [[u8; 32]; 4] = records
        .iter()
        .map(|record| {
            mount_source_consumption_companion_digest_v2(record.namespace, record.key, record.value)
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| MountSourceConsumptionStateError::InvalidValue)?;
    let operation_id: [u8; 16] = records[2]
        .key
        .try_into()
        .map_err(|_| MountSourceConsumptionStateError::InvalidKey)?;
    if successor.prospective_mount_template != projected_template
        || ObjectDigest::from_bytes(consumption.final_create_semantics_digest)
            != BrokerArgumentCommitment::for_canonical_bytes(&consumption.final_create_semantics)
                .digest()
        || record_digests[1] != consumption.source_pin_record_digest
        || record_digests[2] != consumption.create_effect_record_digest
        || record_digests[3] != consumption.create_operation_record_digest
        || operation_id != consumption.operation_id
    {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }

    let source_pin_value = records[1]
        .value
        .ok_or(MountSourceConsumptionStateError::InvalidValue)?;
    let source_pin = decode_source_pin_value_v1(source_pin_value)?;
    if decode_source_pin_key_v1(records[1].key)? != (source_pin.binding_digest, source_pin.handle) {
        return Err(MountSourceConsumptionStateError::InvalidKey);
    }
    let effect_value = records[2]
        .value
        .ok_or(MountSourceConsumptionStateError::InvalidValue)?;
    let effect = structurally_decode_mount_effect_v1(effect_value)?;
    let resource_value = records[3]
        .value
        .ok_or(MountSourceConsumptionStateError::InvalidValue)?;
    let resource = decode_mount_resource_value_v2(resource_value)?;
    if decode_mount_resource_key_v2(records[3].key)? != resource.handle {
        return Err(MountSourceConsumptionStateError::InvalidKey);
    }
    validate_correlations(
        &successor,
        evidence,
        consumption,
        &source_pin,
        &effect,
        &resource,
        operation_id,
    )?;

    let predecessor_ref = RecordRefV2 {
        id: predecessor.acquisition_id,
        revision: predecessor.revision,
        record_digest: predecessor.record_digest,
    };
    let successor_ref = RecordRefV2 {
        id: successor.acquisition_id,
        revision: successor.revision,
        record_digest: successor.record_digest,
    };
    let transaction_digest = transaction_digest(transaction_id, &record_digests);
    Ok(MountSourceConsumptionProjectionV2 {
        transaction_id,
        transaction_digest,
        predecessor: predecessor_ref,
        successor: successor_ref,
        mount_acquisition_id: successor.acquisition_id,
        provider_acquisition_id: successor.provider_acquisition.acquisition_id,
        acquisition_sequence: successor.provider_acquisition.acquisition_sequence,
        source_realization_handle: evidence.source_realization_handle,
        descriptor_commitment: evidence.descriptor_commitment,
        operation_id,
        transport_request_digest: consumption.transport_request_digest,
        final_create_semantics: consumption.final_create_semantics.clone(),
        final_create_semantics_digest: consumption.final_create_semantics_digest,
        assignment_sandbox_id: successor.assignment.sandbox_id,
        assignment_incarnation_id: successor.assignment.incarnation_id,
        assignment_epoch: successor.assignment.assignment_epoch,
        desired_generation: successor.assignment.desired_generation,
        assignment_digest: successor.assignment.assignment_digest,
        prospective_mount_template_digest: successor.prospective_mount_template_digest,
        source_binding_digest: successor.source_binding_digest,
        mount_plan_digest: successor.mount_plan_digest,
        ownership_lease_digest: successor.ownership_lease_digest,
        record_digests,
        source_pin_key_digest: Sha256::digest(records[1].key).into(),
        source_pin_value_digest: Sha256::digest(source_pin_value).into(),
        effect_key_digest: Sha256::digest(records[2].key).into(),
        effect_value_digest: Sha256::digest(effect_value).into(),
        mount_resource_key_digest: Sha256::digest(records[3].key).into(),
        mount_resource_value_digest: Sha256::digest(resource_value).into(),
    })
}

fn active_to_consumed_only(
    predecessor: &crate::mount_source_acquisition_state::SourceAcquisitionRowV2,
    successor: &crate::mount_source_acquisition_state::SourceAcquisitionRowV2,
) -> bool {
    let mut expected = successor.clone();
    expected.revision = predecessor.revision;
    expected.phase = SourceAcquisitionPhaseV2::Active;
    expected.consumption = None;
    expected.record_digest = predecessor.record_digest;
    &expected == predecessor
}

fn validate_correlations(
    acquisition: &crate::mount_source_acquisition_state::SourceAcquisitionRowV2,
    evidence: &crate::mount_source_acquisition_state::SourceAcquisitionEvidenceV2,
    consumption: &crate::mount_source_acquisition_state::ConsumptionEvidenceV2,
    source_pin: &SourcePinRowV1,
    effect: &super::StructurallyDecodedMountEffectV1,
    resource: &MountResourceV1,
    operation_id: [u8; 16],
) -> Result<(), MountSourceConsumptionStateError> {
    let signer = &evidence.historical_lease_signer.signer;
    let proof_class = match evidence.proof_class {
        SourceAcquisitionProofClassV2::ImmutableTree => MountSourceProofClassV1::ImmutableTree,
        SourceAcquisitionProofClassV2::LocalLive => MountSourceProofClassV1::LocalLive,
        SourceAcquisitionProofClassV2::BestEffortReplica => {
            MountSourceProofClassV1::BestEffortReplica
        }
    };
    let MountResourceStateV1::Allocated { creation } = &resource.state else {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    };
    if source_pin.handle != evidence.source_realization_handle
        || source_pin.revision != 1
        || source_pin.binding_bytes != acquisition.source_binding
        || source_pin.binding_digest != acquisition.source_binding_digest
        || source_pin.proof_class != proof_class
        || source_pin.provider_authority_id != signer.authority_id
        || source_pin.provider_authority_generation != signer.authority_generation
        || source_pin.provider_authority_digest != signer.authority_digest
        || source_pin.provider_resource_id != evidence.provider_resource_id
        || source_pin.provider_resource_generation != evidence.provider_resource_generation
        || source_pin.provider_resource_digest != evidence.provider_resource_digest
        || source_pin.provider_catalog_generation != evidence.provider_catalog_generation
        || source_pin.provider_catalog_digest != evidence.provider_catalog_digest
        || source_pin.kernel_boot_id != evidence.source_kernel_boot_id
        || source_pin.device != evidence.source_device
        || source_pin.inode != evidence.source_inode
        || source_pin.unique_mount_id != evidence.source_unique_mount_id
        || source_pin.physical_proof_digest != evidence.source_physical_proof_digest
        || source_pin.admission_operation_id != operation_id
        || source_pin.admission_request_digest != consumption.transport_request_digest
        || !source_pin.current
        || source_pin.lifecycle != SourcePinLifecycleV1::Active
        || effect.status != 0
        || effect.verb != 1
        || effect.target_tag != 0
        || effect.target_identity != [0; 64]
        || effect.request_id != operation_id
        || effect.transport_request_digest != consumption.transport_request_digest
        || effect.semantic_digest != consumption.final_create_semantics_digest
        || effect.plan_digest != acquisition.mount_plan_digest
        || effect.lease_digest != acquisition.ownership_lease_digest
        || !effect.receipt.is_empty()
        || resource.handle != crate::detached_mount_handle_v1(consumption.transport_request_digest)
        || resource.fd_store_key != resource.handle
        || resource.kernel_boot_id != evidence.source_kernel_boot_id
        || resource.revision != 1
        || creation.operation_id != operation_id
        || creation.request_digest != consumption.transport_request_digest
        || resource.binding.sandbox_id != acquisition.assignment.sandbox_id
        || resource.binding.incarnation_id != acquisition.assignment.incarnation_id
        || resource.binding.assignment_epoch != acquisition.assignment.assignment_epoch
        || resource.binding.desired_generation != acquisition.assignment.desired_generation
        || resource.binding.assignment_digest != acquisition.assignment.assignment_digest
        || resource.recipe.source_binding_digest != acquisition.source_binding_digest
        || resource.recipe.source_realization_handle != evidence.source_realization_handle
        || resource.recipe.source_physical_proof_digest != evidence.source_physical_proof_digest
        || resource.recipe.source_kernel_boot_id != evidence.source_kernel_boot_id
        || resource.recipe.source_device != evidence.source_device
        || resource.recipe.source_inode != evidence.source_inode
        || resource.recipe.source_unique_mount_id != evidence.source_unique_mount_id
        || resource.recipe.source_proof_class != proof_class
        || resource.recipe.source_provider_authority_id != signer.authority_id
        || resource.recipe.source_provider_authority_generation != signer.authority_generation
        || resource.recipe.source_provider_authority_digest != signer.authority_digest
        || resource.recipe.source_provider_resource_id != evidence.provider_resource_id
        || resource.recipe.source_provider_resource_generation
            != evidence.provider_resource_generation
        || resource.recipe.source_provider_resource_digest != evidence.provider_resource_digest
        || resource.recipe.source_provider_catalog_generation
            != evidence.provider_catalog_generation
        || resource.recipe.source_provider_catalog_digest != evidence.provider_catalog_digest
        || !mount_resource_matches_semantics(resource, &consumption.final_create_semantics)?
    {
        return Err(MountSourceConsumptionStateError::InvalidValue);
    }
    Ok(())
}

fn mount_resource_matches_semantics(
    resource: &MountResourceV1,
    semantics: &[u8],
) -> Result<bool, MountSourceConsumptionStateError> {
    let decoded = decode_canonical_mount_semantics_v1(semantics)
        .map_err(|_| MountSourceConsumptionStateError::InvalidValue)?;
    let fields = decoded.fields();
    let recipe = &resource.recipe;
    let binding = &resource.binding;
    let source_incarnation = recipe
        .source_incarnation_id
        .as_ref()
        .map_or(&[][..], <[u8; 16]>::as_slice);
    let descriptor = encode_descriptor(&recipe.view_revision)?;
    let attributes = encode_attributes(&recipe.policy.attributes, recipe.policy.mutation);
    let consistency = match recipe.source_consistency {
        MountSourceConsistencyV1::ImmutableRevision => 1,
        MountSourceConsistencyV1::LocalLive => 2,
        MountSourceConsistencyV1::BestEffortReplica => 4,
    };
    Ok(fields[0] == b"AOSMSEM1"
        && fields[1] == 1_u16.to_be_bytes()
        && fields[2] == [1]
        && fields[3] == binding.sandbox_id
        && fields[4] == binding.incarnation_id
        && fields[5] == binding.assignment_epoch.to_be_bytes()
        && fields[6] == binding.desired_generation.to_be_bytes()
        && fields[7] == binding.assignment_digest
        && fields[8] == recipe.attachment_id
        && fields[9] == recipe.destination_slot_id
        && fields[10] == recipe.source_generation.to_be_bytes()
        && fields[11] == binding.namespace_generation.to_be_bytes()
        && fields[12].len() == 32
        && fields[12].iter().any(|byte| *byte != 0)
        && fields[13] == descriptor
        && fields[14] == attributes
        && fields[15].is_empty()
        && fields[16].is_empty()
        && fields[17] == [0, 0]
        && fields[19] == recipe.resource_attachment_generation.to_be_bytes()
        && fields[20] == recipe.source_view_id
        && fields[21] == source_incarnation
        && fields[22] == [consistency]
        && fields[26] == recipe.source_handle)
}

fn encode_descriptor(
    descriptor: &ObjectDescriptorV1,
) -> Result<Vec<u8>, MountSourceConsumptionStateError> {
    let media = descriptor.media_type.as_bytes();
    let media_length =
        u16::try_from(media.len()).map_err(|_| MountSourceConsumptionStateError::InvalidValue)?;
    let mut encoded = Vec::with_capacity(2 + media.len() + 40);
    encoded.extend_from_slice(&media_length.to_be_bytes());
    encoded.extend_from_slice(media);
    encoded.extend_from_slice(&descriptor.sha256_digest);
    encoded.extend_from_slice(&descriptor.encoded_size.to_be_bytes());
    Ok(encoded)
}

fn encode_attributes(attributes: &[OwnedMountAttributeV1], mutation: NativeMutationV1) -> [u8; 7] {
    let contains = |attribute| u8::from(attributes.contains(&attribute));
    [
        contains(OwnedMountAttributeV1::ReadOnly),
        contains(OwnedMountAttributeV1::NoExec),
        contains(OwnedMountAttributeV1::NoSuid),
        contains(OwnedMountAttributeV1::NoDevice),
        contains(OwnedMountAttributeV1::NoAtime),
        contains(OwnedMountAttributeV1::Recursive),
        match mutation {
            NativeMutationV1::ReadOnly => 0,
            NativeMutationV1::ReadWrite => 1,
            NativeMutationV1::PrivateCow => 2,
            NativeMutationV1::AppendOnly => 3,
            NativeMutationV1::Service => 4,
        },
    ]
}

fn transaction_digest(transaction_id: [u8; 16], records: &[[u8; 32]; 4]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(TRANSACTION_DOMAIN);
    digest.update(transaction_id);
    digest.update(4_u32.to_be_bytes());
    for record in records {
        digest.update(record);
    }
    digest.finalize().into()
}
