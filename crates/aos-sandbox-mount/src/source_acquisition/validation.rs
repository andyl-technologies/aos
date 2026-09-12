//! Validation and authenticated evidence projection for AOSMSA01 state.
//!
//! This module owns phase-exact field presence, transition immutability,
//! provider disposition projection, sequence-CAS checks, and signed inventory
//! reconciliation. Journal I/O and table orchestration remain in the parent.

use super::history::validate_global_provider_and_head_history;
use super::inventory::{
    validate_recovered_inventory_projection, validate_recovered_inventory_result,
};
use super::*;

pub(super) fn validate_recovered_table(
    acquisitions: &BTreeMap<[u8; 32], SourceAcquisitionRowV1>,
    heads: &BTreeMap<([u8; 16], [u8; 16]), SourceProviderHeadV1>,
) -> Result<()> {
    let mut operation_ids = std::collections::BTreeSet::new();
    for row in acquisitions.values() {
        if !operation_ids.insert(row.acquire.operation_id)
            || row
                .release
                .is_some_and(|release| !operation_ids.insert(release.operation_id))
        {
            return Err(state_error("source acquisition operation ID is duplicated"));
        }
        let identity = (
            row.provider.holder_authority_id,
            row.provider.provider_authority_id,
        );
        let head = heads
            .get(&identity)
            .ok_or_else(|| state_error("source acquisition provider head is absent"))?;
        validate_head_dominates_row(head, row)?;
        if let Some(release_provider) = row.release_provider {
            validate_head_dominates_provider(head, release_provider, false)?;
        }
        let owns_expected_reservation = |owner| {
            head.pending_query
                .as_ref()
                .is_some_and(|pending| pending.owner == owner)
        };
        if row.phase == SourceAcquisitionPhaseV1::PendingQuery
            && row.acquire_checkpoint.is_none()
            && !owns_expected_reservation(ProviderQueryOwnerV1::Acquire {
                acquisition_id: row.acquisition_id,
            })
            || row.phase == SourceAcquisitionPhaseV1::Releasing
                && row.release_checkpoint.is_none()
                && !owns_expected_reservation(ProviderQueryOwnerV1::Release {
                    acquisition_id: row.acquisition_id,
                })
        {
            return Err(state_error(
                "source acquisition lacks its outstanding provider query",
            ));
        }
    }
    validate_global_provider_and_head_history(acquisitions, heads)?;
    validate_checkpoint_sequence_history(acquisitions, heads)?;
    for head in heads.values() {
        let Some(pending) = &head.pending_query else {
            continue;
        };
        match pending.owner {
            ProviderQueryOwnerV1::Acquire { acquisition_id } => {
                let row = acquisitions.get(&acquisition_id).ok_or_else(|| {
                    state_error("provider Acquire reservation has no acquisition row")
                })?;
                if row.phase != SourceAcquisitionPhaseV1::PendingQuery
                    || row.provider.holder_authority_id != head.holder_authority_id
                    || row.provider.provider_authority_id != head.provider_authority_id
                    || row.provider_acquire_request != pending.signed_request
                {
                    return Err(state_error(
                        "provider Acquire reservation differs from its row",
                    ));
                }
            }
            ProviderQueryOwnerV1::Release { acquisition_id } => {
                let row = acquisitions.get(&acquisition_id).ok_or_else(|| {
                    state_error("provider Release reservation has no acquisition row")
                })?;
                if row.phase != SourceAcquisitionPhaseV1::Releasing
                    || row.provider.holder_authority_id != head.holder_authority_id
                    || row.provider.provider_authority_id != head.provider_authority_id
                    || row.provider_release_request.as_ref() != Some(&pending.signed_request)
                {
                    return Err(state_error(
                        "provider Release reservation differs from its row",
                    ));
                }
                let provider = row.release_provider.ok_or_else(|| {
                    state_error("provider Release reservation lacks its protected context")
                })?;
                validate_head_for_provider_context(head, provider)?;
                validate_release_query(row, provider, &pending.signed_request)?;
            }
            ProviderQueryOwnerV1::Inventory => {
                let signed =
                    SignedSourceProviderRequestV1::from_canonical_bytes(&pending.signed_request)
                        .map_err(|error| state_error(error.to_string()))?;
                let query = decode_inventory_request(signed.subject())
                    .map_err(|error| state_error(error.to_string()))?;
                if query.holder_authority_id() != head.holder_authority_id
                    || query.holder_generation() != head.holder_generation
                    || query.holder_authority_digest().as_bytes() != &head.holder_authority_digest
                    || query
                        .known_inventory_digest()
                        .map(|digest| *digest.as_bytes())
                        != head.inventory_digest
                {
                    return Err(state_error(
                        "provider Inventory reservation differs from head",
                    ));
                }
            }
        }
    }
    for head in heads.values() {
        validate_recovered_inventory_projection(acquisitions, head)?;
    }
    Ok(())
}

pub(super) fn validate_checkpoint_sequence_history(
    acquisitions: &BTreeMap<[u8; 32], SourceAcquisitionRowV1>,
    heads: &BTreeMap<([u8; 16], [u8; 16]), SourceProviderHeadV1>,
) -> Result<()> {
    let mut current_sessions = BTreeMap::new();
    for head in heads.values() {
        if current_sessions
            .insert(head.session_binding, head)
            .is_some()
        {
            return Err(state_error("source provider session binding is duplicated"));
        }
    }
    let mut request_sequences = std::collections::BTreeSet::new();
    let mut response_sequences = std::collections::BTreeSet::new();
    for head in heads.values() {
        if let Some(pending) = &head.pending_query
            && !request_sequences.insert((head.session_binding, pending.request_sequence))
        {
            return Err(state_error(
                "source provider pending request sequence is duplicated",
            ));
        }
    }
    let mut validate = |checkpoint: &ProviderDispositionCheckpointV1| -> Result<()> {
        let signed =
            SignedSourceProviderRequestV1::from_canonical_bytes(&checkpoint.signed_request)
                .map_err(|error| state_error(error.to_string()))?;
        let (_, session_binding, _) = checkpoint_request_identity(&signed, checkpoint.method)?;
        if !request_sequences.insert((session_binding, checkpoint.request_sequence))
            || !response_sequences.insert((session_binding, checkpoint.response_sequence))
        {
            return Err(state_error(
                "source provider disposition sequence is duplicated",
            ));
        }
        if current_sessions.get(&session_binding).is_some_and(|head| {
            checkpoint.request_sequence >= head.next_request_sequence
                || checkpoint.response_sequence >= head.next_response_sequence
        }) {
            return Err(state_error(
                "source provider disposition sequence is ahead of its head",
            ));
        }
        Ok(())
    };
    for row in acquisitions.values() {
        for checkpoint in row
            .acquire_history
            .iter()
            .chain(row.acquire_checkpoint.iter())
            .chain(row.release_history.iter())
            .chain(row.release_checkpoint.iter())
        {
            validate(checkpoint)?;
        }
    }
    for checkpoint in heads
        .values()
        .filter_map(|head| head.last_inventory_checkpoint.as_ref())
    {
        validate(checkpoint)?;
    }
    Ok(())
}

fn validate_head_dominates_row(
    head: &SourceProviderHeadV1,
    row: &SourceAcquisitionRowV1,
) -> Result<()> {
    let provider = row.provider;
    validate_head_dominates_provider(
        head,
        provider,
        row.phase == SourceAcquisitionPhaseV1::PendingQuery,
    )
}

fn validate_head_dominates_provider(
    head: &SourceProviderHeadV1,
    provider: SourceProviderContextSnapshotV1,
    require_current_session: bool,
) -> Result<()> {
    let rollback = head.holder_generation < provider.holder_generation
        || head.holder_authority_id != provider.holder_authority_id
        || head.holder_generation == provider.holder_generation
            && head.holder_authority_digest != provider.holder_authority_digest
        || head.provider_authority_generation < provider.provider_authority_generation
        || head.provider_authority_id != provider.provider_authority_id
        || head.provider_authority_generation == provider.provider_authority_generation
            && head.provider_authority_digest != provider.provider_authority_digest
        || head.route_id != provider.provider_route_id
        || head.resource_namespace_digest != provider.resource_namespace_digest
        || head.route_generation < provider.provider_route_generation
        || head.route_generation == provider.provider_route_generation
            && head.route_digest != provider.provider_route_digest
        || head.provider_key_generation < provider.provider_key_generation
        || head.provider_key_generation == provider.provider_key_generation
            && (head.provider_key_id != provider.provider_key_id
                || head.provider_public_key_digest != provider.provider_public_key_digest);
    if rollback
        || require_current_session
            && (head.session_binding != provider.session_binding
                || head.kernel_boot_id != provider.kernel_boot_id)
    {
        return Err(state_error(
            "source provider head does not dominate acquisition row",
        ));
    }
    Ok(())
}

impl SourceAcquisitionRowV1 {
    pub(super) fn validate(&self) -> Result<()> {
        let mount_request_digest =
            mount_source_acquisition_request_digest_v1(&self.mount_acquire_request);
        let derived_acquisition_id =
            mount_source_acquisition_id_v1(self.acquire.operation_id, mount_request_digest);
        let template_digest =
            prospective_mount_apply_template_digest_v1(&self.prospective_mount_template)
                .map_err(|error| state_error(error.to_string()))?;
        let binding_digest = digest_logical_binding_bytes(&self.source_binding);
        validate_provider_acquire_query(self)?;
        validate_mount_release_request(self)?;
        if self.acquisition_id == [0; 32]
            || self.revision == 0
            || !valid_operation(self.acquire)
            || self.mount_acquire_request.is_empty()
            || self.mount_acquire_request.len() > MAXIMUM_VALUE_BYTES
            || self.acquire.request_digest != *mount_request_digest.as_bytes()
            || self.acquisition_id != *derived_acquisition_id.as_bytes()
            || !valid_assignment(self.assignment)
            || self.prospective_mount_template.is_empty()
            || self.prospective_mount_template_digest != *template_digest.as_bytes()
            || self.source_binding.is_empty()
            || self.source_binding_digest != *binding_digest.as_bytes()
            || self.mount_plan_digest == [0; 32]
            || self.ownership_lease_digest == [0; 32]
            || !valid_provider_context(self.provider)
            || !valid_signed_request(
                &self.provider_acquire_request,
                self.provider_acquire_request_digest,
            )
            || self.record_digest != acquisition_record_digest(self)?
        {
            return Err(state_error(
                "source acquisition row contains a sentinel or bad digest",
            ));
        }
        self.acquire_checkpoint
            .as_ref()
            .map(ProviderDispositionCheckpointV1::validate)
            .transpose()?;
        if let Some(checkpoint) = &self.acquire_checkpoint {
            validate_checkpoint_provider_signer(checkpoint, self.provider, true)?;
        }
        if self.acquire_history.len() > MAXIMUM_DISPOSITION_HISTORY {
            return Err(state_error("provider Acquire history exceeds its bound"));
        }
        for checkpoint in &self.acquire_history {
            checkpoint.validate()?;
            validate_checkpoint_provider_signer(checkpoint, self.provider, true)?;
            if checkpoint.method != ProviderMethodV1::Acquire
                || checkpoint.status == ProviderStatusV1::Complete
            {
                return Err(state_error("provider Acquire history is invalid"));
            }
        }
        if !checkpoint_history_is_ordered(&self.acquire_history, self.acquire_checkpoint.as_ref()) {
            return Err(state_error("provider Acquire history is not ordered"));
        }
        if self.acquire_checkpoint.as_ref().is_some_and(|checkpoint| {
            checkpoint.method != ProviderMethodV1::Acquire
                || (checkpoint.status == ProviderStatusV1::Complete) != self.evidence.is_some()
                || checkpoint.signed_request != self.provider_acquire_request
                || checkpoint.signed_request_digest != self.provider_acquire_request_digest
        }) {
            return Err(state_error(
                "source acquisition provider result shape is invalid",
            ));
        }
        if self.evidence.is_some()
            && self.acquire_checkpoint.as_ref().is_none_or(|checkpoint| {
                checkpoint.method != ProviderMethodV1::Acquire
                    || checkpoint.status != ProviderStatusV1::Complete
            })
        {
            return Err(state_error(
                "source acquisition evidence lacks its Complete disposition",
            ));
        }
        if self
            .evidence
            .as_ref()
            .is_some_and(|evidence| !valid_evidence(evidence))
        {
            return Err(state_error(
                "source acquisition evidence contains a sentinel",
            ));
        }
        if let (Some(checkpoint), Some(evidence)) = (&self.acquire_checkpoint, &self.evidence) {
            validate_recovered_acquire_result(self, checkpoint, evidence)?;
        }
        self.release_checkpoint
            .as_ref()
            .map(ProviderDispositionCheckpointV1::validate)
            .transpose()?;
        if let (Some(checkpoint), Some(provider)) =
            (&self.release_checkpoint, self.release_provider)
        {
            validate_checkpoint_provider_signer(checkpoint, provider, true)?;
        }
        if let (Some(provider), Some(request)) = (
            self.release_provider,
            self.provider_release_request.as_deref(),
        ) {
            validate_release_query(self, provider, request)?;
        }
        if let Some(checkpoint) = &self.release_checkpoint {
            validate_recovered_release_result(self, checkpoint)?;
        }
        if self.release_history.len() > MAXIMUM_DISPOSITION_HISTORY {
            return Err(state_error("provider Release history exceeds its bound"));
        }
        for checkpoint in &self.release_history {
            checkpoint.validate()?;
            if let Some(provider) = self.release_provider {
                validate_checkpoint_provider_signer(checkpoint, provider, false)?;
            }
            if checkpoint.method != ProviderMethodV1::Release
                || checkpoint.status == ProviderStatusV1::Complete
            {
                return Err(state_error("provider Release history is invalid"));
            }
        }
        if !checkpoint_history_is_ordered(&self.release_history, self.release_checkpoint.as_ref()) {
            return Err(state_error("provider Release history is not ordered"));
        }
        if self
            .provider_inventory_digest
            .is_some_and(|digest| !nonzero_digest(digest))
            || self.provider_inventory_digest.is_some()
                != self.provider_inventory_observation_ordinal.is_some()
            || self
                .provider_inventory_observation_ordinal
                .is_some_and(|epoch| epoch == 0)
            || self
                .provider_inventory_observation_ordinal
                .is_some_and(|ordinal| {
                    self.release_inventory_observation_floor
                        .is_none_or(|floor| ordinal <= floor)
                })
        {
            return Err(state_error(
                "source acquisition inventory digest is a sentinel",
            ));
        }
        let phase_shape = if self.phase == SourceAcquisitionPhaseV1::Faulted {
            self.faulted_from.is_some_and(|from| {
                !matches!(
                    from,
                    SourceAcquisitionPhaseV1::Releasing
                        | SourceAcquisitionPhaseV1::Released
                        | SourceAcquisitionPhaseV1::Faulted
                ) && validate_phase_shape(self, from)
            }) && self.fault_digest.is_some_and(nonzero_digest)
        } else {
            self.faulted_from.is_none()
                && self.fault_digest.is_none()
                && validate_phase_shape(self, self.phase)
        };
        let retained_fault_shape = match (self.retained_faulted_from, self.retained_fault_digest) {
            (None, None) => true,
            (Some(from), Some(digest)) => {
                matches!(
                    self.phase,
                    SourceAcquisitionPhaseV1::Releasing | SourceAcquisitionPhaseV1::Released
                ) && !matches!(
                    from,
                    SourceAcquisitionPhaseV1::Releasing
                        | SourceAcquisitionPhaseV1::Released
                        | SourceAcquisitionPhaseV1::Faulted
                ) && nonzero_digest(digest)
                    && validate_retained_fault_origin(self, from)
            }
            _ => false,
        };
        if !phase_shape || !retained_fault_shape {
            return Err(state_error("source acquisition phase fields are not exact"));
        }
        Ok(())
    }
}

fn validate_retained_fault_origin(
    row: &SourceAcquisitionRowV1,
    from: SourceAcquisitionPhaseV1,
) -> bool {
    let has_consumption = row
        .consumed_source_pin_record_digest
        .is_some_and(nonzero_digest)
        && row
            .consumed_create_effect_record_digest
            .is_some_and(nonzero_digest)
        && row
            .consumed_create_operation_record_digest
            .is_some_and(nonzero_digest);
    let no_consumption = row.consumed_source_pin_record_digest.is_none()
        && row.consumed_create_effect_record_digest.is_none()
        && row.consumed_create_operation_record_digest.is_none();
    match from {
        SourceAcquisitionPhaseV1::PendingQuery => {
            no_consumption
                && row.descriptor_custody_digest.is_none()
                && row.positive_custody_digest.is_none()
        }
        SourceAcquisitionPhaseV1::DescriptorCustodied => {
            no_consumption
                && row.evidence.is_some()
                && row.descriptor_custody_digest.is_some_and(nonzero_digest)
                && row.positive_custody_digest.is_none()
        }
        SourceAcquisitionPhaseV1::Active => {
            no_consumption
                && row.evidence.is_some()
                && row.descriptor_custody_digest.is_some_and(nonzero_digest)
                && row.positive_custody_digest.is_some_and(nonzero_digest)
        }
        SourceAcquisitionPhaseV1::Consumed => {
            has_consumption
                && row.evidence.is_some()
                && row.descriptor_custody_digest.is_some_and(nonzero_digest)
                && row.positive_custody_digest.is_some_and(nonzero_digest)
        }
        SourceAcquisitionPhaseV1::Releasing
        | SourceAcquisitionPhaseV1::Released
        | SourceAcquisitionPhaseV1::Faulted => false,
    }
}

fn checkpoint_history_is_ordered(
    history: &[ProviderDispositionCheckpointV1],
    current: Option<&ProviderDispositionCheckpointV1>,
) -> bool {
    history.windows(2).all(|pair| {
        pair[0].request_sequence < pair[1].request_sequence
            && pair[0].response_sequence < pair[1].response_sequence
    }) && history
        .last()
        .zip(current)
        .is_none_or(|(previous, current)| {
            previous.request_sequence < current.request_sequence
                && previous.response_sequence < current.response_sequence
        })
}

impl ProviderDispositionCheckpointV1 {
    pub(super) fn validate(&self) -> Result<()> {
        let signed_request =
            SignedSourceProviderRequestV1::from_canonical_bytes(&self.signed_request)
                .map_err(|error| state_error(error.to_string()))?;
        let signed_status = SignedSourceProviderStatusV1::from_canonical_bytes(&self.signed_status)
            .map_err(|error| state_error(error.to_string()))?;
        let (request_id, session_binding, request_sequence) =
            checkpoint_request_identity(&signed_request, self.method)?;
        let status = signed_status.subject();
        let compact_inventory_result = self.method == ProviderMethodV1::Inventory
            && self.status == ProviderStatusV1::Complete
            && self.signed_result.is_empty();
        if self.request_sequence == 0
            || self.response_sequence == 0
            || !checkpoint_sequences_are_paired(self.request_sequence, self.response_sequence)
            || self.signed_request_digest == [0; 32]
            || self.signed_status_digest == [0; 32]
            || self.result_digest == [0; 32]
            || self.signed_request.is_empty()
            || self.signed_status.is_empty()
            || self.signed_request.len() > MAXIMUM_SIGNED_PROVIDER_BYTES
            || self.signed_status.len() > MAXIMUM_SIGNED_PROVIDER_BYTES
            || self.signed_result.len() > MAXIMUM_SIGNED_PROVIDER_BYTES
            || self.status == ProviderStatusV1::Complete
                && self.signed_result.is_empty()
                && !compact_inventory_result
            || self.status != ProviderStatusV1::Complete && !self.signed_result.is_empty()
            || Sha256::digest(&self.signed_request).as_slice() != self.signed_request_digest
            || Sha256::digest(&self.signed_status).as_slice() != self.signed_status_digest
            || !compact_inventory_result
                && response_result_digest_v1(
                    self.method.protocol(),
                    match self.status {
                        ProviderStatusV1::Complete => SourceProviderStatus::Complete,
                        ProviderStatusV1::Pending => SourceProviderStatus::Pending,
                        ProviderStatusV1::Rejected => SourceProviderStatus::Rejected,
                        ProviderStatusV1::Unavailable => SourceProviderStatus::Unavailable,
                    },
                    (!self.signed_result.is_empty()).then_some(self.signed_result.as_slice()),
                )
                .as_bytes()
                    != &self.result_digest
            || request_sequence != self.request_sequence
            || signed_request.method() != self.method.protocol()
            || status.method() != self.method.protocol()
            || status.status()
                != match self.status {
                    ProviderStatusV1::Complete => SourceProviderStatus::Complete,
                    ProviderStatusV1::Pending => SourceProviderStatus::Pending,
                    ProviderStatusV1::Rejected => SourceProviderStatus::Rejected,
                    ProviderStatusV1::Unavailable => SourceProviderStatus::Unavailable,
                }
            || status.request_id() != request_id
            || status.signed_request_digest().as_bytes() != &self.signed_request_digest
            || status.session_binding().as_bytes() != &session_binding
            || status.response_sequence() != self.response_sequence
            || status.result_digest().as_bytes() != &self.result_digest
            || !(self.method == ProviderMethodV1::Acquire
                && self.status == ProviderStatusV1::Complete)
                && status.descriptor_commitment() != empty_descriptor_set_commitment_v1()
        {
            return Err(state_error("provider disposition checkpoint is invalid"));
        }
        if self.status == ProviderStatusV1::Complete {
            match self.method {
                ProviderMethodV1::Acquire => {
                    SignedSourceProviderReceiptV1::from_canonical_bytes(&self.signed_result)
                        .map_err(|error| state_error(error.to_string()))?;
                }
                ProviderMethodV1::Release => {
                    SignedSourceReleaseReceiptV1::from_canonical_bytes(&self.signed_result)
                        .map_err(|error| state_error(error.to_string()))?;
                }
                ProviderMethodV1::Inventory => {
                    if !compact_inventory_result {
                        SignedSourceProviderInventoryV1::from_canonical_bytes(&self.signed_result)
                            .map_err(|error| state_error(error.to_string()))?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn validate_recovered_acquire_result(
    row: &SourceAcquisitionRowV1,
    checkpoint: &ProviderDispositionCheckpointV1,
    evidence: &SourceAcquisitionEvidenceV1,
) -> Result<()> {
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&checkpoint.signed_request)
            .map_err(|error| state_error(error.to_string()))?;
    let request = decode_acquire_request(signed_request.subject())
        .map_err(|error| state_error(error.to_string()))?;
    let signed_status =
        SignedSourceProviderStatusV1::from_canonical_bytes(&checkpoint.signed_status)
            .map_err(|error| state_error(error.to_string()))?;
    let signed_receipt =
        SignedSourceProviderReceiptV1::from_canonical_bytes(&checkpoint.signed_result)
            .map_err(|error| state_error(error.to_string()))?;
    let receipt = signed_receipt.subject();
    let signed_lease =
        SignedSourceExportLeaseV1::from_canonical_bytes(receipt.signed_export_lease())
            .map_err(|error| state_error(error.to_string()))?;
    let lease = signed_lease.subject();
    let resource = lease.resource();
    let provider = lease.provider();
    let proof_digest = digest_provider_proof(lease.proof());
    let resource_commitment = provider_resource_commitment_v1(resource, proof_digest);
    let proof_class = mount_source_proof_class_from_provider_v1(lease.proof());
    let stored_proof_class = match proof_class {
        aos_sandbox_protocol::MountSourceProofClassV1::ImmutableTree => {
            SourceAcquisitionProofClassV1::ImmutableTree
        }
        aos_sandbox_protocol::MountSourceProofClassV1::LocalLive => {
            SourceAcquisitionProofClassV1::LocalLive
        }
        aos_sandbox_protocol::MountSourceProofClassV1::BestEffortReplica => {
            SourceAcquisitionProofClassV1::BestEffortReplica
        }
    };
    if stored_proof_class != expected_binding_proof_class(&row.source_binding)? {
        return Err(state_error(
            "provider proof class differs from the durable source consistency",
        ));
    }
    let physical_proof = mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
        binding_digest: row.source_binding_digest,
        proof_class,
        provider_authority_id: provider.authority_id(),
        provider_authority_generation: provider.authority_generation(),
        provider_authority_digest: *provider.authority_digest().as_bytes(),
        provider_resource_id: resource.resource_id(),
        provider_resource_generation: resource.resource_generation(),
        provider_resource_digest: *resource_commitment.as_bytes(),
        provider_catalog_generation: resource.catalog_generation(),
        provider_catalog_digest: *resource.catalog_digest().as_bytes(),
        kernel_boot_id: receipt.kernel_boot_id(),
        device: receipt.device(),
        inode: receipt.inode(),
        unique_mount_id: receipt.unique_mount_id(),
    });
    let observation = SourceRootObservationV1::new(
        receipt.kernel_boot_id(),
        receipt.device(),
        receipt.inode(),
        receipt.unique_mount_id(),
        true,
        true,
        true,
    )
    .map_err(|error| state_error(error.to_string()))?;
    let descriptor_commitment = source_root_descriptor_commitment_v1(&observation);
    let expected = SourceAcquisitionEvidenceV1 {
        provider_resource_id: resource.resource_id(),
        provider_resource_generation: resource.resource_generation(),
        provider_resource_digest: *resource_commitment.as_bytes(),
        provider_catalog_generation: resource.catalog_generation(),
        provider_catalog_digest: *resource.catalog_digest().as_bytes(),
        provider_selection_generation: resource.selection_generation(),
        provider_selection_digest: *resource.selection_digest().as_bytes(),
        proof_class: stored_proof_class,
        provider_proof_digest: *proof_digest.as_bytes(),
        lease_id: lease.lease_id(),
        signed_lease_digest: *digest_signed_export_lease(&signed_lease).as_bytes(),
        lease_issued_seconds: lease.issued_seconds(),
        lease_expires_seconds: lease.expires_seconds(),
        source_realization_handle: mount_source_realization_handle_v1(
            row.source_binding_digest,
            physical_proof,
        ),
        source_physical_proof_digest: physical_proof,
        source_kernel_boot_id: receipt.kernel_boot_id(),
        source_device: receipt.device(),
        source_inode: receipt.inode(),
        source_unique_mount_id: receipt.unique_mount_id(),
        descriptor_commitment: *descriptor_commitment.as_bytes(),
    };
    if checkpoint.status != ProviderStatusV1::Complete
        || receipt.request_id() != request.request_id()
        || receipt.request_digest() != digest_acquire_request(&request)
        || receipt.acquisition_id().as_bytes() != &row.acquisition_id
        || receipt.provider_process_instance()
            != signed_status.subject().provider_process_instance()
        || receipt.descriptor_role() != SourceProviderDescriptorRole::SourceRoot
        || signed_status.subject().descriptor_commitment() != descriptor_commitment
        || receipt.lease_digest() != digest_signed_export_lease(&signed_lease)
        || receipt.observed_proof_digest() != proof_digest
        || lease.request_id() != request.request_id()
        || lease.request_digest() != digest_acquire_request(&request)
        || lease.holder_authority_id() != row.provider.holder_authority_id
        || lease.holder_generation() != row.provider.holder_generation
        || lease.holder_authority_digest().as_bytes() != &row.provider.holder_authority_digest
        || lease.binding_digest().as_bytes() != &row.source_binding_digest
        || lease.revocation_digest().as_bytes() != &row.provider.revocation_digest
        || provider.authority_id() != row.provider.provider_authority_id
        || provider.authority_generation() != row.provider.provider_authority_generation
        || provider.authority_digest().as_bytes() != &row.provider.provider_authority_digest
        || provider.key_id() != row.provider.provider_key_id
        || provider.key_generation() != row.provider.provider_key_generation
        || provider.public_key_digest().as_bytes() != &row.provider.provider_public_key_digest
        || signed_receipt.signer() != signed_lease.signer()
        || signed_status.signer() != signed_receipt.signer()
        || signed_receipt.signer().key_id() != row.provider.provider_key_id
        || signed_receipt.signer().authority_id() != row.provider.provider_authority_id
        || signed_receipt.signer().authority_generation()
            != row.provider.provider_authority_generation
        || signed_receipt.signer().authority_digest().as_bytes()
            != &row.provider.provider_authority_digest
        || signed_receipt.signer().usage() != SourceProviderKeyUsageV1::ProviderReceipt
        || signed_receipt.signer().key_generation() != row.provider.provider_key_generation
        || signed_receipt.signer().public_key_digest().as_bytes()
            != &row.provider.provider_public_key_digest
        || resource.resource_namespace_digest().as_bytes()
            != &row.provider.resource_namespace_digest
        || evidence != &expected
    {
        return Err(state_error(
            "Complete provider Acquire result differs from durable evidence",
        ));
    }
    Ok(())
}

fn validate_recovered_release_result(
    row: &SourceAcquisitionRowV1,
    checkpoint: &ProviderDispositionCheckpointV1,
) -> Result<()> {
    if checkpoint.status != ProviderStatusV1::Complete {
        return Ok(());
    }
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&checkpoint.signed_request)
            .map_err(|error| state_error(error.to_string()))?;
    let request = decode_release_request(signed_request.subject())
        .map_err(|error| state_error(error.to_string()))?;
    let signed_status =
        SignedSourceProviderStatusV1::from_canonical_bytes(&checkpoint.signed_status)
            .map_err(|error| state_error(error.to_string()))?;
    let signed_receipt =
        SignedSourceReleaseReceiptV1::from_canonical_bytes(&checkpoint.signed_result)
            .map_err(|error| state_error(error.to_string()))?;
    let receipt = signed_receipt.subject();
    let evidence = row
        .evidence
        .as_ref()
        .ok_or_else(|| state_error("Complete provider Release lacks lease evidence"))?;
    let release_provider = row
        .release_provider
        .ok_or_else(|| state_error("Complete provider Release lacks its protected context"))?;
    let provider = receipt.provider();
    if receipt.request_id() != request.request_id()
        || receipt.request_digest() != digest_release_request(&request)
        || receipt.lease_id() != evidence.lease_id
        || receipt.lease_digest().as_bytes() != &evidence.signed_lease_digest
        || receipt.provider_process_instance()
            != signed_status.subject().provider_process_instance()
        || provider.authority_id() != release_provider.provider_authority_id
        || provider.authority_generation() != release_provider.provider_authority_generation
        || provider.authority_digest().as_bytes() != &release_provider.provider_authority_digest
        || provider.key_id() != release_provider.provider_key_id
        || provider.key_generation() != release_provider.provider_key_generation
        || provider.public_key_digest().as_bytes() != &release_provider.provider_public_key_digest
        || signed_receipt.signer().key_id() != release_provider.provider_key_id
        || signed_receipt.signer().authority_id() != release_provider.provider_authority_id
        || signed_receipt.signer().authority_generation()
            != release_provider.provider_authority_generation
        || signed_receipt.signer().authority_digest().as_bytes()
            != &release_provider.provider_authority_digest
        || signed_receipt.signer().usage() != SourceProviderKeyUsageV1::ProviderReceipt
        || signed_receipt.signer().key_generation() != release_provider.provider_key_generation
        || signed_receipt.signer().public_key_digest().as_bytes()
            != &release_provider.provider_public_key_digest
        || signed_status.signer() != signed_receipt.signer()
        || row.release_generation != Some(receipt.release_generation())
    {
        return Err(state_error(
            "Complete provider Release result differs from durable evidence",
        ));
    }
    Ok(())
}

pub(super) fn acquire_checkpoint(
    signed_request: &SignedSourceProviderRequestV1,
    response: &AcquireSourceResponseV1,
    verified: &VerifiedSourceProviderDispositionV1<VerifiedSourceAcquisitionV1>,
) -> Result<ProviderDispositionCheckpointV1> {
    disposition_checkpoint(
        ProviderMethodV1::Acquire,
        signed_request,
        response.status(),
        response.signed_status().to_canonical_bytes(),
        response.signed_receipt().unwrap_or_default(),
        verified.status(),
        verified.sequence(),
    )
}

pub(super) fn release_checkpoint(
    signed_request: &SignedSourceProviderRequestV1,
    response: &ReleaseSourceResponseV1,
    verified: &VerifiedSourceProviderDispositionV1<VerifiedSourceReleaseV1>,
) -> Result<ProviderDispositionCheckpointV1> {
    disposition_checkpoint(
        ProviderMethodV1::Release,
        signed_request,
        response.status(),
        response.signed_status().to_canonical_bytes(),
        response.signed_receipt().unwrap_or_default(),
        verified.status(),
        verified.sequence(),
    )
}

pub(super) fn inventory_checkpoint(
    signed_request: &SignedSourceProviderRequestV1,
    response: &InventorySourceResponseV1,
    verified: &VerifiedSourceProviderDispositionV1<VerifiedSourceInventoryV1>,
) -> Result<ProviderDispositionCheckpointV1> {
    disposition_checkpoint(
        ProviderMethodV1::Inventory,
        signed_request,
        response.status(),
        response.signed_status().to_canonical_bytes(),
        response.signed_inventory().unwrap_or_default(),
        verified.status(),
        verified.sequence(),
    )
}

#[allow(clippy::too_many_arguments)]
fn disposition_checkpoint(
    method: ProviderMethodV1,
    signed_request: &SignedSourceProviderRequestV1,
    response_status: SourceProviderStatus,
    signed_status: Vec<u8>,
    signed_result: &[u8],
    verified_status: SourceProviderStatus,
    sequence: &aos_sandbox_source_provider_protocol::VerifiedSourceProviderSequenceV1,
) -> Result<ProviderDispositionCheckpointV1> {
    if signed_request.method() != method.protocol()
        || response_status != verified_status
        || sequence.session_binding().as_bytes() == &[0; 32]
    {
        return Err(state_error("verified provider disposition shape differs"));
    }
    let signed_request = signed_request.to_canonical_bytes();
    let status = ProviderStatusV1::from(verified_status);
    let checkpoint = ProviderDispositionCheckpointV1 {
        method,
        status,
        request_sequence: sequence.request_sequence(),
        response_sequence: sequence.response_sequence(),
        signed_request_digest: Sha256::digest(&signed_request).into(),
        signed_status_digest: Sha256::digest(&signed_status).into(),
        result_digest: *response_result_digest_v1(
            method.protocol(),
            verified_status,
            (!signed_result.is_empty()).then_some(signed_result),
        )
        .as_bytes(),
        signed_request,
        signed_status,
        signed_result: signed_result.to_vec(),
    };
    checkpoint.validate()?;
    Ok(checkpoint)
}

pub(super) fn derive_acquisition_evidence(
    row: &SourceAcquisitionRowV1,
    verified: &VerifiedSourceProviderDispositionV1<VerifiedSourceAcquisitionV1>,
    branded: Option<&BrandedSourceRootObservationV1>,
) -> Result<Option<SourceAcquisitionEvidenceV1>> {
    let Some(acquisition) = verified.result() else {
        if branded.is_some() {
            return Err(state_error(
                "noncomplete provider acquisition carried descriptor evidence",
            ));
        }
        return Ok(None);
    };
    let branded = branded.ok_or_else(|| {
        state_error("Complete provider acquisition lacks branded descriptor evidence")
    })?;
    let observation = acquisition.observation();
    let descriptor_commitment = *source_root_descriptor_commitment_v1(observation).as_bytes();
    if branded.descriptor_commitment != descriptor_commitment {
        return Err(state_error("branded descriptor observation differs"));
    }
    let lease = acquisition.signed_lease().subject();
    let resource = lease.resource();
    let mount_proof_class = mount_source_proof_class_from_provider_v1(lease.proof());
    let proof_class = match mount_proof_class {
        aos_sandbox_protocol::MountSourceProofClassV1::ImmutableTree => {
            SourceAcquisitionProofClassV1::ImmutableTree
        }
        aos_sandbox_protocol::MountSourceProofClassV1::LocalLive => {
            SourceAcquisitionProofClassV1::LocalLive
        }
        aos_sandbox_protocol::MountSourceProofClassV1::BestEffortReplica => {
            SourceAcquisitionProofClassV1::BestEffortReplica
        }
    };
    if proof_class != expected_binding_proof_class(&row.source_binding)? {
        return Err(state_error(
            "provider proof class differs from the requested source consistency",
        ));
    }
    let physical_proof = MountSourcePhysicalProofV1 {
        binding_digest: row.source_binding_digest,
        proof_class: mount_proof_class,
        provider_authority_id: row.provider.provider_authority_id,
        provider_authority_generation: row.provider.provider_authority_generation,
        provider_authority_digest: row.provider.provider_authority_digest,
        provider_resource_id: resource.resource_id(),
        provider_resource_generation: resource.resource_generation(),
        provider_resource_digest: *acquisition.provider_resource_commitment().as_bytes(),
        provider_catalog_generation: resource.catalog_generation(),
        provider_catalog_digest: *resource.catalog_digest().as_bytes(),
        kernel_boot_id: observation.kernel_boot_id(),
        device: observation.device(),
        inode: observation.inode(),
        unique_mount_id: observation.unique_mount_id(),
    };
    let source_physical_proof_digest = mount_source_physical_proof_digest_v1(physical_proof);
    let source_realization_handle =
        mount_source_realization_handle_v1(row.source_binding_digest, source_physical_proof_digest);
    Ok(Some(SourceAcquisitionEvidenceV1 {
        provider_resource_id: resource.resource_id(),
        provider_resource_generation: resource.resource_generation(),
        provider_resource_digest: *acquisition.provider_resource_commitment().as_bytes(),
        provider_catalog_generation: resource.catalog_generation(),
        provider_catalog_digest: *resource.catalog_digest().as_bytes(),
        provider_selection_generation: resource.selection_generation(),
        provider_selection_digest: *resource.selection_digest().as_bytes(),
        proof_class,
        provider_proof_digest: *digest_provider_proof(lease.proof()).as_bytes(),
        lease_id: lease.lease_id(),
        signed_lease_digest: *acquisition.lease_digest().as_bytes(),
        lease_issued_seconds: lease.issued_seconds(),
        lease_expires_seconds: lease.expires_seconds(),
        source_realization_handle,
        source_physical_proof_digest,
        source_kernel_boot_id: observation.kernel_boot_id(),
        source_device: observation.device(),
        source_inode: observation.inode(),
        source_unique_mount_id: observation.unique_mount_id(),
        descriptor_commitment,
    }))
}

fn expected_binding_proof_class(bytes: &[u8]) -> Result<SourceAcquisitionProofClassV1> {
    let binding = aos_sandbox_protocol::SourceRealizationBindingV1::from_canonical_bytes(bytes)
        .map_err(|error| state_error(error.to_string()))?;
    match binding.consistency() {
        aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION => {
            Ok(SourceAcquisitionProofClassV1::ImmutableTree)
        }
        aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE => {
            Ok(SourceAcquisitionProofClassV1::LocalLive)
        }
        aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA => {
            Ok(SourceAcquisitionProofClassV1::BestEffortReplica)
        }
        _ => Err(state_error("source acquisition consistency is unsupported")),
    }
}

fn validate_phase_shape(row: &SourceAcquisitionRowV1, phase: SourceAcquisitionPhaseV1) -> bool {
    let has_consumption = row
        .consumed_source_pin_record_digest
        .is_some_and(nonzero_digest)
        && row
            .consumed_create_effect_record_digest
            .is_some_and(nonzero_digest)
        && row
            .consumed_create_operation_record_digest
            .is_some_and(nonzero_digest);
    let no_consumption = row.consumed_source_pin_record_digest.is_none()
        && row.consumed_create_effect_record_digest.is_none()
        && row.consumed_create_operation_record_digest.is_none();
    let release_request_is_exact = valid_optional_signed_request(
        row.provider_release_request.as_deref(),
        row.provider_release_request_digest,
    );
    let initial_release_request_is_exact = valid_optional_signed_request(
        row.initial_provider_release_request.as_deref(),
        row.initial_provider_release_request_digest,
    );
    let release_checkpoint_is_exact = row.release_checkpoint.as_ref().is_none_or(|checkpoint| {
        checkpoint.method == ProviderMethodV1::Release
            && checkpoint.signed_request
                == row.provider_release_request.as_deref().unwrap_or_default()
            && Some(checkpoint.signed_request_digest) == row.provider_release_request_digest
            && (checkpoint.status == ProviderStatusV1::Complete) == row.release_generation.is_some()
    });
    let no_release = row.release.is_none()
        && row.mount_release_request.is_none()
        && row.release_authority.is_none()
        && row.release_provider.is_none()
        && row.release_inventory_observation_floor.is_none()
        && row.provider_release_request.is_none()
        && row.provider_release_request_digest.is_none()
        && row.initial_provider_release_request.is_none()
        && row.initial_provider_release_request_digest.is_none()
        && row.release_checkpoint.is_none()
        && row.release_history.is_empty()
        && row.release_generation.is_none()
        && row.provider_inventory_digest.is_none()
        && row.provider_inventory_observation_ordinal.is_none()
        && row.negative_custody_digest.is_none();

    match phase {
        SourceAcquisitionPhaseV1::PendingQuery => {
            no_release
                && no_consumption
                && row.descriptor_custody_digest.is_none()
                && row.positive_custody_digest.is_none()
        }
        SourceAcquisitionPhaseV1::DescriptorCustodied => {
            no_release
                && no_consumption
                && row.evidence.is_some()
                && row.acquire_checkpoint.as_ref().is_some_and(|checkpoint| {
                    checkpoint.method == ProviderMethodV1::Acquire
                        && checkpoint.status == ProviderStatusV1::Complete
                })
                && row.descriptor_custody_digest.is_some_and(nonzero_digest)
                && row.positive_custody_digest.is_none()
        }
        SourceAcquisitionPhaseV1::Active => {
            no_release
                && no_consumption
                && row.evidence.is_some()
                && row.descriptor_custody_digest.is_some_and(nonzero_digest)
                && row.positive_custody_digest.is_some_and(nonzero_digest)
        }
        SourceAcquisitionPhaseV1::Consumed => {
            no_release
                && has_consumption
                && row.evidence.is_some()
                && row.descriptor_custody_digest.is_some_and(nonzero_digest)
                && row.positive_custody_digest.is_some_and(nonzero_digest)
        }
        SourceAcquisitionPhaseV1::Releasing => {
            row.evidence.is_some()
                && (has_consumption || no_consumption)
                && row.descriptor_custody_digest.is_none_or(nonzero_digest)
                && row.positive_custody_digest.is_none_or(nonzero_digest)
                && (row.positive_custody_digest.is_none()
                    || row.descriptor_custody_digest.is_some())
                && row.release.is_some_and(valid_operation)
                && row.release_provider.is_some_and(valid_provider_context)
                && row.release_inventory_observation_floor.is_some()
                && release_request_is_exact
                && initial_release_request_is_exact
                && release_checkpoint_is_exact
                && row.negative_custody_digest.is_none()
        }
        SourceAcquisitionPhaseV1::Released => {
            let receipt_terminal = row.release_checkpoint.as_ref().is_some_and(|checkpoint| {
                checkpoint.status == ProviderStatusV1::Complete
                    && row
                        .release_generation
                        .is_some_and(|generation| generation != 0)
            });
            let inventory_terminal = row.provider_inventory_digest.is_some_and(nonzero_digest);
            row.evidence.is_some()
                && (has_consumption || no_consumption)
                && row.descriptor_custody_digest.is_none_or(nonzero_digest)
                && row.positive_custody_digest.is_none_or(nonzero_digest)
                && (row.positive_custody_digest.is_none()
                    || row.descriptor_custody_digest.is_some())
                && row.release.is_some_and(valid_operation)
                && row.release_provider.is_some_and(valid_provider_context)
                && row.release_inventory_observation_floor.is_some()
                && release_request_is_exact
                && initial_release_request_is_exact
                && release_checkpoint_is_exact
                && (receipt_terminal || inventory_terminal)
                && row.negative_custody_digest.is_some_and(nonzero_digest)
        }
        SourceAcquisitionPhaseV1::Faulted => false,
    }
}

impl SourceProviderHeadV1 {
    pub(super) fn validate(&self) -> Result<()> {
        self.last_inventory_checkpoint
            .as_ref()
            .map(ProviderDispositionCheckpointV1::validate)
            .transpose()?;
        if let Some(checkpoint) = &self.last_inventory_checkpoint {
            validate_checkpoint_provider_signer_against_head(checkpoint, self)?;
            validate_recovered_inventory_result(self, checkpoint)?;
        }
        if self
            .last_inventory_checkpoint
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.method != ProviderMethodV1::Inventory)
        {
            return Err(state_error(
                "provider head retained a non-Inventory checkpoint",
            ));
        }
        self.pending_query
            .as_ref()
            .map(PendingProviderQueryV1::validate)
            .transpose()?;
        if let Some(pending) = &self.pending_query {
            validate_pending_query(self, pending)?;
        }
        let sequence_heads_are_reachable = match &self.pending_query {
            None => self.next_request_sequence == self.next_response_sequence,
            Some(pending) => {
                self.next_request_sequence == self.next_response_sequence.saturating_add(1)
                    && pending.request_sequence == self.next_response_sequence
            }
        };
        let inventory_shape = match self.inventory_generation {
            None => {
                self.inventory_digest.is_none()
                    && self.signed_inventory_digest.is_none()
                    && self.signed_inventory.is_empty()
                    && self.catalog_generation.is_none()
                    && self.catalog_digest.is_none()
            }
            Some(generation) => {
                let canonical_inventory =
                    SignedSourceProviderInventoryV1::from_canonical_bytes(&self.signed_inventory)
                        .ok();
                let inventory_matches = canonical_inventory.as_ref().is_some_and(|signed| {
                    let inventory = signed.subject();
                    inventory.holder_authority_id() == self.holder_authority_id
                        && inventory.holder_generation() == self.holder_generation
                        && inventory.holder_authority_digest().as_bytes()
                            == &self.holder_authority_digest
                        && inventory.provider().authority_id() == self.provider_authority_id
                        && inventory.provider().authority_generation()
                            == self.provider_authority_generation
                        && inventory.provider().authority_digest().as_bytes()
                            == &self.provider_authority_digest
                        && inventory.inventory_generation() == generation
                        && Some(*digest_inventory(inventory).as_bytes()) == self.inventory_digest
                        && Some(inventory.catalog_generation()) == self.catalog_generation
                        && Some(*inventory.catalog_digest().as_bytes()) == self.catalog_digest
                });
                generation != 0
                    && self.inventory_digest.is_some_and(nonzero_digest)
                    && self.signed_inventory_digest.is_some_and(nonzero_digest)
                    && !self.signed_inventory.is_empty()
                    && self.signed_inventory.len() <= MAXIMUM_SIGNED_PROVIDER_BYTES
                    && self.catalog_generation.is_some_and(|value| value != 0)
                    && self.catalog_digest.is_some_and(nonzero_digest)
                    && self.signed_inventory_digest
                        == Some(Sha256::digest(&self.signed_inventory).into())
                    && inventory_matches
            }
        };
        if self.holder_authority_id == [0; 16]
            || self.holder_generation == 0
            || self.holder_authority_digest == [0; 32]
            || self.provider_authority_id == [0; 16]
            || self.provider_authority_generation == 0
            || self.provider_authority_digest == [0; 32]
            || self.session_binding == [0; 32]
            || self.kernel_boot_id == [0; 16]
            || self.next_request_sequence == 0
            || self.next_response_sequence == 0
            || self.route_id == [0; 16]
            || self.route_generation == 0
            || self.route_digest == [0; 32]
            || self.provider_key_generation == 0
            || self.provider_key_id == [0; 16]
            || self.provider_public_key_digest == [0; 32]
            || self.resource_namespace_digest == [0; 32]
            || self.revocation_digest == [0; 32]
            || self.inventory_generation.is_some() != (self.inventory_observation_ordinal != 0)
            || !sequence_heads_are_reachable
            || !inventory_shape
        {
            return Err(state_error("source provider head is invalid"));
        }
        Ok(())
    }
}

impl PendingProviderQueryV1 {
    pub(super) fn validate(&self) -> Result<()> {
        if self.request_sequence == 0
            || self.signed_request.is_empty()
            || self.signed_request.len() > MAXIMUM_SIGNED_PROVIDER_BYTES
            || self.signed_request_digest == [0; 32]
            || Sha256::digest(&self.signed_request).as_slice() != self.signed_request_digest
        {
            return Err(state_error("pending provider query is invalid"));
        }
        Ok(())
    }
}

pub(super) fn validate_sequence_advance(
    current: &SourceProviderHeadV1,
    checkpoint: &ProviderDispositionCheckpointV1,
    next: &SourceProviderHeadV1,
    owner: ProviderQueryOwnerV1,
) -> Result<()> {
    validate_head_identity(current, next)?;
    validate_sequence_numbers(current, checkpoint, next, owner)?;
    if next.inventory_generation != current.inventory_generation
        || next.inventory_digest != current.inventory_digest
        || next.signed_inventory_digest != current.signed_inventory_digest
        || next.signed_inventory != current.signed_inventory
        || next.catalog_generation != current.catalog_generation
        || next.catalog_digest != current.catalog_digest
        || next.inventory_observation_ordinal != current.inventory_observation_ordinal
        || next.last_inventory_checkpoint != current.last_inventory_checkpoint
        || next.has_untracked_inventory_residuals != current.has_untracked_inventory_residuals
        || next.has_inventory_authority_conflicts != current.has_inventory_authority_conflicts
    {
        return Err(state_error(
            "source provider sequence advance changed the inventory floor",
        ));
    }
    Ok(())
}

pub(super) fn validate_sequence_numbers(
    current: &SourceProviderHeadV1,
    checkpoint: &ProviderDispositionCheckpointV1,
    next: &SourceProviderHeadV1,
    owner: ProviderQueryOwnerV1,
) -> Result<()> {
    let pending = current
        .pending_query
        .as_ref()
        .ok_or_else(|| state_error("source provider response has no reserved request"))?;
    if pending.owner != owner
        || checkpoint.request_sequence != pending.request_sequence
        || checkpoint.signed_request_digest != pending.signed_request_digest
        || checkpoint.signed_request != pending.signed_request
        || checkpoint.response_sequence != current.next_response_sequence
        || next.next_request_sequence != current.next_request_sequence
        || next.next_response_sequence != next_revision(current.next_response_sequence)?
        || next.pending_query.is_some()
    {
        return Err(state_error("source provider sequence CAS failed"));
    }
    Ok(())
}

pub(super) fn validate_head_identity(
    current: &SourceProviderHeadV1,
    next: &SourceProviderHeadV1,
) -> Result<()> {
    if next.holder_authority_id != current.holder_authority_id
        || next.holder_generation != current.holder_generation
        || next.holder_authority_digest != current.holder_authority_digest
        || next.provider_authority_id != current.provider_authority_id
        || next.provider_authority_generation != current.provider_authority_generation
        || next.provider_authority_digest != current.provider_authority_digest
        || next.session_binding != current.session_binding
        || next.kernel_boot_id != current.kernel_boot_id
        || next.route_id != current.route_id
        || next.route_generation != current.route_generation
        || next.route_digest != current.route_digest
        || next.provider_key_generation != current.provider_key_generation
        || next.provider_key_id != current.provider_key_id
        || next.provider_public_key_digest != current.provider_public_key_digest
        || next.resource_namespace_digest != current.resource_namespace_digest
        || next.revocation_digest != current.revocation_digest
    {
        return Err(state_error(
            "source provider head identity changed without session replacement",
        ));
    }
    Ok(())
}

pub(super) fn validate_head_for_provider_context(
    head: &SourceProviderHeadV1,
    provider: SourceProviderContextSnapshotV1,
) -> Result<()> {
    if head.holder_authority_id != provider.holder_authority_id
        || head.holder_generation != provider.holder_generation
        || head.holder_authority_digest != provider.holder_authority_digest
        || head.provider_authority_id != provider.provider_authority_id
        || head.provider_authority_generation != provider.provider_authority_generation
        || head.provider_authority_digest != provider.provider_authority_digest
        || head.session_binding != provider.session_binding
        || head.kernel_boot_id != provider.kernel_boot_id
        || head.route_id != provider.provider_route_id
        || head.route_generation != provider.provider_route_generation
        || head.route_digest != provider.provider_route_digest
        || head.provider_key_generation != provider.provider_key_generation
        || head.provider_key_id != provider.provider_key_id
        || head.provider_public_key_digest != provider.provider_public_key_digest
        || head.resource_namespace_digest != provider.resource_namespace_digest
        || head.revocation_digest != provider.revocation_digest
    {
        return Err(state_error(
            "source provider head does not match the protected query context",
        ));
    }
    Ok(())
}

pub(super) fn same_acquire_identity(
    current: &SourceAcquisitionRowV1,
    replay: &SourceAcquisitionRowV1,
) -> bool {
    current.acquisition_id == replay.acquisition_id
        && current.acquire == replay.acquire
        && current.mount_acquire_request == replay.mount_acquire_request
        && current.assignment == replay.assignment
        && current.prospective_mount_template == replay.prospective_mount_template
        && current.prospective_mount_template_digest == replay.prospective_mount_template_digest
        && current.source_binding == replay.source_binding
        && current.source_binding_digest == replay.source_binding_digest
        && current.mount_plan_digest == replay.mount_plan_digest
        && current.ownership_lease_digest == replay.ownership_lease_digest
        && current.provider == replay.provider
}

pub(super) fn same_stable_inventory(
    previous: &aos_sandbox_source_provider_protocol::SourceProviderInventoryV1,
    next: &aos_sandbox_source_provider_protocol::SourceProviderInventoryV1,
) -> bool {
    previous.holder_authority_id() == next.holder_authority_id()
        && previous.holder_generation() == next.holder_generation()
        && previous.holder_authority_digest() == next.holder_authority_digest()
        && previous.provider() == next.provider()
        && previous.catalog_generation() == next.catalog_generation()
        && previous.catalog_digest() == next.catalog_digest()
        && previous.inventory_generation() == next.inventory_generation()
        && previous.entries() == next.entries()
}
