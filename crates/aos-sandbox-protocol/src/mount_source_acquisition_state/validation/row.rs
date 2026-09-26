//! Acquisition row, lifecycle-shape, and terminal-evidence validation.

use super::*;

pub(super) fn validate_row(
    row: &SourceAcquisitionRowV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    if table
        .provider_heads
        .get(&(
            row.scope.holder_authority_id,
            row.scope.provider_authority_id,
        ))
        .is_none_or(|head| head.scope != row.scope)
    {
        return Err(state_error("acquisition row provider head is missing"));
    }
    let request = decode_historical_acquire_mount_source_request(&row.mount_acquire_request)
        .map_err(|_| state_error("AOSMSA02 acquisition Mount request is invalid"))?;
    let request_digest = mount_source_acquisition_request_digest_v1(&row.mount_acquire_request);
    if row.revision == 0
        || row.record_digest == [0; 32]
        || !valid_scope(row.scope)
        || !provider_acquisition_is_valid(row.provider_acquisition, row.scope)
        || row.acquire.operation_id != *request.header().request_id()
        || row.acquire.request_digest != *request_digest.as_bytes()
        || row.acquisition_id
            != *mount_source_acquisition_id_v1(row.acquire.operation_id, request_digest).as_bytes()
        || row.acquisition_id != *request.acquisition_id().as_bytes()
        || row.assignment.sandbox_id != *request.fence().sandbox_id()
        || row.assignment.incarnation_id != *request.fence().incarnation_id()
        || row.assignment.assignment_epoch != request.fence().assignment_epoch()
        || row.assignment.desired_generation != request.fence().desired_generation()
        || row.assignment.assignment_digest != *request.fence().assignment_digest()
        || row.assignment.namespace_generation != request.prospective_namespace_generation()
        || row.prospective_mount_template != request.prospective_mount_template()
        || row.prospective_mount_template_digest
            != *request.prospective_mount_template_digest().as_bytes()
        || row.source_binding != request.source_binding().canonical_bytes()
        || row.source_binding_digest
            != *digest_logical_binding_bytes(&row.source_binding).as_bytes()
        || row.mount_plan_digest == [0; 32]
        || row.ownership_lease_digest == [0; 32]
    {
        return Err(state_error(
            "AOSMSA02 acquisition row contradicts its Mount request",
        ));
    }
    let acquire_root = exact_attempt(table, row.acquire_lineage.root)?;
    let acquire_tail = exact_attempt(table, row.acquire_lineage.tail)?;
    let ProviderIntentV2::Acquire { value: intent } = &acquire_root.intent else {
        return Err(state_error(
            "acquisition row points to a non-Acquire lineage",
        ));
    };
    if row.acquire_intent_digest != acquire_root.immutable_intent_digest
        || intent.scope != row.scope
        || intent.acquisition_id != row.acquisition_id
        || acquire_tail.provider_acquisition != Some(row.provider_acquisition)
        || intent.mount_request != row.mount_acquire_request
        || intent.mount_request_digest != row.acquire.request_digest
        || intent.assignment != row.assignment
        || intent.mount_plan_digest != row.mount_plan_digest
        || intent.ownership_lease_digest != row.ownership_lease_digest
        || intent.prospective_mount_template != row.prospective_mount_template
        || intent.prospective_mount_template_digest != row.prospective_mount_template_digest
        || intent.source_binding != row.source_binding
        || intent.source_binding_digest != row.source_binding_digest
    {
        return Err(state_error(
            "acquisition row contradicts immutable Acquire intent",
        ));
    }
    validate_release_row(row, table)?;
    validate_scalar_evidence(row)?;
    validate_manager_custody(row, table)?;
    validate_manager_custody_loss(row, table)?;
    validate_row_phase(row)?;
    validate_row_attempt_evidence(row, table)
}

fn validate_manager_custody(
    row: &SourceAcquisitionRowV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let Some(custody) = row.manager_custody else {
        return Ok(());
    };
    let subject_count = custody
        .cleanup_subject_count
        .checked_add(custody.terminal_subject_count);
    if custody.admission_predecessor.id != row.acquisition_id
        || custody.admission_predecessor.revision == 0
        || custody.admission_predecessor.revision >= row.revision
        || custody.admission_predecessor.record_digest == [0; 32]
        || custody.owner_attempt.id == [0; 32]
        || custody.owner_attempt.revision == 0
        || custody.owner_attempt.record_digest == [0; 32]
        || custody.owner_session_id == [0; 32]
        || custody.owner_session_record_digest == [0; 32]
        || custody.manager_kernel_boot_id == [0; 16]
        || custody.manager_execution_commitment == [0; 32]
        || custody.capture_sequence == 0
        || custody.capture_id == [0; 32]
        || custody.capture_record_digest == [0; 32]
        || custody.descriptor_count == 0
        || custody.activation_count > custody.descriptor_count
        || custody.expected_descriptor_count > custody.descriptor_count
        || subject_count != Some(custody.source_subject_count)
        || custody.source_entry_commitment == [0; 32]
        || custody.presence_commitment == [0; 32]
        || custody.evidence_digest != manager_custody_evidence_digest_v2(&custody)
    {
        return Err(state_error(
            "AOSMSA02 manager-custody evidence is malformed",
        ));
    }

    let owner_attempt = exact_attempt(table, custody.owner_attempt)?;
    let owner_session = exact_session(
        table,
        custody.owner_session_id,
        custody.owner_session_record_digest,
    )?;
    if owner_attempt.method != ProviderMethodV2::Acquire
        || owner_attempt.owner
            != (ProviderQueryOwnerV2::Acquire {
                acquisition_id: row.acquisition_id,
            })
        || !is_complete(owner_attempt)
        || owner_attempt.session_id != owner_session.session_id
        || owner_attempt.session_record_digest != owner_session.record_digest
        || owner_attempt.scope != row.scope
        || row.acquire_terminal_attempt != Some(custody.owner_attempt)
    {
        return Err(state_error(
            "AOSMSA02 manager custody does not join its acquisition session",
        ));
    }
    Ok(())
}

fn validate_manager_custody_loss(
    row: &SourceAcquisitionRowV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    use crate::mount_manager_startup::StartupCleanupPhaseV1;

    let Some(loss) = row.manager_custody_loss else {
        return Ok(());
    };
    let subject = loss.subject;
    let origin = match subject.phase {
        StartupCleanupPhaseV1::PendingQuery => SourceAcquisitionPhaseV2::PendingQuery,
        StartupCleanupPhaseV1::DescriptorCustodied => SourceAcquisitionPhaseV2::DescriptorCustodied,
        StartupCleanupPhaseV1::Active => SourceAcquisitionPhaseV2::Active,
        StartupCleanupPhaseV1::Consumed => SourceAcquisitionPhaseV2::Consumed,
    };
    let acquire_reference = RecordRefV2 {
        id: subject.acquire_attempt_id,
        revision: subject.acquire_attempt_revision,
        record_digest: subject.acquire_attempt_record_digest,
    };
    let acquire = exact_attempt(table, acquire_reference)?;
    let source_matches = subject.evidence.is_some_and(|source| {
        row.evidence.as_ref().is_some_and(|evidence| {
            source.source_realization_handle == evidence.source_realization_handle
                && source.descriptor_commitment == evidence.descriptor_commitment
                && source.source_kernel_boot_id == evidence.source_kernel_boot_id
                && source.source_device == evidence.source_device
                && source.source_inode == evidence.source_inode
                && source.source_unique_mount_id == evidence.source_unique_mount_id
        })
    });
    let custody_owner_matches = match (subject.last_custody_owner, row.manager_custody) {
        (None, None) => {
            origin == SourceAcquisitionPhaseV2::PendingQuery
                && loss.kind == ManagerCustodyLossKindV2::NoPriorCustody
        }
        (Some(owner), Some(custody)) => {
            origin != SourceAcquisitionPhaseV2::PendingQuery
                && loss.kind != ManagerCustodyLossKindV2::NoPriorCustody
                && owner.attempt_id == custody.owner_attempt.id
                && owner.attempt_revision == custody.owner_attempt.revision
                && owner.attempt_record_digest == custody.owner_attempt.record_digest
                && owner.session_id == custody.owner_session_id
                && owner.session_record_digest == custody.owner_session_record_digest
                && owner.kernel_boot_id == custody.manager_kernel_boot_id
        }
        _ => false,
    };
    if subject.acquisition_id != row.acquisition_id
        || subject.acquisition_revision == 0
        || subject.acquisition_revision >= row.revision
        || subject.acquisition_record_digest == [0; 32]
        || row.release_from_phase != Some(origin)
        || acquire.method != ProviderMethodV2::Acquire
        || !is_complete(acquire)
        || row.acquire_terminal_attempt != Some(acquire_reference)
        || !source_matches
        || !custody_owner_matches
        || loss.capture_id == [0; 32]
        || loss.capture_record_digest == [0; 32]
        || loss.death_commitment == [0; 32]
        || loss.evidence_digest != manager_custody_loss_evidence_digest_v2(&loss)
    {
        return Err(state_error(
            "AOSMSA02 manager custody loss does not join its cleanup origin",
        ));
    }
    Ok(())
}

pub(super) fn validate_scalar_evidence(row: &SourceAcquisitionRowV2) -> Result<()> {
    if row.descriptor_custody_digest == Some([0; 32])
        || row.positive_custody_digest == Some([0; 32])
        || row.negative_custody_digest == Some([0; 32])
        || row.fault_digest == Some([0; 32])
        || row.retained_fault_digest == Some([0; 32])
        || row
            .manager_custody_loss
            .is_some_and(|loss| loss.evidence_digest == [0; 32])
        || row.consumption.as_ref().is_some_and(|value| {
            !consumption_evidence_is_valid(value)
                || !consumption_matches_template(
                    value,
                    Some(&row.prospective_mount_template),
                    row.prospective_mount_template_digest,
                )
        })
    {
        return Err(state_error("AOSMSA02 evidence contains a zero commitment"));
    }
    if let Some(consumption) = &row.consumption {
        let expected = transaction_id(
            MutationTagV2::Consumption,
            row.scope.holder_authority_id,
            row.scope.provider_authority_id,
            consumption.holder_sequence_revision,
            consumption.provider_head_revision,
            Some(row.acquisition_id),
            Some(row.revision),
            None,
            None,
            None,
        );
        if consumption.transaction_id != expected {
            return Err(state_error(
                "AOSMSA02 consumption transaction identity does not reproduce",
            ));
        }
    }
    if let Some(evidence) = &row.evidence {
        if evidence.provider_acquisition != row.provider_acquisition
            || evidence.acquire_attempt.id == [0; 32]
            || evidence.session_id == [0; 32]
            || evidence.provider_outcome_signer_digest == [0; 32]
            || evidence.provider_resource_id == [0; 32]
            || evidence.provider_resource_generation == 0
            || evidence.provider_resource_digest == [0; 32]
            || evidence.provider_catalog_generation == 0
            || evidence.provider_catalog_digest == [0; 32]
            || evidence.provider_selection_generation == 0
            || evidence.provider_selection_digest == [0; 32]
            || !(1..=4).contains(&evidence.provider_proof_class)
            || evidence.provider_proof_digest == [0; 32]
            || evidence.lease_id == [0; 16]
            || evidence.signed_lease_digest == [0; 32]
            || evidence.lease_issued_seconds < 0
            || evidence.lease_expires_seconds <= evidence.lease_issued_seconds
            || evidence.source_realization_handle == [0; 32]
            || evidence.source_physical_proof_digest == [0; 32]
            || evidence.source_kernel_boot_id == [0; 16]
            || evidence.source_device == 0
            || evidence.source_inode == 0
            || evidence.source_unique_mount_id == 0
            || evidence.descriptor_commitment == [0; 32]
        {
            return Err(state_error("AOSMSA02 acquisition evidence is invalid"));
        }
    }
    Ok(())
}

pub(super) fn validate_release_row(
    row: &SourceAcquisitionRowV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let fields_present = [
        row.release.is_some(),
        row.mount_release_request.is_some(),
        row.release_authority.is_some(),
        row.release_from_phase.is_some(),
        row.release_intent_digest.is_some(),
        row.release_lineage.is_some(),
        row.release_inventory_fence.is_some(),
    ];
    if fields_present.iter().any(|value| *value) && fields_present.iter().any(|value| !*value) {
        return Err(state_error("AOSMSA02 Release intent has partial presence"));
    }
    let Some(lineage) = &row.release_lineage else {
        return Ok(());
    };
    let root = exact_attempt(table, lineage.root)?;
    let ProviderIntentV2::Release { value: intent } = &root.intent else {
        return Err(state_error(
            "acquisition row points to a non-Release lineage",
        ));
    };
    let release = row
        .release
        .ok_or_else(|| state_error("Release operation is missing"))?;
    let body = row
        .mount_release_request
        .as_deref()
        .ok_or_else(|| state_error("Release body is missing"))?;
    let authority = row
        .release_authority
        .ok_or_else(|| state_error("Release authority is missing"))?;
    let evidence = row
        .evidence
        .as_ref()
        .ok_or_else(|| state_error("Release intent lacks retained Acquire evidence"))?;
    let acquire_attempt = exact_attempt(table, evidence.acquire_attempt)?;
    let inventory_fence = row
        .release_inventory_fence
        .as_ref()
        .ok_or_else(|| state_error("Release Inventory fence is missing"))?;
    let release_from = row
        .release_from_phase
        .ok_or_else(|| state_error("Release predecessor phase is missing"))?;
    let retained_projection = projection_from_entries(
        row.scope,
        inventory_fence.projection_epoch,
        &inventory_fence.projection_entries,
    )?;
    let mut releasing_row = row.clone();
    releasing_row.phase = SourceAcquisitionPhaseV2::Releasing;
    releasing_row.release_proof = None;
    releasing_row.negative_custody_digest = None;
    let expected_target_projection = project_row(&releasing_row);
    validate_mount_release_body(body, release, authority, row.acquisition_id)?;
    if row.release_intent_digest != Some(root.immutable_intent_digest)
        || intent.scope != row.scope
        || intent.acquisition_id != row.acquisition_id
        || intent.provider_acquisition != row.provider_acquisition
        || intent.mount_request != body
        || intent.mount_operation != release
        || intent.authority != authority
        || intent.lease_id != evidence.lease_id
        || intent.signed_lease_digest != evidence.signed_lease_digest
        || intent.provider_resource_id != evidence.provider_resource_id
        || intent.provider_resource_digest != evidence.provider_resource_digest
        || intent.provider_proof_digest != evidence.provider_proof_digest
        || intent.descriptor_commitment != evidence.descriptor_commitment
        || root.owner_predecessor_revision != authority.expected_revision
        || root.owner_predecessor_digest != authority.expected_record_digest
        || !attempt_happens_after(table, acquire_attempt, root)?
        || !release_authority_dominates(row.assignment, authority)
        || !matches!(
            release_from,
            SourceAcquisitionPhaseV2::PendingQuery
                | SourceAcquisitionPhaseV2::DescriptorCustodied
                | SourceAcquisitionPhaseV2::Active
                | SourceAcquisitionPhaseV2::Consumed
        )
        || inventory_fence.projection_epoch == 0
        || inventory_fence.projection_digest == [0; 32]
        || inventory_fence.projection_entries.is_empty()
        || inventory_fence.projection_entries.len() > MAXIMUM_SOURCE_ACQUISITIONS
        || retained_projection.digest != inventory_fence.projection_digest
        || inventory_fence
            .projection_entries
            .binary_search_by_key(&row.acquisition_id, |entry| entry.acquisition_id)
            .ok()
            .and_then(|index| inventory_fence.projection_entries.get(index))
            != Some(&expected_target_projection)
    {
        return Err(state_error(
            "acquisition row contradicts immutable Release intent",
        ));
    }
    Ok(())
}

pub(super) fn release_authority_dominates(
    acquire: AssignmentV2,
    release: ReleaseAuthorityV2,
) -> bool {
    if acquire.sandbox_id != release.sandbox_id
        || acquire.incarnation_id != release.incarnation_id
        || release.assignment_epoch < acquire.assignment_epoch
    {
        return false;
    }
    if release.assignment_epoch > acquire.assignment_epoch {
        return true;
    }
    if release.desired_generation < acquire.desired_generation {
        return false;
    }
    release.desired_generation > acquire.desired_generation
        || release.assignment_digest == acquire.assignment_digest
}

pub(super) fn validate_mount_release_body(
    bytes: &[u8],
    operation: MountOperationV2,
    authority: ReleaseAuthorityV2,
    acquisition_id: [u8; 32],
) -> Result<()> {
    let body = ReleaseMountSourceAcquisitionRequest::decode_from_slice(bytes)
        .map_err(|_| state_error("retained Mount Release body is invalid"))?;
    if body.encode_to_vec() != bytes || !body.__buffa_unknown_fields.is_empty() {
        return Err(state_error("retained Mount Release body is noncanonical"));
    }
    let header = body
        .header
        .as_option()
        .ok_or_else(|| state_error("Mount Release header is missing"))?;
    let fence = body
        .fence
        .as_option()
        .ok_or_else(|| state_error("Mount Release fence is missing"))?;
    let digest = mount_source_acquisition_request_digest_v1(bytes);
    if !header.__buffa_unknown_fields.is_empty()
        || !fence.__buffa_unknown_fields.is_empty()
        || header.protocol_major != 2
        || header.protocol_minor != 0
        || header.deadline_boottime_nanoseconds == 0
        || !(crate::MINIMUM_RESPONSE_BYTES..=crate::MAXIMUM_RESPONSE_BYTES)
            .contains(&header.maximum_response_bytes)
        || header.audience.as_known()
            != Some(aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER)
        || header.request_id.as_slice() != operation.operation_id
        || digest.as_bytes() != &operation.request_digest
        || body.acquisition_id.as_slice() != acquisition_id
        || body.expected_revision != authority.expected_revision
        || body.expected_record_digest.as_slice() != authority.expected_record_digest
        || fence.sandbox_id.as_slice() != authority.sandbox_id
        || fence.incarnation_id.as_slice() != authority.incarnation_id
        || fence.assignment_epoch != authority.assignment_epoch
        || fence.desired_generation != authority.desired_generation
        || fence.assignment_digest.as_slice() != authority.assignment_digest
        || authority.sandbox_id == [0; 16]
        || authority.incarnation_id == [0; 16]
        || authority.assignment_epoch == 0
        || authority.desired_generation == 0
        || authority.assignment_digest == [0; 32]
        || authority.expected_revision == 0
        || authority.expected_record_digest == [0; 32]
    {
        return Err(state_error(
            "retained Mount Release body contradicts durable authority",
        ));
    }
    Ok(())
}

pub(super) fn validate_row_phase(row: &SourceAcquisitionRowV2) -> Result<()> {
    let shape = match row.phase {
        SourceAcquisitionPhaseV2::Faulted => row
            .faulted_from
            .is_some_and(|phase| phase_shape(row, phase, false)),
        phase => phase_shape(row, phase, true),
    };
    let fault_pair = row.faulted_from.is_some() == row.fault_digest.is_some();
    let retained_pair = row.retained_faulted_from.is_some() == row.retained_fault_digest.is_some();
    if !shape
        || !fault_pair
        || !retained_pair
        || (row.phase != SourceAcquisitionPhaseV2::Faulted && row.faulted_from.is_some())
        || matches!(
            row.faulted_from,
            Some(SourceAcquisitionPhaseV2::Faulted | SourceAcquisitionPhaseV2::Released)
        )
        || matches!(
            row.retained_faulted_from,
            Some(SourceAcquisitionPhaseV2::Faulted | SourceAcquisitionPhaseV2::Released)
        )
        || (row.retained_faulted_from.is_some()
            && !matches!(
                row.phase,
                SourceAcquisitionPhaseV2::Releasing | SourceAcquisitionPhaseV2::Released
            ))
        || row
            .retained_faulted_from
            .is_some_and(|origin| !retained_origin_evidence_is_present(row, origin))
    {
        return Err(state_error(
            "AOSMSA02 lifecycle phase has invalid field presence",
        ));
    }
    Ok(())
}

pub(super) fn phase_shape(
    row: &SourceAcquisitionRowV2,
    phase: SourceAcquisitionPhaseV2,
    require_no_fault: bool,
) -> bool {
    let has_evidence = row.evidence.is_some();
    let has_manager_custody = row.manager_custody.is_some();
    let has_manager_custody_loss = row.manager_custody_loss.is_some();
    let has_descriptor = row.descriptor_custody_digest.is_some();
    let has_positive = row.positive_custody_digest.is_some();
    let has_consumption = row.consumption.is_some();
    let has_release = row.release_lineage.is_some();
    let has_release_proof = row.release_proof.is_some();
    let has_negative = row.negative_custody_digest.is_some();
    let acquisition_shape = |origin| match origin {
        SourceAcquisitionPhaseV2::PendingQuery => {
            !has_manager_custody && !has_descriptor && !has_positive && !has_consumption
        }
        SourceAcquisitionPhaseV2::DescriptorCustodied => {
            has_evidence
                && has_manager_custody
                && has_descriptor
                && !has_positive
                && !has_consumption
        }
        SourceAcquisitionPhaseV2::Active => {
            has_evidence
                && has_manager_custody
                && has_descriptor
                && has_positive
                && !has_consumption
        }
        SourceAcquisitionPhaseV2::Consumed => {
            has_evidence && has_manager_custody && has_descriptor && has_positive && has_consumption
        }
        SourceAcquisitionPhaseV2::Releasing
        | SourceAcquisitionPhaseV2::Released
        | SourceAcquisitionPhaseV2::Faulted => false,
    };
    let release_from_shape = || {
        row.release_from_phase.is_some_and(acquisition_shape)
            && (row.release_from_phase != Some(SourceAcquisitionPhaseV2::PendingQuery)
                || has_manager_custody_loss)
    };
    let shape = match phase {
        SourceAcquisitionPhaseV2::PendingQuery
        | SourceAcquisitionPhaseV2::DescriptorCustodied
        | SourceAcquisitionPhaseV2::Active
        | SourceAcquisitionPhaseV2::Consumed => {
            acquisition_shape(phase)
                && !has_release
                && row.release_from_phase.is_none()
                && !has_release_proof
                && !has_negative
                && !has_manager_custody_loss
        }
        SourceAcquisitionPhaseV2::Releasing => has_release && release_from_shape() && !has_negative,
        SourceAcquisitionPhaseV2::Released => {
            has_release && release_from_shape() && has_release_proof && has_negative
        }
        SourceAcquisitionPhaseV2::Faulted => false,
    };
    shape && (!require_no_fault || row.faulted_from.is_none())
}

pub(super) fn retained_origin_evidence_is_present(
    row: &SourceAcquisitionRowV2,
    origin: SourceAcquisitionPhaseV2,
) -> bool {
    match origin {
        SourceAcquisitionPhaseV2::PendingQuery => true,
        SourceAcquisitionPhaseV2::DescriptorCustodied => {
            row.evidence.is_some()
                && row.manager_custody.is_some()
                && row.descriptor_custody_digest.is_some()
        }
        SourceAcquisitionPhaseV2::Active => {
            row.evidence.is_some()
                && row.manager_custody.is_some()
                && row.descriptor_custody_digest.is_some()
                && row.positive_custody_digest.is_some()
        }
        SourceAcquisitionPhaseV2::Consumed => {
            row.evidence.is_some()
                && row.manager_custody.is_some()
                && row.descriptor_custody_digest.is_some()
                && row.positive_custody_digest.is_some()
                && row.consumption.is_some()
        }
        SourceAcquisitionPhaseV2::Releasing => row.release_lineage.is_some(),
        SourceAcquisitionPhaseV2::Released | SourceAcquisitionPhaseV2::Faulted => false,
    }
}

pub(super) fn validate_row_attempt_evidence(
    row: &SourceAcquisitionRowV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    if row.acquire_terminal_attempt.is_some() != row.evidence.is_some() {
        return Err(state_error(
            "Acquire terminal attempt and evidence presence differ",
        ));
    }
    if let Some(reference) = row.acquire_terminal_attempt {
        let attempt = exact_attempt(table, reference)?;
        if attempt.method != ProviderMethodV2::Acquire
            || attempt.owner
                != (ProviderQueryOwnerV2::Acquire {
                    acquisition_id: row.acquisition_id,
                })
            || !is_complete(attempt)
            || row.evidence.as_ref().is_some_and(|evidence| {
                evidence.acquire_attempt != reference || evidence.session_id != attempt.session_id
            })
        {
            return Err(state_error(
                "Acquire terminal evidence references the wrong attempt",
            ));
        }
        validate_complete_acquire(row, attempt, table)?;
    }
    let receipt_proof = matches!(
        row.release_proof.as_ref(),
        Some(ReleaseProofV2::ProviderReceipt { .. })
    );
    if receipt_proof != row.release_terminal_attempt.is_some() {
        return Err(state_error(
            "provider receipt proof and terminal Release attempt differ",
        ));
    }
    if let Some(reference) = row.release_terminal_attempt {
        let attempt = exact_attempt(table, reference)?;
        let effective_phase = if row.phase == SourceAcquisitionPhaseV2::Faulted {
            row.faulted_from
        } else {
            Some(row.phase)
        };
        if attempt.method != ProviderMethodV2::Release
            || attempt.owner
                != (ProviderQueryOwnerV2::Release {
                    acquisition_id: row.acquisition_id,
                })
            || !is_complete(attempt)
            || !receipt_proof
            || effective_phase != Some(SourceAcquisitionPhaseV2::Releasing)
        {
            return Err(state_error(
                "Release terminal proof references the wrong attempt",
            ));
        }
        validate_complete_release(row, attempt, table)?;
    }
    match &row.release_proof {
        Some(ReleaseProofV2::ProviderReceipt {
            attempt,
            release_generation,
        }) => {
            if Some(*attempt) != row.release_terminal_attempt || *release_generation == 0 {
                return Err(state_error("provider Release proof is incomplete"));
            }
        }
        Some(ReleaseProofV2::ProviderInventory {
            attempt,
            acquisition_predecessor,
            inventory_digest,
            inventory_observation_ordinal: proof_inventory_observation_ordinal,
            projection_epoch,
        }) => {
            if row.release_terminal_attempt.is_some() {
                return Err(state_error(
                    "Inventory release proof retains a Release terminal attempt",
                ));
            }
            let inventory = exact_attempt(table, *attempt)?;
            let release_tail = exact_attempt(
                table,
                row.release_lineage
                    .as_ref()
                    .ok_or_else(|| state_error("Release lineage is missing"))?
                    .tail,
            )?;
            let fence = row
                .release_inventory_fence
                .as_ref()
                .ok_or_else(|| state_error("Release Inventory fence is missing"))?;
            let head = table
                .provider_heads
                .get(&(
                    row.scope.holder_authority_id,
                    row.scope.provider_authority_id,
                ))
                .ok_or_else(|| state_error("Release Inventory provider head is missing"))?;
            if inventory.method != ProviderMethodV2::Inventory
                || !is_complete(inventory)
                || *inventory_digest == [0; 32]
                || *proof_inventory_observation_ordinal <= fence.inventory_observation_floor
                || *proof_inventory_observation_ordinal > head.inventory_observation_ordinal
                || inventory_observation_ordinal(table, row.scope, inventory)?
                    != *proof_inventory_observation_ordinal
                || *projection_epoch < fence.projection_epoch
                || *projection_epoch > head.current_projection_epoch
                || !attempt_happens_after(table, release_tail, inventory)?
                || !terminal_inventory_matches(table, row, inventory, *inventory_digest)?
                || inventory
                    .inventory_correlations
                    .as_ref()
                    .and_then(|correlations| {
                        correlations
                            .entries
                            .iter()
                            .find(|entry| entry.mount_acquisition_id == row.acquisition_id)
                    })
                    .is_none_or(|entry| entry.acquisition_record != *acquisition_predecessor)
            {
                return Err(state_error("provider Inventory release proof is invalid"));
            }
            if *proof_inventory_observation_ordinal == head.inventory_observation_ordinal
                && head.inventory_floor.as_ref().is_none_or(|floor| {
                    floor.attempt != *attempt || floor.inventory_digest != *inventory_digest
                })
            {
                return Err(state_error(
                    "current Inventory ordinal differs from retained Release proof",
                ));
            }
            if *proof_inventory_observation_ordinal < head.inventory_observation_ordinal {
                let floor = head
                    .inventory_floor
                    .as_ref()
                    .ok_or_else(|| state_error("advanced Inventory head lacks a current floor"))?;
                let current = exact_attempt(table, floor.attempt)?;
                if !attempt_happens_after(table, inventory, current)?
                    || !terminal_inventory_matches(table, row, current, floor.inventory_digest)?
                {
                    return Err(state_error(
                        "released acquisition reappears in current provider Inventory",
                    ));
                }
            }
        }
        None => {}
    }
    Ok(())
}

pub(super) fn terminal_inventory_matches(
    table: &SourceAcquisitionTableV2,
    row: &SourceAcquisitionRowV2,
    attempt: &SourceProviderQueryAttemptV2,
    expected_digest: [u8; 32],
) -> Result<bool> {
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Complete,
        signed_result,
        ..
    } = &attempt.state
    else {
        return Ok(false);
    };
    let signed = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("Release proof Inventory is invalid"))?;
    let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    let correlation = attempt
        .inventory_correlations
        .as_ref()
        .and_then(|correlations| {
            correlations
                .entries
                .iter()
                .find(|entry| entry.mount_acquisition_id == row.acquisition_id)
        });
    let Some(correlation) = correlation else {
        return Ok(false);
    };
    if attempt.method != ProviderMethodV2::Inventory
        || attempt.scope != row.scope
        || signed.subject().holder_authority_id() != row.scope.holder_authority_id
        || signed.subject().provider().authority_id() != row.scope.provider_authority_id
        || signed.subject().holder_generation() != session.root_mount_authority_generation
        || signed.subject().holder_authority_digest().as_bytes()
            != &session.root_mount_authority_digest
        || signed.subject().provider().authority_generation()
            != session.provider_authority_generation
        || signed.subject().provider().authority_digest().as_bytes()
            != &session.provider_authority_digest
        || digest_inventory(signed.subject()).as_bytes() != &expected_digest
        || correlation.provider_acquisition != row.provider_acquisition
        || row.evidence.as_ref().is_none_or(|evidence| {
            correlation.lease_id != Some(evidence.lease_id)
                || correlation.signed_lease_digest != Some(evidence.signed_lease_digest)
        })
        || correlation.acquisition_record.id != row.acquisition_id
        || correlation.acquisition_record.revision > row.revision
        || !matches!(
            correlation.expectation,
            InventoryCorrelationExpectationV2::ReapingReleasedOrAbsent
                | InventoryCorrelationExpectationV2::ReleasedOrAbsent
        )
    {
        return Ok(false);
    }
    let entry = signed.subject().entries().iter().find(|entry| {
        entry.acquisition_id().as_bytes() == &row.provider_acquisition.acquisition_id
    });
    Ok(match entry {
        None => true,
        Some(entry) => {
            entry.state() == aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Released
                && row
                    .evidence
                    .as_ref()
                    .is_some_and(|evidence| inventory_entry_matches_evidence(entry, evidence))
        }
    })
}

pub(super) fn validate_complete_acquire(
    row: &SourceAcquisitionRowV2,
    attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    let ProviderAttemptStateV2::DispositionConsumed {
        verification_anchor,
        signed_status,
        signed_result,
        ..
    } = &attempt.state
    else {
        return Err(state_error("Acquire evidence attempt is not consumed"));
    };
    let signed_receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("retained provider Acquire receipt is invalid"))?;
    let receipt = signed_receipt.subject();
    let signed_lease =
        SignedSourceExportLeaseV1::from_canonical_bytes(receipt.signed_export_lease())
            .map_err(|_| state_error("retained provider export lease is invalid"))?;
    let lease = signed_lease.subject();
    let resource = lease.resource();
    let provider = lease.provider();
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
            .map_err(|_| state_error("retained provider Acquire request is invalid"))?;
    let request = decode_acquire_request(signed_request.subject())
        .map_err(|_| state_error("retained provider Acquire request body is invalid"))?;
    let signed_status =
        aos_sandbox_source_provider_protocol::SignedSourceProviderStatusV1::from_canonical_bytes(
            signed_status,
        )
        .map_err(|_| state_error("retained provider Acquire status is invalid"))?;
    let proof_digest = digest_provider_proof(lease.proof());
    let resource_digest = provider_resource_commitment_v1(resource, proof_digest);
    let evidence = row
        .evidence
        .as_ref()
        .ok_or_else(|| state_error("Complete Acquire lacks durable evidence"))?;
    let selection_floor = historical_selection_floor(evidence)?;
    let (catalog_floor, requested_selection_floor) =
        crate::mount_source_acquisition_state::protocol_acquire_verification_floor_v2(
            attempt.acquire_verification_floor.as_ref().ok_or_else(|| {
                state_error("Complete Acquire lacks its pre-I/O verification floor")
            })?,
        )?;
    let lease_signer = &evidence.historical_lease_signer.signer;
    verify_provider_receipt_and_lease(
        &signed_receipt,
        &session.signers[3].public_key,
        &lease_signer.public_key,
    )
    .map_err(|_| state_error("retained provider Acquire graph signature is invalid"))?;
    let mount_proof = mount_source_proof_class_from_provider_v1(lease.proof());
    let proof_class = match mount_proof {
        crate::MountSourceProofClassV1::ImmutableTree => {
            SourceAcquisitionProofClassV2::ImmutableTree
        }
        crate::MountSourceProofClassV1::LocalLive => SourceAcquisitionProofClassV2::LocalLive,
        crate::MountSourceProofClassV1::BestEffortReplica => {
            SourceAcquisitionProofClassV2::BestEffortReplica
        }
    };
    let binding = SourceRealizationBindingV1::from_canonical_bytes(&row.source_binding)
        .map_err(|_| state_error("retained source binding is invalid"))?;
    if proof_class != expected_binding_proof_class(&binding)?
        || (proof_class == SourceAcquisitionProofClassV2::LocalLive
            && !binding.matches_local_live_provider_proof(lease.proof()))
    {
        return Err(state_error(
            "provider proof differs from immutable Acquire source binding",
        ));
    }
    let physical = mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
        binding_digest: row.source_binding_digest,
        proof_class: mount_proof,
        provider_authority_id: provider.authority_id(),
        provider_authority_generation: provider.authority_generation(),
        provider_authority_digest: *provider.authority_digest().as_bytes(),
        provider_resource_id: resource.resource_id(),
        provider_resource_generation: resource.resource_generation(),
        provider_resource_digest: *resource_digest.as_bytes(),
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
    .map_err(|_| state_error("retained SourceRoot observation is invalid"))?;
    let descriptor = source_root_descriptor_commitment_v1(&observation);
    let expected = SourceAcquisitionEvidenceV2 {
        acquire_attempt: RecordRefV2 {
            id: attempt.attempt_id,
            revision: attempt.revision,
            record_digest: attempt.record_digest,
        },
        outcome_verification_anchor: *verification_anchor,
        provider_acquisition: row.provider_acquisition,
        session_id: session.session_id,
        provider_outcome_signer_digest: session.signers[3].public_key_fingerprint,
        historical_lease_signer: evidence.historical_lease_signer.clone(),
        provider_resource_id: resource.resource_id(),
        provider_resource_generation: resource.resource_generation(),
        provider_resource_digest: *resource_digest.as_bytes(),
        provider_catalog_generation: resource.catalog_generation(),
        provider_catalog_digest: *resource.catalog_digest().as_bytes(),
        provider_selection_generation: resource.selection_generation(),
        provider_selection_digest: *resource.selection_digest().as_bytes(),
        provider_proof_class: lease.proof().class_code(),
        proof_class,
        provider_proof_digest: *proof_digest.as_bytes(),
        lease_id: lease.lease_id(),
        signed_lease_digest: *digest_signed_export_lease(&signed_lease).as_bytes(),
        lease_issued_seconds: lease.issued_seconds(),
        lease_expires_seconds: lease.expires_seconds(),
        source_realization_handle: mount_source_realization_handle_v1(
            row.source_binding_digest,
            physical,
        ),
        source_physical_proof_digest: physical,
        source_kernel_boot_id: receipt.kernel_boot_id(),
        source_device: receipt.device(),
        source_inode: receipt.inode(),
        source_unique_mount_id: receipt.unique_mount_id(),
        descriptor_commitment: *descriptor.as_bytes(),
    };
    let duration = lease
        .expires_seconds()
        .checked_sub(lease.issued_seconds())
        .and_then(|seconds| u64::try_from(seconds).ok());
    let proof_bit = lease.proof().capability_bit();
    let floor_snapshot = &evidence.historical_lease_signer.selection_floor;
    let historical_floor = &evidence.historical_lease_signer;
    if row.evidence.as_ref() != Some(&expected)
        || !signer_matches(&session.signers[3], signed_receipt.signer())
        || !signer_matches(lease_signer, signed_lease.signer())
        || <[u8; 32]>::from(Sha256::digest(lease_signer.public_key))
            != lease_signer.public_key_fingerprint
        || !interval_contains(
            lease_signer.authority_valid_from_seconds,
            lease_signer.authority_valid_until_seconds,
            lease.issued_seconds(),
        )
        || !interval_contains(
            lease_signer.key_valid_from_seconds,
            lease_signer.key_valid_until_seconds,
            lease.issued_seconds(),
        )
        || receipt.request_id() != attempt.request_id
        || receipt.request_digest() != digest_acquire_request(&request)
        || receipt.acquisition_id().as_bytes() != &row.provider_acquisition.acquisition_id
        || receipt.provider_process_instance() != session.provider_process_instance
        || receipt.kernel_boot_id() != request.boot_id()
        || receipt.descriptor_role() != SourceProviderDescriptorRole::SourceRoot
        || receipt.lease_digest() != digest_signed_export_lease(&signed_lease)
        || receipt.observed_proof_digest() != proof_digest
        || lease.request_id() != attempt.request_id
        || lease.request_digest() != digest_acquire_request(&request)
        || lease.holder_authority_id() != session.scope.holder_authority_id
        || lease.holder_generation() != session.root_mount_authority_generation
        || lease.holder_authority_digest().as_bytes() != &session.root_mount_authority_digest
        || lease.binding_digest().as_bytes() != &row.source_binding_digest
        || lease.revocation_digest() != request.revocation_digest()
        || matches!(
            lease.proof(),
            aos_sandbox_source_provider_protocol::SourceProviderProofV1::LocalLiveExport {
                proof,
                ..
            } if proof.consumer_authority_id() != request.holder_authority_id()
                || proof.consumer_generation() != request.holder_generation()
        )
        || session.authenticated_at_seconds >= request.deadline_seconds()
        || lease.issued_seconds() < session.authenticated_at_seconds
        || session.authenticated_at_seconds >= lease.expires_seconds()
        || lease.expires_seconds() > request.deadline_seconds()
        || lease.expires_seconds()
            > attempt
                .normalized_acquire_intent
                .as_ref()
                .map_or(0, |value| value.maximum_lease_expiry_seconds)
        || duration
            .is_none_or(|seconds| seconds == 0 || seconds > request.requested_lease_seconds())
        || provider.authority_id() != lease_signer.authority_id
        || provider.authority_generation() != lease_signer.authority_generation
        || provider.authority_digest().as_bytes() != &lease_signer.authority_digest
        || !generation_dominates_snapshot(
            lease_signer.authority_generation,
            lease_signer.authority_digest,
            session.provider_authority_generation,
            session.provider_authority_digest,
        )
        || resource.resource_namespace_digest().as_bytes()
            != &session.scope.resource_namespace_digest
        || proof_bit & session.negotiated_capabilities.proof_class_capabilities == 0
        || lease.proof().requires_kernel_coupled() != request.kernel_coupled()
        || (request.kernel_coupled() && !session.negotiated_capabilities.supports_kernel_coupled)
        || (request.recursive() && !session.negotiated_capabilities.supports_recursive)
        || lease.proof().topology().observed_submounts() > request.requested_maximum_submounts()
        || (!request.recursive() && lease.proof().topology().observed_submounts() != 0)
        || selection_floor.acquisition_id() != request.acquisition_id()
        || selection_floor.provider_authority_id() != provider.authority_id()
        || selection_floor.route_id() != session.scope.route_id
        || selection_floor.resource() != resource
        || selection_floor.outcome_signer() != signed_lease.signer()
        || selection_floor.lease_id() != lease.lease_id()
        || selection_floor.signed_lease_digest() != digest_signed_export_lease(&signed_lease)
        || selection_floor.proof_class() != lease.proof().class_code()
        || selection_floor.proof_digest() != proof_digest
        || selection_floor.resource_commitment() != resource_digest
        || requested_selection_floor
            .as_ref()
            .is_some_and(|floor| floor != &selection_floor)
        || floor_snapshot.acquisition_id != row.provider_acquisition.acquisition_id
        || floor_snapshot.provider_authority_id != provider.authority_id()
        || floor_snapshot.route_id != session.scope.route_id
        || floor_snapshot.resource_namespace_digest != session.scope.resource_namespace_digest
        || floor_snapshot.catalog_generation != resource.catalog_generation()
        || floor_snapshot.catalog_digest != *resource.catalog_digest().as_bytes()
        || floor_snapshot.resource_id != resource.resource_id()
        || floor_snapshot.resource_generation != resource.resource_generation()
        || floor_snapshot.resource_digest != *resource.resource_digest().as_bytes()
        || floor_snapshot.selection_generation != resource.selection_generation()
        || floor_snapshot.selection_digest != *resource.selection_digest().as_bytes()
        || floor_snapshot.lease_id != lease.lease_id()
        || floor_snapshot.signed_lease_digest
            != *digest_signed_export_lease(&signed_lease).as_bytes()
        || floor_snapshot.proof_class != lease.proof().class_code()
        || floor_snapshot.proof_digest != *proof_digest.as_bytes()
        || floor_snapshot.resource_commitment != *resource_digest.as_bytes()
        || historical_floor.catalog_floor_provider_authority_id
            != catalog_floor.provider_authority_id()
        || historical_floor.catalog_floor_resource_namespace_digest
            != *catalog_floor.resource_namespace_digest().as_bytes()
        || historical_floor.minimum_catalog_generation != catalog_floor.minimum_catalog_generation()
        || historical_floor.minimum_catalog_digest
            != *catalog_floor.minimum_catalog_digest().as_bytes()
        || resource.catalog_generation() < catalog_floor.minimum_catalog_generation()
        || (resource.catalog_generation() == catalog_floor.minimum_catalog_generation()
            && resource.catalog_digest() != catalog_floor.minimum_catalog_digest())
        || !generation_dominates_snapshot(
            floor_snapshot.trust_generation,
            floor_snapshot.trust_digest,
            session.trust_generation,
            session.trust_digest,
        )
        || !generation_dominates_snapshot(
            floor_snapshot.revocation_generation,
            floor_snapshot.revocation_digest,
            session.revocation_generation,
            session.revocation_digest,
        )
        || signed_status.subject().descriptor_commitment() != descriptor
    {
        return Err(state_error(
            "Complete provider Acquire graph differs from durable evidence",
        ));
    }
    Ok(())
}

pub(super) fn validate_complete_release(
    row: &SourceAcquisitionRowV2,
    attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    let ProviderAttemptStateV2::DispositionConsumed { signed_result, .. } = &attempt.state else {
        return Err(state_error("Release evidence attempt is not consumed"));
    };
    let signed_receipt = SignedSourceReleaseReceiptV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("retained provider Release receipt is invalid"))?;
    let receipt = signed_receipt.subject();
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
            .map_err(|_| state_error("retained provider Release request is invalid"))?;
    let request = decode_release_request(signed_request.subject())
        .map_err(|_| state_error("retained provider Release body is invalid"))?;
    verify_release_receipt(&signed_receipt, &session.signers[3].public_key)
        .map_err(|_| state_error("retained provider Release receipt signature is invalid"))?;
    let evidence = row
        .evidence
        .as_ref()
        .ok_or_else(|| state_error("provider Release receipt lacks acquisition evidence"))?;
    let release_generation = receipt.release_generation();
    if let Some(ReleaseProofV2::ProviderReceipt {
        attempt: reference,
        release_generation: retained_generation,
    }) = row.release_proof.as_ref()
    {
        if reference.id != attempt.attempt_id || *retained_generation != release_generation {
            return Err(state_error(
                "Release receipt proof does not reference terminal attempt",
            ));
        }
    } else if row.release_proof.is_some() {
        return Err(state_error(
            "Release receipt attempt conflicts with Inventory terminal proof",
        ));
    }
    if !signer_matches(&session.signers[3], signed_receipt.signer())
        || receipt.request_id() != attempt.request_id
        || receipt.request_digest() != digest_release_request(&request)
        || receipt.lease_id() != evidence.lease_id
        || receipt.lease_digest().as_bytes() != &evidence.signed_lease_digest
        || receipt.provider().authority_id() != session.scope.provider_authority_id
        || receipt.provider().authority_generation() != session.provider_authority_generation
        || receipt.provider().authority_digest().as_bytes() != &session.provider_authority_digest
        || receipt.provider_process_instance() != session.provider_process_instance
        || release_generation == 0
        || receipt.released_seconds() < session.authenticated_at_seconds
        || receipt.released_seconds() > request.deadline_seconds()
        || session.authenticated_at_seconds >= request.deadline_seconds()
    {
        return Err(state_error(
            "Complete provider Release graph is inconsistent",
        ));
    }
    Ok(())
}

pub(super) fn expected_binding_proof_class(
    binding: &SourceRealizationBindingV1,
) -> Result<SourceAcquisitionProofClassV2> {
    match binding.consistency() {
        aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION => Ok(SourceAcquisitionProofClassV2::ImmutableTree),
        aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE => Ok(SourceAcquisitionProofClassV2::LocalLive),
        aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA => Ok(SourceAcquisitionProofClassV2::BestEffortReplica),
        _ => Err(state_error("retained source binding uses an unsupported consistency")),
    }
}
