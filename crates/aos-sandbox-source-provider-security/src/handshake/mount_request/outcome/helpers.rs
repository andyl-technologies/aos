//! Exact AOSMSA02 transition and outcome-verification helpers.

use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::handshake::mount_request) enum ExactMountRecordKindV2 {
    Acquisition,
    Attempt,
    Head,
}

pub(in crate::handshake::mount_request) fn transaction_has_exact_record_kinds(
    transaction: &aos_sandbox::JournalTransaction,
    expected: &[ExactMountRecordKindV2],
) -> bool {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        StoredRecordV2, decode_mount_source_state_record_v2,
    };

    transaction.records().len() == expected.len()
        && transaction
            .records()
            .iter()
            .zip(expected)
            .all(|(record, expected)| {
                let Some(value) = record.value() else {
                    return false;
                };
                let actual = match decode_mount_source_state_record_v2(record.key(), value) {
                    Ok(StoredRecordV2::Acquisition { .. }) => ExactMountRecordKindV2::Acquisition,
                    Ok(StoredRecordV2::ProviderQueryAttempt { .. }) => {
                        ExactMountRecordKindV2::Attempt
                    }
                    Ok(StoredRecordV2::ProviderHead { .. }) => ExactMountRecordKindV2::Head,
                    Ok(
                        StoredRecordV2::HolderSequence { .. }
                        | StoredRecordV2::ProviderSession { .. },
                    )
                    | Err(_) => return false,
                };
                actual == *expected
            })
}

pub(in crate::handshake::mount_request) fn attempt_reference(
    attempt: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderQueryAttemptV2,
) -> aos_sandbox_protocol::mount_source_acquisition_state::RecordRefV2 {
    aos_sandbox_protocol::mount_source_acquisition_state::RecordRefV2 {
        id: attempt.attempt_id,
        revision: attempt.revision,
        record_digest: attempt.record_digest,
    }
}

#[derive(Clone, Copy)]
pub(in crate::handshake::mount_request) enum LifecycleStageV2 {
    DescriptorCustodied,
    Active,
    Consumed,
    Releasing,
    Released(ObjectDigest),
}

pub(in crate::handshake::mount_request) fn validate_lifecycle_row(
    journal: &impl MountSourceAcquisitionJournalViewV2,
    snapshot: &aos_sandbox::ProtectedJournalSnapshot,
    acquisition_key: &[u8],
    acquisition_record: &[u8],
    projection: &crate::MountSourceRootCustodyProjectionV2,
    stage: LifecycleStageV2,
) -> Result<([u8; 32], [u8; 32]), SourceProviderSecurityError> {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        SourceAcquisitionPhaseV2, StoredRecordV2, decode_mount_source_state_record_v2,
    };

    let graph = validated_mount_state(journal)?;
    let row = match decode_mount_source_state_record_v2(acquisition_key, acquisition_record) {
        Ok(StoredRecordV2::Acquisition { value }) => value,
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    validate_lifecycle_row_in_graph(
        &graph,
        acquisition_key,
        acquisition_record,
        projection,
        stage,
    )?;
    if journal.validate_current_snapshot(snapshot).is_err()
        || journal.current_value(acquisition_key).ok().flatten() != Some(acquisition_record)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let evidence = row
        .evidence
        .as_ref()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    Ok((row.acquisition_id, evidence.source_realization_handle))
}

pub(in crate::handshake::mount_request) fn validate_lifecycle_row_in_graph(
    graph: &aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
    acquisition_key: &[u8],
    acquisition_record: &[u8],
    projection: &crate::MountSourceRootCustodyProjectionV2,
    stage: LifecycleStageV2,
) -> Result<(), SourceProviderSecurityError> {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        SourceAcquisitionPhaseV2, StoredRecordV2, decode_mount_source_state_record_v2,
    };

    let row = match decode_mount_source_state_record_v2(acquisition_key, acquisition_record) {
        Ok(StoredRecordV2::Acquisition { value }) => value,
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    let evidence = row
        .evidence
        .as_ref()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let session = graph
        .provider_sessions
        .get(&evidence.session_id)
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let observation = projection.observation();
    let stage_matches = match stage {
        LifecycleStageV2::DescriptorCustodied => {
            row.phase == SourceAcquisitionPhaseV2::DescriptorCustodied
                && row.descriptor_custody_digest
                    == Some(*projection.lifecycle_commitment().as_bytes())
                && row.positive_custody_digest.is_none()
                && row.consumption.is_none()
        }
        LifecycleStageV2::Active => {
            row.phase == SourceAcquisitionPhaseV2::Active
                && row.positive_custody_digest
                    == Some(*projection.lifecycle_commitment().as_bytes())
                && row.consumption.is_none()
        }
        LifecycleStageV2::Consumed => {
            row.phase == SourceAcquisitionPhaseV2::Consumed && row.consumption.is_some()
        }
        LifecycleStageV2::Releasing => {
            row.phase == SourceAcquisitionPhaseV2::Releasing
                && row.release_lineage.is_some()
                && row.release_from_phase.is_some()
                && row.release_proof.is_none()
        }
        LifecycleStageV2::Released(negative_custody_digest) => {
            row.phase == SourceAcquisitionPhaseV2::Released
                && row.release_proof.is_some()
                && row.negative_custody_digest == Some(*negative_custody_digest.as_bytes())
        }
    };
    if !stage_matches
        || row.manager_custody != projection.manager_custody()
        || row.manager_custody_loss != projection.manager_custody_loss()
        || projection
            .mount_acquisition_id()
            .is_some_and(|identifier| identifier != row.acquisition_id)
        || projection.provider_acquisition()
            != (
                row.provider_acquisition.acquisition_id,
                row.provider_acquisition.acquisition_sequence,
            )
        || projection.lease()
            != (
                evidence.lease_id,
                ObjectDigest::from_bytes(evidence.signed_lease_digest),
            )
        || projection.session_binding() != ObjectDigest::from_bytes(session.session_binding)
        || projection.descriptor_commitment()
            != ObjectDigest::from_bytes(evidence.descriptor_commitment)
        || projection.signed_outcome_digest().as_bytes() == &[0; 32]
        || projection
            .source_realization_handle()
            .is_some_and(|identity| identity != evidence.source_realization_handle)
        || observation.kernel_boot_id != evidence.source_kernel_boot_id
        || observation.device != evidence.source_device
        || observation.inode != evidence.source_inode
        || observation.unique_mount_id != evidence.source_unique_mount_id
        || graph.acquisitions.get(&row.acquisition_id) != Some(&row)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}

pub(in crate::handshake::mount_request) fn consumption_projection_matches(
    acquisition_key: &[u8],
    acquisition_record: &[u8],
    custody: &crate::MountSourceRootCustodyProjectionV2,
    companions: &aos_sandbox::MountSourceConsumptionCompanionProjectionV2,
) -> bool {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        StoredRecordV2, decode_mount_source_state_record_v2,
        mount_source_consumption_companion_digest_v2,
    };

    let Ok(StoredRecordV2::Acquisition { value }) =
        decode_mount_source_state_record_v2(acquisition_key, acquisition_record)
    else {
        return false;
    };
    let Some(consumption) = value.consumption else {
        return false;
    };
    let record_digests = companions.record_digests();
    let (operation_id, transport_request_digest, semantics_digest, semantics) =
        companions.final_create();
    let assignment = &value.assignment;
    let evidence = match &value.evidence {
        Some(evidence) => evidence,
        None => return false,
    };
    record_digests[0]
        == mount_source_consumption_companion_digest_v2(
            aos_sandbox::RecordNamespace::MountSourceAcquisition as u16,
            acquisition_key,
            Some(acquisition_record),
        )
        && record_digests[1] == consumption.source_pin_record_digest
        && record_digests[2] == consumption.create_effect_record_digest
        && record_digests[3] == consumption.create_operation_record_digest
        && operation_id == consumption.operation_id
        && transport_request_digest == consumption.transport_request_digest
        && semantics_digest == consumption.final_create_semantics_digest
        && semantics == consumption.final_create_semantics.as_slice()
        && companions.acquisition_identity()
            == (
                value.acquisition_id,
                value.provider_acquisition.acquisition_id,
                value.provider_acquisition.acquisition_sequence,
            )
        && companions.source_identity()
            == (
                evidence.source_realization_handle,
                evidence.descriptor_commitment,
            )
        && companions.operation_id() != [0; 16]
        && companions.assignment()
            == (
                assignment.sandbox_id,
                assignment.incarnation_id,
                assignment.assignment_epoch,
                assignment.desired_generation,
                assignment.assignment_digest,
            )
        && companions.semantic_commitments()
            == (
                value.prospective_mount_template_digest,
                value.source_binding_digest,
                value.mount_plan_digest,
                value.ownership_lease_digest,
            )
        && custody.mount_acquisition_id() == Some(value.acquisition_id)
        && custody.provider_acquisition()
            == (
                value.provider_acquisition.acquisition_id,
                value.provider_acquisition.acquisition_sequence,
            )
        && custody.source_realization_handle() == Some(evidence.source_realization_handle)
        && custody.descriptor_commitment().as_bytes() == &evidence.descriptor_commitment
}

pub(in crate::handshake::mount_request) fn consumption_transaction_id_is_exact(
    transaction: &aos_sandbox::JournalTransaction,
    acquisition_key: &[u8],
    acquisition_record: &[u8],
) -> bool {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        StoredRecordV2, decode_mount_source_state_record_v2,
    };

    let Ok(StoredRecordV2::Acquisition { value: row }) =
        decode_mount_source_state_record_v2(acquisition_key, acquisition_record)
    else {
        return false;
    };
    let Some(consumption) = row.consumption else {
        return false;
    };
    transaction.id() == &consumption.transaction_id
}

pub(in crate::handshake::mount_request) fn lifecycle_projection_with_mount_id(
    projection: &crate::MountSourceRootCustodyProjectionV2,
    mount_acquisition_id: [u8; 32],
    source_realization_handle: [u8; 32],
) -> crate::MountSourceRootCustodyProjectionV2 {
    projection.bind_mount_row(mount_acquisition_id, source_realization_handle)
}

pub(in crate::handshake::mount_request) fn commit_or_read_exact_mount_transaction(
    journal: &mut aos_sandbox::ProtectedJournalAuthority<'_>,
    transaction: &aos_sandbox::JournalTransaction,
) -> Result<aos_sandbox::ProtectedJournalSnapshot, SourceProviderSecurityError> {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        MAXIMUM_MOUNT_SOURCE_STATE_MATERIALIZED_BYTES, MAXIMUM_SOURCE_ACQUISITIONS,
        MAXIMUM_SOURCE_HOLDER_SEQUENCES, MAXIMUM_SOURCE_PROVIDER_ATTEMPTS,
        MAXIMUM_SOURCE_PROVIDER_HEADS, MAXIMUM_SOURCE_PROVIDER_SESSIONS, RecordKindV2, key_kind,
    };

    journal
        .validate_mount_source_acquisition_owner_authority()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let mut current = std::collections::BTreeMap::new();
    let mut materialized_bytes = 0usize;
    let mut kind_counts = [0usize; 5];
    for (key, value) in journal
        .records()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
    {
        materialized_bytes = materialized_bytes
            .checked_add(key.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if materialized_bytes > MAXIMUM_MOUNT_SOURCE_STATE_MATERIALIZED_BYTES {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }

        let (index, maximum) =
            match key_kind(key).map_err(|_| SourceProviderSecurityError::SessionContinuity)? {
                RecordKindV2::Acquisition => (0, MAXIMUM_SOURCE_ACQUISITIONS),
                RecordKindV2::ProviderHead => (1, MAXIMUM_SOURCE_PROVIDER_HEADS),
                RecordKindV2::HolderSequence => (2, MAXIMUM_SOURCE_HOLDER_SEQUENCES),
                RecordKindV2::ProviderSession => (3, MAXIMUM_SOURCE_PROVIDER_SESSIONS),
                RecordKindV2::ProviderQueryAttempt => (4, MAXIMUM_SOURCE_PROVIDER_ATTEMPTS),
            };
        kind_counts[index] = kind_counts[index]
            .checked_add(1)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if kind_counts[index] > maximum || current.insert(key.to_vec(), value.to_vec()).is_some() {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
    }
    if transaction
        .records()
        .iter()
        .any(|record| record.namespace() != aos_sandbox::RecordNamespace::MountSourceAcquisition)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let applied = transaction
        .records()
        .iter()
        .map(|record| match record.value() {
            Some(value) => current.get(record.key()).map(Vec::as_slice) == Some(value),
            None => !current.contains_key(record.key()),
        })
        .collect::<Vec<_>>();
    let all_applied = applied.iter().all(|value| *value);
    if !all_applied && applied.iter().any(|value| *value) {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }

    let mut touched = std::collections::BTreeSet::new();
    let mut prospective_bytes = materialized_bytes;
    for record in transaction.records() {
        if !touched.insert(record.key()) {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        if let Some(previous) = current.get(record.key()) {
            prospective_bytes = prospective_bytes
                .checked_sub(record.key().len() + previous.len())
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        }
        if let Some(value) = record.value() {
            aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(
                record.key(),
                value,
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            prospective_bytes = prospective_bytes
                .checked_add(record.key().len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        }
        if prospective_bytes > MAXIMUM_MOUNT_SOURCE_STATE_MATERIALIZED_BYTES {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
    }

    let current_graph =
        aos_sandbox_protocol::mount_source_acquisition_state::validate_mount_source_state_graph_v2(
            current
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let mut prospective = current;
    for record in transaction.records() {
        match record.value() {
            Some(value) => {
                prospective.insert(record.key().to_vec(), value.to_vec());
            }
            None => {
                prospective.remove(record.key());
            }
        }
    }
    let prospective_graph =
        aos_sandbox_protocol::mount_source_acquisition_state::validate_mount_source_state_graph_v2(
            prospective
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;

    if all_applied {
        validate_applied_lifecycle_transaction_id(&current_graph, transaction)?;
        if !journal
            .contains_mount_source_acquisition_transaction(transaction.id())
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
    } else {
        validate_exact_lifecycle_transition(&current_graph, &prospective_graph, transaction)?;
        let preflight = journal
            .preflight_transactions(core::slice::from_ref(transaction))
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        journal
            .validate_preflight_for_effect(&preflight, core::slice::from_ref(transaction))
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        journal
            .commit(transaction)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    }
    let snapshot = journal
        .snapshot()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    for record in transaction.records() {
        let exact = match record.value() {
            Some(value) => journal.get(record.key()).ok().flatten() == Some(value),
            None => journal.get(record.key()).ok().flatten().is_none(),
        };
        if !exact {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
    }
    Ok(snapshot)
}

fn validate_applied_lifecycle_transaction_id(
    current: &aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
    transaction: &aos_sandbox::JournalTransaction,
) -> Result<(), SourceProviderSecurityError> {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        MutationTagV2, ProviderAttemptStateV2, ProviderQueryOwnerV2, SourceAcquisitionPhaseV2,
        StoredRecordV2, decode_mount_source_state_record_v2, transaction_id,
    };

    let mut row = None;
    let mut attempt = None;
    let mut head = None;
    for record in transaction.records() {
        let value = record
            .value()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        match decode_mount_source_state_record_v2(record.key(), value)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        {
            StoredRecordV2::Acquisition { value } if row.replace(value).is_none() => {}
            StoredRecordV2::ProviderQueryAttempt { value } if attempt.replace(value).is_none() => {}
            StoredRecordV2::ProviderHead { value } if head.replace(value).is_none() => {}
            _ => return Err(SourceProviderSecurityError::SessionContinuity),
        }
    }

    let (tag, scope, acquisition, attempt_identity, head_revision) = match (
        row.as_ref(),
        attempt.as_ref(),
        head.as_ref(),
    ) {
        (Some(row), None, None) if transaction.records().len() == 1 => {
            let startup_rebind = row.manager_custody.is_some_and(|custody| {
                    custody.origin
                        == aos_sandbox_protocol::mount_source_acquisition_state::ManagerCustodyOriginV2::StartupCapture
                        && custody.admission_predecessor.id == row.acquisition_id
                        && custody.admission_predecessor.revision.checked_add(1)
                            == Some(row.revision)
                });
            let tag = if startup_rebind {
                MutationTagV2::StartupCustodyRebind
            } else {
                match row.phase {
                    SourceAcquisitionPhaseV2::DescriptorCustodied => MutationTagV2::Custody,
                    SourceAcquisitionPhaseV2::Active => MutationTagV2::Activation,
                    SourceAcquisitionPhaseV2::Released => MutationTagV2::FinishRelease,
                    _ => return Err(SourceProviderSecurityError::SessionContinuity),
                }
            };
            let head = current
                .provider_heads
                .get(&(
                    row.scope.holder_authority_id,
                    row.scope.provider_authority_id,
                ))
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            (
                tag,
                row.scope,
                Some((row.acquisition_id, row.revision)),
                None,
                head.revision,
            )
        }
        (None, Some(attempt), None) if transaction.records().len() == 1 => {
            if !matches!(
                attempt.state,
                ProviderAttemptStateV2::DispositionConsumed { .. }
            ) {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            let ProviderQueryOwnerV2::Acquire { acquisition_id } = attempt.owner else {
                return Err(SourceProviderSecurityError::SessionContinuity);
            };
            let row = current
                .acquisitions
                .get(&acquisition_id)
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let head = current
                .provider_heads
                .get(&(
                    attempt.scope.holder_authority_id,
                    attempt.scope.provider_authority_id,
                ))
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            (
                MutationTagV2::ConsumeOutcome,
                attempt.scope,
                Some((row.acquisition_id, row.revision)),
                Some((attempt.attempt_id, attempt.revision)),
                head.revision,
            )
        }
        (Some(row), Some(attempt), Some(head)) if transaction.records().len() == 3 => {
            if row.scope != attempt.scope || row.scope != head.scope {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            let tag = if row.phase == SourceAcquisitionPhaseV2::Releasing
                && matches!(attempt.state, ProviderAttemptStateV2::Reserved)
            {
                MutationTagV2::BeginRelease
            } else if matches!(
                attempt.state,
                ProviderAttemptStateV2::DispositionConsumed { .. }
            ) {
                MutationTagV2::ConsumeOutcome
            } else {
                return Err(SourceProviderSecurityError::SessionContinuity);
            };
            (
                tag,
                row.scope,
                Some((row.acquisition_id, row.revision)),
                Some((attempt.attempt_id, attempt.revision)),
                head.revision,
            )
        }
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    let holder_sequence_revision = current
        .holder_sequences
        .get(&scope.holder_authority_id)
        .map_or(0, |value| value.revision);
    let expected = transaction_id(
        tag,
        scope.holder_authority_id,
        scope.provider_authority_id,
        holder_sequence_revision,
        head_revision,
        acquisition.map(|value| value.0),
        acquisition.map(|value| value.1),
        attempt_identity.map(|value| value.0),
        attempt_identity.map(|value| value.1),
        None,
    );
    let initial_startup_custody = matches!(tag, MutationTagV2::StartupCustodyRebind)
        && row.as_ref().is_some_and(|row| {
            row.phase == SourceAcquisitionPhaseV2::DescriptorCustodied
                && row.manager_custody.is_some_and(|custody| {
                    custody.admission_predecessor.revision.checked_add(1) == Some(row.revision)
                })
        });
    let alternate = initial_startup_custody.then(|| {
        transaction_id(
            MutationTagV2::Custody,
            scope.holder_authority_id,
            scope.provider_authority_id,
            holder_sequence_revision,
            head_revision,
            acquisition.map(|value| value.0),
            acquisition.map(|value| value.1),
            attempt_identity.map(|value| value.0),
            attempt_identity.map(|value| value.1),
            None,
        )
    });
    if transaction.id() != &expected && alternate.as_ref() != Some(transaction.id()) {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}

pub(in crate::handshake::mount_request) fn validate_exact_lifecycle_transition(
    current: &aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
    prospective: &aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
    transaction: &aos_sandbox::JournalTransaction,
) -> Result<(), SourceProviderSecurityError> {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        MutationTagV2, ProviderAttemptStateV2, ProviderQueryOwnerV2, SourceAcquisitionPhaseV2,
        StoredRecordV2, decode_mount_source_state_record_v2, transaction_id,
    };

    let mut changed_acquisition = None;
    let mut changed_attempt = None;
    let mut changed_head = None;

    for record in transaction.records() {
        let value = record
            .value()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let decoded = decode_mount_source_state_record_v2(record.key(), value)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        match decoded {
            StoredRecordV2::Acquisition { value: next } => {
                let previous = current
                    .acquisitions
                    .get(&next.acquisition_id)
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                if startup_custody_rebind_is_exact(previous, &next) {
                    if changed_acquisition.replace(next).is_some() {
                        return Err(SourceProviderSecurityError::SessionContinuity);
                    }
                    continue;
                }
                if previous.revision.checked_add(1) != Some(next.revision)
                    || previous.acquisition_id != next.acquisition_id
                    || previous.provider_acquisition != next.provider_acquisition
                    || previous.scope != next.scope
                    || previous.acquire != next.acquire
                    || previous.mount_acquire_request != next.mount_acquire_request
                    || previous.acquire_intent_digest != next.acquire_intent_digest
                    || previous.acquire_lineage.root != next.acquire_lineage.root
                    || previous.acquire_lineage.next_attempt_number
                        != next.acquire_lineage.next_attempt_number
                    || previous
                        .acquire_terminal_attempt
                        .is_some_and(|attempt| next.acquire_terminal_attempt != Some(attempt))
                    || previous.assignment != next.assignment
                    || previous.prospective_mount_template != next.prospective_mount_template
                    || previous.prospective_mount_template_digest
                        != next.prospective_mount_template_digest
                    || previous.source_binding != next.source_binding
                    || previous.source_binding_digest != next.source_binding_digest
                    || previous.mount_plan_digest != next.mount_plan_digest
                    || previous.ownership_lease_digest != next.ownership_lease_digest
                    || previous
                        .evidence
                        .as_ref()
                        .is_some_and(|evidence| next.evidence.as_ref() != Some(evidence))
                    || previous
                        .manager_custody
                        .is_some_and(|custody| next.manager_custody != Some(custody))
                    || previous
                        .descriptor_custody_digest
                        .is_some_and(|digest| next.descriptor_custody_digest != Some(digest))
                    || previous
                        .positive_custody_digest
                        .is_some_and(|digest| next.positive_custody_digest != Some(digest))
                    || previous
                        .consumption
                        .as_ref()
                        .is_some_and(|evidence| next.consumption.as_ref() != Some(evidence))
                    || previous
                        .release
                        .is_some_and(|release| next.release != Some(release))
                    || previous
                        .mount_release_request
                        .as_ref()
                        .is_some_and(|request| next.mount_release_request.as_ref() != Some(request))
                    || previous
                        .release_authority
                        .is_some_and(|authority| next.release_authority != Some(authority))
                    || previous
                        .release_from_phase
                        .is_some_and(|phase| next.release_from_phase != Some(phase))
                    || previous
                        .release_intent_digest
                        .is_some_and(|digest| next.release_intent_digest != Some(digest))
                    || previous.release_lineage.as_ref().is_some_and(|lineage| {
                        next.release_lineage.as_ref().is_none_or(|next_lineage| {
                            next_lineage.root != lineage.root
                                || next_lineage.next_attempt_number != lineage.next_attempt_number
                        })
                    })
                    || previous
                        .release_terminal_attempt
                        .is_some_and(|attempt| next.release_terminal_attempt != Some(attempt))
                    || previous
                        .release_inventory_fence
                        .as_ref()
                        .is_some_and(|fence| next.release_inventory_fence.as_ref() != Some(fence))
                    || previous
                        .release_proof
                        .as_ref()
                        .is_some_and(|proof| next.release_proof.as_ref() != Some(proof))
                    || previous
                        .negative_custody_digest
                        .is_some_and(|digest| next.negative_custody_digest != Some(digest))
                    || !fault_and_recovery_transition_is_exact(previous, &next)
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                if changed_acquisition.replace(next).is_some() {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
            }
            StoredRecordV2::ProviderQueryAttempt { value: next } => {
                if let Some(previous) = current.provider_attempts.get(&next.attempt_id) {
                    let mut expected = previous.clone();
                    expected.revision = next.revision;
                    expected.state = next.state.clone();
                    expected.record_digest = next.record_digest;
                    if previous.revision.checked_add(1) != Some(next.revision)
                        || !matches!(previous.state, ProviderAttemptStateV2::Reserved)
                        || expected != next
                    {
                        return Err(SourceProviderSecurityError::SessionContinuity);
                    }
                } else {
                    if next.revision != 1 || !matches!(next.state, ProviderAttemptStateV2::Reserved)
                    {
                        return Err(SourceProviderSecurityError::SessionContinuity);
                    }
                    match next.owner {
                        ProviderQueryOwnerV2::Acquire { acquisition_id }
                        | ProviderQueryOwnerV2::Release { acquisition_id } => {
                            let previous = current
                                .acquisitions
                                .get(&acquisition_id)
                                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                            if next.owner_predecessor_revision != previous.revision
                                || next.owner_predecessor_digest != previous.record_digest
                            {
                                return Err(SourceProviderSecurityError::SessionContinuity);
                            }
                        }
                        ProviderQueryOwnerV2::Inventory => {
                            return Err(SourceProviderSecurityError::SessionContinuity);
                        }
                    }
                }
                if changed_attempt.replace(next).is_some() {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
            }
            StoredRecordV2::ProviderHead { value: next } => {
                let previous = current
                    .provider_heads
                    .get(&(
                        next.scope.holder_authority_id,
                        next.scope.provider_authority_id,
                    ))
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                if previous.revision.checked_add(1) != Some(next.revision)
                    || previous.scope != next.scope
                    || previous.holder_authority_generation != next.holder_authority_generation
                    || previous.holder_authority_digest != next.holder_authority_digest
                    || previous.provider_authority_generation != next.provider_authority_generation
                    || previous.provider_authority_digest != next.provider_authority_digest
                    || previous.current_session_id != next.current_session_id
                    || previous.current_session_record_digest != next.current_session_record_digest
                    || !head_direction_and_projection_are_exact(
                        previous,
                        &next,
                        current,
                        prospective,
                    )?
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                if changed_head.replace(next).is_some() {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
            }
            StoredRecordV2::HolderSequence { .. } | StoredRecordV2::ProviderSession { .. } => {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
        }
    }

    // The prospective graph is retained in the signature so this boundary
    // cannot accidentally regress to record-local validation.
    if prospective.acquisitions.len() < current.acquisitions.len()
        || prospective.provider_heads.len() != current.provider_heads.len()
        || prospective.provider_sessions != current.provider_sessions
        || prospective.holder_sequences != current.holder_sequences
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }

    let (tag, scope, acquisition, attempt, head_revision) = match (
        changed_acquisition.as_ref(),
        changed_attempt.as_ref(),
        changed_head.as_ref(),
    ) {
        (Some(next), None, None) if transaction.records().len() == 1 => {
            let previous = current
                .acquisitions
                .get(&next.acquisition_id)
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let tag = match (previous.phase, next.phase, previous.faulted_from) {
                (phase, next_phase, _)
                    if phase == next_phase && startup_custody_rebind_is_exact(previous, next) =>
                {
                    MutationTagV2::StartupCustodyRebind
                }
                (
                    SourceAcquisitionPhaseV2::PendingQuery,
                    SourceAcquisitionPhaseV2::DescriptorCustodied,
                    _,
                ) => MutationTagV2::Custody,
                (
                    SourceAcquisitionPhaseV2::DescriptorCustodied,
                    SourceAcquisitionPhaseV2::Active,
                    _,
                ) => MutationTagV2::Activation,
                (SourceAcquisitionPhaseV2::Releasing, SourceAcquisitionPhaseV2::Released, _)
                | (
                    SourceAcquisitionPhaseV2::Faulted,
                    SourceAcquisitionPhaseV2::Released,
                    Some(SourceAcquisitionPhaseV2::Releasing),
                ) => MutationTagV2::FinishRelease,
                _ => return Err(SourceProviderSecurityError::SessionContinuity),
            };
            let head = current
                .provider_heads
                .get(&(
                    next.scope.holder_authority_id,
                    next.scope.provider_authority_id,
                ))
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            (
                tag,
                next.scope,
                Some((next.acquisition_id, next.revision)),
                None,
                head.revision,
            )
        }
        (Some(next_row), Some(next_attempt), Some(next_head))
            if transaction.records().len() == 3 =>
        {
            let previous_attempt = current.provider_attempts.get(&next_attempt.attempt_id);
            let tag = if previous_attempt.is_none()
                && matches!(next_attempt.state, ProviderAttemptStateV2::Reserved)
                && next_row.phase == SourceAcquisitionPhaseV2::Releasing
            {
                MutationTagV2::BeginRelease
            } else if previous_attempt
                .is_some_and(|value| matches!(value.state, ProviderAttemptStateV2::Reserved))
                && !matches!(next_attempt.state, ProviderAttemptStateV2::Reserved)
            {
                MutationTagV2::ConsumeOutcome
            } else {
                return Err(SourceProviderSecurityError::SessionContinuity);
            };
            if next_row.scope != next_attempt.scope || next_row.scope != next_head.scope {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            (
                tag,
                next_row.scope,
                Some((next_row.acquisition_id, next_row.revision)),
                Some((next_attempt.attempt_id, next_attempt.revision)),
                next_head.revision,
            )
        }
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    let holder_sequence_revision = current
        .holder_sequences
        .get(&scope.holder_authority_id)
        .map_or(0, |value| value.revision);
    let expected_transaction_id = transaction_id(
        tag,
        scope.holder_authority_id,
        scope.provider_authority_id,
        holder_sequence_revision,
        head_revision,
        acquisition.map(|value| value.0),
        acquisition.map(|value| value.1),
        attempt.map(|value| value.0),
        attempt.map(|value| value.1),
        None,
    );
    if transaction.id() != &expected_transaction_id {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}

fn startup_custody_rebind_is_exact(
    previous: &aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionRowV2,
    next: &aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionRowV2,
) -> bool {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        ManagerCustodyOriginV2, SourceAcquisitionPhaseV2,
    };

    let effective_phase = if previous.phase == SourceAcquisitionPhaseV2::Faulted {
        previous.faulted_from
    } else {
        Some(previous.phase)
    };
    let custody_origin = if effective_phase == Some(SourceAcquisitionPhaseV2::Releasing) {
        previous.release_from_phase
    } else {
        effective_phase
    };
    let Some(custody) = next.manager_custody else {
        return false;
    };
    if !matches!(
        effective_phase,
        Some(
            SourceAcquisitionPhaseV2::DescriptorCustodied
                | SourceAcquisitionPhaseV2::Active
                | SourceAcquisitionPhaseV2::Consumed
                | SourceAcquisitionPhaseV2::Releasing
        )
    ) || custody.origin != ManagerCustodyOriginV2::StartupCapture
        || custody.admission_predecessor.id != previous.acquisition_id
        || custody.admission_predecessor.revision != previous.revision
        || custody.admission_predecessor.record_digest != previous.record_digest
        || previous.manager_custody == Some(custody)
        || next.manager_custody_loss.is_some()
        || next.descriptor_custody_digest.is_none()
        || matches!(
            custody_origin,
            Some(SourceAcquisitionPhaseV2::Active | SourceAcquisitionPhaseV2::Consumed)
        ) != next.positive_custody_digest.is_some()
    {
        return false;
    }

    let mut expected = previous.clone();
    expected.revision = next.revision;
    expected.manager_custody = Some(custody);
    expected.manager_custody_loss = None;
    expected.descriptor_custody_digest = next.descriptor_custody_digest;
    expected.positive_custody_digest = next.positive_custody_digest;
    expected.record_digest = next.record_digest;
    previous.revision.checked_add(1) == Some(next.revision) && expected == *next
}

fn fault_and_recovery_transition_is_exact(
    previous: &aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionRowV2,
    next: &aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionRowV2,
) -> bool {
    use aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionPhaseV2;

    let fault_is_exact = if previous.phase == SourceAcquisitionPhaseV2::Faulted
        && next.phase == SourceAcquisitionPhaseV2::Releasing
    {
        next.faulted_from.is_none()
            && next.fault_digest.is_none()
            && next.retained_faulted_from == previous.faulted_from
            && next.retained_fault_digest == previous.fault_digest
    } else if previous.phase == SourceAcquisitionPhaseV2::Faulted
        && previous.faulted_from == Some(SourceAcquisitionPhaseV2::Releasing)
        && next.phase == SourceAcquisitionPhaseV2::Released
    {
        next.faulted_from.is_none()
            && next.fault_digest.is_none()
            && next.retained_faulted_from == previous.faulted_from
            && next.retained_fault_digest == previous.fault_digest
    } else {
        next.faulted_from == previous.faulted_from
            && next.fault_digest == previous.fault_digest
            && next.retained_faulted_from == previous.retained_faulted_from
            && next.retained_fault_digest == previous.retained_fault_digest
    };
    fault_is_exact && next.recovery == previous.recovery
}

fn head_direction_and_projection_are_exact(
    previous: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderHeadV2,
    next: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderHeadV2,
    current: &aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
    prospective: &aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
) -> Result<bool, SourceProviderSecurityError> {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        ProviderAttemptStateV2, project_scope,
    };

    let direction_is_exact = match (previous.pending_attempt, next.pending_attempt) {
        (None, Some(pending)) => {
            previous.next_request_sequence.checked_add(1) == Some(next.next_request_sequence)
                && next.next_response_sequence == previous.next_response_sequence
                && prospective
                    .provider_attempts
                    .get(&pending.id)
                    .is_some_and(|attempt| {
                        attempt.revision == pending.revision
                            && attempt.record_digest == pending.record_digest
                            && matches!(attempt.state, ProviderAttemptStateV2::Reserved)
                    })
        }
        (Some(pending), None) => {
            next.next_request_sequence == previous.next_request_sequence
                && previous.next_response_sequence.checked_add(1)
                    == Some(next.next_response_sequence)
                && prospective
                    .provider_attempts
                    .get(&pending.id)
                    .is_some_and(|attempt| {
                        attempt.revision == pending.revision.checked_add(1).unwrap_or(0)
                            && !matches!(attempt.state, ProviderAttemptStateV2::Reserved)
                    })
        }
        _ => false,
    };
    if !direction_is_exact {
        return Ok(false);
    }

    let previous_entries = aos_sandbox_protocol::mount_source_acquisition_state::projection_entries(
        previous.scope,
        &current.acquisitions,
    );
    let next_entries = aos_sandbox_protocol::mount_source_acquisition_state::projection_entries(
        previous.scope,
        &prospective.acquisitions,
    );
    let expected_epoch = if next_entries == previous_entries {
        previous.current_projection_epoch
    } else {
        previous
            .current_projection_epoch
            .checked_add(1)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?
    };
    let expected_projection =
        project_scope(previous.scope, expected_epoch, &prospective.acquisitions)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    Ok(next.current_projection_epoch == expected_epoch
        && next.current_projection_digest == expected_projection.digest
        && previous.inventory_observation_ordinal == next.inventory_observation_ordinal
        && previous.inventory_floor == next.inventory_floor
        && previous.last_inventory_attempt == next.last_inventory_attempt
        && previous.last_reconciliation == next.last_reconciliation
        && previous.recovery_barrier == next.recovery_barrier)
}

pub(in crate::handshake::mount_request) fn exact_put_record(
    transaction: &aos_sandbox::JournalTransaction,
    predicate: impl Fn(&[u8], &[u8]) -> bool,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut matches = transaction.records().iter().filter_map(|record| {
        let value = record.value()?;
        predicate(record.key(), value).then(|| (record.key().to_vec(), value.to_vec()))
    });
    let result = matches.next()?;
    matches.next().is_none().then_some(result)
}

pub(super) fn graph_retains_pending_source_root_custody(
    graph: &aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
    attempt: aos_sandbox_protocol::mount_source_acquisition_state::RecordRefV2,
) -> bool {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        AcquisitionRecoveryV2, SourceAcquisitionPhaseV2,
    };

    let mut rows = graph.acquisitions.values().filter(|row| {
        row.phase == SourceAcquisitionPhaseV2::PendingQuery
            && row.descriptor_custody_digest.is_none()
            && matches!(row.recovery, AcquisitionRecoveryV2::Ready)
            && row.acquire_terminal_attempt == Some(attempt)
            && row
                .evidence
                .as_ref()
                .is_some_and(|evidence| evidence.acquire_attempt == attempt)
    });
    rows.next().is_some() && rows.next().is_none()
}

pub(super) fn graph_retains_recoverable_source_root_custody(
    graph: &aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
    attempt: aos_sandbox_protocol::mount_source_acquisition_state::RecordRefV2,
) -> bool {
    use aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionPhaseV2;

    if graph_retains_pending_source_root_custody(graph, attempt) {
        return true;
    }
    let mut rows = graph.acquisitions.values().filter(|row| {
        let effective_phase = if row.phase == SourceAcquisitionPhaseV2::Faulted {
            row.faulted_from
        } else {
            Some(row.phase)
        };
        let exact_fault_shape = row.phase != SourceAcquisitionPhaseV2::Faulted
            || (row.fault_digest.is_some()
                && row.retained_faulted_from.is_none()
                && row.retained_fault_digest.is_none());
        matches!(
            effective_phase,
            Some(
                SourceAcquisitionPhaseV2::DescriptorCustodied
                    | SourceAcquisitionPhaseV2::Active
                    | SourceAcquisitionPhaseV2::Consumed
                    | SourceAcquisitionPhaseV2::Releasing
            )
        ) && exact_fault_shape
            && row.acquire_terminal_attempt == Some(attempt)
            && row
                .evidence
                .as_ref()
                .is_some_and(|evidence| evidence.acquire_attempt == attempt)
            && row.descriptor_custody_digest.is_some()
            && row.negative_custody_digest.is_none()
            && row.release_proof.is_none()
    });
    rows.next().is_some() && rows.next().is_none()
}

#[allow(clippy::too_many_arguments)]
pub(in crate::handshake::mount_request) fn verify_historical_acquire_equivalent(
    signed_request: &SignedSourceProviderRequestV1,
    receipt: &SignedSourceProviderReceiptV1,
    signed_lease: &SignedSourceExportLeaseV1,
    session: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderSessionV2,
    provider: &SourceProviderAuthorityV1,
    holder: &SourceProviderAuthorityV1,
    catalog_floor: &ProviderCatalogFloorV1,
    selection_floor: Option<&SourceSelectionFloorV1>,
    now_seconds: i64,
    observation: Option<&aos_sandbox_source_provider_protocol::SourceRootObservationV1>,
) -> Result<(), SourceProviderSecurityError> {
    let request = decode_acquire_request(signed_request.subject())
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let root_record_signer = &session.signers[1];
    let retained_outcome_signer = &session.signers[3];
    let expected_lease_signer = selection_floor
        .map(SourceSelectionFloorV1::outcome_signer)
        .unwrap_or_else(|| {
            // The retained session owns the no-selection-floor lease signer.
            // Its closed durable projection is compared field-by-field below.
            signed_lease.signer()
        });
    let signed_request_signer = signed_request.signer();
    verify_request(signed_request, &root_record_signer.public_key)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;

    let request_holder = request.holder_authority();
    let request_execution = request.execution_bindings();
    let request_bounds = request.requested_bounds();
    let lease = signed_lease.subject();
    let lease_holder = lease.holder_authority();
    let lease_commitments = lease.holder_commitments();
    let lease_validity = lease.validity();
    let topology = lease.proof().topology();
    let Some(observation) = observation else {
        return Err(SourceProviderSecurityError::DescriptorObservation);
    };
    let receipt_observation = receipt.subject().physical_observation();
    let proof_digest = digest_provider_proof(lease.proof());
    let lease_digest = digest_signed_export_lease(signed_lease);
    let lease_duration = lease_validity
        .1
        .checked_sub(lease_validity.0)
        .and_then(|seconds| u64::try_from(seconds).ok());
    let local_live_consumer_matches = match lease.proof() {
        aos_sandbox_source_provider_protocol::SourceProviderProofV1::LocalLiveExport {
            proof,
            ..
        } => proof.consumer_authority() == (holder.authority_id(), holder.authority_generation()),
        _ => true,
    };
    let nonrecursive_shape = request_bounds.1 || topology.observed_submounts() == 0;
    let expected_lease_provider = selection_floor
        .map(SourceSelectionFloorV1::outcome_signer)
        .map(|signer| {
            (
                signer.authority_id(),
                signer.authority_generation(),
                signer.authority_digest(),
            )
        })
        .unwrap_or((
            provider.authority_id(),
            provider.authority_generation(),
            provider.authority_digest(),
        ));
    if request.acquisition_version()
        != aos_sandbox_source_provider_protocol::ACQUIRE_SOURCE_REQUEST_VERSION_V2
        || signed_request_signer.authority_id() != root_record_signer.authority_id
        || signed_request_signer.authority_generation() != root_record_signer.authority_generation
        || signed_request_signer.authority_digest().as_bytes()
            != &root_record_signer.authority_digest
        || signed_request_signer.key_id() != root_record_signer.key_id
        || signed_request_signer.key_generation() != root_record_signer.key_generation
        || signed_request_signer.usage() != SourceProviderKeyUsageV1::RootMountRecord
        || signed_lease.signer() != expected_lease_signer
        || (selection_floor.is_none()
            && (signed_lease.signer().authority_id() != retained_outcome_signer.authority_id
                || signed_lease.signer().authority_generation()
                    != retained_outcome_signer.authority_generation
                || signed_lease.signer().authority_digest().as_bytes()
                    != &retained_outcome_signer.authority_digest
                || signed_lease.signer().key_id() != retained_outcome_signer.key_id
                || signed_lease.signer().key_generation()
                    != retained_outcome_signer.key_generation
                || signed_lease.signer().public_key_digest().as_bytes()
                    != &retained_outcome_signer.public_key_fingerprint))
        || signed_lease.signer().usage() != SourceProviderKeyUsageV1::ProviderOutcome
        || request.session_binding() != ObjectDigest::from_bytes(session.session_binding)
        || request_holder
            != (
                holder.authority_id(),
                holder.authority_generation(),
                holder.authority_digest(),
            )
        || request_execution.0 != session.node_id
        || request_execution.1 != session.kernel_boot_id
        || request_execution.2 != ObjectDigest::from_bytes(session.revocation_digest)
        || receipt.subject().request_identity()
            != (request.request_id(), digest_acquire_request(&request))
        || receipt.subject().acquisition_id() != request.acquisition_id()
        || receipt.subject().provider_process_instance() != session.provider_process_instance
        || receipt.subject().lease_digest() != lease_digest
        || receipt.subject().observed_proof_digest() != proof_digest
        || receipt_observation
            != (
                observation.kernel_boot_id,
                observation.device,
                observation.inode,
                observation.unique_mount_id,
            )
        || observation.kernel_boot_id != request_execution.1
        || !observation.directory
        || !observation.o_path
        || !observation.read_only
        || lease.request_identity() != (request.request_id(), digest_acquire_request(&request))
        || lease_holder != request_holder
        || lease_commitments != (request.binding_digest(), request_execution.2)
        || (
            lease.provider().authority_id(),
            lease.provider().authority_generation(),
            lease.provider().authority_digest(),
        ) != expected_lease_provider
        || lease.resource().resource_namespace_digest()
            != ObjectDigest::from_bytes(session.scope.resource_namespace_digest)
        || lease.proof().capability_bit() & session.negotiated_capabilities.proof_class_capabilities
            == 0
        || request_bounds.1 && !session.negotiated_capabilities.supports_recursive
        || request_bounds.3 && !session.negotiated_capabilities.supports_kernel_coupled
        || lease.proof().requires_kernel_coupled() != request_bounds.3
        || topology.observed_submounts() > request_bounds.2
        || !nonrecursive_shape
        || !local_live_consumer_matches
        || lease_validity.0 > now_seconds
        || lease_validity.1 <= now_seconds
        || lease_validity.1 > request.deadline_seconds()
        || lease_validity.1 > session.current_valid_until_seconds
        || lease_duration.is_none_or(|duration| duration == 0 || duration > request_bounds.0)
        || catalog_floor.provider_authority_id() != provider.authority_id()
        || catalog_floor.resource_namespace_digest()
            != ObjectDigest::from_bytes(session.scope.resource_namespace_digest)
        || selection_floor.is_none()
            && (lease.resource().catalog_generation() < catalog_floor.minimum_catalog_generation()
                || (lease.resource().catalog_generation()
                    == catalog_floor.minimum_catalog_generation()
                    && lease.resource().catalog_digest() != catalog_floor.minimum_catalog_digest()))
        || selection_floor.is_some_and(|floor| {
            floor.acquisition_id() != request.acquisition_id()
                || floor.provider_authority_id() != provider.authority_id()
                || floor.route_id() != session.scope.route_id
                || floor.resource() != lease.resource()
                || floor.outcome_signer() != signed_lease.signer()
                || floor.lease_id() != lease.lease_id()
                || floor.signed_lease_digest() != lease_digest
                || floor.proof_class() != lease.proof().class_code()
                || floor.proof_digest() != proof_digest
                || floor.resource_commitment()
                    != provider_resource_commitment_v1(lease.resource(), proof_digest)
        })
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}
