//! Durable assignment, attempt-state, and retention-state codecs.

use super::*;

pub(super) fn encode_assignment_record(record: &AssignmentRecord) -> Vec<u8> {
    let request = record.request.canonical_bytes();
    let response = record.response.canonical_bytes();
    let mut payload = Vec::with_capacity(
        ASSIGNMENT_MAGIC.len() + request.len() + response.len() + 2 * size_of::<u32>(),
    );
    payload.extend_from_slice(ASSIGNMENT_MAGIC);
    push_bytes(&mut payload, &request);
    push_bytes(&mut payload, &response);
    seal(payload, ASSIGNMENT_CHECKSUM_DOMAIN)
}

pub(super) fn decode_assignment_record(
    bytes: &[u8],
) -> Result<AssignmentRecord, AssignmentLedgerError> {
    let payload = open_sealed(bytes, ASSIGNMENT_CHECKSUM_DOMAIN)?;
    let mut cursor = RecordCursor::new(payload);
    cursor.require(ASSIGNMENT_MAGIC)?;
    let request = SubmitAttemptRequest::from_canonical_bytes(cursor.bytes()?)?;
    let response = SubmitAttemptResponse::from_canonical_bytes(cursor.bytes()?)?;
    cursor.finish()?;
    AssignmentRecord::new(request, response).map_err(Into::into)
}

pub(super) fn encode_attempt_state(
    key: AttemptExecutionKey,
    state: AttemptRuntimeState,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(ATTEMPT_STATE_MAGIC);
    push_bytes(&mut payload, key.lineage.to_text().as_bytes());
    push_bytes(&mut payload, key.attempt.to_text().as_bytes());
    push_bytes(&mut payload, &key.scope.canonical_bytes());
    payload.extend_from_slice(&state.execution_basis().as_bytes());
    encode_attempt_origin(&mut payload, state.origin());
    match state {
        AttemptRuntimeState::Running {
            daemon_epoch,
            execution,
            ..
        } => {
            payload.push(0);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
        }
        AttemptRuntimeState::CheckpointRequested {
            daemon_epoch,
            execution,
            ..
        } => {
            payload.push(4);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
        }
        AttemptRuntimeState::CheckpointPublishing {
            daemon_epoch,
            execution,
            checkpoint,
            ..
        } => {
            payload.push(5);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
            push_bytes(&mut payload, checkpoint.to_text().as_bytes());
        }
        AttemptRuntimeState::Paused {
            daemon_epoch,
            execution,
            checkpoint,
            promotion_basis,
            ..
        } => {
            payload.push(6);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
            push_bytes(&mut payload, checkpoint.to_text().as_bytes());
            encode_checkpoint_promotion_basis(&mut payload, promotion_basis);
        }
        AttemptRuntimeState::CheckpointPromoting {
            daemon_epoch,
            execution,
            source_checkpoint,
            promoted_checkpoint,
            promotion_basis,
            ..
        } => {
            payload.push(7);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
            push_bytes(&mut payload, source_checkpoint.to_text().as_bytes());
            push_bytes(&mut payload, promoted_checkpoint.to_text().as_bytes());
            encode_checkpoint_promotion_basis(&mut payload, promotion_basis);
        }
        AttemptRuntimeState::Completed {
            daemon_epoch,
            execution,
            observation,
            finding_candidate,
            prepared_result_digest,
            ..
        } => {
            payload.push(1);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
            push_bytes(&mut payload, observation.to_text().as_bytes());
            encode_optional_finding_candidate(&mut payload, finding_candidate.candidate());
            payload.push(u8::from(finding_candidate.is_acknowledged()));
            encode_optional_campaign_hash(&mut payload, prepared_result_digest);
        }
        AttemptRuntimeState::Publishing {
            daemon_epoch,
            execution,
            observation,
            finding_candidate,
            finding_replay_captures,
            finding_exact_retention_roots,
            prepared_result_digest,
            ..
        } => {
            payload.push(3);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
            push_bytes(&mut payload, observation.to_text().as_bytes());
            encode_optional_finding_candidate(&mut payload, finding_candidate);
            encode_optional_finding_replay_captures(&mut payload, finding_replay_captures);
            encode_finding_exact_retention_roots(&mut payload, finding_exact_retention_roots);
            encode_optional_campaign_hash(&mut payload, prepared_result_digest);
        }
        AttemptRuntimeState::Canceled {
            daemon_epoch,
            execution,
            ..
        } => {
            payload.push(2);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
        }
        AttemptRuntimeState::TerminalFailure {
            daemon_epoch,
            execution,
            ..
        } => {
            payload.push(8);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
        }
    }
    seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN)
}

pub(super) fn decode_attempt_state(
    bytes: &[u8],
) -> Result<(AttemptExecutionKey, AttemptRuntimeState), AssignmentLedgerError> {
    let (payload, magic) = if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN) {
        (payload, ATTEMPT_STATE_MAGIC)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V14) {
        (payload, ATTEMPT_STATE_MAGIC_V14)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V13) {
        (payload, ATTEMPT_STATE_MAGIC_V13)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V12) {
        (payload, ATTEMPT_STATE_MAGIC_V12)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V11) {
        (payload, ATTEMPT_STATE_MAGIC_V11)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V10) {
        (payload, ATTEMPT_STATE_MAGIC_V10)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V9) {
        (payload, ATTEMPT_STATE_MAGIC_V9)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V8) {
        (payload, ATTEMPT_STATE_MAGIC_V8)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V7) {
        (payload, ATTEMPT_STATE_MAGIC_V7)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V6) {
        (payload, ATTEMPT_STATE_MAGIC_V6)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V5) {
        (payload, ATTEMPT_STATE_MAGIC_V5)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V4) {
        (payload, ATTEMPT_STATE_MAGIC_V4)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V3) {
        (payload, ATTEMPT_STATE_MAGIC_V3)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V2) {
        (payload, ATTEMPT_STATE_MAGIC_V2)
    } else {
        (
            open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V1)?,
            ATTEMPT_STATE_MAGIC_V1,
        )
    };
    let mut cursor = RecordCursor::new(payload);
    cursor.require(magic)?;
    let lineage = parse_typed(cursor.bytes()?, CampaignLineageId::parse)?;
    let attempt = parse_typed(cursor.bytes()?, AttemptId::parse)?;
    let scope = if ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
        || magic == ATTEMPT_STATE_MAGIC_V13)
        || magic == ATTEMPT_STATE_MAGIC_V12
        || magic == ATTEMPT_STATE_MAGIC_V11
    {
        AttemptExecutionScope::from_canonical_bytes(cursor.bytes()?)?
    } else {
        AttemptExecutionScope::Semantic
    };
    let execution_basis = CampaignHash::from_bytes(cursor.fixed()?);
    let origin = if ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
        || magic == ATTEMPT_STATE_MAGIC_V13)
        || magic == ATTEMPT_STATE_MAGIC_V12
        || magic == ATTEMPT_STATE_MAGIC_V11
        || magic == ATTEMPT_STATE_MAGIC_V10
        || magic == ATTEMPT_STATE_MAGIC_V9
        || magic == ATTEMPT_STATE_MAGIC_V8
        || magic == ATTEMPT_STATE_MAGIC_V7
        || magic == ATTEMPT_STATE_MAGIC_V6
        || magic == ATTEMPT_STATE_MAGIC_V5
        || magic == ATTEMPT_STATE_MAGIC_V4
    {
        decode_attempt_origin(
            &mut cursor,
            ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                || magic == ATTEMPT_STATE_MAGIC_V13)
                || magic == ATTEMPT_STATE_MAGIC_V12,
        )?
    } else {
        AttemptExecutionOrigin::Initial
    };
    let tag = cursor.byte()?;
    let daemon_epoch = DaemonEpoch::from_bytes(cursor.fixed()?)?;
    let execution = ExecutionId::from_bytes(cursor.fixed()?)?;
    let state = match tag {
        0 => AttemptRuntimeState::Running {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
        },
        1 => {
            let observation = parse_typed(cursor.bytes()?, ObservationId::parse)?;
            let finding_candidate = decode_optional_finding_candidate(&mut cursor, magic)?;
            let finding_candidate_acknowledged = if ((magic == ATTEMPT_STATE_MAGIC
                || magic == ATTEMPT_STATE_MAGIC_V14)
                || magic == ATTEMPT_STATE_MAGIC_V13)
                || magic == ATTEMPT_STATE_MAGIC_V12
                || magic == ATTEMPT_STATE_MAGIC_V11
                || magic == ATTEMPT_STATE_MAGIC_V10
                || magic == ATTEMPT_STATE_MAGIC_V9
            {
                match cursor.byte()? {
                    0 => false,
                    1 => true,
                    _ => return Err(corrupt("attempt-state-finding-candidate-acknowledged-tag")),
                }
            } else {
                false
            };
            let finding_candidate = match (finding_candidate, finding_candidate_acknowledged) {
                (None, false) => CompletedFindingCandidate::None,
                (Some(candidate), false) => CompletedFindingCandidate::Pending(candidate),
                (Some(candidate), true) => CompletedFindingCandidate::Acknowledged(candidate),
                (None, true) => {
                    return Err(corrupt(
                        "attempt-state-acknowledged-finding-candidate-missing",
                    ));
                }
            };
            AttemptRuntimeState::Completed {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
                observation,
                finding_candidate,
                prepared_result_digest: if magic == ATTEMPT_STATE_MAGIC {
                    decode_optional_campaign_hash(&mut cursor)?
                } else {
                    None
                },
            }
        }
        2 => AttemptRuntimeState::Canceled {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
        },
        8 if ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
            || magic == ATTEMPT_STATE_MAGIC_V13)
            || magic == ATTEMPT_STATE_MAGIC_V12
            || magic == ATTEMPT_STATE_MAGIC_V11
            || magic == ATTEMPT_STATE_MAGIC_V10
            || magic == ATTEMPT_STATE_MAGIC_V9
            || magic == ATTEMPT_STATE_MAGIC_V8
            || magic == ATTEMPT_STATE_MAGIC_V7 =>
        {
            AttemptRuntimeState::TerminalFailure {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
            }
        }
        3 if ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
            || magic == ATTEMPT_STATE_MAGIC_V13)
            || magic == ATTEMPT_STATE_MAGIC_V12
            || magic == ATTEMPT_STATE_MAGIC_V11
            || magic == ATTEMPT_STATE_MAGIC_V10
            || magic == ATTEMPT_STATE_MAGIC_V9
            || magic == ATTEMPT_STATE_MAGIC_V8
            || magic == ATTEMPT_STATE_MAGIC_V7
            || magic == ATTEMPT_STATE_MAGIC_V6
            || magic == ATTEMPT_STATE_MAGIC_V5
            || magic == ATTEMPT_STATE_MAGIC_V4
            || magic == ATTEMPT_STATE_MAGIC_V3
            || magic == ATTEMPT_STATE_MAGIC_V2 =>
        {
            AttemptRuntimeState::Publishing {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
                observation: parse_typed(cursor.bytes()?, ObservationId::parse)?,
                finding_candidate: decode_optional_finding_candidate(&mut cursor, magic)?,
                finding_replay_captures: if (magic == ATTEMPT_STATE_MAGIC
                    || magic == ATTEMPT_STATE_MAGIC_V14)
                    || magic == ATTEMPT_STATE_MAGIC_V13
                {
                    decode_optional_finding_replay_captures(&mut cursor)?
                } else {
                    None
                },
                finding_exact_retention_roots: if magic == ATTEMPT_STATE_MAGIC
                    || magic == ATTEMPT_STATE_MAGIC_V14
                {
                    decode_finding_exact_retention_roots(&mut cursor)?
                } else {
                    [None; MAX_PUBLISHING_FINDING_EXACT_ROOTS]
                },
                prepared_result_digest: if magic == ATTEMPT_STATE_MAGIC
                    || magic == ATTEMPT_STATE_MAGIC_V14
                {
                    decode_optional_campaign_hash(&mut cursor)?
                } else {
                    None
                },
            }
        }
        4 if (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
            || magic == ATTEMPT_STATE_MAGIC_V13)
            || magic == ATTEMPT_STATE_MAGIC_V12)
            || magic == ATTEMPT_STATE_MAGIC_V11
            || magic == ATTEMPT_STATE_MAGIC_V10
            || magic == ATTEMPT_STATE_MAGIC_V9
            || magic == ATTEMPT_STATE_MAGIC_V8
            || magic == ATTEMPT_STATE_MAGIC_V7
            || magic == ATTEMPT_STATE_MAGIC_V6
            || magic == ATTEMPT_STATE_MAGIC_V5
            || magic == ATTEMPT_STATE_MAGIC_V4
            || magic == ATTEMPT_STATE_MAGIC_V3 =>
        {
            AttemptRuntimeState::CheckpointRequested {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
            }
        }
        5 if (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
            || magic == ATTEMPT_STATE_MAGIC_V13)
            || magic == ATTEMPT_STATE_MAGIC_V12)
            || magic == ATTEMPT_STATE_MAGIC_V11
            || magic == ATTEMPT_STATE_MAGIC_V10
            || magic == ATTEMPT_STATE_MAGIC_V9
            || magic == ATTEMPT_STATE_MAGIC_V8
            || magic == ATTEMPT_STATE_MAGIC_V7
            || magic == ATTEMPT_STATE_MAGIC_V6
            || magic == ATTEMPT_STATE_MAGIC_V5
            || magic == ATTEMPT_STATE_MAGIC_V4
            || magic == ATTEMPT_STATE_MAGIC_V3 =>
        {
            AttemptRuntimeState::CheckpointPublishing {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
                checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
            }
        }
        6 if (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
            || magic == ATTEMPT_STATE_MAGIC_V13)
            || magic == ATTEMPT_STATE_MAGIC_V12)
            || magic == ATTEMPT_STATE_MAGIC_V11
            || magic == ATTEMPT_STATE_MAGIC_V10
            || magic == ATTEMPT_STATE_MAGIC_V9
            || magic == ATTEMPT_STATE_MAGIC_V8
            || magic == ATTEMPT_STATE_MAGIC_V7
            || magic == ATTEMPT_STATE_MAGIC_V6
            || magic == ATTEMPT_STATE_MAGIC_V5
            || magic == ATTEMPT_STATE_MAGIC_V4
            || magic == ATTEMPT_STATE_MAGIC_V3 =>
        {
            AttemptRuntimeState::Paused {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
                checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
                promotion_basis: if matches!(
                    magic,
                    ATTEMPT_STATE_MAGIC
                        | ATTEMPT_STATE_MAGIC_V14
                        | ATTEMPT_STATE_MAGIC_V13
                        | ATTEMPT_STATE_MAGIC_V12
                        | ATTEMPT_STATE_MAGIC_V11
                        | ATTEMPT_STATE_MAGIC_V10
                        | ATTEMPT_STATE_MAGIC_V9
                        | ATTEMPT_STATE_MAGIC_V8
                        | ATTEMPT_STATE_MAGIC_V7
                        | ATTEMPT_STATE_MAGIC_V6
                ) {
                    decode_checkpoint_promotion_basis(
                        &mut cursor,
                        (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                            || magic == ATTEMPT_STATE_MAGIC_V13)
                            || magic == ATTEMPT_STATE_MAGIC_V12)
                            || magic == ATTEMPT_STATE_MAGIC_V11
                            || magic == ATTEMPT_STATE_MAGIC_V10,
                        (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                            || magic == ATTEMPT_STATE_MAGIC_V13)
                            || magic == ATTEMPT_STATE_MAGIC_V12)
                            || magic == ATTEMPT_STATE_MAGIC_V11,
                        ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                            || magic == ATTEMPT_STATE_MAGIC_V13)
                            || magic == ATTEMPT_STATE_MAGIC_V12,
                    )?
                } else {
                    None
                },
            }
        }
        7 if (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
            || magic == ATTEMPT_STATE_MAGIC_V13)
            || magic == ATTEMPT_STATE_MAGIC_V12)
            || magic == ATTEMPT_STATE_MAGIC_V11
            || magic == ATTEMPT_STATE_MAGIC_V10
            || magic == ATTEMPT_STATE_MAGIC_V9
            || magic == ATTEMPT_STATE_MAGIC_V8
            || magic == ATTEMPT_STATE_MAGIC_V7
            || magic == ATTEMPT_STATE_MAGIC_V6
            || magic == ATTEMPT_STATE_MAGIC_V5 =>
        {
            AttemptRuntimeState::CheckpointPromoting {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
                source_checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
                promoted_checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
                promotion_basis: if matches!(
                    magic,
                    ATTEMPT_STATE_MAGIC
                        | ATTEMPT_STATE_MAGIC_V14
                        | ATTEMPT_STATE_MAGIC_V13
                        | ATTEMPT_STATE_MAGIC_V12
                        | ATTEMPT_STATE_MAGIC_V11
                        | ATTEMPT_STATE_MAGIC_V10
                        | ATTEMPT_STATE_MAGIC_V9
                        | ATTEMPT_STATE_MAGIC_V8
                        | ATTEMPT_STATE_MAGIC_V7
                        | ATTEMPT_STATE_MAGIC_V6
                ) {
                    decode_checkpoint_promotion_basis(
                        &mut cursor,
                        (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                            || magic == ATTEMPT_STATE_MAGIC_V13)
                            || magic == ATTEMPT_STATE_MAGIC_V12)
                            || magic == ATTEMPT_STATE_MAGIC_V11
                            || magic == ATTEMPT_STATE_MAGIC_V10,
                        (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                            || magic == ATTEMPT_STATE_MAGIC_V13)
                            || magic == ATTEMPT_STATE_MAGIC_V12)
                            || magic == ATTEMPT_STATE_MAGIC_V11,
                        ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                            || magic == ATTEMPT_STATE_MAGIC_V13)
                            || magic == ATTEMPT_STATE_MAGIC_V12,
                    )?
                } else {
                    None
                },
            }
        }
        _ => return Err(corrupt("attempt-state-unknown-tag")),
    };
    let promotion_basis = match state {
        AttemptRuntimeState::Paused {
            promotion_basis, ..
        }
        | AttemptRuntimeState::CheckpointPromoting {
            promotion_basis, ..
        } => promotion_basis,
        AttemptRuntimeState::Running { .. }
        | AttemptRuntimeState::CheckpointRequested { .. }
        | AttemptRuntimeState::CheckpointPublishing { .. }
        | AttemptRuntimeState::Publishing { .. }
        | AttemptRuntimeState::Completed { .. }
        | AttemptRuntimeState::Canceled { .. }
        | AttemptRuntimeState::TerminalFailure { .. } => None,
    };
    if let Some(promotion_basis) = promotion_basis
        && attempt_execution_basis_digest_for_start_mode(
            lineage,
            attempt,
            promotion_basis.resources(),
            promotion_basis.retention(),
            promotion_basis.start_mode(),
        ) != execution_basis
    {
        return Err(corrupt("checkpoint-promotion-execution-basis-mismatch"));
    }
    let key = AttemptExecutionKey::new_scoped(lineage, attempt, scope);
    if !state.validates_for_key(key) {
        return Err(corrupt("attempt-state-does-not-match-execution-scope"));
    }
    cursor.finish()?;
    Ok((key, state))
}

pub(super) fn encode_optional_finding_candidate(
    payload: &mut Vec<u8>,
    candidate: Option<FindingCandidateBundleId>,
) {
    match candidate {
        Some(candidate) => {
            payload.push(1);
            push_bytes(payload, candidate.to_text().as_bytes());
        }
        None => payload.push(0),
    }
}

pub(super) fn encode_optional_finding_replay_captures(
    payload: &mut Vec<u8>,
    captures: Option<FindingReplayCaptureSet>,
) {
    match captures {
        Some(captures) => {
            payload.push(1);
            push_bytes(payload, &captures.canonical_bytes());
        }
        None => payload.push(0),
    }
}

pub(super) fn decode_optional_finding_replay_captures(
    cursor: &mut RecordCursor<'_>,
) -> Result<Option<FindingReplayCaptureSet>, AssignmentLedgerError> {
    match cursor.byte()? {
        0 => Ok(None),
        1 => FindingReplayCaptureSet::from_canonical_bytes(cursor.bytes()?)
            .map(Some)
            .map_err(Into::into),
        _ => Err(corrupt("attempt-state-finding-replay-captures-option-tag")),
    }
}

pub(super) fn encode_finding_exact_retention_roots(
    payload: &mut Vec<u8>,
    roots: [Option<ExactCheckpointId>; MAX_PUBLISHING_FINDING_EXACT_ROOTS],
) {
    for root in roots {
        match root {
            Some(root) => {
                payload.push(1);
                push_bytes(payload, root.to_text().as_bytes());
            }
            None => payload.push(0),
        }
    }
}

pub(super) fn encode_optional_campaign_hash(payload: &mut Vec<u8>, digest: Option<CampaignHash>) {
    match digest {
        Some(digest) => {
            payload.push(1);
            payload.extend_from_slice(&digest.as_bytes());
        }
        None => payload.push(0),
    }
}

pub(super) fn decode_optional_campaign_hash(
    cursor: &mut RecordCursor<'_>,
) -> Result<Option<CampaignHash>, AssignmentLedgerError> {
    match cursor.byte()? {
        0 => Ok(None),
        1 => {
            let bytes = cursor.fixed::<32>()?;
            Ok(Some(CampaignHash::from_bytes(bytes)))
        }
        _ => Err(corrupt("attempt-state-campaign-hash-option-tag")),
    }
}

pub(super) fn decode_finding_exact_retention_roots(
    cursor: &mut RecordCursor<'_>,
) -> Result<[Option<ExactCheckpointId>; MAX_PUBLISHING_FINDING_EXACT_ROOTS], AssignmentLedgerError>
{
    let mut roots = [None; MAX_PUBLISHING_FINDING_EXACT_ROOTS];
    for root in &mut roots {
        *root = match cursor.byte()? {
            0 => None,
            1 => Some(parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?),
            _ => return Err(corrupt("attempt-state-finding-exact-root-option-tag")),
        };
    }
    Ok(roots)
}

pub(super) fn decode_optional_finding_candidate(
    cursor: &mut RecordCursor<'_>,
    magic: &[u8],
) -> Result<Option<FindingCandidateBundleId>, AssignmentLedgerError> {
    if magic != ATTEMPT_STATE_MAGIC
        && magic != ATTEMPT_STATE_MAGIC_V14
        && magic != ATTEMPT_STATE_MAGIC_V13
        && magic != ATTEMPT_STATE_MAGIC_V12
        && magic != ATTEMPT_STATE_MAGIC_V11
        && magic != ATTEMPT_STATE_MAGIC_V10
        && magic != ATTEMPT_STATE_MAGIC_V9
        && magic != ATTEMPT_STATE_MAGIC_V8
    {
        return Ok(None);
    }
    match cursor.byte()? {
        0 => Ok(None),
        1 => parse_typed(cursor.bytes()?, FindingCandidateBundleId::parse).map(Some),
        _ => Err(corrupt("attempt-state-finding-candidate-option-tag")),
    }
}

pub(super) fn encode_checkpoint_promotion_basis(
    payload: &mut Vec<u8>,
    basis: Option<CheckpointPromotionExecutionBasis>,
) {
    let Some(basis) = basis else {
        payload.push(0);
        return;
    };
    payload.push(1);
    let resources = basis.resources();
    payload.extend_from_slice(&resources.maximum_vcpus().to_be_bytes());
    payload.extend_from_slice(&resources.maximum_resident_bytes().to_be_bytes());
    payload.extend_from_slice(&resources.maximum_disk_bytes().to_be_bytes());
    payload.extend_from_slice(&resources.maximum_execution_quanta().to_be_bytes());
    payload.push(match basis.retention() {
        ExecutionRetentionIntent::Discard => 0,
        ExecutionRetentionIntent::RetainOnFailure => 1,
        ExecutionRetentionIntent::RetainAlways => 2,
    });
    match basis.start_mode() {
        AttemptStartMode::Execute => payload.push(0),
        AttemptStartMode::CaptureMaterializedStart { configuration } => {
            payload.push(1);
            push_bytes(payload, configuration.to_text().as_bytes());
        }
        AttemptStartMode::SavepointCapture {
            request,
            configuration,
        } => {
            payload.push(2);
            push_bytes(payload, request.to_text().as_bytes());
            push_bytes(payload, configuration.to_text().as_bytes());
        }
        AttemptStartMode::SelectedSavepoint {
            snapshot,
            selection,
            request,
        } => {
            payload.push(3);
            push_bytes(payload, snapshot.to_text().as_bytes());
            push_bytes(payload, selection.to_text().as_bytes());
            push_bytes(payload, request.to_text().as_bytes());
        }
    }
}

pub(super) fn decode_checkpoint_promotion_basis(
    cursor: &mut RecordCursor<'_>,
    has_start_mode: bool,
    has_savepoint_capture: bool,
    has_selected_savepoint: bool,
) -> Result<Option<CheckpointPromotionExecutionBasis>, AssignmentLedgerError> {
    match cursor.byte()? {
        0 => Ok(None),
        1 => {
            let resources = AttemptResourceLimits::new(
                u32::from_be_bytes(cursor.fixed()?),
                u64::from_be_bytes(cursor.fixed()?),
                u64::from_be_bytes(cursor.fixed()?),
                u64::from_be_bytes(cursor.fixed()?),
            )?;
            let retention = match cursor.byte()? {
                0 => ExecutionRetentionIntent::Discard,
                1 => ExecutionRetentionIntent::RetainOnFailure,
                2 => ExecutionRetentionIntent::RetainAlways,
                _ => return Err(corrupt("checkpoint-promotion-retention-tag")),
            };
            let start_mode = if has_start_mode {
                match cursor.byte()? {
                    0 => AttemptStartMode::Execute,
                    1 => AttemptStartMode::CaptureMaterializedStart {
                        configuration: parse_typed(
                            cursor.bytes()?,
                            ConfigurationArtifactId::parse,
                        )?,
                    },
                    2 if has_savepoint_capture => AttemptStartMode::SavepointCapture {
                        request: parse_typed(cursor.bytes()?, CampaignFactId::parse)?,
                        configuration: parse_typed(
                            cursor.bytes()?,
                            ConfigurationArtifactId::parse,
                        )?,
                    },
                    3 if has_selected_savepoint => AttemptStartMode::SelectedSavepoint {
                        snapshot: parse_typed(cursor.bytes()?, CampaignSnapshotId::parse)?,
                        selection: parse_typed(cursor.bytes()?, CampaignFactId::parse)?,
                        request: parse_typed(cursor.bytes()?, CampaignFactId::parse)?,
                    },
                    _ => return Err(corrupt("checkpoint-promotion-start-mode-tag")),
                }
            } else {
                AttemptStartMode::Execute
            };
            Ok(Some(CheckpointPromotionExecutionBasis::new_for_start_mode(
                resources, retention, start_mode,
            )))
        }
        _ => Err(corrupt("checkpoint-promotion-basis-tag")),
    }
}

pub(super) fn encode_attempt_origin(payload: &mut Vec<u8>, origin: AttemptExecutionOrigin) {
    match origin {
        AttemptExecutionOrigin::Initial => payload.push(0),
        AttemptExecutionOrigin::ExactCheckpoint {
            assignment,
            request_digest,
            prior_execution,
            checkpoint,
        } => {
            payload.push(1);
            payload.extend_from_slice(&assignment.as_bytes());
            payload.extend_from_slice(&request_digest.as_bytes());
            payload.extend_from_slice(&prior_execution.as_bytes());
            push_bytes(payload, checkpoint.to_text().as_bytes());
        }
        AttemptExecutionOrigin::SelectedSavepoint {
            certificate,
            request,
            source_attempt,
            source_execution,
            source_checkpoint,
            resume,
        } => {
            payload.push(2);
            push_bytes(payload, certificate.to_text().as_bytes());
            push_bytes(payload, request.to_text().as_bytes());
            push_bytes(payload, source_attempt.to_text().as_bytes());
            payload.extend_from_slice(&source_execution.as_bytes());
            push_bytes(payload, source_checkpoint.to_text().as_bytes());
            match resume {
                Some(resume) => {
                    payload.push(1);
                    payload.extend_from_slice(&resume.assignment.as_bytes());
                    payload.extend_from_slice(&resume.request_digest.as_bytes());
                    payload.extend_from_slice(&resume.prior_execution.as_bytes());
                    push_bytes(payload, resume.checkpoint.to_text().as_bytes());
                }
                None => payload.push(0),
            }
        }
    }
}

pub(super) fn decode_attempt_origin(
    cursor: &mut RecordCursor<'_>,
    has_selected_savepoint: bool,
) -> Result<AttemptExecutionOrigin, AssignmentLedgerError> {
    match cursor.byte()? {
        0 => Ok(AttemptExecutionOrigin::Initial),
        1 => Ok(AttemptExecutionOrigin::ExactCheckpoint {
            assignment: AssignmentId::from_bytes(cursor.fixed()?)?,
            request_digest: CampaignHash::from_bytes(cursor.fixed()?),
            prior_execution: ExecutionId::from_bytes(cursor.fixed()?)?,
            checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
        }),
        2 if has_selected_savepoint => {
            let certificate = parse_typed(cursor.bytes()?, CampaignFactId::parse)?;
            let request = parse_typed(cursor.bytes()?, CampaignFactId::parse)?;
            let source_attempt = parse_typed(cursor.bytes()?, AttemptId::parse)?;
            let source_execution = ExecutionId::from_bytes(cursor.fixed()?)?;
            let source_checkpoint = parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?;
            let resume = match cursor.byte()? {
                0 => None,
                1 => Some(ExactCheckpointResumeBasis {
                    assignment: AssignmentId::from_bytes(cursor.fixed()?)?,
                    request_digest: CampaignHash::from_bytes(cursor.fixed()?),
                    prior_execution: ExecutionId::from_bytes(cursor.fixed()?)?,
                    checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
                }),
                _ => return Err(corrupt("attempt-state-selected-resume-option-tag")),
            };
            Ok(AttemptExecutionOrigin::SelectedSavepoint {
                certificate,
                request,
                source_attempt,
                source_execution,
                source_checkpoint,
                resume,
            })
        }
        _ => Err(corrupt("attempt-state-origin-unknown-tag")),
    }
}

pub(super) fn parse_typed<T>(
    bytes: &[u8],
    parse: impl FnOnce(&str) -> Result<T, CampaignCodecError>,
) -> Result<T, AssignmentLedgerError> {
    if bytes.len() > MAX_TYPED_ID_BYTES {
        return Err(corrupt("typed-id-too-large"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| corrupt("typed-id-not-utf8"))?;
    parse(text).map_err(Into::into)
}

pub(super) fn load_or_create_retention_state(
    root: &Path,
) -> Result<AssignmentRetentionState, AssignmentLedgerError> {
    let path = root.join(RETENTION_STATE_FILE);
    if let Some(bytes) =
        read_optional_with_limit(&path, MAX_RETENTION_STATE_BYTES, "retention-state-size")?
    {
        return decode_retention_state(&bytes);
    }

    let mut instance = [0_u8; 32];
    let random_path = Path::new("/dev/urandom");
    File::open(random_path)
        .and_then(|mut source| source.read_exact(&mut instance))
        .map_err(|source| io_error("read-retention-instance", random_path, source))?;
    let state = AssignmentRetentionState {
        instance,
        generation: 1,
    };
    persist_retention_state(root, state)?;
    Ok(state)
}

pub(super) fn persist_retention_state(
    root: &Path,
    state: AssignmentRetentionState,
) -> Result<(), AssignmentLedgerError> {
    replace_mutable(
        &root.join(RETENTION_STATE_FILE),
        &encode_retention_state(state),
    )
}

pub(super) fn encode_retention_state(state: AssignmentRetentionState) -> Vec<u8> {
    let mut payload = Vec::with_capacity(RETENTION_STATE_MAGIC.len() + 32 + size_of::<u64>() + 32);
    payload.extend_from_slice(RETENTION_STATE_MAGIC);
    payload.extend_from_slice(&state.instance);
    payload.extend_from_slice(&state.generation.to_le_bytes());
    seal(payload, RETENTION_STATE_CHECKSUM_DOMAIN)
}

pub(super) fn decode_retention_state(
    bytes: &[u8],
) -> Result<AssignmentRetentionState, AssignmentLedgerError> {
    if bytes.len() as u64 > MAX_RETENTION_STATE_BYTES {
        return Err(corrupt("retention-state-size"));
    }
    let payload = open_sealed(bytes, RETENTION_STATE_CHECKSUM_DOMAIN)?;
    let mut cursor = RecordCursor::new(payload);
    cursor.require(RETENTION_STATE_MAGIC)?;
    let instance = cursor.fixed()?;
    let generation = u64::from_le_bytes(cursor.fixed()?);
    cursor.finish()?;
    if generation == 0 {
        return Err(corrupt("retention-state-zero-generation"));
    }
    Ok(AssignmentRetentionState {
        instance,
        generation,
    })
}

pub(super) fn seal(mut payload: Vec<u8>, domain: &str) -> Vec<u8> {
    let checksum = CampaignHash::derive(domain, &payload);
    payload.extend_from_slice(&checksum.as_bytes());
    payload
}

pub(super) fn open_sealed<'a>(
    bytes: &'a [u8],
    domain: &str,
) -> Result<&'a [u8], AssignmentLedgerError> {
    if bytes.len() < 32 || bytes.len() as u64 > MAX_LEDGER_RECORD_BYTES {
        return Err(corrupt("record-size"));
    }
    let payload_length = bytes.len() - 32;
    let (payload, checksum) = bytes.split_at(payload_length);
    if checksum != CampaignHash::derive(domain, payload).as_bytes() {
        return Err(corrupt("record-checksum"));
    }
    Ok(payload)
}

pub(super) fn push_bytes(target: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
}

pub(super) struct RecordCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> RecordCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AssignmentLedgerError> {
        if self.remaining.len() < length {
            return Err(corrupt("record-truncated"));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], AssignmentLedgerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| corrupt("record-fixed-width"))
    }

    fn byte(&mut self) -> Result<u8, AssignmentLedgerError> {
        Ok(self.fixed::<1>()?[0])
    }

    fn bytes(&mut self) -> Result<&'a [u8], AssignmentLedgerError> {
        let length = u32::from_be_bytes(self.fixed()?) as usize;
        self.take(length)
    }

    fn require(&mut self, expected: &[u8]) -> Result<(), AssignmentLedgerError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(corrupt("record-magic"))
        }
    }

    fn finish(self) -> Result<(), AssignmentLedgerError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(corrupt("record-trailing-bytes"))
        }
    }
}

pub(super) fn read_optional_bounded(path: &Path) -> Result<Option<Vec<u8>>, AssignmentLedgerError> {
    read_optional_with_limit(path, MAX_LEDGER_RECORD_BYTES, "record-size")
}

pub(super) fn read_optional_with_limit(
    path: &Path,
    limit: u64,
    size_reason: &'static str,
) -> Result<Option<Vec<u8>>, AssignmentLedgerError> {
    let descriptor = match open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(source) if source == rustix::io::Errno::NOENT => return Ok(None),
        Err(source) => {
            return Err(io_error(
                "open-record",
                path,
                std::io::Error::from_raw_os_error(source.raw_os_error()),
            ));
        }
    };
    let file = File::from(descriptor);
    if !file
        .metadata()
        .map_err(|source| io_error("inspect-record", path, source))?
        .is_file()
    {
        return Err(corrupt("record-not-regular-file"));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read-record", path, source))?;
    if bytes.len() as u64 > limit {
        return Err(corrupt(size_reason));
    }
    Ok(Some(bytes))
}

pub(super) fn publish_immutable(path: &Path, bytes: &[u8]) -> Result<bool, AssignmentLedgerError> {
    let directory = record_directory(path)?;
    let (staging_path, mut staging) = create_staging(directory)?;
    staging
        .write_all(bytes)
        .and_then(|()| staging.sync_all())
        .map_err(|source| io_error("write-assignment-staging", &staging_path, source))?;
    let published = match fs::hard_link(&staging_path, path) {
        Ok(()) => true,
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(source) => return Err(io_error("publish-assignment", path, source)),
    };
    fs::remove_file(&staging_path)
        .map_err(|source| io_error("remove-assignment-staging", &staging_path, source))?;
    sync_directory(directory)?;
    Ok(published)
}

pub(super) fn replace_mutable(path: &Path, bytes: &[u8]) -> Result<(), AssignmentLedgerError> {
    let directory = record_directory(path)?;
    let (staging_path, mut staging) = create_staging(directory)?;
    staging
        .write_all(bytes)
        .and_then(|()| staging.sync_all())
        .map_err(|source| io_error("write-attempt-staging", &staging_path, source))?;
    fs::rename(&staging_path, path)
        .map_err(|source| io_error("publish-attempt-state", path, source))?;
    sync_directory(directory)
}

pub(super) fn remove_mutable(path: &Path) -> Result<(), AssignmentLedgerError> {
    match fs::remove_file(path) {
        Ok(()) => {
            let directory = path
                .parent()
                .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
            sync_directory(directory)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove-attempt-state", path, source)),
    }
}

pub(super) fn record_directory(path: &Path) -> Result<&Path, AssignmentLedgerError> {
    let directory = path
        .parent()
        .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
    create_directory_durable(directory)?;
    Ok(directory)
}

pub(super) fn sync_record_parent(path: &Path) -> Result<(), AssignmentLedgerError> {
    let directory = path
        .parent()
        .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
    sync_directory(directory)
}

pub(super) fn sync_record_parent_if_present(path: &Path) -> Result<(), AssignmentLedgerError> {
    let directory = path
        .parent()
        .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
    if directory.is_dir() {
        sync_directory(directory)
    } else {
        Ok(())
    }
}

pub(super) fn create_staging(directory: &Path) -> Result<(PathBuf, File), AssignmentLedgerError> {
    loop {
        let ordinal = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(".staging-{}-{ordinal}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error("create-staging", &path, source)),
        }
    }
}

pub(super) fn create_directory_durable(path: &Path) -> Result<(), AssignmentLedgerError> {
    if path.as_os_str().is_empty() || path == Path::new(".") {
        return Ok(());
    }
    if path.is_dir() {
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| corrupt("directory-has-no-parent"))?;
    if parent != path {
        create_directory_durable(parent)?;
    }
    match fs::create_dir(path) {
        Ok(()) => sync_directory(parent),
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {
            Ok(())
        }
        Err(source) => Err(io_error("create-directory", path, source)),
    }
}

pub(super) fn require_existing_directory(path: &Path) -> Result<(), AssignmentLedgerError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("inspect-directory", path, source))?;
    if !metadata.file_type().is_dir() {
        return Err(corrupt("existing-root-not-directory"));
    }
    Ok(())
}

pub(super) fn open_existing_writer_lock(path: &Path) -> Result<File, AssignmentLedgerError> {
    let file = File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|source| {
            io_error(
                "open-writer-lock",
                path,
                std::io::Error::from_raw_os_error(source.raw_os_error()),
            )
        })?,
    );
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect-writer-lock", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(corrupt("writer-lock-not-regular-file"));
    }
    Ok(file)
}

pub(super) fn sync_directory(path: &Path) -> Result<(), AssignmentLedgerError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync-directory", path, source))
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(super) fn corrupt(reason: &'static str) -> AssignmentLedgerError {
    AssignmentLedgerError::Corrupt { reason }
}

pub(super) fn io_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> AssignmentLedgerError {
    AssignmentLedgerError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
