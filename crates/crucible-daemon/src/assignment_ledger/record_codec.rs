//! Canonical encoding and decoding for assignment-ledger records.

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
            ..
        } => {
            payload.push(1);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
            push_bytes(&mut payload, observation.to_text().as_bytes());
            encode_optional_finding_candidate(&mut payload, finding_candidate.candidate());
            payload.push(u8::from(finding_candidate.is_acknowledged()));
        }
        AttemptRuntimeState::Publishing {
            daemon_epoch,
            execution,
            observation,
            finding_candidate,
            ..
        } => {
            payload.push(3);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
            push_bytes(&mut payload, observation.to_text().as_bytes());
            encode_optional_finding_candidate(&mut payload, finding_candidate);
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
    let payload = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN)?;
    let magic = ATTEMPT_STATE_MAGIC;
    let mut cursor = RecordCursor::new(payload);
    cursor.require(magic)?;
    let lineage = parse_typed(cursor.bytes()?, CampaignLineageId::parse)?;
    let attempt = parse_typed(cursor.bytes()?, AttemptId::parse)?;
    let scope = AttemptExecutionScope::from_canonical_bytes(cursor.bytes()?)?;
    let execution_basis = CampaignHash::from_bytes(cursor.fixed()?);
    let origin = decode_attempt_origin(&mut cursor)?;
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
            let finding_candidate = decode_optional_finding_candidate(&mut cursor)?;
            let finding_candidate_acknowledged = match cursor.byte()? {
                0 => false,
                1 => true,
                _ => return Err(corrupt("attempt-state-finding-candidate-acknowledged-tag")),
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
            }
        }
        2 => AttemptRuntimeState::Canceled {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
        },
        8 => AttemptRuntimeState::TerminalFailure {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
        },
        3 => AttemptRuntimeState::Publishing {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
            observation: parse_typed(cursor.bytes()?, ObservationId::parse)?,
            finding_candidate: decode_optional_finding_candidate(&mut cursor)?,
        },
        4 => AttemptRuntimeState::CheckpointRequested {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
        },
        5 => AttemptRuntimeState::CheckpointPublishing {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
            checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
        },
        6 => AttemptRuntimeState::Paused {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
            checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
            promotion_basis: decode_checkpoint_promotion_basis(&mut cursor)?,
        },
        7 => AttemptRuntimeState::CheckpointPromoting {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
            source_checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
            promoted_checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
            promotion_basis: decode_checkpoint_promotion_basis(&mut cursor)?,
        },
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
            promotion_basis.retention_policy(),
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

fn encode_optional_finding_candidate(
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

fn decode_optional_finding_candidate(
    cursor: &mut RecordCursor<'_>,
) -> Result<Option<FindingCandidateBundleId>, AssignmentLedgerError> {
    match cursor.byte()? {
        0 => Ok(None),
        1 => parse_typed(cursor.bytes()?, FindingCandidateBundleId::parse).map(Some),
        _ => Err(corrupt("attempt-state-finding-candidate-option-tag")),
    }
}

fn encode_checkpoint_promotion_basis(
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
    match basis.retention_policy() {
        AttemptRetentionPolicyDisposition::Disabled => payload.push(0),
        AttemptRetentionPolicyDisposition::Required(policy) => {
            payload.push(1);
            push_bytes(payload, policy.snapshot().to_text().as_bytes());
            push_bytes(payload, policy.admission().to_text().as_bytes());
            push_bytes(payload, policy.policy().to_text().as_bytes());
        }
    }
}

fn decode_checkpoint_promotion_basis(
    cursor: &mut RecordCursor<'_>,
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
            let start_mode = match cursor.byte()? {
                0 => AttemptStartMode::Execute,
                1 => AttemptStartMode::CaptureMaterializedStart {
                    configuration: parse_typed(cursor.bytes()?, ConfigurationArtifactId::parse)?,
                },
                2 => AttemptStartMode::SavepointCapture {
                    request: parse_typed(cursor.bytes()?, CampaignFactId::parse)?,
                    configuration: parse_typed(cursor.bytes()?, ConfigurationArtifactId::parse)?,
                },
                3 => AttemptStartMode::SelectedSavepoint {
                    snapshot: parse_typed(cursor.bytes()?, CampaignSnapshotId::parse)?,
                    selection: parse_typed(cursor.bytes()?, CampaignFactId::parse)?,
                    request: parse_typed(cursor.bytes()?, CampaignFactId::parse)?,
                },
                _ => return Err(corrupt("checkpoint-promotion-start-mode-tag")),
            };
            let retention_policy = match cursor.byte()? {
                0 => AttemptRetentionPolicyDisposition::Disabled,
                1 => AttemptRetentionPolicyDisposition::Required(AttemptRetentionPolicyBasis::new(
                    parse_typed(cursor.bytes()?, CampaignSnapshotId::parse)?,
                    parse_typed(cursor.bytes()?, AttemptAdmissionId::parse)?,
                    parse_typed(cursor.bytes()?, CampaignPolicyId::parse)?,
                )),
                _ => return Err(corrupt("checkpoint-promotion-retention-policy-tag")),
            };
            Ok(Some(CheckpointPromotionExecutionBasis::new_for_start_mode(
                resources,
                retention,
                start_mode,
                retention_policy,
            )))
        }
        _ => Err(corrupt("checkpoint-promotion-basis-tag")),
    }
}

fn encode_attempt_origin(payload: &mut Vec<u8>, origin: AttemptExecutionOrigin) {
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

fn decode_attempt_origin(
    cursor: &mut RecordCursor<'_>,
) -> Result<AttemptExecutionOrigin, AssignmentLedgerError> {
    match cursor.byte()? {
        0 => Ok(AttemptExecutionOrigin::Initial),
        1 => Ok(AttemptExecutionOrigin::ExactCheckpoint {
            assignment: AssignmentId::from_bytes(cursor.fixed()?)?,
            request_digest: CampaignHash::from_bytes(cursor.fixed()?),
            prior_execution: ExecutionId::from_bytes(cursor.fixed()?)?,
            checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
        }),
        2 => {
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

fn parse_typed<T>(
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
    authority: &crate::anchored_fs::AnchoredDirectory,
    root: &Path,
) -> Result<AssignmentRetentionState, AssignmentLedgerError> {
    let path = root.join(RETENTION_STATE_FILE);
    if let Some(bytes) = read_optional_with_limit(
        authority,
        &path,
        MAX_RETENTION_STATE_BYTES,
        "retention-state-size",
    )? {
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
    persist_retention_state(authority, root, state)?;
    Ok(state)
}

pub(super) fn persist_retention_state(
    authority: &crate::anchored_fs::AnchoredDirectory,
    root: &Path,
    state: AssignmentRetentionState,
) -> Result<(), AssignmentLedgerError> {
    replace_mutable(
        authority,
        &root.join(RETENTION_STATE_FILE),
        &encode_retention_state(state),
    )
}

fn encode_retention_state(state: AssignmentRetentionState) -> Vec<u8> {
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

struct RecordCursor<'a> {
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
