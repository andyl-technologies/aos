//! Canonical fixed-width codec for lifecycle operation snapshots.
//!
//! ```text
//! AOSLIF01 | version:1 | phase:1 | terminal-result:1 | intent:260 |
//! operation-id:16 | caller:16 | project:16 | idempotency:32 | normalized-request:32 |
//! accepted-at:8 | record-revision:8 | forward:4 | compensated:4 |
//! semantic-commit-slot:200 | failure-slot:48 | retry-slot:16 |
//! finished-slot:16 | predecessor-slot:40 | expectation-count:4 |
//! step-count:4 | semantic-fact-length:4 | semantic-method-facts:M |
//! expectations:60*N | steps:35692*N | digest:32
//! intent = method:1 | flags:1 | reserved:6 | primary-id:16 |
//! secondary-id:16 | tertiary-id:16 | environment-generation:8 |
//! desired-resource-fence:72 | runtime-sandbox:16 | active-incarnation:16 |
//! assignment-epoch:8 | namespace-generation:8 |
//! target-generation:8 | target-expectation:68
//! semantic-commit-slot = present:1 | reserved:7 | sequence:8 |
//! resource-kind:1 | reserved:7 | resource-id:16 | expected-generation:8 |
//! expected-document-present:1 | reserved:7 | expected-document:32 |
//! successor-generation:8 | desired-document:32 | CAS-digest:32 |
//! journal-commit:32 | committed-at:8
//! ```
//!
//! Integers are big endian. Optional slots have a presence byte, reserved zero
//! bytes, and fixed zero-filled payload when absent. The final SHA-256 covers a
//! purpose domain and all preceding bytes. Decode validates the exact total
//! length before allocating either collection.

use super::attempt::{
    LifecycleAttemptStateV1, LifecycleEffectAttemptV1, LifecycleEffectDirectionV1,
    MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP,
};
use super::intent::{
    DesiredStateCasV1, DesiredStateFenceV1, LifecycleFailureClassV1, LifecycleFailureV1,
    LifecycleIntentV1, LifecycleResourceV1, LifecycleResumeSourceV1, LifecycleRetryV1,
    LifecycleStepClassV1, LifecycleStepDomainV1, LifecycleStepStateV1, LifecycleTargetFenceV1,
    LifecycleTimeV1, LiveRuntimeFenceV1, ResourceExpectationV1, ResourceExpectedStateV1,
};
use super::model::{
    DesiredStateCasDigestV1, DesiredStateDocumentDigestV1, LifecycleFailureDigestV1,
    LifecycleIdempotencyDigestV1, LifecycleInventoryDigestV1, LifecycleJournalCommitDigestV1,
    LifecycleNormalizedRequestDigestV1, LifecycleOperationV1, LifecyclePhaseV1,
    LifecycleRecordDigestV1, LifecycleResourceStateDigestV1, LifecycleSemanticCommitV1,
    LifecycleStepAdmissionDigestV1, LifecycleStepBodyDigestV1, LifecycleStepPlanDigestV1,
    LifecycleStepRequestDigestV1, LifecycleStepResultDigestV1, LifecycleStepV1,
    LifecycleTerminalResultV1, MAXIMUM_LIFECYCLE_EXPECTATIONS, MAXIMUM_LIFECYCLE_STEPS,
};
use super::projection::LifecycleModelError;
use super::semantic::{
    LifecycleAssignmentCommitFactV1, LifecycleCascadeTombstonePlanV1, LifecycleCommittedResourceV1,
    LifecycleDependencyEdgeV1, LifecycleMethodSemanticCommitV1, LifecycleReadCommitFactV1,
    LifecycleReservationCommitFactV1, LifecycleRetentionAcknowledgementV1,
    LifecycleSemanticCommitFactV1, LifecycleSnapshotManifestDigestV1, LifecycleTransactionIdV1,
};
use super::semantic_format::{decode_semantic_fact, encode_semantic_fact, preflight_semantic_fact};
use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, ExecutionId, IncarnationId, NamespaceGeneration,
    ObjectDigest, OperationId, ResourceId, Revision, SandboxId, SnapshotId, ViewId,
};

const MAGIC: &[u8; 8] = b"AOSLIF01";
const VERSION: u16 = 1;
const INTENT_BYTES: usize = 260;
const FIXED_BODY_BYTES: usize = 740;
const EXPECTATION_BYTES: usize = 60;
const ATTEMPT_BYTES: usize = 276;
const ATTEMPT_SLOTS_PER_STEP: usize = MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP * 2;
const STEP_BYTES: usize = 364 + ATTEMPT_BYTES * ATTEMPT_SLOTS_PER_STEP;
const DIGEST_BYTES: usize = 32;
const MAXIMUM_SEMANTIC_FACT_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_RECORD_BYTES: usize = FIXED_BODY_BYTES
    + MAXIMUM_SEMANTIC_FACT_BYTES
    + MAXIMUM_LIFECYCLE_EXPECTATIONS * EXPECTATION_BYTES
    + MAXIMUM_LIFECYCLE_STEPS * STEP_BYTES
    + DIGEST_BYTES;

/// Encodes one validated lifecycle snapshot in exact v1 form.
///
/// # Errors
///
/// Returns [`LifecycleModelError`] if the exact canonical length exceeds a
/// fixed ceiling, cannot be represented, or checked allocation fails.
pub fn encode_operation_record_v1(
    operation: &LifecycleOperationV1,
) -> Result<Vec<u8>, LifecycleModelError> {
    let semantic_fact = operation
        .method_semantic_commit()
        .map(encode_semantic_fact)
        .transpose()?
        .unwrap_or_default();
    let length = FIXED_BODY_BYTES
        .checked_add(semantic_fact.len())
        .and_then(|total| {
            total.checked_add(
                operation
                    .expectations()
                    .len()
                    .checked_mul(EXPECTATION_BYTES)?,
            )
        })
        .and_then(|total| total.checked_add(operation.steps().len().checked_mul(STEP_BYTES)?))
        .and_then(|total| total.checked_add(DIGEST_BYTES))
        .filter(|total| *total <= MAXIMUM_RECORD_BYTES)
        .ok_or(LifecycleModelError::InvalidModel)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| LifecycleModelError::Allocation)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(operation.phase() as u8);
    bytes.push(operation.terminal_result().map_or(0, |value| value as u8));
    encode_intent(&mut bytes, operation.intent());
    bytes.extend_from_slice(operation.operation_id().as_bytes());
    bytes.extend_from_slice(operation.caller().as_bytes());
    bytes.extend_from_slice(operation.project().as_bytes());
    bytes.extend_from_slice(operation.idempotency().digest().as_bytes());
    bytes.extend_from_slice(operation.normalized_request().digest().as_bytes());
    bytes.extend_from_slice(&operation.accepted_at().get().to_be_bytes());
    bytes.extend_from_slice(&operation.record_revision().get().to_be_bytes());
    bytes.extend_from_slice(&operation.forward_progress().to_be_bytes());
    bytes.extend_from_slice(&operation.compensation_progress().to_be_bytes());
    encode_semantic_commit(&mut bytes, operation.semantic_commit());
    encode_failure(&mut bytes, operation.failure());
    encode_retry(&mut bytes, operation.retry());
    encode_optional_time(&mut bytes, operation.finished_at());
    encode_predecessor(&mut bytes, operation.predecessor_digest());
    push_count(&mut bytes, operation.expectations().len());
    push_count(&mut bytes, operation.steps().len());
    push_count(&mut bytes, semantic_fact.len());
    bytes.extend_from_slice(&semantic_fact);
    for expectation in operation.expectations() {
        encode_expectation(&mut bytes, expectation);
    }
    for step in operation.steps() {
        encode_step(&mut bytes, step);
    }
    let digest = hash_record(&bytes);
    bytes.extend_from_slice(digest.digest().as_bytes());
    debug_assert_eq!(bytes.len(), length);
    if bytes.len() != length {
        return Err(LifecycleModelError::InvalidModel);
    }
    Ok(bytes)
}

/// Decodes one exact, bounded lifecycle snapshot.
///
/// # Errors
///
/// Returns [`LifecycleModelError`] for malformed bytes, count/length overflow,
/// allocation failure, non-canonical model state, or a digest mismatch.
pub fn decode_operation_record_v1(
    encoded: &[u8],
) -> Result<LifecycleOperationV1, LifecycleModelError> {
    if encoded.len() < FIXED_BODY_BYTES + DIGEST_BYTES || encoded.len() > MAXIMUM_RECORD_BYTES {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let (body, stored_digest) = encoded.split_at(encoded.len() - DIGEST_BYTES);
    if hash_record(body).digest().as_bytes() != stored_digest {
        return Err(LifecycleModelError::CorruptEncoding);
    }

    // Counts live at the end of the fixed prefix. Preflight the exact length
    // before any collection allocation or variable-region parsing.
    let counts = body
        .get(FIXED_BODY_BYTES - 12..FIXED_BODY_BYTES)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    let expectation_count = usize_from_u32(&counts[..4])?;
    let step_count = usize_from_u32(&counts[4..8])?;
    let semantic_fact_length = usize_from_u32(&counts[8..])?;
    if expectation_count == 0
        || expectation_count > MAXIMUM_LIFECYCLE_EXPECTATIONS
        || step_count == 0
        || step_count > MAXIMUM_LIFECYCLE_STEPS
    {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let expected_length = FIXED_BODY_BYTES
        .checked_add(semantic_fact_length)
        .checked_add(
            expectation_count
                .checked_mul(EXPECTATION_BYTES)
                .ok_or(LifecycleModelError::CorruptEncoding)?,
        )
        .and_then(|value| value.checked_add(step_count.checked_mul(STEP_BYTES)?))
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    if body.len() != expected_length {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let semantic_fact_region = body
        .get(FIXED_BODY_BYTES..FIXED_BODY_BYTES + semantic_fact_length)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    preflight_semantic_fact(semantic_fact_region)?;
    let expectation_region = expectation_count
        .checked_mul(EXPECTATION_BYTES)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    let step_region_offset = FIXED_BODY_BYTES
        .checked_add(semantic_fact_length)
        .ok_or(LifecycleModelError::CorruptEncoding)?
        .checked_add(expectation_region)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    for index in 0..step_count {
        let offset = step_region_offset
            .checked_add(
                index
                    .checked_mul(STEP_BYTES)
                    .ok_or(LifecycleModelError::CorruptEncoding)?,
            )
            .ok_or(LifecycleModelError::CorruptEncoding)?;
        let header = body
            .get(offset..offset + 16)
            .ok_or(LifecycleModelError::CorruptEncoding)?;
        if usize_from_u32(&header[8..12])? > MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP
            || usize_from_u32(&header[12..16])? > MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP
        {
            return Err(LifecycleModelError::CorruptEncoding);
        }
    }

    let mut bytes = body;
    if take::<8>(&mut bytes)? != *MAGIC || u16::from_be_bytes(take(&mut bytes)?) != VERSION {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let phase = decode_phase(take::<1>(&mut bytes)?[0])?;
    let terminal_result = decode_terminal(take::<1>(&mut bytes)?[0])?;
    let intent = decode_intent(take_slice(&mut bytes, INTENT_BYTES)?)?;
    let operation_id = OperationId::from_bytes(take(&mut bytes)?);
    if operation_id.as_bytes() == &[0; 16] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let caller = aos_sandbox_core::PrincipalId::from_bytes(take(&mut bytes)?);
    let project = aos_sandbox_core::ProjectId::from_bytes(take(&mut bytes)?);
    let idempotency =
        LifecycleIdempotencyDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut bytes)?))?;
    let normalized_request = LifecycleNormalizedRequestDigestV1::from_stored(
        ObjectDigest::from_bytes(take(&mut bytes)?),
    )?;
    if normalized_request != normalized_request_digest_v1(&intent) {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let accepted_at = LifecycleTimeV1::from_stored(u64::from_be_bytes(take(&mut bytes)?))?;
    let record_revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let forward_progress = u32::from_be_bytes(take(&mut bytes)?);
    let compensation_progress = u32::from_be_bytes(take(&mut bytes)?);
    let semantic_witness = decode_semantic_commit(&mut bytes)?;
    let failure = decode_failure(&mut bytes)?;
    let retry = decode_retry(&mut bytes)?;
    let finished_at = decode_optional_time(&mut bytes)?;
    let predecessor_digest = decode_predecessor(&mut bytes)?;
    if usize_from_u32(&take::<4>(&mut bytes)?)? != expectation_count
        || usize_from_u32(&take::<4>(&mut bytes)?)? != step_count
        || usize_from_u32(&take::<4>(&mut bytes)?)? != semantic_fact_length
    {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let semantic_fact = decode_semantic_fact(
        take_slice(&mut bytes, semantic_fact_length)?,
        semantic_witness,
    )?;

    let mut expectations = Vec::new();
    expectations
        .try_reserve_exact(expectation_count)
        .map_err(|_| LifecycleModelError::Allocation)?;
    for _ in 0..expectation_count {
        expectations.push(decode_expectation(&mut bytes)?);
    }
    let mut steps = Vec::new();
    steps
        .try_reserve_exact(step_count)
        .map_err(|_| LifecycleModelError::Allocation)?;
    for _ in 0..step_count {
        steps.push(decode_step(&mut bytes)?);
    }
    if !bytes.is_empty() {
        return Err(LifecycleModelError::CorruptEncoding);
    }

    let semantic_commit = match (semantic_witness, semantic_fact) {
        (Some(witness), Some((facts, evidence))) => Some(
            LifecycleMethodSemanticCommitV1::new(witness, facts, evidence, &intent, &expectations)
                .map_err(|_| LifecycleModelError::CorruptEncoding)?,
        ),
        (None, None) => None,
        _ => return Err(LifecycleModelError::CorruptEncoding),
    };
    LifecycleOperationV1::new(
        operation_id,
        caller,
        project,
        idempotency,
        intent,
        accepted_at,
        record_revision,
        expectations,
        steps,
        phase,
        forward_progress,
        compensation_progress,
        semantic_commit,
        failure,
        retry,
        terminal_result,
        finished_at,
        predecessor_digest,
    )
    .map_err(|_| LifecycleModelError::CorruptEncoding)
}

pub(super) fn record_digest(
    encoded: &[u8],
) -> Result<LifecycleRecordDigestV1, LifecycleModelError> {
    let body_length = encoded
        .len()
        .checked_sub(DIGEST_BYTES)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    Ok(hash_record(&encoded[..body_length]))
}

fn encode_intent(bytes: &mut Vec<u8>, intent: &LifecycleIntentV1) {
    let mut slot = [0_u8; INTENT_BYTES];
    slot[0] = intent.method() as u8;
    let (primary, secondary, tertiary, desired, environment, live) = match intent {
        LifecycleIntentV1::Create { sandbox } => (sandbox.as_bytes(), None, None, None, None, None),
        LifecycleIntentV1::Fork { source, target } => (
            source.as_bytes(),
            Some(target.as_bytes()),
            None,
            None,
            None,
            None,
        ),
        LifecycleIntentV1::Restore { snapshot, sandbox } => (
            snapshot.as_bytes(),
            Some(sandbox.as_bytes()),
            None,
            None,
            None,
            None,
        ),
        LifecycleIntentV1::UpdateEnvironment {
            sandbox,
            environment_generation,
            fence,
        } => (
            sandbox.as_bytes(),
            None,
            None,
            Some(*fence),
            Some(*environment_generation),
            None,
        ),
        LifecycleIntentV1::UpdatePolicy { sandbox, fence } => {
            (sandbox.as_bytes(), None, None, Some(*fence), None, None)
        }
        LifecycleIntentV1::Start { sandbox, fence } => {
            (sandbox.as_bytes(), None, None, Some(*fence), None, None)
        }
        LifecycleIntentV1::Stop { sandbox, fence }
        | LifecycleIntentV1::SuspendMemory { sandbox, fence } => (
            sandbox.as_bytes(),
            None,
            None,
            Some(fence.desired()),
            None,
            Some(*fence),
        ),
        LifecycleIntentV1::Resume { sandbox, source } => match source {
            LifecycleResumeSourceV1::Memory { fence } => (
                sandbox.as_bytes(),
                None,
                None,
                Some(fence.desired()),
                None,
                Some(*fence),
            ),
            LifecycleResumeSourceV1::Hibernated { snapshot, fence } => (
                sandbox.as_bytes(),
                Some(snapshot.as_bytes()),
                None,
                Some(*fence),
                None,
                None,
            ),
        },
        LifecycleIntentV1::Hibernate {
            sandbox,
            snapshot,
            fence,
            ..
        }
        | LifecycleIntentV1::Snapshot {
            sandbox,
            snapshot,
            fence,
            ..
        } => (
            sandbox.as_bytes(),
            Some(snapshot.as_bytes()),
            None,
            Some(fence.desired()),
            None,
            Some(*fence),
        ),
        LifecycleIntentV1::DeleteSandbox { sandbox, fence } => {
            (sandbox.as_bytes(), None, None, Some(*fence), None, None)
        }
        LifecycleIntentV1::DeleteSnapshot { snapshot, fence } => {
            (snapshot.as_bytes(), None, None, Some(*fence), None, None)
        }
        LifecycleIntentV1::CreateExecution {
            sandbox,
            execution,
            fence,
            ..
        } => (
            sandbox.as_bytes(),
            Some(execution.as_bytes()),
            None,
            Some(fence.desired()),
            None,
            Some(*fence),
        ),
        LifecycleIntentV1::CancelExecution {
            execution, fence, ..
        } => (
            execution.as_bytes(),
            None,
            None,
            Some(fence.desired()),
            None,
            Some(*fence),
        ),
        LifecycleIntentV1::CreateView { view } => (view.as_bytes(), None, None, None, None, None),
        LifecycleIntentV1::AttachView {
            sandbox,
            view,
            attachment,
            fence,
            ..
        } => (
            sandbox.as_bytes(),
            Some(view.as_bytes()),
            Some(attachment.as_bytes()),
            Some(fence.desired()),
            None,
            Some(*fence),
        ),
        LifecycleIntentV1::ReplaceAttachment {
            attachment,
            view,
            fence,
            ..
        } => (
            attachment.as_bytes(),
            Some(view.as_bytes()),
            None,
            Some(fence.desired()),
            None,
            Some(*fence),
        ),
        LifecycleIntentV1::DetachView {
            attachment, fence, ..
        } => (
            attachment.as_bytes(),
            None,
            None,
            Some(fence.desired()),
            None,
            Some(*fence),
        ),
        LifecycleIntentV1::ReleaseView { view, fence } => {
            (view.as_bytes(), None, None, Some(*fence), None, None)
        }
        LifecycleIntentV1::AttenuateCapability { parent, child } => (
            parent.as_bytes(),
            Some(child.as_bytes()),
            None,
            None,
            None,
            None,
        ),
        LifecycleIntentV1::RenewCapability { capability, fence }
        | LifecycleIntentV1::RevokeCapability { capability, fence } => {
            (capability.as_bytes(), None, None, Some(*fence), None, None)
        }
    };
    let target = match intent {
        LifecycleIntentV1::Hibernate { target_fence, .. }
        | LifecycleIntentV1::Snapshot { target_fence, .. }
        | LifecycleIntentV1::CreateExecution { target_fence, .. }
        | LifecycleIntentV1::CancelExecution { target_fence, .. }
        | LifecycleIntentV1::AttachView { target_fence, .. }
        | LifecycleIntentV1::ReplaceAttachment { target_fence, .. }
        | LifecycleIntentV1::DetachView { target_fence, .. } => Some(*target_fence),
        _ => None,
    };
    slot[1] = u8::from(desired.is_some())
        | (u8::from(live.is_some()) << 1)
        | (u8::from(target.is_some()) << 2);
    slot[8..24].copy_from_slice(primary);
    if let Some(value) = secondary {
        slot[24..40].copy_from_slice(value);
    }
    if let Some(value) = tertiary {
        slot[40..56].copy_from_slice(value);
    }
    if let Some(value) = environment {
        slot[56..64].copy_from_slice(&value.get().to_be_bytes());
    }
    if let Some(value) = desired {
        slot[64] = value.resource().code();
        slot[72..88].copy_from_slice(value.resource().as_bytes());
        slot[88..96].copy_from_slice(&value.expected_generation().get().to_be_bytes());
        slot[96..104].copy_from_slice(&value.resource_revision().get().to_be_bytes());
        slot[104..136].copy_from_slice(value.resource_state().digest().as_bytes());
    }
    if let Some(value) = live {
        slot[136..152].copy_from_slice(value.sandbox().as_bytes());
        slot[152..168].copy_from_slice(value.incarnation().as_bytes());
        slot[168..176].copy_from_slice(&value.assignment_epoch().get().to_be_bytes());
        slot[176..184].copy_from_slice(&value.namespace_generation().get().to_be_bytes());
    }
    if let Some(value) = target {
        let mut encoded = Vec::with_capacity(76);
        encoded.extend_from_slice(&value.expected_generation().get().to_be_bytes());
        encode_expected_resource(&mut encoded, value.resource(), value.expected());
        slot[184..260].copy_from_slice(&encoded);
    }
    bytes.extend_from_slice(&slot);
}

/// Derives the normalized request commitment from exact canonical intent bytes.
#[must_use]
pub fn normalized_request_digest_v1(
    intent: &LifecycleIntentV1,
) -> LifecycleNormalizedRequestDigestV1 {
    let mut canonical = Vec::with_capacity(INTENT_BYTES);
    encode_intent(&mut canonical, intent);
    LifecycleNormalizedRequestDigestV1::commit(&canonical)
}

fn decode_intent(mut bytes: &[u8]) -> Result<LifecycleIntentV1, LifecycleModelError> {
    let method = take::<1>(&mut bytes)?[0];
    let flags = take::<1>(&mut bytes)?[0];
    if flags & !0b111 != 0
        || flags & 0b10 != 0 && flags & 0b01 == 0
        || take::<6>(&mut bytes)? != [0; 6]
    {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let primary = take::<16>(&mut bytes)?;
    let secondary = take::<16>(&mut bytes)?;
    let tertiary = take::<16>(&mut bytes)?;
    let environment = u64::from_be_bytes(take(&mut bytes)?);
    let mut fence_slot = take_slice(&mut bytes, 72)?;
    let desired_value = if flags & 0b01 == 0 {
        if fence_slot != [0; 72] {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        None
    } else {
        let resource_code = take::<1>(&mut fence_slot)?[0];
        if take::<7>(&mut fence_slot)? != [0; 7] {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        let resource = LifecycleResourceV1::from_code(resource_code, take(&mut fence_slot)?)?;
        let generation = DesiredGeneration::new(u64::from_be_bytes(take(&mut fence_slot)?));
        let revision = Revision::new(u64::from_be_bytes(take(&mut fence_slot)?));
        let state = LifecycleResourceStateDigestV1::from_stored(ObjectDigest::from_bytes(take(
            &mut fence_slot,
        )?))?;
        Some(
            DesiredStateFenceV1::new(resource, generation, revision, state)
                .map_err(|_| LifecycleModelError::CorruptEncoding)?,
        )
    };
    let mut runtime_slot = take_slice(&mut bytes, 48)?;
    let live_value = if flags & 0b10 == 0 {
        if runtime_slot != [0; 48] {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        None
    } else {
        Some(
            LiveRuntimeFenceV1::new(
                SandboxId::from_bytes(take(&mut runtime_slot)?),
                desired_value.ok_or(LifecycleModelError::CorruptEncoding)?,
                IncarnationId::from_bytes(take(&mut runtime_slot)?),
                AssignmentEpoch::new(u64::from_be_bytes(take(&mut runtime_slot)?)),
                NamespaceGeneration::new(u64::from_be_bytes(take(&mut runtime_slot)?)),
            )
            .map_err(|_| LifecycleModelError::CorruptEncoding)?,
        )
    };
    let mut target_slot = take_slice(&mut bytes, 76)?;
    let target_value = if flags & 0b100 == 0 {
        if target_slot != [0; 76] {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        None
    } else {
        let generation = DesiredGeneration::new(u64::from_be_bytes(take(&mut target_slot)?));
        let (resource, expected) = decode_expected_resource(&mut target_slot)?;
        Some(
            LifecycleTargetFenceV1::new(resource, generation, expected)
                .map_err(|_| LifecycleModelError::CorruptEncoding)?,
        )
    };
    if !bytes.is_empty() || primary == [0; 16] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let desired = || desired_value.ok_or(LifecycleModelError::CorruptEncoding);
    let live = || live_value.ok_or(LifecycleModelError::CorruptEncoding);
    let target = || target_value.ok_or(LifecycleModelError::CorruptEncoding);
    let zero_secondary = secondary == [0; 16];
    let zero_tertiary = tertiary == [0; 16];
    let zero_desired = desired_value.is_none();
    let zero_environment = environment == 0;
    let zero_live = live_value.is_none();
    let method_requires_target = matches!(method, 9 | 10 | 14 | 15 | 17 | 18 | 19);
    if method_requires_target != target_value.is_some() {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    match method {
        1 if zero_secondary && zero_tertiary && zero_desired && zero_environment && zero_live => {
            Ok(LifecycleIntentV1::Create {
                sandbox: SandboxId::from_bytes(primary),
            })
        }
        2 if !zero_secondary && zero_tertiary && zero_desired && zero_environment && zero_live => {
            Ok(LifecycleIntentV1::Fork {
                source: SnapshotId::from_bytes(primary),
                target: SandboxId::from_bytes(secondary),
            })
        }
        3 if !zero_secondary && zero_tertiary && zero_desired && zero_environment && zero_live => {
            Ok(LifecycleIntentV1::Restore {
                snapshot: SnapshotId::from_bytes(primary),
                sandbox: SandboxId::from_bytes(secondary),
            })
        }
        4 if zero_secondary && zero_tertiary && !zero_desired && !zero_environment && zero_live => {
            Ok(LifecycleIntentV1::UpdateEnvironment {
                sandbox: SandboxId::from_bytes(primary),
                environment_generation: Revision::new(environment),
                fence: desired()?,
            })
        }
        5 if zero_secondary && zero_tertiary && !zero_desired && zero_environment && zero_live => {
            Ok(LifecycleIntentV1::Start {
                sandbox: SandboxId::from_bytes(primary),
                fence: desired()?,
            })
        }
        6 if zero_secondary && zero_tertiary && !zero_desired && zero_environment && !zero_live => {
            Ok(LifecycleIntentV1::Stop {
                sandbox: SandboxId::from_bytes(primary),
                fence: live()?,
            })
        }
        7 if zero_secondary && zero_tertiary && !zero_desired && zero_environment && !zero_live => {
            Ok(LifecycleIntentV1::SuspendMemory {
                sandbox: SandboxId::from_bytes(primary),
                fence: live()?,
            })
        }
        8 if zero_secondary && zero_tertiary && !zero_desired && zero_environment && !zero_live => {
            Ok(LifecycleIntentV1::Resume {
                sandbox: SandboxId::from_bytes(primary),
                source: LifecycleResumeSourceV1::Memory { fence: live()? },
            })
        }
        8 if !zero_secondary && zero_tertiary && !zero_desired && zero_environment && zero_live => {
            Ok(LifecycleIntentV1::Resume {
                sandbox: SandboxId::from_bytes(primary),
                source: LifecycleResumeSourceV1::Hibernated {
                    snapshot: SnapshotId::from_bytes(secondary),
                    fence: desired()?,
                },
            })
        }
        9 if !zero_secondary
            && zero_tertiary
            && !zero_desired
            && zero_environment
            && !zero_live =>
        {
            Ok(LifecycleIntentV1::Hibernate {
                sandbox: SandboxId::from_bytes(primary),
                snapshot: SnapshotId::from_bytes(secondary),
                fence: live()?,
                target_fence: target()?,
            })
        }
        10 if !zero_secondary
            && zero_tertiary
            && !zero_desired
            && zero_environment
            && !zero_live =>
        {
            Ok(LifecycleIntentV1::Snapshot {
                sandbox: SandboxId::from_bytes(primary),
                snapshot: SnapshotId::from_bytes(secondary),
                fence: live()?,
                target_fence: target()?,
            })
        }
        11 if zero_secondary && zero_tertiary && !zero_desired && zero_environment && zero_live => {
            Ok(LifecycleIntentV1::DeleteSandbox {
                sandbox: SandboxId::from_bytes(primary),
                fence: desired()?,
            })
        }
        12 if zero_secondary && zero_tertiary && !zero_desired && zero_environment && zero_live => {
            Ok(LifecycleIntentV1::DeleteSnapshot {
                snapshot: SnapshotId::from_bytes(primary),
                fence: desired()?,
            })
        }
        13 if zero_secondary && zero_tertiary && !zero_desired && zero_environment && zero_live => {
            Ok(LifecycleIntentV1::UpdatePolicy {
                sandbox: SandboxId::from_bytes(primary),
                fence: desired()?,
            })
        }
        14 if !zero_secondary
            && zero_tertiary
            && !zero_desired
            && zero_environment
            && !zero_live =>
        {
            Ok(LifecycleIntentV1::CreateExecution {
                sandbox: SandboxId::from_bytes(primary),
                execution: ExecutionId::from_bytes(secondary),
                fence: live()?,
                target_fence: target()?,
            })
        }
        15 if zero_secondary
            && zero_tertiary
            && !zero_desired
            && zero_environment
            && !zero_live =>
        {
            Ok(LifecycleIntentV1::CancelExecution {
                execution: ExecutionId::from_bytes(primary),
                fence: live()?,
                target_fence: target()?,
            })
        }
        16 if zero_secondary && zero_tertiary && zero_desired && zero_environment && zero_live => {
            Ok(LifecycleIntentV1::CreateView {
                view: ViewId::from_bytes(primary),
            })
        }
        17 if !zero_secondary
            && !zero_tertiary
            && !zero_desired
            && zero_environment
            && !zero_live =>
        {
            Ok(LifecycleIntentV1::AttachView {
                sandbox: SandboxId::from_bytes(primary),
                view: ViewId::from_bytes(secondary),
                attachment: ResourceId::from_bytes(tertiary),
                fence: live()?,
                target_fence: target()?,
            })
        }
        18 if !zero_secondary
            && zero_tertiary
            && !zero_desired
            && zero_environment
            && !zero_live =>
        {
            Ok(LifecycleIntentV1::ReplaceAttachment {
                attachment: ResourceId::from_bytes(primary),
                view: ViewId::from_bytes(secondary),
                fence: live()?,
                target_fence: target()?,
            })
        }
        19 if zero_secondary
            && zero_tertiary
            && !zero_desired
            && zero_environment
            && !zero_live =>
        {
            Ok(LifecycleIntentV1::DetachView {
                attachment: ResourceId::from_bytes(primary),
                fence: live()?,
                target_fence: target()?,
            })
        }
        20 if zero_secondary && zero_tertiary && !zero_desired && zero_environment && zero_live => {
            Ok(LifecycleIntentV1::ReleaseView {
                view: ViewId::from_bytes(primary),
                fence: desired()?,
            })
        }
        21 if !zero_secondary && zero_tertiary && zero_desired && zero_environment && zero_live => {
            Ok(LifecycleIntentV1::AttenuateCapability {
                parent: ResourceId::from_bytes(primary),
                child: ResourceId::from_bytes(secondary),
            })
        }
        22 if zero_secondary && zero_tertiary && !zero_desired && zero_environment && zero_live => {
            Ok(LifecycleIntentV1::RenewCapability {
                capability: ResourceId::from_bytes(primary),
                fence: desired()?,
            })
        }
        23 if zero_secondary && zero_tertiary && !zero_desired && zero_environment && zero_live => {
            Ok(LifecycleIntentV1::RevokeCapability {
                capability: ResourceId::from_bytes(primary),
                fence: desired()?,
            })
        }
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}

fn encode_expectation(bytes: &mut Vec<u8>, value: &ResourceExpectationV1) {
    bytes.push(value.resource().code());
    match value.expected() {
        ResourceExpectedStateV1::Absent => {
            bytes.push(0);
            bytes.extend_from_slice(&[0; 2]);
            bytes.extend_from_slice(value.resource().as_bytes());
            bytes.extend_from_slice(&[0; 40]);
        }
        ResourceExpectedStateV1::Present {
            revision,
            state_digest,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&[0; 2]);
            bytes.extend_from_slice(value.resource().as_bytes());
            bytes.extend_from_slice(&revision.get().to_be_bytes());
            bytes.extend_from_slice(state_digest.digest().as_bytes());
        }
    }
}

fn decode_expectation(bytes: &mut &[u8]) -> Result<ResourceExpectationV1, LifecycleModelError> {
    let kind = take::<1>(bytes)?[0];
    let presence = take::<1>(bytes)?[0];
    if take::<2>(bytes)? != [0; 2] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let resource = LifecycleResourceV1::from_code(kind, take(bytes)?)?;
    let revision = u64::from_be_bytes(take(bytes)?);
    let digest = ObjectDigest::from_bytes(take(bytes)?);
    match presence {
        0 if revision == 0 && digest.as_bytes() == &[0; 32] => {
            ResourceExpectationV1::absent(resource)
        }
        1 => ResourceExpectationV1::present(
            resource,
            Revision::new(revision),
            LifecycleResourceStateDigestV1::from_stored(digest)?,
        ),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
    .map_err(|_| LifecycleModelError::CorruptEncoding)
}

fn encode_step(bytes: &mut Vec<u8>, step: &LifecycleStepV1) {
    let flags = u8::from(step.compensation_request().is_some())
        | (u8::from(step.result().is_some()) << 1)
        | (u8::from(step.compensation_result().is_some()) << 2)
        | (u8::from(step.inventory().is_some()) << 3)
        | (u8::from(step.failure().is_some()) << 4)
        | (u8::from(step.retry().is_some()) << 5);
    bytes.extend_from_slice(&step.index().to_be_bytes());
    bytes.push(step.class() as u8);
    bytes.push(step.domain() as u8);
    bytes.push(step.state() as u8);
    bytes.push(flags);
    push_count(bytes, step.forward_attempts().len());
    push_count(bytes, step.compensation_attempts().len());
    bytes.extend_from_slice(step.request().digest().as_bytes());
    bytes.extend_from_slice(step.request_body().digest().as_bytes());
    bytes.extend_from_slice(step.plan().digest().as_bytes());
    push_optional_digest(bytes, step.compensation_request().map(|v| v.digest()));
    push_optional_digest(bytes, step.compensation_body().map(|v| v.digest()));
    push_optional_digest(bytes, step.compensation_plan().map(|v| v.digest()));
    push_optional_digest(bytes, step.result().map(|v| v.digest()));
    push_optional_digest(bytes, step.compensation_result().map(|v| v.digest()));
    push_optional_digest(bytes, step.inventory().map(|v| v.digest()));
    match step.failure() {
        Some(value) => {
            bytes.push(value.class() as u8);
            bytes.extend_from_slice(&[0; 7]);
            bytes.extend_from_slice(value.detail().digest().as_bytes());
            bytes.extend_from_slice(&value.observed_at().get().to_be_bytes());
        }
        None => bytes.extend_from_slice(&[0; 48]),
    }
    match step.retry() {
        Some(value) => {
            bytes.extend_from_slice(&value.attempt().to_be_bytes());
            bytes.extend_from_slice(&value.not_before().get().to_be_bytes());
        }
        None => bytes.extend_from_slice(&[0; 12]),
    }
    encode_attempt_slots(bytes, step.forward_attempts());
    encode_attempt_slots(bytes, step.compensation_attempts());
}

fn decode_step(bytes: &mut &[u8]) -> Result<LifecycleStepV1, LifecycleModelError> {
    let index = u32::from_be_bytes(take(bytes)?);
    let class = decode_step_class(take::<1>(bytes)?[0])?;
    let domain = decode_step_domain(take::<1>(bytes)?[0])?;
    let state = decode_step_state(take::<1>(bytes)?[0])?;
    let flags = take::<1>(bytes)?[0];
    if flags & !0x3f != 0 {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let forward_attempt_count = usize_from_u32(&take::<4>(bytes)?)?;
    let compensation_attempt_count = usize_from_u32(&take::<4>(bytes)?)?;
    let request =
        LifecycleStepRequestDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let request_body =
        LifecycleStepBodyDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let plan = LifecycleStepPlanDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let compensation_request = optional_digest(bytes, flags & 1 != 0)?
        .map(LifecycleStepRequestDigestV1::from_stored)
        .transpose()?;
    let compensation_body = optional_digest(bytes, flags & 1 != 0)?
        .map(LifecycleStepBodyDigestV1::from_stored)
        .transpose()?;
    let compensation_plan = optional_digest(bytes, flags & 1 != 0)?
        .map(LifecycleStepPlanDigestV1::from_stored)
        .transpose()?;
    let result = optional_digest(bytes, flags & 2 != 0)?
        .map(LifecycleStepResultDigestV1::from_stored)
        .transpose()?;
    let compensation_result = optional_digest(bytes, flags & 4 != 0)?
        .map(LifecycleStepResultDigestV1::from_stored)
        .transpose()?;
    let inventory = optional_digest(bytes, flags & 8 != 0)?
        .map(LifecycleInventoryDigestV1::from_stored)
        .transpose()?;
    let failure_bytes = take_slice(bytes, 48)?;
    let failure = if flags & 16 != 0 {
        decode_step_failure(failure_bytes)?
    } else if failure_bytes == [0; 48] {
        None
    } else {
        return Err(LifecycleModelError::CorruptEncoding);
    };
    let retry_bytes = take_slice(bytes, 12)?;
    let retry = if flags & 32 != 0 {
        decode_retry_present(retry_bytes)?
    } else if retry_bytes == [0; 12] {
        None
    } else {
        return Err(LifecycleModelError::CorruptEncoding);
    };
    let forward_attempts = decode_attempt_slots(bytes, forward_attempt_count)?;
    let compensation_attempts = decode_attempt_slots(bytes, compensation_attempt_count)?;
    LifecycleStepV1::new(
        index,
        class,
        domain,
        request,
        request_body,
        plan,
        compensation_request,
        compensation_body,
        compensation_plan,
        state,
        forward_attempts,
        compensation_attempts,
        result,
        compensation_result,
        inventory,
        failure,
        retry,
    )
    .map_err(|_| LifecycleModelError::CorruptEncoding)
}

fn encode_attempt_slots(bytes: &mut Vec<u8>, attempts: &[LifecycleEffectAttemptV1]) {
    for attempt in attempts {
        let flags = u8::from(attempt.result().is_some())
            | (u8::from(attempt.failure().is_some()) << 1)
            | (u8::from(attempt.inventory().is_some()) << 2)
            | (u8::from(attempt.retry().is_some()) << 3)
            | (u8::from(attempt.observed_at().is_some()) << 4);
        bytes.extend_from_slice(&attempt.number().to_be_bytes());
        bytes.push(attempt.direction() as u8);
        bytes.push(attempt.state() as u8);
        bytes.push(flags);
        bytes.push(0);
        bytes.extend_from_slice(attempt.request().digest().as_bytes());
        bytes.extend_from_slice(attempt.body().digest().as_bytes());
        bytes.extend_from_slice(attempt.plan().digest().as_bytes());
        bytes.extend_from_slice(attempt.admission().digest().as_bytes());
        bytes.extend_from_slice(&attempt.started_at().get().to_be_bytes());
        push_optional_digest(bytes, attempt.result().map(|value| value.digest()));
        match attempt.failure() {
            Some(value) => {
                bytes.push(value.class() as u8);
                bytes.extend_from_slice(&[0; 7]);
                bytes.extend_from_slice(value.detail().digest().as_bytes());
                bytes.extend_from_slice(&value.observed_at().get().to_be_bytes());
            }
            None => bytes.extend_from_slice(&[0; 48]),
        }
        push_optional_digest(bytes, attempt.inventory().map(|value| value.digest()));
        match attempt.retry() {
            Some(value) => {
                bytes.extend_from_slice(&value.attempt().to_be_bytes());
                bytes.extend_from_slice(&value.not_before().get().to_be_bytes());
            }
            None => bytes.extend_from_slice(&[0; 12]),
        }
        bytes.extend_from_slice(
            &attempt
                .observed_at()
                .map_or(0, LifecycleTimeV1::get)
                .to_be_bytes(),
        );
    }
    for _ in attempts.len()..MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP {
        bytes.extend_from_slice(&[0; ATTEMPT_BYTES]);
    }
}

fn decode_attempt_slots(
    bytes: &mut &[u8],
    count: usize,
) -> Result<Vec<LifecycleEffectAttemptV1>, LifecycleModelError> {
    if count > MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let mut attempts = Vec::new();
    attempts
        .try_reserve_exact(count)
        .map_err(|_| LifecycleModelError::Allocation)?;
    for _ in 0..count {
        attempts.push(decode_attempt(bytes)?);
    }
    for _ in count..MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP {
        if take_slice(bytes, ATTEMPT_BYTES)? != [0; ATTEMPT_BYTES] {
            return Err(LifecycleModelError::CorruptEncoding);
        }
    }
    Ok(attempts)
}

fn decode_attempt(bytes: &mut &[u8]) -> Result<LifecycleEffectAttemptV1, LifecycleModelError> {
    let number = u32::from_be_bytes(take(bytes)?);
    let direction = decode_attempt_direction(take::<1>(bytes)?[0])?;
    let state = decode_attempt_state(take::<1>(bytes)?[0])?;
    let flags = take::<1>(bytes)?[0];
    if flags & !0x1f != 0 || take::<1>(bytes)? != [0] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let request =
        LifecycleStepRequestDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let body = LifecycleStepBodyDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let plan = LifecycleStepPlanDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let admission =
        LifecycleStepAdmissionDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let started_at = LifecycleTimeV1::from_stored(u64::from_be_bytes(take(bytes)?))?;
    let result = optional_digest(bytes, flags & 1 != 0)?
        .map(LifecycleStepResultDigestV1::from_stored)
        .transpose()?;
    let failure_slot = take_slice(bytes, 48)?;
    let failure = if flags & 2 != 0 {
        decode_step_failure(failure_slot)?
    } else if failure_slot == [0; 48] {
        None
    } else {
        return Err(LifecycleModelError::CorruptEncoding);
    };
    let inventory = optional_digest(bytes, flags & 4 != 0)?
        .map(LifecycleInventoryDigestV1::from_stored)
        .transpose()?;
    let retry_slot = take_slice(bytes, 12)?;
    let retry = if flags & 8 != 0 {
        decode_retry_present(retry_slot)?
    } else if retry_slot == [0; 12] {
        None
    } else {
        return Err(LifecycleModelError::CorruptEncoding);
    };
    let observed_raw = u64::from_be_bytes(take(bytes)?);
    let observed_at = match (flags & 16 != 0, observed_raw) {
        (false, 0) => None,
        (true, value) => Some(LifecycleTimeV1::from_stored(value)?),
        _ => return Err(LifecycleModelError::CorruptEncoding),
    };
    LifecycleEffectAttemptV1::new(
        number,
        direction,
        request,
        body,
        plan,
        admission,
        started_at,
        state,
        result,
        failure,
        inventory,
        retry,
        observed_at,
    )
    .map_err(|_| LifecycleModelError::CorruptEncoding)
}

fn encode_semantic_commit(bytes: &mut Vec<u8>, value: Option<LifecycleSemanticCommitV1>) {
    match value {
        Some(v) => {
            bytes.push(1);
            bytes.extend_from_slice(&[0; 7]);
            bytes.extend_from_slice(&v.sequence().to_be_bytes());
            let cas = v.desired_state_cas();
            bytes.push(cas.resource().code());
            bytes.extend_from_slice(&[0; 7]);
            bytes.extend_from_slice(cas.resource().as_bytes());
            bytes.extend_from_slice(&cas.expected_generation().get().to_be_bytes());
            bytes.push(u8::from(cas.expected_state().is_some()));
            bytes.extend_from_slice(&[0; 7]);
            bytes.extend_from_slice(
                cas.expected_state()
                    .map_or(ObjectDigest::from_bytes([0; 32]), |digest| digest.digest())
                    .as_bytes(),
            );
            bytes.extend_from_slice(&cas.successor_generation().get().to_be_bytes());
            bytes.extend_from_slice(cas.desired_state().digest().as_bytes());
            bytes.extend_from_slice(cas.digest().digest().as_bytes());
            bytes.extend_from_slice(v.journal_commit_digest().digest().as_bytes());
            bytes.extend_from_slice(&v.committed_at().get().to_be_bytes());
        }
        None => bytes.extend_from_slice(&[0; 200]),
    }
}
fn decode_semantic_commit(
    bytes: &mut &[u8],
) -> Result<Option<LifecycleSemanticCommitV1>, LifecycleModelError> {
    let slot = take_slice(bytes, 200)?;
    if slot == [0; 200] {
        return Ok(None);
    }
    let mut slot = slot;
    if take::<1>(&mut slot)? != [1] || take::<7>(&mut slot)? != [0; 7] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let sequence = u64::from_be_bytes(take(&mut slot)?);
    let resource_code = take::<1>(&mut slot)?[0];
    if take::<7>(&mut slot)? != [0; 7] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let resource = LifecycleResourceV1::from_code(resource_code, take(&mut slot)?)?;
    let expected = DesiredGeneration::new(u64::from_be_bytes(take(&mut slot)?));
    let expected_present = take::<1>(&mut slot)?[0];
    if expected_present > 1 || take::<7>(&mut slot)? != [0; 7] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let expected_document = ObjectDigest::from_bytes(take(&mut slot)?);
    let expected_state = match expected_present {
        0 if expected_document.as_bytes() == &[0; 32] => None,
        1 => Some(DesiredStateDocumentDigestV1::from_stored(
            expected_document,
        )?),
        _ => return Err(LifecycleModelError::CorruptEncoding),
    };
    let successor = DesiredGeneration::new(u64::from_be_bytes(take(&mut slot)?));
    let desired_state =
        DesiredStateDocumentDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut slot)?))?;
    let stored_cas =
        DesiredStateCasDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut slot)?))?;
    let cas = DesiredStateCasV1::new(resource, expected, expected_state, successor, desired_state)
        .map_err(|_| LifecycleModelError::CorruptEncoding)?;
    if cas.digest() != stored_cas {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    LifecycleSemanticCommitV1::new(
        sequence,
        cas,
        LifecycleJournalCommitDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut slot)?))?,
        LifecycleTimeV1::from_stored(u64::from_be_bytes(take(&mut slot)?))?,
    )
    .map(Some)
    .map_err(|_| LifecycleModelError::CorruptEncoding)
}

fn encode_failure(bytes: &mut Vec<u8>, value: Option<LifecycleFailureV1>) {
    match value {
        Some(v) => {
            bytes.push(1);
            bytes.push(v.class() as u8);
            bytes.extend_from_slice(&[0; 6]);
            bytes.extend_from_slice(v.detail().digest().as_bytes());
            bytes.extend_from_slice(&v.observed_at().get().to_be_bytes());
        }
        None => bytes.extend_from_slice(&[0; 48]),
    }
}
fn decode_failure(bytes: &mut &[u8]) -> Result<Option<LifecycleFailureV1>, LifecycleModelError> {
    let slot = take_slice(bytes, 48)?;
    if slot == [0; 48] {
        Ok(None)
    } else {
        let mut slot = slot;
        if take::<1>(&mut slot)? != [1] {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        decode_failure_present(slot)
    }
}
fn decode_failure_present(
    mut slot: &[u8],
) -> Result<Option<LifecycleFailureV1>, LifecycleModelError> {
    let class = decode_failure_class(take::<1>(&mut slot)?[0])?;
    if take::<6>(&mut slot)? != [0; 6] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let detail = LifecycleFailureDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut slot)?))?;
    let time = LifecycleTimeV1::from_stored(u64::from_be_bytes(take(&mut slot)?))?;
    if !slot.is_empty() {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    Ok(Some(LifecycleFailureV1::new(class, detail, time)))
}
fn decode_step_failure(mut slot: &[u8]) -> Result<Option<LifecycleFailureV1>, LifecycleModelError> {
    let class = decode_failure_class(take::<1>(&mut slot)?[0])?;
    if take::<7>(&mut slot)? != [0; 7] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let detail = LifecycleFailureDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut slot)?))?;
    let time = LifecycleTimeV1::from_stored(u64::from_be_bytes(take(&mut slot)?))?;
    if !slot.is_empty() {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    Ok(Some(LifecycleFailureV1::new(class, detail, time)))
}

fn encode_retry(bytes: &mut Vec<u8>, value: Option<LifecycleRetryV1>) {
    match value {
        Some(v) => {
            bytes.push(1);
            bytes.extend_from_slice(&[0; 3]);
            bytes.extend_from_slice(&v.attempt().to_be_bytes());
            bytes.extend_from_slice(&v.not_before().get().to_be_bytes());
        }
        None => bytes.extend_from_slice(&[0; 16]),
    }
}
fn decode_retry(bytes: &mut &[u8]) -> Result<Option<LifecycleRetryV1>, LifecycleModelError> {
    let slot = take_slice(bytes, 16)?;
    if slot == [0; 16] {
        Ok(None)
    } else {
        let mut slot = slot;
        if take::<1>(&mut slot)? != [1] || take::<3>(&mut slot)? != [0; 3] {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        decode_retry_present(slot)
    }
}
fn decode_retry_present(mut slot: &[u8]) -> Result<Option<LifecycleRetryV1>, LifecycleModelError> {
    let attempt = u32::from_be_bytes(take(&mut slot)?);
    let time = LifecycleTimeV1::from_stored(u64::from_be_bytes(take(&mut slot)?))?;
    if !slot.is_empty() {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    LifecycleRetryV1::new(attempt, time)
        .map(Some)
        .map_err(|_| LifecycleModelError::CorruptEncoding)
}

fn encode_optional_time(bytes: &mut Vec<u8>, value: Option<LifecycleTimeV1>) {
    match value {
        Some(v) => {
            bytes.push(1);
            bytes.extend_from_slice(&[0; 7]);
            bytes.extend_from_slice(&v.get().to_be_bytes());
        }
        None => bytes.extend_from_slice(&[0; 16]),
    }
}
fn decode_optional_time(bytes: &mut &[u8]) -> Result<Option<LifecycleTimeV1>, LifecycleModelError> {
    let present = take::<1>(bytes)?[0];
    if take::<7>(bytes)? != [0; 7] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let value = u64::from_be_bytes(take(bytes)?);
    match (present, value) {
        (0, 0) => Ok(None),
        (1, value) => LifecycleTimeV1::from_stored(value).map(Some),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}
fn encode_predecessor(bytes: &mut Vec<u8>, value: Option<LifecycleRecordDigestV1>) {
    match value {
        Some(v) => {
            bytes.push(1);
            bytes.extend_from_slice(&[0; 7]);
            bytes.extend_from_slice(v.digest().as_bytes());
        }
        None => bytes.extend_from_slice(&[0; 40]),
    }
}
fn decode_predecessor(
    bytes: &mut &[u8],
) -> Result<Option<LifecycleRecordDigestV1>, LifecycleModelError> {
    let present = take::<1>(bytes)?[0];
    if take::<7>(bytes)? != [0; 7] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let value = ObjectDigest::from_bytes(take(bytes)?);
    match present {
        0 if value.as_bytes() == &[0; 32] => Ok(None),
        1 => LifecycleRecordDigestV1::from_stored(value).map(Some),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}

fn optional_digest(
    bytes: &mut &[u8],
    present: bool,
) -> Result<Option<ObjectDigest>, LifecycleModelError> {
    let value = ObjectDigest::from_bytes(take(bytes)?);
    if present && value.as_bytes() != &[0; 32] {
        Ok(Some(value))
    } else if !present && value.as_bytes() == &[0; 32] {
        Ok(None)
    } else {
        Err(LifecycleModelError::CorruptEncoding)
    }
}
fn push_optional_digest(bytes: &mut Vec<u8>, value: Option<ObjectDigest>) {
    bytes.extend_from_slice(
        value
            .unwrap_or(ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
}
fn push_count(bytes: &mut Vec<u8>, count: usize) {
    let encoded = count.to_be_bytes();
    bytes.extend_from_slice(&encoded[encoded.len() - 4..]);
}
fn hash_record(bytes: &[u8]) -> LifecycleRecordDigestV1 {
    LifecycleRecordDigestV1::commit(bytes)
}

fn decode_phase(v: u8) -> Result<LifecyclePhaseV1, LifecycleModelError> {
    match v {
        1 => Ok(LifecyclePhaseV1::Accepted),
        2 => Ok(LifecyclePhaseV1::Preparing),
        3 => Ok(LifecyclePhaseV1::Prepared),
        4 => Ok(LifecyclePhaseV1::ReadyToCommit),
        5 => Ok(LifecyclePhaseV1::Committed),
        6 => Ok(LifecyclePhaseV1::Completing),
        7 => Ok(LifecyclePhaseV1::Compensating),
        8 => Ok(LifecyclePhaseV1::Terminal),
        9 => Ok(LifecyclePhaseV1::RetryWaiting),
        10 => Ok(LifecyclePhaseV1::Residual),
        11 => Ok(LifecyclePhaseV1::PermanentlyBlocked),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}
fn decode_terminal(v: u8) -> Result<Option<LifecycleTerminalResultV1>, LifecycleModelError> {
    match v {
        0 => Ok(None),
        1 => Ok(Some(LifecycleTerminalResultV1::Succeeded)),
        2 => Ok(Some(LifecycleTerminalResultV1::FailedBeforeCommit)),
        3 => Ok(Some(LifecycleTerminalResultV1::CanceledBeforeCommit)),
        4 => Ok(Some(LifecycleTerminalResultV1::BlockedBeforeCommit)),
        5 => Ok(Some(LifecycleTerminalResultV1::BlockedAfterCommit)),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}
fn decode_step_class(v: u8) -> Result<LifecycleStepClassV1, LifecycleModelError> {
    match v {
        1 => Ok(LifecycleStepClassV1::PreCommitReversible),
        2 => Ok(LifecycleStepClassV1::PostCommitForward),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}
fn decode_step_domain(v: u8) -> Result<LifecycleStepDomainV1, LifecycleModelError> {
    match v {
        1 => Ok(LifecycleStepDomainV1::Controller),
        2 => Ok(LifecycleStepDomainV1::Host),
        3 => Ok(LifecycleStepDomainV1::Storage),
        4 => Ok(LifecycleStepDomainV1::Mount),
        5 => Ok(LifecycleStepDomainV1::Network),
        6 => Ok(LifecycleStepDomainV1::Content),
        7 => Ok(LifecycleStepDomainV1::Environment),
        8 => Ok(LifecycleStepDomainV1::Git),
        9 => Ok(LifecycleStepDomainV1::Guest),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}
fn decode_step_state(v: u8) -> Result<LifecycleStepStateV1, LifecycleModelError> {
    match v {
        1 => Ok(LifecycleStepStateV1::Planned),
        2 => Ok(LifecycleStepStateV1::Applying),
        3 => Ok(LifecycleStepStateV1::Applied),
        4 => Ok(LifecycleStepStateV1::Compensating),
        5 => Ok(LifecycleStepStateV1::Compensated),
        6 => Ok(LifecycleStepStateV1::Residual),
        7 => Ok(LifecycleStepStateV1::PermanentlyBlocked),
        8 => Ok(LifecycleStepStateV1::Canceled),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}
fn decode_attempt_direction(value: u8) -> Result<LifecycleEffectDirectionV1, LifecycleModelError> {
    match value {
        1 => Ok(LifecycleEffectDirectionV1::Forward),
        2 => Ok(LifecycleEffectDirectionV1::Compensation),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}
fn decode_attempt_state(value: u8) -> Result<LifecycleAttemptStateV1, LifecycleModelError> {
    match value {
        1 => Ok(LifecycleAttemptStateV1::Reserved),
        2 => Ok(LifecycleAttemptStateV1::Ambiguous),
        3 => Ok(LifecycleAttemptStateV1::Succeeded),
        4 => Ok(LifecycleAttemptStateV1::Failed),
        5 => Ok(LifecycleAttemptStateV1::PermanentlyBlocked),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}
fn decode_failure_class(v: u8) -> Result<LifecycleFailureClassV1, LifecycleModelError> {
    match v {
        1 => Ok(LifecycleFailureClassV1::Conflict),
        2 => Ok(LifecycleFailureClassV1::AuthorityUnavailable),
        3 => Ok(LifecycleFailureClassV1::AmbiguousEffect),
        4 => Ok(LifecycleFailureClassV1::Capacity),
        5 => Ok(LifecycleFailureClassV1::DependencyHeld),
        6 => Ok(LifecycleFailureClassV1::CorruptState),
        _ => Err(LifecycleModelError::CorruptEncoding),
    }
}
fn usize_from_u32(bytes: &[u8]) -> Result<usize, LifecycleModelError> {
    let raw: [u8; 4] = bytes
        .try_into()
        .map_err(|_| LifecycleModelError::CorruptEncoding)?;
    usize::try_from(u32::from_be_bytes(raw)).map_err(|_| LifecycleModelError::CorruptEncoding)
}
fn take_slice<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], LifecycleModelError> {
    let (value, remaining) = bytes
        .split_at_checked(length)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    *bytes = remaining;
    Ok(value)
}
fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], LifecycleModelError> {
    take_slice(bytes, N)?
        .try_into()
        .map_err(|_| LifecycleModelError::CorruptEncoding)
}
