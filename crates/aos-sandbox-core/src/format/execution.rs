//! Canonical codecs and digests for portable execution semantics.
//!
//! `execution-spec-v1` is the fixed array:
//!
//! ```text
//! [1, execution-id, target, environment-descriptor,
//!  canonical-base-environment-bytes, environment-generation, command,
//!  argument-envelope, resource-admission, io-policy, timeout-ns,
//!  principal-id, audit-id]
//! ```
//!
//! Nested forms are exact arrays. `target` contains sandbox/incarnation IDs,
//! assignment epoch/digest, namespace generation, and payload boot ID.
//! `command` contains argv, ordered overlay entries, a component path, and
//! credentials. `argument-envelope` contains purpose-committed runtime
//! argument-limit evidence, the derived charge, and effective-environment digest.
//! `resource-admission` contains distinct
//! requested/admitted sets plus the exact parent profile and commitment.
//! `io-policy` contains terminal/output/disconnect variants and a detached or
//! OpenSSH route; the OpenSSH route includes algorithm, raw key, derived key
//! digest, and closed capabilities.
//!
//! ```text
//! target = [sandbox[16], incarnation[16], assignment-epoch,
//!           assignment-digest[32], namespace-generation, payload-boot-id[16]]
//! command = [[* argument-bytes], [* [overlay-name, overlay-value-bytes]],
//!            [* path-component-bytes], [uid, gid, [* supplementary-gid]]]
//! feature = [namespace-text, major, minor]
//! argument-envelope = [runtime-argument-evidence, accounted-bytes,
//!                      effective-environment-digest[32]]
//! runtime-argument-evidence = [feature, runtime-profile-digest[32], target,
//!                              runtime-limit, evidence-commitment[32]]
//! resource-admission = [[* requested], [* admitted], [* parent-limit],
//!                       parent-profile-digest[32], output-byte-admission]
//! requested = [dimension, [0] / [1, maximum] / [2, relative-weight], feature]
//! admitted = [dimension, [0, maximum] / [1, relative-weight], feature]
//! parent-limit = [dimension, [0] / [1, maximum] / [2, grant-id[16]], feature]
//! output-byte-admission = [20, requested, admitted, canonical-assignment-bytes,
//!                          reservation-commitment[32],
//!                          broker-ledger-feature]
//! io-policy = [terminal, output, disconnect, access-route]
//! terminal = 0 ; none
//!          / 1 ; PTY
//! output = [0] ; live stream
//!        / [1, stdout-maximum, stderr-maximum] ; bounded capture
//! disconnect = 0 ; cancel
//!            / 1 ; detached continuation
//! access-route = [0] ; detached
//!              / [1, 0, ed25519-key[32], key-digest[32], [* capability]]
//! capability = 0..8 ; stdin, stdout, stderr, resize, signal, SFTP, Git,
//!                   ; TCP forwarding, agent forwarding
//! ```
//!
//! Execution-local resource sublimits use the core closed codes: processes `2`,
//! memory `3`, CPU weight `4`, CPU quota `5`, I/O weight `6`, I/O bandwidth `7`,
//! and open files `9`. Other core dimension
//! codes may appear only in the retained parent profile; they cannot appear in
//! requested or admitted execution sets. Feature arrays and descriptors reuse
//! their canonical core-v1 encodings. `canonical-base-environment-bytes` is a
//! byte string containing the complete output of the environment-v1 codec, not
//! a second ad hoc environment schema.
//! Core storage `Bytes` is not an execution capture dimension. Output capture
//! uses a distinct core [`crate::ResourceDimension::OutputBytes`] claim and
//! broker-ledger 1.0. The claim is nonauthorizing: before execution or capture
//! effects, a protected adapter must obtain ledger admission bound to the exact
//! execution ID, revalidate the current assignment, and reserve the claimed
//! bytes. Open-file settings require broker-ledger 1.0; process, memory, CPU,
//! and I/O settings require cgroup-v2 1.0. CPU and I/O weight
//! request/admission pairs are explicit and do not inherit a parent weight.
//! Parent weight entries may be absent; retained entries must be bounded,
//! registry-valid, and use the exact cgroup-v2 feature, but are not child
//! ceilings.
//! The retained parent-profile digest must equal the embedded assignment's
//! resource commitment, closing both resource claims to the same assignment.
//!
//! `key-digest` is SHA-256 over the ASCII domain
//! `aos-sandbox-openssh-public-key-v1`, a NUL byte, the one-byte algorithm
//! code, `u64be(key-length)`, and the canonical raw key bytes. It is encoded
//! as a checked commitment, never accepted as a substitute for key material.
//! Runtime argument-limit evidence is likewise self-consistent and target-bound,
//! but nonauthorizing; a protected runtime adapter must establish profile
//! commitment provenance and target freshness before constructing it.
//!
//! `execution-observation-v1` is:
//!
//! ```text
//! [1, execution-id, execution-spec-digest, phase, desired-generation,
//!  observation-sequence, terminal-result, captured-output, reason-code,
//!  [wall-seconds, wall-nanoseconds]]
//! terminal-result = [0] ; absent for nonterminal phases
//!                 / [1, exit-code]
//!                 / [2, signal, core-dumped]
//!                 / [3] ; canceled
//!                 / [4, failure-reason]
//!                 / [5] ; lost
//! captured-output = [0] ; absent before terminality or for streaming
//!                 / [1] ; unavailable final capture
//!                 / [2, [* captured-stream]] ; partial capture
//!                 / [3, [stdout-stream, stderr-stream]] ; complete capture
//! captured-stream = [stream, content-descriptor, captured-bytes, truncated]
//! ```
//!
//! Phase codes `0..=7` are requested, admitted, starting, running, exited,
//! canceled, failed, and lost respectively. The desired generation and
//! sequence are nonzero unsigned integers, the reason code is bounded core
//! text, wall seconds is signed, and wall nanoseconds is in `0..1_000_000_000`.
//! The execution ID and exact execution-spec digest prevent a journal from
//! attaching the observation to another admitted execution. Terminal result
//! variants must match the phase exactly, and core-dumped is true only for the
//! closed core-capable signal subset. Captured streams are
//! sorted and unique, appear only for terminal observations of capture-mode
//! executions, and remain within their per-stream admitted byte ceilings. An
//! exited capture-mode execution requires complete stdout and stderr evidence.
//! `Failed(OutputCapture)` exists only for capture mode and carries partial or
//! unavailable capture evidence, never a complete disposition.
//!
//! Every variable collection is checked against its semantic ceiling before
//! allocation. Argument and overlay decoders also debit aggregate byte budgets
//! before cloning each string.

use sha2::{Digest as _, Sha256};

use crate::model::{
    CapturedStreamV1, Environment, EnvironmentEntry, ExecutionAccessRouteV1,
    ExecutionArgumentEnvelopeV1, ExecutionCapturedOutputV1, ExecutionCapturedStreamKindV1,
    ExecutionCommandV1, ExecutionCredentialsV1, ExecutionDisconnectPolicyV1,
    ExecutionEndpointCapabilityV1, ExecutionEnvironmentEntry, ExecutionFailureReasonV1,
    ExecutionIoV1, ExecutionObservationPhaseV1, ExecutionObservationV1,
    ExecutionOutputByteAdmissionV1, ExecutionOutputModeV1, ExecutionPublicKeyAlgorithmV1,
    ExecutionPublicKeyV1, ExecutionResourceAdmissionV1, ExecutionResourceRequestV1,
    ExecutionResourceRequestValueV1, ExecutionResourceSublimitV1, ExecutionResourceSublimitValueV1,
    ExecutionRuntimeArgumentLimitV1, ExecutionSignalV1, ExecutionSpecV1, ExecutionTargetV1,
    ExecutionTerminalModeV1, ExecutionTerminalResultV1, ExecutionTimeoutV1, InvalidExecutionSpec,
    Limit, LimitDimension, LimitValue, MAX_ENVIRONMENT_NAME_BYTES, MAX_ENVIRONMENT_VALUE_BYTES,
    MAX_EXECUTION_ARGUMENT_BYTES, MAX_EXECUTION_ARGUMENT_STRING_BYTES, MAX_EXECUTION_ARGUMENTS,
    MAX_EXECUTION_BASE_ENVIRONMENT_BYTES, MAX_EXECUTION_BASE_ENVIRONMENT_CBOR_ITEMS,
    MAX_EXECUTION_BASE_ENVIRONMENT_COLLECTION_ITEMS, MAX_EXECUTION_BASE_ENVIRONMENT_FEATURES,
    MAX_EXECUTION_CAPTURED_STREAMS, MAX_EXECUTION_ENDPOINT_CAPABILITIES,
    MAX_EXECUTION_ENVIRONMENT_BYTES, MAX_EXECUTION_ENVIRONMENT_ENTRIES,
    MAX_EXECUTION_ENVIRONMENT_NAME_BYTES, MAX_EXECUTION_ENVIRONMENT_VALUE_BYTES,
    MAX_EXECUTION_OUTPUT_ASSIGNMENT_BYTES, MAX_EXECUTION_RESOURCE_SETTINGS,
    MAX_EXECUTION_STRING_BYTES, MAX_EXECUTION_SUPPLEMENTARY_GROUPS, PayloadBootId, ResourceProfile,
};
use crate::registry::DescriptorRole;
use crate::state::{ReasonCode, TransitionTime};
use crate::{
    AssignmentEpoch, AuditId, CanonicalAssignmentManifestV1, DesiredGeneration, ExecutionId,
    GrantId, IncarnationId, NamespaceGeneration, ObjectDigest, ObservationSequence, PathName,
    PrincipalId, RelativePath, ResourceDimension, Revision, SandboxId,
};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::tree::{
    decode_descriptor, decode_descriptor_for_role, decode_feature, encode_descriptor,
    encode_feature, exact_bytes, semantics,
};

const EXECUTION_SPEC_DIGEST_DOMAIN: &[u8] = b"aos-sandbox-execution-spec-v1\0";
const RESOURCE_PROFILE_DIGEST_DOMAIN: &[u8] = b"aos-sandbox-resource-profile-v1\0";
const MAX_EXECUTION_SPEC_CBOR_ITEMS: usize = 32_768;
const MAX_EXECUTION_OBSERVATION_CBOR_ITEMS: usize = 128;

/// Encodes one execution specification in its exact canonical v1 form.
#[must_use]
pub fn encode_execution_spec_v1(specification: &ExecutionSpecV1) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(13);
    encoder.unsigned(1);
    encoder.bytes(specification.execution().as_bytes());
    encode_target(&mut encoder, specification.target());
    encode_descriptor(&mut encoder, specification.environment_descriptor());
    encoder.bytes(&super::encode_environment(specification.base_environment()));
    encoder.unsigned(specification.environment_generation().get());
    encode_command(&mut encoder, specification.command());
    encode_argument_envelope(&mut encoder, specification.argument_envelope());
    encode_resource_admission(&mut encoder, specification.resources());
    encode_io(&mut encoder, specification.io());
    encoder.unsigned(specification.timeout().nanoseconds());
    encoder.bytes(specification.principal().as_bytes());
    encoder.bytes(specification.audit().as_bytes());
    encoder.finish()
}

/// Decodes one exact canonical v1 execution specification.
///
/// Embedded base-environment bytes are independently decoded and reproduced.
/// The claimed argument charge and effective-environment digest are compared
/// with values derived from that environment and the overlay. OpenSSH key
/// digests and parent resource-profile commitments are similarly rederived.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for noncanonical CBOR, a wrong schema,
/// pre-allocation bound failure, unknown closed value, sentinel field, digest
/// substitution, or invalid cross-field execution semantics.
pub fn decode_execution_spec_v1(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<ExecutionSpecV1, CanonicalCborError> {
    let nested_limits = limits;
    let mut decoder = Decoder::new(
        bytes,
        execution_item_limits(limits, MAX_EXECUTION_SPEC_CBOR_ITEMS),
    )?;
    decoder.array(13)?;
    decoder.exact("execution specification version", 1)?;
    let execution = ExecutionId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let target = decode_target(&mut decoder)?;
    let environment_descriptor = decode_descriptor(&mut decoder)?;
    let base_environment_bytes = decoder.bytes(MAX_EXECUTION_BASE_ENVIRONMENT_BYTES)?;
    let base_environment = decode_base_environment(
        base_environment_bytes,
        nested_environment_limits(nested_limits, base_environment_bytes.len()),
    )?;
    let environment_generation = Revision::new(decoder.unsigned()?);
    let command = decode_command(&mut decoder)?;
    let claimed_envelope = decode_argument_envelope(&mut decoder)?;
    let resources = decode_resource_admission(&mut decoder, nested_limits)?;
    let io = decode_io(&mut decoder)?;
    let timeout = ExecutionTimeoutV1::new(decoder.unsigned()?)
        .map_err(|error| semantics("execution timeout", error))?;
    let principal = PrincipalId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let audit = AuditId::from_bytes(exact_bytes(&mut decoder, 16)?);
    decoder.finish()?;

    let specification = ExecutionSpecV1::new(
        execution,
        target,
        environment_descriptor,
        base_environment,
        environment_generation,
        command,
        claimed_envelope.runtime_evidence().clone(),
        resources,
        io,
        timeout,
        principal,
        audit,
    )
    .map_err(|error| semantics("execution specification", error))?;
    if specification.argument_envelope() != &claimed_envelope {
        return Err(semantics(
            "execution argument envelope",
            InvalidExecutionSpec::ArgumentEnvelopeMismatch,
        ));
    }
    Ok(specification)
}

/// Computes the exact domain-separated digest of an execution specification.
///
/// The SHA-256 preimage is `aos-sandbox-execution-spec-v1`, one NUL byte, and
/// the exact bytes from [`encode_execution_spec_v1`].
#[must_use]
pub fn execution_spec_digest_v1(specification: &ExecutionSpecV1) -> ObjectDigest {
    domain_digest(
        EXECUTION_SPEC_DIGEST_DOMAIN,
        &encode_execution_spec_v1(specification),
    )
}

/// Computes the exact commitment used to bind a parent resource profile.
///
/// The SHA-256 preimage is `aos-sandbox-resource-profile-v1`, one NUL byte,
/// followed by the canonical deterministic-CBOR encoding of the complete profile.
#[must_use]
pub fn resource_profile_digest_v1(profile: &ResourceProfile) -> ObjectDigest {
    let mut encoder = Encoder::new();
    encode_resource_profile(&mut encoder, profile);
    domain_digest(RESOURCE_PROFILE_DIGEST_DOMAIN, &encoder.finish())
}

/// Encodes one versioned execution observation in exact canonical form.
#[must_use]
pub fn encode_execution_observation_v1(observation: &ExecutionObservationV1) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(10);
    encoder.unsigned(1);
    encoder.bytes(observation.execution().as_bytes());
    encoder.bytes(observation.specification_digest().as_bytes());
    encoder.unsigned(observation_phase_code(observation.phase()));
    encoder.unsigned(observation.desired_generation().get());
    encoder.unsigned(observation.sequence().get());
    encode_terminal_result(&mut encoder, observation.terminal_result());
    encode_captured_output(&mut encoder, observation.captured_output());
    encoder.text(observation.reason().as_str());
    encoder.array(2);
    encoder.signed(observation.transition_time().seconds());
    encoder.unsigned(u64::from(observation.transition_time().nanoseconds()));
    encoder.finish()
}

/// Decodes one exact canonical v1 execution observation.
///
/// `specification` supplies the admitted output mode and per-stream capture
/// ceilings; encoded observation bytes cannot self-authorize broader capture.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for an execution/specification binding
/// mismatch, unknown closed value, malformed terminal or capture evidence,
/// invalid reason/time values, or zero ordering counters.
pub fn decode_execution_observation_v1(
    bytes: &[u8],
    limits: DecodeLimits,
    specification: &ExecutionSpecV1,
) -> Result<ExecutionObservationV1, CanonicalCborError> {
    let limits = execution_item_limits(limits, MAX_EXECUTION_OBSERVATION_CBOR_ITEMS);
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(10)?;
    decoder.exact("execution observation version", 1)?;
    let execution = ExecutionId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let specification_digest = ObjectDigest::from_bytes(exact_bytes(&mut decoder, 32)?);
    let phase = decode_observation_phase(&mut decoder)?;
    let desired_generation = DesiredGeneration::new(decoder.unsigned()?);
    let sequence = ObservationSequence::new(decoder.unsigned()?);
    let terminal_result = decode_terminal_result(&mut decoder)?;
    let captured_output = decode_captured_output(&mut decoder)?;
    let reason = ReasonCode::new(decoder.text(128)?.to_owned())
        .map_err(|error| semantics("execution observation reason", error))?;
    decoder.array(2)?;
    let seconds = decoder.signed()?;
    let nanoseconds = decode_u32(&mut decoder, "execution observation nanoseconds")?;
    let transition_time = TransitionTime::new(seconds, nanoseconds)
        .map_err(|error| semantics("execution observation time", error))?;
    decoder.finish()?;
    let observation = ExecutionObservationV1::new(
        specification,
        phase,
        desired_generation,
        sequence,
        terminal_result,
        captured_output,
        reason,
        transition_time,
    )
    .map_err(|error| semantics("execution observation", error))?;
    if observation.execution() != execution
        || observation.specification_digest() != specification_digest
    {
        return Err(semantics(
            "execution observation",
            InvalidExecutionSpec::InvalidObservation,
        ));
    }
    Ok(observation)
}

fn encode_target(encoder: &mut Encoder, target: &ExecutionTargetV1) {
    encoder.array(6);
    encoder.bytes(target.sandbox().as_bytes());
    encoder.bytes(target.incarnation().as_bytes());
    encoder.unsigned(target.assignment_epoch().get());
    encoder.bytes(target.assignment_digest().as_bytes());
    encoder.unsigned(target.namespace_generation().get());
    encoder.bytes(target.payload_boot_id().as_bytes());
}

fn decode_target(decoder: &mut Decoder<'_>) -> Result<ExecutionTargetV1, CanonicalCborError> {
    decoder.array(6)?;
    let sandbox = SandboxId::from_bytes(exact_bytes(decoder, 16)?);
    let incarnation = IncarnationId::from_bytes(exact_bytes(decoder, 16)?);
    let assignment_epoch = AssignmentEpoch::new(decoder.unsigned()?);
    let assignment_digest = ObjectDigest::from_bytes(exact_bytes(decoder, 32)?);
    let namespace_generation = NamespaceGeneration::new(decoder.unsigned()?);
    let payload_boot_id = PayloadBootId::new(exact_bytes(decoder, 16)?)
        .map_err(|error| semantics("payload boot identity", error))?;
    ExecutionTargetV1::new(
        sandbox,
        incarnation,
        assignment_epoch,
        assignment_digest,
        namespace_generation,
        payload_boot_id,
    )
    .map_err(|error| semantics("execution target", error))
}

fn encode_command(encoder: &mut Encoder, command: &ExecutionCommandV1) {
    encoder.array(4);
    encoder.array(command.arguments().len());
    for argument in command.arguments() {
        encoder.bytes(argument);
    }
    encoder.array(command.environment_overlay().len());
    for entry in command.environment_overlay() {
        encoder.array(2);
        encoder.text(entry.name());
        encoder.bytes(entry.value());
    }
    encode_path(encoder, command.working_directory());
    encode_credentials(encoder, command.credentials());
}

fn decode_command(decoder: &mut Decoder<'_>) -> Result<ExecutionCommandV1, CanonicalCborError> {
    decoder.array(4)?;
    let arguments = decode_arguments(decoder)?;
    let environment = decode_environment_overlay(decoder)?;
    let working_directory = decode_path(decoder)?;
    let credentials = decode_credentials(decoder)?;
    ExecutionCommandV1::new(arguments, environment, working_directory, credentials)
        .map_err(|error| semantics("execution command", error))
}

fn decode_arguments(decoder: &mut Decoder<'_>) -> Result<Vec<Vec<u8>>, CanonicalCborError> {
    let length = decoder.bounded_array_len(MAX_EXECUTION_ARGUMENTS)?;
    let mut remaining = MAX_EXECUTION_ARGUMENT_BYTES;
    let mut arguments = Vec::with_capacity(length);
    for _ in 0..length {
        let argument = decoder.bytes(remaining.min(MAX_EXECUTION_ARGUMENT_STRING_BYTES))?;
        remaining = remaining
            .checked_sub(argument.len())
            .ok_or(CanonicalCborError::ItemBudgetExceeded)?;
        arguments.push(argument.to_vec());
    }
    Ok(arguments)
}

fn decode_environment_overlay(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<ExecutionEnvironmentEntry>, CanonicalCborError> {
    let length = decoder.bounded_array_len(MAX_EXECUTION_ENVIRONMENT_ENTRIES)?;
    let mut remaining = MAX_EXECUTION_ENVIRONMENT_BYTES;
    let mut environment = Vec::with_capacity(length);
    for _ in 0..length {
        decoder.array(2)?;
        let name = decoder.text(remaining.min(MAX_EXECUTION_ENVIRONMENT_NAME_BYTES))?;
        remaining = remaining
            .checked_sub(name.len())
            .ok_or(CanonicalCborError::ItemBudgetExceeded)?;
        let value = decoder.bytes(remaining.min(MAX_EXECUTION_ENVIRONMENT_VALUE_BYTES))?;
        remaining = remaining
            .checked_sub(value.len())
            .ok_or(CanonicalCborError::ItemBudgetExceeded)?;
        let entry = ExecutionEnvironmentEntry::new(name.to_owned(), value.to_vec())
            .map_err(|error| semantics("execution environment entry", error))?;
        environment.push(entry);
    }
    Ok(environment)
}

fn encode_argument_envelope(encoder: &mut Encoder, envelope: &ExecutionArgumentEnvelopeV1) {
    encoder.array(3);
    encode_runtime_argument_evidence(encoder, envelope.runtime_evidence());
    encoder.unsigned(envelope.accounted_bytes());
    encoder.bytes(envelope.effective_environment_digest().as_bytes());
}

fn decode_argument_envelope(
    decoder: &mut Decoder<'_>,
) -> Result<ExecutionArgumentEnvelopeV1, CanonicalCborError> {
    decoder.array(3)?;
    let runtime_evidence = decode_runtime_argument_evidence(decoder)?;
    let accounted = decoder.unsigned()?;
    let digest = ObjectDigest::from_bytes(exact_bytes(decoder, 32)?);
    if accounted == 0 || digest.as_bytes() == &[0; 32] {
        return Err(semantics(
            "execution argument envelope",
            InvalidExecutionSpec::ArgumentEnvelopeMismatch,
        ));
    }
    Ok(ExecutionArgumentEnvelopeV1::from_claimed_parts(
        runtime_evidence,
        accounted,
        digest,
    ))
}

fn encode_runtime_argument_evidence(
    encoder: &mut Encoder,
    evidence: &ExecutionRuntimeArgumentLimitV1,
) {
    encoder.array(5);
    encode_feature(encoder, evidence.runtime_profile());
    encoder.bytes(evidence.runtime_profile_commitment().as_bytes());
    encode_target(encoder, evidence.target());
    encoder.unsigned(evidence.runtime_limit_bytes());
    encoder.bytes(evidence.evidence_commitment().as_bytes());
}

fn decode_runtime_argument_evidence(
    decoder: &mut Decoder<'_>,
) -> Result<ExecutionRuntimeArgumentLimitV1, CanonicalCborError> {
    decoder.array(5)?;
    let runtime_profile = decode_feature(decoder)?;
    let runtime_profile_commitment = ObjectDigest::from_bytes(exact_bytes(decoder, 32)?);
    let target = decode_target(decoder)?;
    let runtime_limit_bytes = decoder.unsigned()?;
    let claimed_commitment = ObjectDigest::from_bytes(exact_bytes(decoder, 32)?);
    let evidence = ExecutionRuntimeArgumentLimitV1::new(
        runtime_profile,
        runtime_profile_commitment,
        target,
        runtime_limit_bytes,
    )
    .map_err(|error| semantics("runtime argument-limit evidence", error))?;
    if evidence.evidence_commitment() != claimed_commitment {
        return Err(semantics(
            "runtime argument-limit evidence",
            InvalidExecutionSpec::RuntimeArgumentEvidenceMismatch,
        ));
    }
    Ok(evidence)
}

fn encode_credentials(encoder: &mut Encoder, credentials: &ExecutionCredentialsV1) {
    encoder.array(3);
    encoder.unsigned(u64::from(credentials.user_id()));
    encoder.unsigned(u64::from(credentials.primary_group_id()));
    encoder.array(credentials.supplementary_group_ids().len());
    for group_id in credentials.supplementary_group_ids() {
        encoder.unsigned(u64::from(*group_id));
    }
}

fn decode_credentials(
    decoder: &mut Decoder<'_>,
) -> Result<ExecutionCredentialsV1, CanonicalCborError> {
    decoder.array(3)?;
    let user_id = decode_u32(decoder, "execution user ID")?;
    let primary_group_id = decode_u32(decoder, "execution primary group ID")?;
    let group_count = decoder.bounded_array_len(MAX_EXECUTION_SUPPLEMENTARY_GROUPS)?;
    let mut supplementary_group_ids = Vec::with_capacity(group_count);
    for _ in 0..group_count {
        supplementary_group_ids.push(decode_u32(decoder, "execution supplementary group ID")?);
    }
    ExecutionCredentialsV1::new(user_id, primary_group_id, supplementary_group_ids)
        .map_err(|error| semantics("execution credentials", error))
}

fn encode_resource_admission(encoder: &mut Encoder, resources: &ExecutionResourceAdmissionV1) {
    encoder.array(5);
    encoder.array(resources.requested().len());
    for request in resources.requested() {
        encoder.array(3);
        encoder.unsigned(request.dimension() as u64);
        encode_requested_resource_value(encoder, request.value());
        encode_feature(encoder, request.enforcement());
    }
    encoder.array(resources.admitted().len());
    for admitted in resources.admitted() {
        encoder.array(3);
        encoder.unsigned(admitted.dimension() as u64);
        encode_admitted_resource_value(encoder, admitted.value());
        encode_feature(encoder, admitted.enforcement());
    }
    encode_resource_profile(encoder, resources.parent_profile());
    encoder.bytes(resources.parent_profile_commitment().as_bytes());
    encode_output_byte_admission(encoder, resources.output_bytes());
}

fn decode_resource_admission(
    decoder: &mut Decoder<'_>,
    nested_limits: DecodeLimits,
) -> Result<ExecutionResourceAdmissionV1, CanonicalCborError> {
    decoder.array(5)?;
    let requested =
        decoder.bounded_vec(MAX_EXECUTION_RESOURCE_SETTINGS, decode_resource_request)?;
    let admitted =
        decoder.bounded_vec(MAX_EXECUTION_RESOURCE_SETTINGS, decode_resource_sublimit)?;
    let parent_profile = decode_resource_profile(decoder)?;
    let parent_commitment = ObjectDigest::from_bytes(exact_bytes(decoder, 32)?);
    let output_bytes = decode_output_byte_admission(decoder, nested_limits)?;
    ExecutionResourceAdmissionV1::new(
        requested,
        admitted,
        parent_profile,
        parent_commitment,
        output_bytes,
    )
    .map_err(|error| semantics("execution resource admission", error))
}

fn encode_output_byte_admission(encoder: &mut Encoder, admission: &ExecutionOutputByteAdmissionV1) {
    encoder.array(6);
    encoder.unsigned(ResourceDimension::OutputBytes as u64);
    encoder.unsigned(admission.requested_bytes());
    encoder.unsigned(admission.admitted_bytes());
    encoder.bytes(admission.assignment().canonical_bytes());
    encoder.bytes(admission.reservation_commitment().as_bytes());
    encode_feature(encoder, admission.enforcement());
}

fn decode_output_byte_admission(
    decoder: &mut Decoder<'_>,
    nested_limits: DecodeLimits,
) -> Result<ExecutionOutputByteAdmissionV1, CanonicalCborError> {
    decoder.array(6)?;
    decoder.exact(
        "execution output reservation dimension",
        ResourceDimension::OutputBytes as u64,
    )?;
    let requested_bytes = decoder.unsigned()?;
    let admitted_bytes = decoder.unsigned()?;
    let assignment_bytes = decoder.bytes(MAX_EXECUTION_OUTPUT_ASSIGNMENT_BYTES)?;
    let assignment = CanonicalAssignmentManifestV1::from_canonical_bytes(
        assignment_bytes,
        embedded_assignment_limits(nested_limits, assignment_bytes.len()),
    )?;
    let claimed_commitment = ObjectDigest::from_bytes(exact_bytes(decoder, 32)?);
    let claimed_enforcement = decode_feature(decoder)?;
    let admission =
        ExecutionOutputByteAdmissionV1::new(requested_bytes, admitted_bytes, assignment)
            .map_err(|error| semantics("execution output-byte admission", error))?;
    if admission.reservation_commitment() != claimed_commitment
        || admission.enforcement() != &claimed_enforcement
    {
        return Err(semantics(
            "execution output-byte admission",
            InvalidExecutionSpec::InvalidOutputAdmission,
        ));
    }
    Ok(admission)
}

fn encode_requested_resource_value(encoder: &mut Encoder, value: ExecutionResourceRequestValueV1) {
    match value {
        ExecutionResourceRequestValueV1::Inherit => {
            encoder.array(1);
            encoder.unsigned(0);
        }
        ExecutionResourceRequestValueV1::Maximum(maximum) => {
            encoder.array(2);
            encoder.unsigned(1);
            encoder.unsigned(maximum);
        }
        ExecutionResourceRequestValueV1::RelativeWeight(weight) => {
            encoder.array(2);
            encoder.unsigned(2);
            encoder.unsigned(u64::from(weight));
        }
    }
}

fn decode_resource_request(
    decoder: &mut Decoder<'_>,
) -> Result<ExecutionResourceRequestV1, CanonicalCborError> {
    decoder.array(3)?;
    let dimension = decode_limit_dimension(decoder)?;
    let value = decode_requested_resource_value(decoder)?;
    let claimed_enforcement = decode_feature(decoder)?;
    let request = ExecutionResourceRequestV1::new(dimension, value)
        .map_err(|error| semantics("execution resource request", error))?;
    if request.enforcement() != &claimed_enforcement {
        return Err(semantics(
            "execution resource request",
            InvalidExecutionSpec::ResourceEnforcementMismatch,
        ));
    }
    Ok(request)
}

fn decode_requested_resource_value(
    decoder: &mut Decoder<'_>,
) -> Result<ExecutionResourceRequestValueV1, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let kind = decoder.closed("execution requested resource value", 2)?;
    match (kind, length) {
        (0, 1) => Ok(ExecutionResourceRequestValueV1::Inherit),
        (1, 2) => Ok(ExecutionResourceRequestValueV1::Maximum(
            decoder.unsigned()?,
        )),
        (2, 2) => Ok(ExecutionResourceRequestValueV1::RelativeWeight(decode_u16(
            decoder,
            "execution requested resource weight",
        )?)),
        _ => Err(CanonicalCborError::ArrayLength {
            expected: if kind == 0 { 1 } else { 2 },
            actual: length,
            offset,
        }),
    }
}

fn encode_admitted_resource_value(encoder: &mut Encoder, value: ExecutionResourceSublimitValueV1) {
    encoder.array(2);
    match value {
        ExecutionResourceSublimitValueV1::Maximum(maximum) => {
            encoder.unsigned(0);
            encoder.unsigned(maximum);
        }
        ExecutionResourceSublimitValueV1::RelativeWeight(weight) => {
            encoder.unsigned(1);
            encoder.unsigned(u64::from(weight));
        }
    }
}

fn decode_resource_sublimit(
    decoder: &mut Decoder<'_>,
) -> Result<ExecutionResourceSublimitV1, CanonicalCborError> {
    decoder.array(3)?;
    let dimension = decode_limit_dimension(decoder)?;
    decoder.array(2)?;
    let value = match decoder.closed("execution admitted resource value", 1)? {
        0 => ExecutionResourceSublimitValueV1::Maximum(decoder.unsigned()?),
        1 => ExecutionResourceSublimitValueV1::RelativeWeight(decode_u16(
            decoder,
            "execution admitted resource weight",
        )?),
        _ => unreachable!("closed execution admitted resource value"),
    };
    let claimed_enforcement = decode_feature(decoder)?;
    let sublimit = ExecutionResourceSublimitV1::new(dimension, value)
        .map_err(|error| semantics("execution resource sublimit", error))?;
    if sublimit.enforcement() != &claimed_enforcement {
        return Err(semantics(
            "execution resource sublimit",
            InvalidExecutionSpec::ResourceEnforcementMismatch,
        ));
    }
    Ok(sublimit)
}

fn encode_resource_profile(encoder: &mut Encoder, profile: &ResourceProfile) {
    encoder.array(profile.limits().len());
    for limit in profile.limits() {
        encoder.array(3);
        encoder.unsigned(limit.dimension() as u64);
        encode_parent_limit_value(encoder, limit.value());
        encode_feature(encoder, limit.enforcement());
    }
}

fn decode_resource_profile(
    decoder: &mut Decoder<'_>,
) -> Result<ResourceProfile, CanonicalCborError> {
    let limits = decoder.bounded_vec(MAX_EXECUTION_RESOURCE_SETTINGS, decode_parent_limit)?;
    ResourceProfile::new(limits).map_err(|error| semantics("parent resource profile", error))
}

fn encode_parent_limit_value(encoder: &mut Encoder, value: LimitValue) {
    match value {
        LimitValue::Inherited => {
            encoder.array(1);
            encoder.unsigned(0);
        }
        LimitValue::Bounded(maximum) => {
            encoder.array(2);
            encoder.unsigned(1);
            encoder.unsigned(maximum);
        }
        LimitValue::Unlimited(grant) => {
            encoder.array(2);
            encoder.unsigned(2);
            encoder.bytes(grant.as_bytes());
        }
    }
}

fn decode_parent_limit(decoder: &mut Decoder<'_>) -> Result<Limit, CanonicalCborError> {
    decoder.array(3)?;
    let dimension = decode_limit_dimension(decoder)?;
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let kind = decoder.closed("parent resource limit value", 2)?;
    let value = match (kind, length) {
        (0, 1) => LimitValue::Inherited,
        (1, 2) => LimitValue::Bounded(decoder.unsigned()?),
        (2, 2) => LimitValue::Unlimited(GrantId::from_bytes(exact_bytes(decoder, 16)?)),
        _ => {
            return Err(CanonicalCborError::ArrayLength {
                expected: if kind == 0 { 1 } else { 2 },
                actual: length,
                offset,
            });
        }
    };
    let enforcement = decode_feature(decoder)?;
    Ok(Limit::new(dimension, value, enforcement))
}

fn decode_limit_dimension(decoder: &mut Decoder<'_>) -> Result<LimitDimension, CanonicalCborError> {
    Ok(match decoder.closed("execution resource dimension", 15)? {
        0 => LimitDimension::Bytes,
        1 => LimitDimension::Inodes,
        2 => LimitDimension::Processes,
        3 => LimitDimension::Memory,
        4 => LimitDimension::CpuWeight,
        5 => LimitDimension::CpuQuota,
        6 => LimitDimension::IoWeight,
        7 => LimitDimension::IoBandwidth,
        8 => LimitDimension::MountCount,
        9 => LimitDimension::OpenFiles,
        10 => LimitDimension::FuseRequests,
        11 => LimitDimension::FuseMemory,
        12 => LimitDimension::CacheBytes,
        13 => LimitDimension::SnapshotCount,
        14 => LimitDimension::ChildCount,
        15 => LimitDimension::ExecutionCount,
        _ => unreachable!("closed execution resource dimension"),
    })
}

fn encode_io(encoder: &mut Encoder, io: &ExecutionIoV1) {
    encoder.array(4);
    encoder.unsigned(match io.terminal_mode() {
        ExecutionTerminalModeV1::None => 0,
        ExecutionTerminalModeV1::Pty => 1,
    });
    match io.output_mode() {
        ExecutionOutputModeV1::Stream => {
            encoder.array(1);
            encoder.unsigned(0);
        }
        ExecutionOutputModeV1::Capture {
            maximum_stdout_bytes,
            maximum_stderr_bytes,
        } => {
            encoder.array(3);
            encoder.unsigned(1);
            encoder.unsigned(maximum_stdout_bytes);
            encoder.unsigned(maximum_stderr_bytes);
        }
    }
    encoder.unsigned(match io.disconnect_policy() {
        ExecutionDisconnectPolicyV1::Cancel => 0,
        ExecutionDisconnectPolicyV1::Continue => 1,
    });
    encode_access_route(encoder, io.access_route());
}

fn decode_io(decoder: &mut Decoder<'_>) -> Result<ExecutionIoV1, CanonicalCborError> {
    decoder.array(4)?;
    let terminal_mode = match decoder.closed("execution terminal mode", 1)? {
        0 => ExecutionTerminalModeV1::None,
        1 => ExecutionTerminalModeV1::Pty,
        _ => unreachable!("closed execution terminal mode"),
    };
    let output_mode = decode_output_mode(decoder)?;
    let disconnect_policy = match decoder.closed("execution disconnect policy", 1)? {
        0 => ExecutionDisconnectPolicyV1::Cancel,
        1 => ExecutionDisconnectPolicyV1::Continue,
        _ => unreachable!("closed execution disconnect policy"),
    };
    let access_route = decode_access_route(decoder)?;
    ExecutionIoV1::new(terminal_mode, output_mode, disconnect_policy, access_route)
        .map_err(|error| semantics("execution I/O policy", error))
}

fn decode_output_mode(
    decoder: &mut Decoder<'_>,
) -> Result<ExecutionOutputModeV1, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let mode = decoder.closed("execution output mode", 1)?;
    match (mode, length) {
        (0, 1) => Ok(ExecutionOutputModeV1::Stream),
        (1, 3) => Ok(ExecutionOutputModeV1::Capture {
            maximum_stdout_bytes: decoder.unsigned()?,
            maximum_stderr_bytes: decoder.unsigned()?,
        }),
        _ => Err(CanonicalCborError::ArrayLength {
            expected: if mode == 0 { 1 } else { 3 },
            actual: length,
            offset,
        }),
    }
}

fn encode_access_route(encoder: &mut Encoder, route: &ExecutionAccessRouteV1) {
    match route {
        ExecutionAccessRouteV1::Detached => {
            encoder.array(1);
            encoder.unsigned(0);
        }
        ExecutionAccessRouteV1::OpenSsh(route) => {
            let public_key = route.public_key();
            let capabilities = route.capabilities();
            encoder.array(5);
            encoder.unsigned(1);
            encoder.unsigned(match public_key.algorithm() {
                ExecutionPublicKeyAlgorithmV1::SshEd25519 => 0,
            });
            encoder.bytes(public_key.key_material());
            encoder.bytes(public_key.digest().as_bytes());
            encoder.array(capabilities.len());
            for capability in capabilities {
                encoder.unsigned(*capability as u64);
            }
        }
    }
}

fn decode_access_route(
    decoder: &mut Decoder<'_>,
) -> Result<ExecutionAccessRouteV1, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let route = decoder.closed("execution access route", 1)?;
    match (route, length) {
        (0, 1) => Ok(ExecutionAccessRouteV1::Detached),
        (1, 5) => {
            decoder.closed("execution public-key algorithm", 0)?;
            let key_material = exact_bytes(decoder, 32)?;
            let claimed_digest = ObjectDigest::from_bytes(exact_bytes(decoder, 32)?);
            let public_key = ExecutionPublicKeyV1::new_ssh_ed25519(key_material)
                .map_err(|error| semantics("execution public key", error))?;
            if public_key.digest() != claimed_digest {
                return Err(semantics(
                    "execution public key",
                    InvalidExecutionSpec::InvalidPublicKey,
                ));
            }
            let capabilities = decoder.bounded_vec(
                MAX_EXECUTION_ENDPOINT_CAPABILITIES,
                decode_endpoint_capability,
            )?;
            ExecutionAccessRouteV1::open_ssh(public_key, capabilities)
                .map_err(|error| semantics("execution access route", error))
        }
        _ => Err(CanonicalCborError::ArrayLength {
            expected: if route == 0 { 1 } else { 5 },
            actual: length,
            offset,
        }),
    }
}

fn decode_endpoint_capability(
    decoder: &mut Decoder<'_>,
) -> Result<ExecutionEndpointCapabilityV1, CanonicalCborError> {
    Ok(match decoder.closed("execution endpoint capability", 8)? {
        0 => ExecutionEndpointCapabilityV1::StandardInput,
        1 => ExecutionEndpointCapabilityV1::StandardOutput,
        2 => ExecutionEndpointCapabilityV1::StandardError,
        3 => ExecutionEndpointCapabilityV1::TerminalResize,
        4 => ExecutionEndpointCapabilityV1::SignalForwarding,
        5 => ExecutionEndpointCapabilityV1::Sftp,
        6 => ExecutionEndpointCapabilityV1::Git,
        7 => ExecutionEndpointCapabilityV1::TcpForwarding,
        8 => ExecutionEndpointCapabilityV1::AgentForwarding,
        _ => unreachable!("closed execution endpoint capability"),
    })
}

fn decode_base_environment(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<Environment, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(5)?;
    decoder.exact("embedded base environment version", 1)?;
    let closure = decoder
        .bounded_vec(MAX_EXECUTION_BASE_ENVIRONMENT_COLLECTION_ITEMS, |decoder| {
            decode_descriptor_for_role(decoder, DescriptorRole::EnvironmentClosure)
        })?;
    let variables = decoder.bounded_vec(
        MAX_EXECUTION_ENVIRONMENT_ENTRIES,
        decode_base_environment_entry,
    )?;
    let command_search_path =
        decoder.bounded_vec(MAX_EXECUTION_BASE_ENVIRONMENT_COLLECTION_ITEMS, decode_path)?;
    let required_features =
        decoder.bounded_vec(MAX_EXECUTION_BASE_ENVIRONMENT_FEATURES, decode_feature)?;
    decoder.finish()?;
    Environment::new(closure, variables, command_search_path, required_features)
        .map_err(|error| semantics("embedded base environment", error))
}

fn decode_base_environment_entry(
    decoder: &mut Decoder<'_>,
) -> Result<EnvironmentEntry, CanonicalCborError> {
    decoder.array(2)?;
    let name = decoder.text(MAX_ENVIRONMENT_NAME_BYTES)?.to_owned();
    let value = decoder.text(MAX_ENVIRONMENT_VALUE_BYTES)?.to_owned();
    EnvironmentEntry::new(name, value).map_err(|error| semantics("base environment entry", error))
}

fn encode_path(encoder: &mut Encoder, path: &RelativePath) {
    encoder.array(path.components().len());
    for component in path.components() {
        encoder.bytes(component.as_bytes());
    }
}

fn decode_path(decoder: &mut Decoder<'_>) -> Result<RelativePath, CanonicalCborError> {
    let components = decoder.bounded_vec(RelativePath::MAX_COMPONENTS, |decoder| {
        PathName::new(decoder.bytes(255)?.to_vec())
            .map_err(|error| semantics("working-directory component", error))
    })?;
    RelativePath::new(components).map_err(|error| semantics("working directory", error))
}

fn encode_terminal_result(encoder: &mut Encoder, result: Option<ExecutionTerminalResultV1>) {
    match result {
        None => {
            encoder.array(1);
            encoder.unsigned(0);
        }
        Some(ExecutionTerminalResultV1::Exited { code }) => {
            encoder.array(2);
            encoder.unsigned(1);
            encoder.unsigned(u64::from(code));
        }
        Some(ExecutionTerminalResultV1::Signaled {
            signal,
            core_dumped,
        }) => {
            encoder.array(3);
            encoder.unsigned(2);
            encoder.unsigned(signal as u64);
            encoder.boolean(core_dumped);
        }
        Some(ExecutionTerminalResultV1::Canceled) => {
            encoder.array(1);
            encoder.unsigned(3);
        }
        Some(ExecutionTerminalResultV1::Failed { reason }) => {
            encoder.array(2);
            encoder.unsigned(4);
            encoder.unsigned(reason as u64);
        }
        Some(ExecutionTerminalResultV1::Lost) => {
            encoder.array(1);
            encoder.unsigned(5);
        }
    }
}

fn decode_terminal_result(
    decoder: &mut Decoder<'_>,
) -> Result<Option<ExecutionTerminalResultV1>, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let kind = decoder.closed("execution terminal result", 5)?;
    match (kind, length) {
        (0, 1) => Ok(None),
        (1, 2) => Ok(Some(ExecutionTerminalResultV1::Exited {
            code: decode_u8(decoder, "execution exit status")?,
        })),
        (2, 3) => Ok(Some(ExecutionTerminalResultV1::Signaled {
            signal: decode_execution_signal(decoder)?,
            core_dumped: decoder.boolean()?,
        })),
        (3, 1) => Ok(Some(ExecutionTerminalResultV1::Canceled)),
        (4, 2) => Ok(Some(ExecutionTerminalResultV1::Failed {
            reason: decode_execution_failure_reason(decoder)?,
        })),
        (5, 1) => Ok(Some(ExecutionTerminalResultV1::Lost)),
        _ => Err(CanonicalCborError::ArrayLength {
            expected: match kind {
                1 | 4 => 2,
                2 => 3,
                _ => 1,
            },
            actual: length,
            offset,
        }),
    }
}

fn decode_execution_signal(
    decoder: &mut Decoder<'_>,
) -> Result<ExecutionSignalV1, CanonicalCborError> {
    Ok(match decoder.closed("execution terminal signal", 22)? {
        0 => ExecutionSignalV1::Hangup,
        1 => ExecutionSignalV1::Interrupt,
        2 => ExecutionSignalV1::Quit,
        3 => ExecutionSignalV1::IllegalInstruction,
        4 => ExecutionSignalV1::Trap,
        5 => ExecutionSignalV1::Abort,
        6 => ExecutionSignalV1::Bus,
        7 => ExecutionSignalV1::FloatingPointException,
        8 => ExecutionSignalV1::Kill,
        9 => ExecutionSignalV1::User1,
        10 => ExecutionSignalV1::SegmentationFault,
        11 => ExecutionSignalV1::User2,
        12 => ExecutionSignalV1::BrokenPipe,
        13 => ExecutionSignalV1::Alarm,
        14 => ExecutionSignalV1::Terminate,
        15 => ExecutionSignalV1::StackFault,
        16 => ExecutionSignalV1::CpuLimit,
        17 => ExecutionSignalV1::FileSizeLimit,
        18 => ExecutionSignalV1::VirtualAlarm,
        19 => ExecutionSignalV1::Profiling,
        20 => ExecutionSignalV1::Io,
        21 => ExecutionSignalV1::Power,
        22 => ExecutionSignalV1::BadSystemCall,
        _ => unreachable!("closed execution terminal signal"),
    })
}

fn decode_execution_failure_reason(
    decoder: &mut Decoder<'_>,
) -> Result<ExecutionFailureReasonV1, CanonicalCborError> {
    Ok(match decoder.closed("execution failure reason", 8)? {
        0 => ExecutionFailureReasonV1::Admission,
        1 => ExecutionFailureReasonV1::Environment,
        2 => ExecutionFailureReasonV1::Resource,
        3 => ExecutionFailureReasonV1::Credentials,
        4 => ExecutionFailureReasonV1::Start,
        5 => ExecutionFailureReasonV1::Runtime,
        6 => ExecutionFailureReasonV1::OutputCapture,
        7 => ExecutionFailureReasonV1::Timeout,
        8 => ExecutionFailureReasonV1::Internal,
        _ => unreachable!("closed execution failure reason"),
    })
}

fn encode_captured_output(
    encoder: &mut Encoder,
    captured_output: Option<&ExecutionCapturedOutputV1>,
) {
    match captured_output {
        None => {
            encoder.array(1);
            encoder.unsigned(0);
        }
        Some(ExecutionCapturedOutputV1::Unavailable) => {
            encoder.array(1);
            encoder.unsigned(1);
        }
        Some(ExecutionCapturedOutputV1::Partial { streams }) => {
            encoder.array(2);
            encoder.unsigned(2);
            encode_captured_streams(encoder, streams);
        }
        Some(ExecutionCapturedOutputV1::Complete { streams }) => {
            encoder.array(2);
            encoder.unsigned(3);
            encode_captured_streams(encoder, streams);
        }
    }
}

fn encode_captured_streams(encoder: &mut Encoder, streams: &[CapturedStreamV1]) {
    encoder.array(streams.len());
    for stream in streams {
        encode_captured_stream(encoder, stream);
    }
}

fn decode_captured_output(
    decoder: &mut Decoder<'_>,
) -> Result<Option<ExecutionCapturedOutputV1>, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let kind = decoder.closed("execution captured-output disposition", 3)?;
    match (kind, length) {
        (0, 1) => Ok(None),
        (1, 1) => Ok(Some(ExecutionCapturedOutputV1::Unavailable)),
        (2, 2) => Ok(Some(ExecutionCapturedOutputV1::Partial {
            streams: decoder.bounded_vec(MAX_EXECUTION_CAPTURED_STREAMS, decode_captured_stream)?,
        })),
        (3, 2) => {
            let streams =
                decoder.bounded_vec(MAX_EXECUTION_CAPTURED_STREAMS, decode_captured_stream)?;
            let converted: Result<
                [CapturedStreamV1; MAX_EXECUTION_CAPTURED_STREAMS],
                Vec<CapturedStreamV1>,
            > = streams.try_into();
            let streams = match converted {
                Ok(streams) => streams,
                Err(streams) => {
                    return Err(CanonicalCborError::ArrayLength {
                        expected: MAX_EXECUTION_CAPTURED_STREAMS,
                        actual: streams.len(),
                        offset,
                    });
                }
            };
            Ok(Some(ExecutionCapturedOutputV1::Complete { streams }))
        }
        _ => Err(CanonicalCborError::ArrayLength {
            expected: if kind <= 1 { 1 } else { 2 },
            actual: length,
            offset,
        }),
    }
}

fn encode_captured_stream(encoder: &mut Encoder, stream: &CapturedStreamV1) {
    encoder.array(4);
    encoder.unsigned(stream.stream() as u64);
    encode_descriptor(encoder, stream.descriptor());
    encoder.unsigned(stream.captured_bytes());
    encoder.boolean(stream.truncated());
}

fn decode_captured_stream(
    decoder: &mut Decoder<'_>,
) -> Result<CapturedStreamV1, CanonicalCborError> {
    decoder.array(4)?;
    let stream = match decoder.closed("execution captured stream", 1)? {
        0 => ExecutionCapturedStreamKindV1::Stdout,
        1 => ExecutionCapturedStreamKindV1::Stderr,
        _ => unreachable!("closed execution captured stream"),
    };
    let descriptor = decode_descriptor_for_role(decoder, DescriptorRole::FileContent)?;
    let captured_bytes = decoder.unsigned()?;
    let truncated = decoder.boolean()?;
    CapturedStreamV1::new(stream, descriptor, captured_bytes, truncated)
        .map_err(|error| semantics("execution captured stream", error))
}

fn observation_phase_code(phase: ExecutionObservationPhaseV1) -> u64 {
    match phase {
        ExecutionObservationPhaseV1::Requested => 0,
        ExecutionObservationPhaseV1::Admitted => 1,
        ExecutionObservationPhaseV1::Starting => 2,
        ExecutionObservationPhaseV1::Running => 3,
        ExecutionObservationPhaseV1::Exited => 4,
        ExecutionObservationPhaseV1::Canceled => 5,
        ExecutionObservationPhaseV1::Failed => 6,
        ExecutionObservationPhaseV1::Lost => 7,
    }
}

fn decode_observation_phase(
    decoder: &mut Decoder<'_>,
) -> Result<ExecutionObservationPhaseV1, CanonicalCborError> {
    Ok(match decoder.closed("execution observation phase", 7)? {
        0 => ExecutionObservationPhaseV1::Requested,
        1 => ExecutionObservationPhaseV1::Admitted,
        2 => ExecutionObservationPhaseV1::Starting,
        3 => ExecutionObservationPhaseV1::Running,
        4 => ExecutionObservationPhaseV1::Exited,
        5 => ExecutionObservationPhaseV1::Canceled,
        6 => ExecutionObservationPhaseV1::Failed,
        7 => ExecutionObservationPhaseV1::Lost,
        _ => unreachable!("closed execution observation phase"),
    })
}

fn nested_environment_limits(parent: DecodeLimits, encoded_bytes: usize) -> DecodeLimits {
    DecodeLimits {
        maximum_bytes: encoded_bytes.min(parent.maximum_bytes),
        maximum_collection_items: MAX_EXECUTION_BASE_ENVIRONMENT_COLLECTION_ITEMS
            .min(parent.maximum_collection_items),
        maximum_total_items: MAX_EXECUTION_BASE_ENVIRONMENT_CBOR_ITEMS
            .min(encoded_bytes)
            .min(parent.maximum_total_items),
        maximum_byte_string_bytes: MAX_EXECUTION_STRING_BYTES.min(parent.maximum_byte_string_bytes),
        maximum_text_bytes: MAX_ENVIRONMENT_VALUE_BYTES.min(parent.maximum_text_bytes),
        maximum_depth: 64.min(parent.maximum_depth),
    }
}

fn embedded_assignment_limits(parent: DecodeLimits, encoded_bytes: usize) -> DecodeLimits {
    DecodeLimits {
        maximum_bytes: encoded_bytes
            .min(MAX_EXECUTION_OUTPUT_ASSIGNMENT_BYTES)
            .min(parent.maximum_bytes),
        maximum_collection_items: 4_096.min(parent.maximum_collection_items),
        maximum_total_items: 16_384.min(parent.maximum_total_items),
        maximum_byte_string_bytes: MAX_EXECUTION_OUTPUT_ASSIGNMENT_BYTES
            .min(parent.maximum_byte_string_bytes),
        maximum_text_bytes: 255.min(parent.maximum_text_bytes),
        maximum_depth: 64.min(parent.maximum_depth),
    }
}

fn execution_item_limits(mut limits: DecodeLimits, maximum_total_items: usize) -> DecodeLimits {
    limits.maximum_total_items = limits.maximum_total_items.min(maximum_total_items);
    limits
}

fn decode_u16(decoder: &mut Decoder<'_>, object: &'static str) -> Result<u16, CanonicalCborError> {
    let value = decoder.unsigned()?;
    u16::try_from(value).map_err(|_| CanonicalCborError::InvalidSemantics {
        object,
        message: format!("unsigned value {value} exceeds the v1 16-bit range"),
    })
}

fn decode_u8(decoder: &mut Decoder<'_>, object: &'static str) -> Result<u8, CanonicalCborError> {
    let value = decoder.unsigned()?;
    u8::try_from(value).map_err(|_| CanonicalCborError::InvalidSemantics {
        object,
        message: format!("unsigned value {value} exceeds the v1 8-bit range"),
    })
}

fn decode_u32(decoder: &mut Decoder<'_>, object: &'static str) -> Result<u32, CanonicalCborError> {
    let value = decoder.unsigned()?;
    u32::try_from(value).map_err(|_| CanonicalCborError::InvalidSemantics {
        object,
        message: format!("unsigned value {value} exceeds the v1 32-bit range"),
    })
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}
