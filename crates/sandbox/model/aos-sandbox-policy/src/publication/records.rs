//! Encodes and compares the existing exact Policy publication record formats.
//!
//! These byte/model/recovery comparisons borrow the actual schema/validator and
//! use the canonical output codec. They establish no native role or lender.

use super::*;
use super::geometry::{
    CURRENT_BODY_BYTES, DIAGNOSTICS_BODY_FIXED_BYTES, EFFECT_BODY_BYTES,
    candidate_payload_bytes_v1,
};

pub(crate) fn transaction_prerequisites(
    records: &[PolicyCompilerJournalEnvelopeV1],
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<PolicyPublicationPrerequisitesV1, PolicyCompilerJournalErrorV1> {
    let mut retained = None;
    for envelope in records {
        let candidate = match envelope.key().kind() {
            PolicyCompilerJournalRecordKindV1::Candidate => Some(
                validate_candidate_payload(policy_body(envelope, validator)?)?.prerequisite_tuple,
            ),
            PolicyCompilerJournalRecordKindV1::Effect => {
                Some(decode_effect_header(policy_body(envelope, validator)?)?.prerequisite_tuple)
            }
            PolicyCompilerJournalRecordKindV1::Current => {
                Some(decode_current_payload(policy_body(envelope, validator)?)?.prerequisite_tuple)
            }
            _ => None,
        };
        if let Some(candidate) = candidate {
            if retained.as_ref().is_some_and(|value| value != &candidate) {
                return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
            }
            retained = Some(candidate);
        }
    }
    retained.ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)
}

#[derive(Clone, Copy)]
pub(crate) struct CurrentPolicyHeadV1 {
    pub(crate) generation: u64,
    pub(crate) envelope_revision: u64,
    pub(crate) envelope_digest: ObjectDigest,
}

pub(crate) fn validate_policy_projection(
    projection: &PolicyCompilerJournalProjectionV1,
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    let mut candidate_generations = BTreeMap::<[u8; 32], BTreeSet<u64>>::new();
    let mut current_generations = BTreeMap::<[u8; 32], u64>::new();
    for envelope in projection.records() {
        validate_policy_key(envelope.key())?;
        match envelope.key().kind() {
            PolicyCompilerJournalRecordKindV1::Candidate => {
                let candidate = validate_candidate_payload(policy_body(envelope, validator)?)?;
                let target = envelope.key().identity()[..32]
                    .try_into()
                    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                if !candidate_generations
                    .entry(target)
                    .or_default()
                    .insert(candidate.generation)
                {
                    return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
                }
            }
            PolicyCompilerJournalRecordKindV1::Diagnostics => {
                decode_diagnostics_payload(policy_body(envelope, validator)?)?;
            }
            PolicyCompilerJournalRecordKindV1::Effect => {
                let effect = decode_effect_header(policy_body(envelope, validator)?)?;
                let target = &envelope.key().identity()[..32];
                let candidate_key = policy_key_from_identity(
                    PolicyCompilerJournalRecordKindV1::Candidate,
                    target,
                    effect.candidate,
                )?;
                let diagnostics_key = policy_key_from_identity(
                    PolicyCompilerJournalRecordKindV1::Diagnostics,
                    target,
                    effect.candidate,
                )?;
                let candidate = projection
                    .records()
                    .iter()
                    .find(|record| record.key() == &candidate_key)
                    .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                let diagnostics = projection
                    .records()
                    .iter()
                    .find(|record| record.key() == &diagnostics_key)
                    .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                let candidate_header =
                    validate_candidate_payload(policy_body(candidate, validator)?)?;
                if candidate_header.generation != effect.generation
                    || candidate_header.candidate != effect.candidate
                    || candidate_header.normalized_input != effect.normalized_input
                    || candidate_header.diagnostics != effect.diagnostics
                    || candidate_header.prerequisites != effect.prerequisites
                    || candidate_header.outputs != effect.outputs
                    || digest_bytes(DIAGNOSTICS_DOMAIN, policy_body(diagnostics, validator)?)
                        != effect.diagnostics
                {
                    return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
                }
            }
            PolicyCompilerJournalRecordKindV1::Current => {
                let current = decode_current_payload(policy_body(envelope, validator)?)?;
                let target = envelope
                    .key()
                    .identity()
                    .try_into()
                    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                if current_generations
                    .insert(target, current.generation)
                    .is_some()
                {
                    return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
                }
            }
            PolicyCompilerJournalRecordKindV1::Checkpoint => {}
        }
    }
    if candidate_generations.len() != current_generations.len() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    for (target, generations) in &candidate_generations {
        let current = current_generations
            .get(target)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let count = u64::try_from(generations.len())
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        if count != *current
            || generations
                .iter()
                .copied()
                .enumerate()
                .any(|(index, generation)| {
                    u64::try_from(index)
                        .ok()
                        .and_then(|value| value.checked_add(1))
                        != Some(generation)
                })
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
    }
    for current in projection
        .records()
        .iter()
        .filter(|record| record.key().kind() == PolicyCompilerJournalRecordKindV1::Current)
    {
        let head = decode_current_payload(policy_body(current, validator)?)?;
        let identity = current.key().identity();
        if identity.len() != 32 || head.generation != current.revision() {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let candidate_key = policy_key_from_identity(
            PolicyCompilerJournalRecordKindV1::Candidate,
            identity,
            head.candidate,
        )?;
        let diagnostic_key = policy_key_from_identity(
            PolicyCompilerJournalRecordKindV1::Diagnostics,
            identity,
            head.candidate,
        )?;
        let candidate = projection
            .records()
            .iter()
            .find(|record| record.key() == &candidate_key)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let diagnostics = projection
            .records()
            .iter()
            .find(|record| record.key() == &diagnostic_key)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let candidate_header = validate_candidate_payload(policy_body(candidate, validator)?)?;
        if candidate.revision() != 1
            || candidate.predecessor().is_some()
            || diagnostics.revision() != 1
            || diagnostics.predecessor().is_some()
            || !candidate_header.matches_current(&head)
            || digest_bytes(DIAGNOSTICS_DOMAIN, policy_body(diagnostics, validator)?)
                != head.diagnostics
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
    }
    for transaction in projection.transactions() {
        validate_policy_transaction(
            transaction.transaction_id(),
            transaction.records(),
            validator,
        )?;
    }
    Ok(())
}

pub(crate) fn validate_policy_transaction(
    transaction_id: [u8; 16],
    records: &[PolicyCompilerJournalEnvelopeV1],
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    use PolicyCompilerJournalRecordKindV1 as Kind;
    if records.len() == 1 && records[0].key().kind() == Kind::Checkpoint {
        return Ok(());
    }
    if records.len() == 1 && records[0].key().kind() == Kind::Effect {
        let effect = &records[0];
        let header = decode_effect_header(policy_body(effect, validator)?)?;
        if header.state != PolicyEffectStateV1::Observed || effect.revision() != 2 {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let mut prepared_body = policy_body(effect, validator)?.to_vec();
        prepared_body[330] = PolicyEffectStateV1::Prepared as u8;
        prepared_body[331..363].fill(0);
        let prepared =
            policy_reducer_envelope(effect.key().clone(), 1, None, &prepared_body, validator)?;
        if effect.predecessor() != Some(prepared.digest()) {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        return Ok(());
    }
    if !matches!(records.len(), 3 | 4) {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let one = |kind| {
        let mut matches = records.iter().filter(|record| record.key().kind() == kind);
        let first = matches.next();
        if matches.next().is_some() {
            None
        } else {
            first
        }
    };
    let candidate =
        one(Kind::Candidate).ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let diagnostics =
        one(Kind::Diagnostics).ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let effect = one(Kind::Effect);
    let current = one(Kind::Current);
    if effect.is_none() {
        let current = current.ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        if records.len() != 3 {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let candidate_header = validate_candidate_payload(policy_body(candidate, validator)?)?;
        let current_header = decode_current_payload(policy_body(current, validator)?)?;
        let target = &candidate.key().identity()[..32];
        if current.key().identity() != target
            || &diagnostics.key().identity()[..32] != target
            || candidate_header.generation != current_header.generation
            || candidate_header.candidate != current_header.candidate
            || candidate_header.normalized_input != current_header.normalized_input
            || candidate_header.diagnostics != current_header.diagnostics
            || candidate_header.prerequisites != current_header.prerequisites
            || candidate_header.prerequisite_tuple != current_header.prerequisite_tuple
            || digest_bytes(DIAGNOSTICS_DOMAIN, policy_body(diagnostics, validator)?)
                != candidate_header.diagnostics
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        return Ok(());
    }
    let effect = effect.ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    if (records.len() == 4) != current.is_some() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let candidate_header = validate_candidate_payload(policy_body(candidate, validator)?)?;
    let effect_header = decode_effect_header(policy_body(effect, validator)?)?;
    let target = &candidate.key().identity()[..32];
    if effect_header.state != PolicyEffectStateV1::Prepared
        || effect.key().identity()[32..] != transaction_id
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    if &diagnostics.key().identity()[..32] != target
        || &effect.key().identity()[..32] != target
        || candidate_header.generation != effect_header.generation
        || candidate_header.candidate != effect_header.candidate
        || candidate_header.normalized_input != effect_header.normalized_input
        || candidate_header.diagnostics != effect_header.diagnostics
        || candidate_header.prerequisites != effect_header.prerequisites
        || candidate_header.outputs != effect_header.outputs
        || candidate_header.prerequisite_tuple != effect_header.prerequisite_tuple
        || digest_bytes(DIAGNOSTICS_DOMAIN, policy_body(diagnostics, validator)?)
            != candidate_header.diagnostics
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    if let Some(current) = current {
        let current_header = decode_current_payload(policy_body(current, validator)?)?;
        if current.key().identity() != target
            || candidate_header.generation != current_header.generation
            || candidate_header.candidate != current_header.candidate
            || candidate_header.normalized_input != current_header.normalized_input
            || candidate_header.diagnostics != current_header.diagnostics
            || candidate_header.prerequisites != current_header.prerequisites
            || candidate_header.prerequisite_tuple != current_header.prerequisite_tuple
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
    }
    Ok(())
}

pub(crate) fn validate_policy_key(
    key: &PolicyCompilerJournalKeyV1,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    let identity = key.identity();
    let expected_length = match key.kind() {
        PolicyCompilerJournalRecordKindV1::Candidate
        | PolicyCompilerJournalRecordKindV1::Diagnostics => 64,
        PolicyCompilerJournalRecordKindV1::Effect => 48,
        PolicyCompilerJournalRecordKindV1::Current => 32,
        PolicyCompilerJournalRecordKindV1::Checkpoint => 32,
    };
    if identity.len() != expected_length {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let invalid_identity = match key.kind() {
        PolicyCompilerJournalRecordKindV1::Candidate
        | PolicyCompilerJournalRecordKindV1::Diagnostics => {
            identity[..16] == [0; 16]
                || identity[16..32] == [0; 16]
                || identity[32..].iter().all(|byte| *byte == 0)
        }
        PolicyCompilerJournalRecordKindV1::Effect => {
            identity[..16] == [0; 16] || identity[16..32] == [0; 16] || identity[32..] == [0; 16]
        }
        PolicyCompilerJournalRecordKindV1::Current => {
            identity[..16] == [0; 16] || identity[16..32] == [0; 16]
        }
        PolicyCompilerJournalRecordKindV1::Checkpoint => identity.iter().all(|byte| *byte == 0),
    };
    if invalid_identity {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    Ok(())
}

pub(crate) struct DecodedCurrentPolicyHeadV1 {
    pub(crate) project: ProjectId,
    pub(crate) sandbox: SandboxId,
    pub(crate) generation: u64,
    pub(crate) candidate: ObjectDigest,
    pub(crate) normalized_input: ObjectDigest,
    pub(crate) diagnostics: ObjectDigest,
    pub(crate) prerequisites: ObjectDigest,
    pub(crate) prerequisite_tuple: PolicyPublicationPrerequisitesV1,
}

/// Describes structurally validated Candidate fields as comparison DATA.
pub struct DecodedCandidateHeaderV1 {
    pub(crate) project: ProjectId,
    pub(crate) sandbox: SandboxId,
    pub(crate) generation: u64,
    pub(crate) candidate: ObjectDigest,
    pub(crate) normalized_input: ObjectDigest,
    pub(crate) diagnostics: ObjectDigest,
    pub(crate) prerequisites: ObjectDigest,
    pub(crate) prerequisite_tuple: PolicyPublicationPrerequisitesV1,
    pub(crate) outputs: [(ObjectDigest, u64); 4],
    pub(crate) preimage: [ObjectDigest; 5],
}

impl DecodedCandidateHeaderV1 {
    /// Copies the project claimed by the structurally checked Candidate.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Copies the sandbox claimed by the structurally checked Candidate.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Copies the structurally checked publication generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Borrows the four digest/size claims in canonical output order.
    #[must_use]
    pub const fn outputs(&self) -> &[(ObjectDigest, u64); 4] {
        &self.outputs
    }
}

impl DecodedCandidateHeaderV1 {
    pub(crate) fn matches_current(&self, current: &DecodedCurrentPolicyHeadV1) -> bool {
        self.project == current.project
            && self.sandbox == current.sandbox
            && self.generation == current.generation
            && self.candidate == current.candidate
            && self.normalized_input == current.normalized_input
            && self.diagnostics == current.diagnostics
            && self.prerequisites == current.prerequisites
            && self.prerequisite_tuple == current.prerequisite_tuple
    }
}

pub(crate) struct DecodedEffectHeaderV1 {
    pub(crate) state: PolicyEffectStateV1,
    pub(crate) observation: ObjectDigest,
    pub(crate) generation: u64,
    pub(crate) candidate: ObjectDigest,
    pub(crate) normalized_input: ObjectDigest,
    pub(crate) diagnostics: ObjectDigest,
    pub(crate) prerequisites: ObjectDigest,
    pub(crate) prerequisite_tuple: PolicyPublicationPrerequisitesV1,
    pub(crate) outputs: [(ObjectDigest, u64); 4],
}

pub(crate) fn current_policy_head(
    projection: &PolicyCompilerJournalProjectionV1,
    project: ProjectId,
    sandbox: SandboxId,
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<Option<CurrentPolicyHeadV1>, PolicyCompilerJournalErrorV1> {
    let key = policy_current_key(project, sandbox)?;
    projection
        .records()
        .iter()
        .find(|record| record.key() == &key)
        .map(|envelope| {
            let decoded = decode_current_payload(policy_body(envelope, validator)?)?;
            if decoded.generation != envelope.revision() {
                return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
            }
            Ok(CurrentPolicyHeadV1 {
                generation: decoded.generation,
                envelope_revision: envelope.revision(),
                envelope_digest: envelope.digest(),
            })
        })
        .transpose()
}

pub(crate) fn policy_key(
    kind: PolicyCompilerJournalRecordKindV1,
    project: ProjectId,
    sandbox: SandboxId,
    subject: ObjectDigest,
) -> Result<PolicyCompilerJournalKeyV1, PolicyCompilerJournalErrorV1> {
    if project.as_bytes() == &[0; 16]
        || sandbox.as_bytes() == &[0; 16]
        || subject.as_bytes() == &[0; 32]
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let mut identity = Vec::with_capacity(64);
    identity.extend_from_slice(project.as_bytes());
    identity.extend_from_slice(sandbox.as_bytes());
    identity.extend_from_slice(subject.as_bytes());
    Ok(PolicyCompilerJournalKeyV1::new(kind, identity)?)
}

pub(crate) fn policy_key_from_identity(
    kind: PolicyCompilerJournalRecordKindV1,
    target: &[u8],
    subject: ObjectDigest,
) -> Result<PolicyCompilerJournalKeyV1, PolicyCompilerJournalErrorV1> {
    if target.len() != 32 || subject.as_bytes() == &[0; 32] {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let mut identity = Vec::with_capacity(64);
    identity.extend_from_slice(target);
    identity.extend_from_slice(subject.as_bytes());
    Ok(PolicyCompilerJournalKeyV1::new(kind, identity)?)
}

pub(crate) fn policy_current_key(
    project: ProjectId,
    sandbox: SandboxId,
) -> Result<PolicyCompilerJournalKeyV1, PolicyCompilerJournalErrorV1> {
    if project.as_bytes() == &[0; 16] || sandbox.as_bytes() == &[0; 16] {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let mut identity = Vec::with_capacity(32);
    identity.extend_from_slice(project.as_bytes());
    identity.extend_from_slice(sandbox.as_bytes());
    Ok(PolicyCompilerJournalKeyV1::new(
        PolicyCompilerJournalRecordKindV1::Current,
        identity,
    )?)
}

pub(crate) fn policy_effect_key(
    project: ProjectId,
    sandbox: SandboxId,
    transaction: [u8; 16],
) -> Result<PolicyCompilerJournalKeyV1, PolicyCompilerJournalErrorV1> {
    if transaction == [0; 16] {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let mut identity = Vec::with_capacity(48);
    identity.extend_from_slice(project.as_bytes());
    identity.extend_from_slice(sandbox.as_bytes());
    identity.extend_from_slice(&transaction);
    Ok(PolicyCompilerJournalKeyV1::new(
        PolicyCompilerJournalRecordKindV1::Effect,
        identity,
    )?)
}

pub(crate) fn policy_reducer_envelope(
    key: PolicyCompilerJournalKeyV1,
    revision: u64,
    predecessor: Option<ObjectDigest>,
    canonical_body: &[u8],
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<PolicyCompilerJournalEnvelopeV1, PolicyCompilerJournalErrorV1> {
    let payload = encode_reducer_payload_with_validator::<PolicyCompilerJournalSchemaV1>(
        &key,
        canonical_body,
        validator,
    )?;
    Ok(PolicyCompilerJournalEnvelopeV1::new_with_validator(
        key,
        revision,
        predecessor,
        payload,
        validator,
    )?)
}

pub(crate) fn policy_body<'body>(
    envelope: &'body PolicyCompilerJournalEnvelopeV1,
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<&'body [u8], PolicyCompilerJournalErrorV1> {
    Ok(
        decode_reducer_payload_with_validator::<PolicyCompilerJournalSchemaV1>(
            envelope.key(),
            envelope.payload(),
            validator,
        )?
        .body(),
    )
}

pub(crate) fn output_descriptors(
    portable: &crate::PortablePolicyOutputV1,
) -> [(u8, PortableMediaType, &ObjectDescriptor); 4] {
    [
        (1, PortableMediaType::Policy, portable.policy_descriptor()),
        (
            2,
            PortableMediaType::Optimization,
            portable.optimization_descriptor(),
        ),
        (
            3,
            PortableMediaType::Content,
            portable.namespace_graph_descriptor(),
        ),
        (
            4,
            PortableMediaType::Content,
            portable.advisory_program_descriptor(),
        ),
    ]
}

pub(crate) fn encode_candidate_payload(
    generation: u64,
    verified: PublicationBodyFieldsV1<'_>,
    diagnostics: ObjectDigest,
) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
    let portable = verified.candidate.portable();
    let fields = [
        portable.policy_bytes(),
        portable.optimization_bytes(),
        portable.namespace_graph_bytes(),
        portable.advisory_program_bytes(),
    ];
    let capacity = candidate_payload_bytes_v1(verified.candidate)
        .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    bytes.extend_from_slice(CANDIDATE_MAGIC);
    bytes.extend_from_slice(&3_u16.to_be_bytes());
    bytes.extend_from_slice(verified.project.as_bytes());
    bytes.extend_from_slice(verified.sandbox.as_bytes());
    bytes.extend_from_slice(verified.candidate.commitment().digest().as_bytes());
    bytes.extend_from_slice(verified.normalized_input.as_bytes());
    bytes.extend_from_slice(diagnostics.as_bytes());
    bytes.extend_from_slice(verified.prerequisites.digest().as_bytes());
    append_prerequisite_tuple(&mut bytes, verified.prerequisites);
    bytes.extend_from_slice(&generation.to_be_bytes());
    for (media_code, expected_media, descriptor) in output_descriptors(portable) {
        if descriptor.media_type().as_str() != expected_media.as_str() {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        bytes.push(media_code);
        bytes.extend_from_slice(descriptor.digest().as_bytes());
        bytes.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
    }
    for commitment in verified.candidate.commitment_plan_digests() {
        bytes.extend_from_slice(commitment.as_bytes());
    }
    for field in fields {
        let length = u32::try_from(field.len())
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(bytes)
}

pub(crate) fn encode_diagnostics_payload(
    project: ProjectId,
    sandbox: SandboxId,
    candidate: ObjectDigest,
    canonical_diagnostics: &[u8],
) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
    validate_canonical_diagnostics(canonical_diagnostics)?;
    let length = u32::try_from(canonical_diagnostics.len())
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let mut bytes = Vec::with_capacity(DIAGNOSTICS_BODY_FIXED_BYTES + canonical_diagnostics.len());
    bytes.extend_from_slice(b"AOSPCD01");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(project.as_bytes());
    bytes.extend_from_slice(sandbox.as_bytes());
    bytes.extend_from_slice(candidate.as_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(canonical_diagnostics);
    bytes.extend_from_slice(digest_bytes(DIAGNOSTICS_DOMAIN, canonical_diagnostics).as_bytes());
    Ok(bytes)
}

pub(crate) fn decode_diagnostics_payload(
    bytes: &[u8],
) -> Result<&[u8], PolicyCompilerJournalErrorV1> {
    if bytes.len() < 111 || &bytes[..8] != b"AOSPCD01" || bytes[8..10] != 1_u16.to_be_bytes() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let length = usize::try_from(u32::from_be_bytes(
        bytes[74..78]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    ))
    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let payload_end = 78_usize
        .checked_add(length)
        .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    if length == 0 || bytes.len() != payload_end + 32 {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let payload = &bytes[78..payload_end];
    if digest_bytes(DIAGNOSTICS_DOMAIN, payload).as_bytes() != &bytes[payload_end..] {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    validate_canonical_diagnostics(payload)?;
    Ok(payload)
}

pub(crate) fn validate_canonical_diagnostics(
    bytes: &[u8],
) -> Result<(), PolicyCompilerJournalErrorV1> {
    canonical_output::validate_diagnostics(bytes)
}

pub(crate) fn encode_effect_payload(
    transaction_id: [u8; 16],
    generation: u64,
    verified: PublicationBodyFieldsV1<'_>,
    diagnostics: ObjectDigest,
) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
    let portable = verified.candidate.portable();
    let mut bytes = Vec::with_capacity(EFFECT_BODY_BYTES);
    bytes.extend_from_slice(b"AOSPCE01");
    bytes.extend_from_slice(&3_u16.to_be_bytes());
    bytes.extend_from_slice(verified.project.as_bytes());
    bytes.extend_from_slice(verified.sandbox.as_bytes());
    bytes.extend_from_slice(&transaction_id);
    bytes.extend_from_slice(verified.candidate.commitment().digest().as_bytes());
    bytes.extend_from_slice(verified.normalized_input.as_bytes());
    bytes.extend_from_slice(diagnostics.as_bytes());
    bytes.extend_from_slice(verified.prerequisites.digest().as_bytes());
    append_prerequisite_tuple(&mut bytes, verified.prerequisites);
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.push(PolicyEffectStateV1::Prepared as u8);
    bytes.extend_from_slice(&[0; 32]);
    for (media_code, expected_media, descriptor) in output_descriptors(portable) {
        if descriptor.media_type().as_str() != expected_media.as_str() {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        bytes.push(media_code);
        bytes.extend_from_slice(descriptor.digest().as_bytes());
        bytes.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
    }
    Ok(bytes)
}

pub(crate) fn encode_observed_effect_payload(
    prepared: &[u8],
    observation: ObjectDigest,
) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
    let header = decode_effect_header(prepared)?;
    if header.state != PolicyEffectStateV1::Prepared || observation.as_bytes() == &[0; 32] {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let mut observed = prepared.to_vec();
    observed[330] = PolicyEffectStateV1::Observed as u8;
    observed[331..363].copy_from_slice(observation.as_bytes());
    let decoded = decode_effect_header(&observed)?;
    if decoded.state != PolicyEffectStateV1::Observed || decoded.observation != observation {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    Ok(observed)
}

pub(crate) fn encode_current_payload(
    project: ProjectId,
    sandbox: SandboxId,
    generation: u64,
    candidate: ObjectDigest,
    normalized_input: ObjectDigest,
    diagnostics: ObjectDigest,
    prerequisites: &PolicyPublicationPrerequisitesV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CURRENT_BODY_BYTES);
    bytes.extend_from_slice(CURRENT_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(project.as_bytes());
    bytes.extend_from_slice(sandbox.as_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(candidate.as_bytes());
    bytes.extend_from_slice(normalized_input.as_bytes());
    bytes.extend_from_slice(diagnostics.as_bytes());
    bytes.extend_from_slice(prerequisites.digest().as_bytes());
    append_prerequisite_tuple(&mut bytes, prerequisites);
    bytes
}

pub(crate) fn append_prerequisite_tuple(
    bytes: &mut Vec<u8>,
    prerequisites: &PolicyPublicationPrerequisitesV1,
) {
    bytes.extend_from_slice(prerequisites.ancestry_head().as_bytes());
    bytes.extend_from_slice(prerequisites.compiler_authority_head().as_bytes());
    bytes.extend_from_slice(prerequisites.cache_domain_head().as_bytes());
    bytes.extend_from_slice(prerequisites.revocation_head().as_bytes());
    bytes.extend_from_slice(&prerequisites.generation().to_be_bytes());
}

pub(crate) fn decode_current_payload(
    bytes: &[u8],
) -> Result<DecodedCurrentPolicyHeadV1, PolicyCompilerJournalErrorV1> {
    if bytes.len() != 314 || &bytes[..8] != CURRENT_MAGIC || bytes[8..10] != 1_u16.to_be_bytes() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let generation = u64::from_be_bytes(
        bytes[42..50]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    let digest_at = |offset: usize| -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
        let digest = ObjectDigest::from_bytes(
            bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        );
        if digest.as_bytes() == &[0; 32] {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        Ok(digest)
    };
    if generation == 0 {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let prerequisites = digest_at(146)?;
    let prerequisite_tuple = decode_prerequisite_tuple(bytes, 178, prerequisites)?;
    Ok(DecodedCurrentPolicyHeadV1 {
        project: ProjectId::from_bytes(
            bytes[10..26]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        ),
        sandbox: SandboxId::from_bytes(
            bytes[26..42]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        ),
        generation,
        candidate: digest_at(50)?,
        normalized_input: digest_at(82)?,
        diagnostics: digest_at(114)?,
        prerequisites,
        prerequisite_tuple,
    })
}

pub(crate) fn decode_candidate_header(
    bytes: &[u8],
) -> Result<DecodedCandidateHeaderV1, PolicyCompilerJournalErrorV1> {
    if bytes.len() < CANDIDATE_V3_FIXED_BYTES
        || &bytes[..8] != CANDIDATE_MAGIC
        || bytes[8..10] != 3_u16.to_be_bytes()
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let digest_at = |offset: usize| -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
        let digest = ObjectDigest::from_bytes(
            bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        );
        if digest.as_bytes() == &[0; 32] {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        Ok(digest)
    };
    let mut outputs = [(ObjectDigest::from_bytes([0; 32]), 0_u64); 4];
    for (index, (output, offset)) in outputs
        .iter_mut()
        .zip([314_usize, 355, 396, 437])
        .enumerate()
    {
        if bytes[offset] != (index as u8) + 1 {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let size = u64::from_be_bytes(
            bytes[offset + 33..offset + 41]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        );
        if size == 0 {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        *output = (digest_at(offset + 1)?, size);
    }
    let generation = u64::from_be_bytes(
        bytes[306..314]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    if generation == 0 {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let preimage = [
        digest_at(CANDIDATE_PLAN_OFFSET)?,
        digest_at(CANDIDATE_PLAN_OFFSET + 32)?,
        digest_at(CANDIDATE_PLAN_OFFSET + 64)?,
        digest_at(CANDIDATE_PLAN_OFFSET + 96)?,
        digest_at(CANDIDATE_PLAN_OFFSET + 128)?,
    ];
    let prerequisites = digest_at(138)?;
    let prerequisite_tuple = decode_prerequisite_tuple(bytes, 170, prerequisites)?;
    Ok(DecodedCandidateHeaderV1 {
        project: ProjectId::from_bytes(
            bytes[10..26]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        ),
        sandbox: SandboxId::from_bytes(
            bytes[26..42]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        ),
        generation,
        candidate: digest_at(42)?,
        normalized_input: digest_at(74)?,
        diagnostics: digest_at(106)?,
        prerequisites,
        prerequisite_tuple,
        outputs,
        preimage,
    })
}

/// Checks domain bodies for a nonauthorizing protected-state readback.
pub(crate) fn validate_state_candidate_body(
    record: &aos_sandbox_protocol::domain_ledger::records::ProtectedCurrentRecordCandidateV1<
        PolicyCompilerJournalSchemaV1,
    >,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    validate_policy_key(record.key())?;
    let identity = record.key().identity();
    let body = record.body();
    let matches_identity = match record.key().kind() {
        PolicyCompilerJournalRecordKindV1::Candidate => {
            let header = validate_candidate_payload(body)?;
            body.get(10..42) == identity.get(..32)
                && identity.get(32..) == Some(header.candidate.as_bytes().as_slice())
        }
        PolicyCompilerJournalRecordKindV1::Current => {
            decode_current_payload(body)?;
            body.get(10..42) == Some(identity)
        }
        PolicyCompilerJournalRecordKindV1::Diagnostics => {
            decode_diagnostics_payload(body)?;
            body.get(10..74) == Some(identity)
        }
        PolicyCompilerJournalRecordKindV1::Effect => {
            decode_effect_header(body)?;
            body.get(10..58) == Some(identity)
        }
        // The existing structural decoder already validated checkpoint bytes.
        PolicyCompilerJournalRecordKindV1::Checkpoint => body.is_empty(),
    };
    if !matches_identity {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    Ok(())
}

pub(crate) fn validate_candidate_payload(
    bytes: &[u8],
) -> Result<DecodedCandidateHeaderV1, PolicyCompilerJournalErrorV1> {
    validated_candidate_body(bytes).map(|(header, _)| header)
}

/// Borrows every canonical V3 output with its exact field boundaries.
///
/// This validates complete preimage consistency, not current publication authority.
///
/// # Errors
///
/// Returns [`PolicyCompilerJournalErrorV1`] for unknown versions, malformed
/// framing, noncanonical output bytes, or a descriptor/commitment mismatch.
pub(crate) fn candidate_output_bytes(
    bytes: &[u8],
) -> Result<[&[u8]; 4], PolicyCompilerJournalErrorV1> {
    validated_candidate_body(bytes).map(|(_, outputs)| outputs)
}

/// Borrows structurally checked header/output claims without publication authority.
///
/// # Errors
/// Rejects unsupported versions, malformed/noncanonical outputs, descriptor
/// mismatches or incomplete/substituted V3 preimage consistency.
pub fn validated_candidate_body(
    bytes: &[u8],
) -> Result<(DecodedCandidateHeaderV1, [&[u8]; 4]), PolicyCompilerJournalErrorV1> {
    let header = decode_candidate_header(bytes)?;
    let mut cursor = CANDIDATE_V3_FIXED_BYTES;
    let mut outputs = [&[][..]; 4];
    for (index, (digest, expected_size)) in header.outputs.iter().enumerate() {
        let length_end = cursor
            .checked_add(4)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let length = usize::try_from(u32::from_be_bytes(
            bytes
                .get(cursor..length_end)
                .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        ))
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let payload_end = length_end
            .checked_add(length)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let payload = bytes
            .get(length_end..payload_end)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let actual_size = u64::try_from(payload.len())
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let media_kind = match index {
            0 => PortableMediaType::Policy,
            1 => PortableMediaType::Optimization,
            2 | 3 => PortableMediaType::Content,
            _ => return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication),
        };
        let media = MediaType::new(media_kind.as_str())
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        // Core descriptors bind the registered media type and exact length,
        // not just the payload. Reuse the compiler's descriptor profile.
        let actual_digest = descriptor_for_bytes(media, payload).digest();
        if actual_size == 0 || actual_size != *expected_size || actual_digest != *digest {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        match index {
            0 => {
                let decoded = decode_policy(payload, DecodeLimits::default())
                    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                if encode_policy(&decoded) != payload {
                    return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
                }
            }
            1 => {
                let decoded = decode_optimization(payload, DecodeLimits::default())
                    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                if encode_optimization(&decoded) != payload {
                    return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
                }
            }
            2 => canonical_output::validate_namespace(payload)?,
            3 => canonical_output::validate_advisory(payload)?,
            _ => return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication),
        }
        outputs[index] = payload;
        cursor = payload_end;
    }
    if cursor != bytes.len() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }

    {
        let media = |kind: PortableMediaType| {
            MediaType::new(kind.as_str())
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)
        };
        let descriptors = [
            ObjectDescriptor::new(
                media(PortableMediaType::Policy)?,
                header.outputs[0].0,
                header.outputs[0].1,
            ),
            ObjectDescriptor::new(
                media(PortableMediaType::Optimization)?,
                header.outputs[1].0,
                header.outputs[1].1,
            ),
            ObjectDescriptor::new(
                media(PortableMediaType::Content)?,
                header.outputs[2].0,
                header.outputs[2].1,
            ),
            ObjectDescriptor::new(
                media(PortableMediaType::Content)?,
                header.outputs[3].0,
                header.outputs[3].1,
            ),
        ];
        if compiled_policy_candidate_digest_v1(header.preimage, descriptors.each_ref())
            .map_err(crate::PolicyModelError::from)?
            != header.candidate
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
    }

    Ok((header, outputs))
}

/// Compares retained V3 claims with one complete typed compiler derivation.
///
/// This is shared byte consistency, not publication or read authority. The
/// eventual Root-last owner must independently authenticate input provenance,
/// the complete prerequisite tuple and current owner cuts. In particular,
/// neither a normalized-input digest nor these bytes reconstruct typed input.
///
/// # Errors
///
/// Rejects legacy evidence, changed target/generation/prerequisites, any
/// substituted plan, diagnostic or portable output, or noncanonical framing.
pub fn compare_recompiled_candidate_derivation_v1(
    bytes: &[u8],
    input: &PolicyCompilerInputV1,
    candidate: &CompiledPolicyCandidateV1,
    generation: u64,
    prerequisites: &PolicyPublicationPrerequisitesV1,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    let (header, outputs) = validated_candidate_body(bytes)?;
    let diagnostics = aos_sandbox_protocol::policy_data::canonical_bytes(
        DIAGNOSTICS_DOMAIN,
        candidate.explanation(),
    )
    .map_err(crate::PolicyModelError::from)?;
    if header.project != input.project().project()
        || header.sandbox != input.sandbox()
        || header.generation != generation
        || header.prerequisite_tuple != *prerequisites
        || header.prerequisites != prerequisites.digest()
        || header.normalized_input
            != normalized_policy_input_digest_v1(input)
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?
        || header.candidate != candidate.commitment().digest()
        || header.preimage != candidate.commitment_plan_digests()
        || header.diagnostics != digest_bytes(DIAGNOSTICS_DOMAIN, &diagnostics)
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }

    let portable = candidate.portable();
    let expected_bytes = [
        portable.policy_bytes(),
        portable.optimization_bytes(),
        portable.namespace_graph_bytes(),
        portable.advisory_program_bytes(),
    ];
    for (index, (_, _, descriptor)) in output_descriptors(portable).into_iter().enumerate() {
        if outputs[index] != expected_bytes[index]
            || header.outputs[index] != (descriptor.digest(), descriptor.encoded_size())
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
    }
    Ok(())
}

pub(crate) fn decode_effect_header(
    bytes: &[u8],
) -> Result<DecodedEffectHeaderV1, PolicyCompilerJournalErrorV1> {
    if bytes.len() != 527 || &bytes[..8] != b"AOSPCE01" || bytes[8..10] != 3_u16.to_be_bytes() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let digest_at = |offset: usize| -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
        let digest = ObjectDigest::from_bytes(
            bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        );
        if digest.as_bytes() == &[0; 32] {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        Ok(digest)
    };
    let mut outputs = [(ObjectDigest::from_bytes([0; 32]), 0_u64); 4];
    for (index, (output, offset)) in outputs
        .iter_mut()
        .zip([363_usize, 404, 445, 486])
        .enumerate()
    {
        if bytes[offset] != (index as u8) + 1 {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let descriptor = digest_at(offset + 1)?;
        let size = u64::from_be_bytes(
            bytes[offset + 33..offset + 41]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        );
        if size == 0 {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        *output = (descriptor, size);
    }
    let prerequisites = digest_at(154)?;
    let prerequisite_tuple = decode_prerequisite_tuple(bytes, 186, prerequisites)?;
    let generation = u64::from_be_bytes(
        bytes[322..330]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    if generation == 0 {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let state = match bytes[330] {
        1 => PolicyEffectStateV1::Prepared,
        2 => PolicyEffectStateV1::Observed,
        _ => return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication),
    };
    let observation = ObjectDigest::from_bytes(
        bytes[331..363]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    if (state == PolicyEffectStateV1::Prepared && observation.as_bytes() != &[0; 32])
        || (state == PolicyEffectStateV1::Observed && observation.as_bytes() == &[0; 32])
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    Ok(DecodedEffectHeaderV1 {
        state,
        observation,
        generation,
        candidate: digest_at(58)?,
        normalized_input: digest_at(90)?,
        diagnostics: digest_at(122)?,
        prerequisites,
        prerequisite_tuple,
        outputs,
    })
}

pub(crate) fn decode_prerequisite_tuple(
    bytes: &[u8],
    offset: usize,
    expected_digest: ObjectDigest,
) -> Result<PolicyPublicationPrerequisitesV1, PolicyCompilerJournalErrorV1> {
    let digest_at = |start: usize| -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
        Ok(ObjectDigest::from_bytes(
            bytes
                .get(start..start + 32)
                .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        ))
    };
    let generation_offset = offset
        .checked_add(128)
        .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let generation = u64::from_be_bytes(
        bytes
            .get(generation_offset..generation_offset + 8)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    let prerequisites = PolicyPublicationPrerequisitesV1::new(
        digest_at(offset)?,
        digest_at(offset + 32)?,
        digest_at(offset + 64)?,
        digest_at(offset + 96)?,
        generation,
    )?;
    if prerequisites.digest() != expected_digest {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    Ok(prerequisites)
}

pub(crate) fn prerequisite_digest(value: &PolicyPublicationPrerequisitesV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(PREREQUISITE_DOMAIN);
    hasher.update(value.ancestry_head.as_bytes());
    hasher.update(value.compiler_authority_head.as_bytes());
    hasher.update(value.cache_domain_head.as_bytes());
    hasher.update(value.revocation_head.as_bytes());
    hasher.update(value.generation.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(crate) fn digest_bytes(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    ObjectDigest::from_bytes(hasher.finalize().into())
}
