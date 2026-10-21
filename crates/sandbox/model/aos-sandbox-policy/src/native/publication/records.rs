//! Joins actual postcommit/effect custody to the sole portable record codec.

use super::*;

pub(super) fn validated_postcommit_prerequisites(
    validated: &ValidatedDomainPostcommitV1<'_, PolicyCompilerJournalSchemaV1>,
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<PolicyPublicationPrerequisitesV1, PolicyCompilerJournalErrorV1> {
    let mut retained = None;
    for record in validated.records() {
        let envelope = record.envelope();
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
            PolicyCompilerJournalRecordKindV1::Diagnostics
            | PolicyCompilerJournalRecordKindV1::Checkpoint => None,
        };
        if let Some(candidate) = candidate {
            if retained
                .as_ref()
                .is_some_and(|current| current != &candidate)
            {
                return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
            }
            retained = Some(candidate);
        }
    }
    retained.ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)
}

pub(super) fn policy_effect_observation_request(
    effect: &ProtectedDomainEnvelopeV1<PolicyCompilerJournalSchemaV1>,
    body: &[u8],
    settlement_transaction_id: [u8; 16],
    result: ObjectDigest,
    prerequisites: ObjectDigest,
) -> Result<PolicyEffectObservationRequestV1, PolicyCompilerJournalErrorV1> {
    let identity = effect.key().identity();
    let header = decode_effect_header(body)?;
    if identity.len() != 48
        || header.state != PolicyEffectStateV1::Prepared
        || settlement_transaction_id == [0; 16]
        || result.as_bytes() == &[0; 32]
        || header.prerequisites != prerequisites
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let project = ProjectId::from_bytes(
        identity[..16]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    let sandbox = SandboxId::from_bytes(
        identity[16..32]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    let effect_transaction_id = identity[32..48]
        .try_into()
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let mut output_hasher = Sha256::new();
    output_hasher.update(b"aos.sandbox.policy-compiler.effect-outputs.v1\0");
    for (digest, size) in header.outputs {
        output_hasher.update(digest.as_bytes());
        output_hasher.update(size.to_be_bytes());
    }

    Ok(PolicyEffectObservationRequestV1 {
        project,
        sandbox,
        effect_transaction_id,
        settlement_transaction_id,
        effect_predecessor: effect.digest(),
        outputs: ObjectDigest::from_bytes(output_hasher.finalize().into()),
        generation: header.generation,
        result,
        prerequisites,
    })
}

