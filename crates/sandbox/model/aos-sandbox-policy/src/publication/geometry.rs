//! Measures Q04 publication byte representations before their construction.
//!
//! Widths describe untrusted DATA, never a replay result, paid allocation or
//! publication capability. The actual role must admit all overlapping models,
//! decoder work and controls before invoking its original constructors.

use super::{CANDIDATE_V3_FIXED_BYTES, CompiledPolicyCandidateV1, PolicyCompilerJournalErrorV1,
    PolicyCompilerJournalKeyV1, PolicyCompilerJournalSchemaV1};
use aos_sandbox_protocol::domain_ledger::records::{
    ENVELOPE_FIXED_BYTES, reducer_payload_encoded_bytes_v1,
};

pub(crate) const DIAGNOSTICS_BODY_FIXED_BYTES: usize = 78 + 32;
pub(crate) const EFFECT_BODY_BYTES: usize = 527;
pub(crate) const CURRENT_BODY_BYTES: usize = 314;

// These are the exact inputs used by encode_candidate_payload, including the
// four existing u32 lengths. Sharing this fold avoids a second wire-size recipe.
pub(crate) fn candidate_payload_bytes_v1(candidate: &CompiledPolicyCandidateV1) -> Option<usize> {
    let portable = candidate.portable();
    [portable.policy_bytes(), portable.optimization_bytes(),
        portable.namespace_graph_bytes(), portable.advisory_program_bytes()]
        .into_iter()
        .try_fold(0_usize, |total, field| total.checked_add(4)?.checked_add(field.len()))?
        .checked_add(CANDIDATE_V3_FIXED_BYTES)
}

// Field order is the actual Candidate, Diagnostics, Effect, Current transaction.
// Headers stay private to the native role; no caller can install paid state.
pub(crate) struct Q04PublicationByteShapeV1 {
    pub(crate) bodies: [usize; 4],
    pub(crate) key_identities: [usize; 4],
    pub(crate) keys: [usize; 4],
    pub(crate) reducer_payloads: [usize; 4],
    pub(crate) envelopes: [usize; 4],
}

// diagnostics_frame_bytes is the actual bounded canonical JSON frame length,
// counted by the existing canonical serializer after its fixed entry is paid.
// No configured byte ceiling substitutes for the retained candidate's shape.
pub(crate) fn q04_publication_byte_shape_v1(
    candidate: &CompiledPolicyCandidateV1,
    diagnostics_frame_bytes: usize,
) -> Result<Q04PublicationByteShapeV1, PolicyCompilerJournalErrorV1> {
    let invalid = || PolicyCompilerJournalErrorV1::NonCanonicalPublication;
    let bodies = [
        candidate_payload_bytes_v1(candidate).ok_or_else(invalid)?,
        DIAGNOSTICS_BODY_FIXED_BYTES.checked_add(diagnostics_frame_bytes).ok_or_else(invalid)?,
        EFFECT_BODY_BYTES,
        CURRENT_BODY_BYTES,
    ];
    let key_identities = [64, 64, 48, 32];
    let mut keys = [0; 4];
    let mut reducer_payloads = [0; 4];
    let mut envelopes = [0; 4];

    for index in 0..4 {
        keys[index] = PolicyCompilerJournalKeyV1::encoded_bytes_for_identity_v1(key_identities[index])?;
        // Every actual Policy member has a body companion and semantic tuple.
        // The encoder may deduplicate equal digests; two bounds that live
        // allocation without claiming either digest has already been checked.
        reducer_payloads[index] = reducer_payload_encoded_bytes_v1::<PolicyCompilerJournalSchemaV1>(
            bodies[index], 2,
        )?;
        envelopes[index] = ENVELOPE_FIXED_BYTES.checked_add(reducer_payloads[index]).ok_or_else(invalid)?;
    }

    Ok(Q04PublicationByteShapeV1 { bodies, key_identities, keys, reducer_payloads, envelopes })
}
