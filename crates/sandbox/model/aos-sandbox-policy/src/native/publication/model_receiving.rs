//! Prices schema replay models before the actual native publication claim.
//!
//! The actual held canonical row count/byte extent bounds generic replay and
//! schema joins. Strict output decoders use that same extent; none is run by
//! this invoice. Candidate ownership moves into verification and is not cloned.

use super::*;
use crate::publication::records;
use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;
use aos_sandbox_protocol::domain_ledger::records::ReplayProjectionRecordsCaptureV1;
use std::mem::size_of;

/// Bounds newly reached replay/decoder models and two actual validator clones.
///
/// The caller must fund this complete amount before its first validator clone
/// or schema replay. The already-resident original validator, native parser,
/// canonical journal maps and prospective preflight are excluded. The three
/// generic projection suppliers occur once. The actual Work supplies its own
/// adapter/Prepared/Pending controls separately; this is no funding grant.
pub(in crate::native) fn schema_replay_model_receiving_bytes_v1(
    actual_rows: usize,
    actual_encoded_bytes: usize,
    validator: &PolicyCompilerReplayValidatorV1,
) -> Option<usize> {
    type Capture = ReplayProjectionRecordsCaptureV1<PolicyCompilerJournalSchemaV1>;
    // Work passes validator.clone() to claim; claim clones that map into the
    // protected adapter and retains the passed map as its schema validator.
    let validator_clones = nodes::<ObjectDigest, PolicyPublicationPrerequisitesV1>(
        validator.authenticated_prerequisites.len(),
    )?
    .checked_mul(2)?
    .checked_add(size_of::<PolicyCompilerReplayValidatorV1>().checked_mul(4)?)?;
    let projection = Capture::receiving_construction_bytes_v1()?
        .checked_add(Capture::receiving_carrier_bytes_v1(actual_rows)?)?
        .checked_add(Capture::receiving_encoded_backing_bytes_v1(
            actual_encoded_bytes,
        )?)?;
    // Projection-wide Candidate/Current joins are additional schema indices.
    // The sum of all nested generation entries is bounded by actual rows.
    let joins = nodes::<[u8; 32], BTreeSet<u64>>(actual_rows)?
        .checked_add(nodes::<u64, ()>(actual_rows)?)?
        .checked_add(nodes::<[u8; 32], u64>(actual_rows)?)?
        .checked_add(size_of::<(
            BTreeMap<[u8; 32], BTreeSet<u64>>,
            BTreeMap<[u8; 32], u64>,
        )>())?;
    // Two lookup keys coexist in a projection join. Each owns an identity
    // and its canonical encoding; the third cell covers its constructor/return.
    // Widths come from the same canonical key measure, not the row byte extent.
    let lookup_identity = size_of::<ProjectId>()
        .checked_add(size_of::<SandboxId>())?
        .checked_add(size_of::<ObjectDigest>())?;
    let lookup_encoded =
        PolicyCompilerJournalKeyV1::encoded_bytes_for_identity_v1(lookup_identity).ok()?;
    let lookup_backing = lookup_identity
        .checked_add(lookup_encoded)?
        .checked_mul(3)?;
    // The Observed-Effect schema branch reconstructs its Prepared envelope for
    // the predecessor comparison. This is additional to generic replay copies.
    let effect_body = super::geometry::EFFECT_BODY_BYTES;
    let effect_reducer =
        aos_sandbox_protocol::domain_ledger::records::reducer_payload_encoded_bytes_v1::<
            PolicyCompilerJournalSchemaV1,
        >(effect_body, 2)
        .ok()?;
    let effect_envelope = effect_reducer
        .checked_add(aos_sandbox_protocol::domain_ledger::records::ENVELOPE_FIXED_BYTES)?;
    let observed_effect = effect_body
        .checked_add(effect_reducer.checked_mul(4)?)?
        .checked_add(effect_envelope.checked_mul(2)?)?
        .checked_add(size_of::<PolicyCompilerJournalEnvelopeV1>().checked_mul(2)?)?
        .checked_add(size_of::<
            Result<PolicyCompilerJournalEnvelopeV1, PolicyCompilerJournalErrorV1>,
        >())?;
    let headers = size_of::<records::DecodedCandidateHeaderV1>()
        .checked_mul(3)?
        .checked_add(size_of::<records::DecodedCurrentPolicyHeadV1>().checked_mul(3)?)?
        .checked_add(size_of::<records::DecodedEffectHeaderV1>().checked_mul(3)?)?
        .checked_add(size_of::<
            Result<records::DecodedCandidateHeaderV1, PolicyCompilerJournalErrorV1>,
        >())?
        .checked_add(size_of::<
            Result<records::DecodedCurrentPolicyHeadV1, PolicyCompilerJournalErrorV1>,
        >())?
        .checked_add(size_of::<
            Result<records::DecodedEffectHeaderV1, PolicyCompilerJournalErrorV1>,
        >())?
        .checked_add(size_of::<[PolicyCompilerJournalKeyV1; 3]>())?
        .checked_add(lookup_backing)?
        .checked_add(size_of::<Result<usize, DomainLedgerDataError>>().checked_mul(2)?)?
        .checked_add(size_of::<[ObjectDescriptor; 4]>().checked_mul(2)?)?
        .checked_add(size_of::<sha2::Sha256>().checked_mul(2)?)?;
    let portable = aos_sandbox_model::format::policy_decoding_receiving_bytes_v1(
        actual_encoded_bytes,
        DecodeLimits::default(),
    )?;
    let json = canonical_output::model_receiving_bytes_v1(actual_encoded_bytes)?;
    validator_clones
        .checked_add(projection)?
        .checked_add(joins)?
        .checked_add(headers)?
        .checked_add(observed_effect)?
        .checked_add(portable.max(json))
}

/// Bounds the actual new keyed replay/schema collections before growth.
///
/// Generic replay's seven named collections occur once. The two actual new
/// validator maps exclude the resident original. Candidate/current generation
/// maps contribute two outer indices and one aggregate nested generation set.
/// Namespace sequence/DAG indices and advisory semantic keys are alternative
/// output validators; closed class values and Rust carriers are not names.
pub(in crate::native) fn schema_replay_model_metadata_entries_v1(
    actual_rows: usize,
    actual_encoded_bytes: usize,
    validator: &PolicyCompilerReplayValidatorV1,
) -> Option<usize> {
    type Capture = ReplayProjectionRecordsCaptureV1<PolicyCompilerJournalSchemaV1>;
    let replay = Capture::receiving_named_entries_v2(actual_rows)?;
    let validators = validator.authenticated_prerequisites.len().checked_mul(2)?;
    let joins = actual_rows.checked_mul(3)?;
    let namespace = crate::namespace::portable_order_metadata_entries_v1(actual_encoded_bytes)?;
    let advisory = actual_encoded_bytes;
    replay
        .checked_add(validators)?
        .checked_add(joins)?
        .checked_add(namespace.max(advisory))
}
