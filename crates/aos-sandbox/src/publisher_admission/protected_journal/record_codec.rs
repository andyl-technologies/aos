//! Canonical protected Publisher records and reducer framing.
//!
//! Records begin with an eight-byte magic and a big-endian version. Integer
//! fields use big-endian encoding; identifiers and digests keep fixed widths.
//!
//! ```text
//! AOSPAM01: version, kind, key/value lengths, key, protected value
//! AOSPAH01: version, sequence, chain head, epoch, state/outstanding digests,
//!           outstanding count, poison bit (127 bytes)
//! AOSPAE01: version, transaction/permit/operation IDs, artifact/permit digests,
//!           checkpoint sequence/state/commitment, chain head (226 bytes)
//! AOSPAS01: version, disposition, reserved byte, reservation/effect lineage,
//!           terminal and poison budgets (308 bytes)
//! ```
//!
//! The protected journal owns semantic replay, capacity custody, and Journal
//! operations. These recipes retain its canonical bytes and validation order.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::domain_ledger::records::{
    bind_domain_capacity_request_v1, decode_reducer_payload_with_validator,
    encode_reducer_payload_with_validator, validate_domain_capacity_lineage_v1,
};

use super::{
    AdmissionLimits, AuthorityCheckpointV1, CHECKPOINT_COMMITMENT_DOMAIN,
    CapacitySettlementDispositionV1, CompletionEffectBindingV1, CompletionPermitV1,
    CompletionSettlementLineageV1, LedgerMutation, PublisherAdmissionJournalEnvelopeV1,
    PublisherAdmissionJournalErrorV1, PublisherAdmissionJournalKeyV1,
    PublisherAdmissionJournalSchemaV1, decode_protected_record_v1, maximum_admission_limits,
};

const HEAD_MAGIC: &[u8; 8] = b"AOSPAH01";
const MUTATION_MAGIC: &[u8; 8] = b"AOSPAM01";

/// Commits the canonical current head to the checkpoint domain.
pub(super) fn checkpoint_commitment(
    checkpoint: &AuthorityCheckpointV1,
    chain_head: ObjectDigest,
) -> ObjectDigest {
    let current = encode_current_head(checkpoint, chain_head);
    super::super::model::digest_parts(CHECKPOINT_COMMITMENT_DOMAIN, &[&current])
}

/// Encodes one complete protected ledger mutation.
///
/// # Errors
///
/// Returns an error if key or value lengths exceed the encoded widths.
pub(super) fn encode_mutation(
    mutation: &LedgerMutation,
) -> Result<Vec<u8>, PublisherAdmissionJournalErrorV1> {
    let key_length = u16::try_from(mutation.key.len())
        .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let value_length = u32::try_from(mutation.value.len())
        .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let mut bytes = Vec::with_capacity(19 + mutation.key.len() + mutation.value.len());
    bytes.extend_from_slice(MUTATION_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(mutation.kind as u8);
    bytes.extend_from_slice(&key_length.to_be_bytes());
    bytes.extend_from_slice(&value_length.to_be_bytes());
    bytes.extend_from_slice(&mutation.key);
    bytes.extend_from_slice(&mutation.value);
    Ok(bytes)
}

/// Decodes and checks one canonical protected ledger mutation.
///
/// # Errors
///
/// Returns an error for invalid framing, protected records, or canonical bytes.
pub(super) fn decode_mutation(
    bytes: &[u8],
    limits: AdmissionLimits,
) -> Result<LedgerMutation, PublisherAdmissionJournalErrorV1> {
    if bytes.len() < 17 || &bytes[..8] != MUTATION_MAGIC || bytes[8..10] != 1_u16.to_be_bytes() {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let key_length = usize::from(u16::from_be_bytes([bytes[11], bytes[12]]));
    let value_length = usize::try_from(u32::from_be_bytes([
        bytes[13], bytes[14], bytes[15], bytes[16],
    ]))
    .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let key_end = 17_usize
        .checked_add(key_length)
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let value_end = key_end
        .checked_add(value_length)
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    if value_end != bytes.len() {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let value = bytes[key_end..].to_vec();
    let decoded = decode_protected_record_v1(&value, limits)?;
    if decoded.kind as u8 != bytes[10] || decoded.key != bytes[17..key_end] {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let mutation = LedgerMutation {
        kind: decoded.kind,
        key: bytes[17..key_end].to_vec(),
        value,
    };
    if encode_mutation(&mutation)? != bytes {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok(mutation)
}

/// Encodes the reducer checkpoint and chain head.
pub(super) fn encode_current_head(
    checkpoint: &AuthorityCheckpointV1,
    chain_head: ObjectDigest,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(123);
    bytes.extend_from_slice(HEAD_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&checkpoint.sequence.to_be_bytes());
    bytes.extend_from_slice(chain_head.as_bytes());
    bytes.extend_from_slice(&checkpoint.epoch.get().to_be_bytes());
    bytes.extend_from_slice(checkpoint.state_digest.as_bytes());
    bytes.extend_from_slice(checkpoint.outstanding_digest.as_bytes());
    bytes.extend_from_slice(&checkpoint.outstanding_count.to_be_bytes());
    bytes.push(u8::from(checkpoint.poisoned));
    bytes
}

/// Checks a current-head record and reads its sequence and chain head.
///
/// # Errors
///
/// Returns an error for invalid framing, flags, or required nonzero fields.
pub(super) fn decode_current_head(
    bytes: &[u8],
) -> Result<(u64, ObjectDigest), PublisherAdmissionJournalErrorV1> {
    if bytes.len() != 127
        || &bytes[..8] != HEAD_MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[126] > 1
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let sequence = u64::from_be_bytes(
        bytes[10..18]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let chain_head = ObjectDigest::from_bytes(
        bytes[18..50]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let epoch = u64::from_be_bytes(
        bytes[50..58]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let state_digest = &bytes[58..90];
    let outstanding_digest = &bytes[90..122];
    if sequence == 0
        || epoch == 0
        || chain_head.as_bytes() == &[0; 32]
        || state_digest == [0; 32]
        || outstanding_digest == [0; 32]
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok((sequence, chain_head))
}

/// Encodes the original permit and its checkpoint commitment.
pub(super) fn encode_effect_permit(
    transaction: [u8; 16],
    permit: &CompletionPermitV1,
    checkpoint: &AuthorityCheckpointV1,
    chain_head: ObjectDigest,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(226);
    bytes.extend_from_slice(b"AOSPAE01");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&transaction);
    bytes.extend_from_slice(permit.permit.as_bytes());
    bytes.extend_from_slice(permit.operation.as_bytes());
    bytes.extend_from_slice(permit.artifact_digest.as_bytes());
    bytes.extend_from_slice(permit.permit_digest.as_bytes());
    bytes.extend_from_slice(&checkpoint.sequence.to_be_bytes());
    bytes.extend_from_slice(checkpoint.state_digest.as_bytes());
    bytes.extend_from_slice(checkpoint_commitment(checkpoint, chain_head).as_bytes());
    bytes.extend_from_slice(chain_head.as_bytes());
    bytes
}

/// Encodes a retained completion-effect binding.
pub(super) fn encode_effect_binding(binding: &CompletionEffectBindingV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(226);
    bytes.extend_from_slice(b"AOSPAE01");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&binding.transaction);
    bytes.extend_from_slice(&binding.permit);
    bytes.extend_from_slice(&binding.operation);
    bytes.extend_from_slice(binding.artifact.as_bytes());
    bytes.extend_from_slice(binding.permit_digest.as_bytes());
    bytes.extend_from_slice(&binding.checkpoint_sequence.to_be_bytes());
    bytes.extend_from_slice(binding.checkpoint_state.as_bytes());
    bytes.extend_from_slice(binding.checkpoint_commitment.as_bytes());
    bytes.extend_from_slice(binding.chain_head.as_bytes());
    bytes
}

/// Decodes a complete completion-effect binding and rejects sentinels.
///
/// # Errors
///
/// Returns an error for invalid framing or sentinel identifiers and digests.
pub(super) fn decode_effect_permit(
    bytes: &[u8],
) -> Result<CompletionEffectBindingV1, PublisherAdmissionJournalErrorV1> {
    if bytes.len() != 226 || &bytes[..8] != b"AOSPAE01" || bytes[8..10] != 1_u16.to_be_bytes() {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let transaction = bytes[10..26]
        .try_into()
        .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let permit = bytes[26..42]
        .try_into()
        .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let operation = bytes[42..58]
        .try_into()
        .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?;
    let artifact = ObjectDigest::from_bytes(
        bytes[58..90]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let permit_digest = ObjectDigest::from_bytes(
        bytes[90..122]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let checkpoint_sequence = u64::from_be_bytes(
        bytes[122..130]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let checkpoint_state = ObjectDigest::from_bytes(
        bytes[130..162]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let checkpoint_commitment = ObjectDigest::from_bytes(
        bytes[162..194]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    let chain_head = ObjectDigest::from_bytes(
        bytes[194..226]
            .try_into()
            .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?,
    );
    if transaction == [0; 16]
        || permit == [0; 16]
        || operation == [0; 16]
        || checkpoint_sequence == 0
        || [
            artifact,
            permit_digest,
            checkpoint_state,
            checkpoint_commitment,
            chain_head,
        ]
        .iter()
        .any(|digest| digest.as_bytes() == &[0; 32])
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok(CompletionEffectBindingV1 {
        transaction,
        permit,
        operation,
        artifact,
        permit_digest,
        checkpoint_sequence,
        checkpoint_state,
        checkpoint_commitment,
        chain_head,
    })
}

/// Encodes the reservation and terminal settlement lineage.
pub(super) fn encode_capacity_settlement(lineage: &CompletionSettlementLineageV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(308);
    bytes.extend_from_slice(b"AOSPAS01");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(lineage.disposition as u8);
    bytes.push(0);
    bytes.extend_from_slice(&lineage.admission_transaction_id);
    bytes.extend_from_slice(&lineage.owner_id);
    bytes.extend_from_slice(lineage.owner_digest.as_bytes());
    bytes.extend_from_slice(&lineage.reservation_id);
    bytes.extend_from_slice(&lineage.permit);
    bytes.extend_from_slice(&lineage.operation);
    bytes.extend_from_slice(lineage.artifact.as_bytes());
    bytes.extend_from_slice(lineage.permit_digest.as_bytes());
    bytes.extend_from_slice(lineage.checkpoint.as_bytes());
    bytes.extend_from_slice(lineage.chain_head.as_bytes());
    bytes.extend_from_slice(&lineage.terminal_records.to_be_bytes());
    bytes.extend_from_slice(&lineage.terminal_bytes.to_be_bytes());
    bytes.extend_from_slice(&lineage.poison_records.to_be_bytes());
    bytes.extend_from_slice(&lineage.poison_bytes.to_be_bytes());
    bytes
}

/// Decodes and validates canonical capacity-settlement lineage.
///
/// # Errors
///
/// Returns an error for invalid framing, lineage, budgets, or canonical bytes.
pub(super) fn decode_capacity_settlement(
    bytes: &[u8],
) -> Result<CompletionSettlementLineageV1, PublisherAdmissionJournalErrorV1> {
    if bytes.len() != 308
        || &bytes[..8] != b"AOSPAS01"
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[11] != 0
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    let digest = |start: usize| -> Result<ObjectDigest, PublisherAdmissionJournalErrorV1> {
        let value = ObjectDigest::from_bytes(capacity_settlement_array(bytes, start)?);
        if value.as_bytes() == &[0; 32] {
            return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
        }
        Ok(value)
    };
    let lineage = CompletionSettlementLineageV1 {
        disposition: CapacitySettlementDispositionV1::from_byte(bytes[10])?,
        admission_transaction_id: capacity_settlement_array(bytes, 12)?,
        owner_id: capacity_settlement_array(bytes, 28)?,
        owner_digest: digest(60)?,
        reservation_id: capacity_settlement_array(bytes, 92)?,
        permit: capacity_settlement_array(bytes, 124)?,
        operation: capacity_settlement_array(bytes, 140)?,
        artifact: digest(156)?,
        permit_digest: digest(188)?,
        checkpoint: digest(220)?,
        chain_head: digest(252)?,
        terminal_records: u32::from_be_bytes(capacity_settlement_array(bytes, 284)?),
        terminal_bytes: u64::from_be_bytes(capacity_settlement_array(bytes, 288)?),
        poison_records: u32::from_be_bytes(capacity_settlement_array(bytes, 296)?),
        poison_bytes: u64::from_be_bytes(capacity_settlement_array(bytes, 300)?),
    };
    if lineage.admission_transaction_id == [0; 16]
        || lineage.owner_id == [0; 32]
        || lineage.reservation_id == [0; 32]
        || lineage.permit == [0; 16]
        || lineage.operation == [0; 16]
        || lineage.terminal_records == 0
        || lineage.terminal_bytes == 0
        || lineage.poison_records == 0
        || lineage.poison_bytes == 0
        || bind_domain_capacity_request_v1::<PublisherAdmissionJournalSchemaV1>(lineage.request())
            != lineage.request()
        || !validate_domain_capacity_lineage_v1::<PublisherAdmissionJournalSchemaV1>(
            &lineage.request(),
            lineage.admission_transaction_id,
            lineage.reservation_id,
        )
        || encode_capacity_settlement(&lineage) != bytes
    {
        return Err(PublisherAdmissionJournalErrorV1::InvalidMutationBatch);
    }
    Ok(lineage)
}

/// Reads one fixed-width capacity-settlement field.
///
/// # Errors
///
/// Returns an error if the field range or exact width is unavailable.
///
/// # Panics
///
/// Panics if `start + LENGTH` overflows with overflow checks enabled.
pub(super) fn capacity_settlement_array<const LENGTH: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; LENGTH], PublisherAdmissionJournalErrorV1> {
    bytes
        .get(start..start + LENGTH)
        .ok_or(PublisherAdmissionJournalErrorV1::InvalidMutationBatch)?
        .try_into()
        .map_err(|_| PublisherAdmissionJournalErrorV1::InvalidMutationBatch)
}

/// Validates and frames one canonical Publisher reducer body.
///
/// # Errors
///
/// Returns an error if schema validation or envelope construction fails.
pub(super) fn publisher_reducer_envelope(
    key: PublisherAdmissionJournalKeyV1,
    revision: u64,
    predecessor: Option<ObjectDigest>,
    canonical_body: &[u8],
    validator: AdmissionLimits,
) -> Result<PublisherAdmissionJournalEnvelopeV1, PublisherAdmissionJournalErrorV1> {
    let payload = encode_reducer_payload_with_validator::<PublisherAdmissionJournalSchemaV1>(
        &key,
        canonical_body,
        &validator,
    )?;
    Ok(PublisherAdmissionJournalEnvelopeV1::new_with_validator(
        key,
        revision,
        predecessor,
        payload,
        &validator,
    )?)
}

/// Validates a reducer payload and borrows its original body.
///
/// # Errors
///
/// Returns an error if the reducer payload fails schema validation.
pub(super) fn publisher_body(
    envelope: &PublisherAdmissionJournalEnvelopeV1,
) -> Result<&[u8], PublisherAdmissionJournalErrorV1> {
    let validator = maximum_admission_limits();
    Ok(
        decode_reducer_payload_with_validator::<PublisherAdmissionJournalSchemaV1>(
            envelope.key(),
            envelope.payload(),
            &validator,
        )?
        .body(),
    )
}
