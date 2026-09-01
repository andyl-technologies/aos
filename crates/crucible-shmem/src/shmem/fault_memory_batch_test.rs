//! Memory-mutation batch codec tests.

use super::*;
use crate::{
    MEMORY_MUTATION_NO_VCPU, MemoryMutationAddressSpace, MemoryMutationAtomicity,
    MemoryMutationTransformKind,
};

fn action(id: u8, address: u64) -> MemoryMutationBatchActionV1 {
    MemoryMutationBatchActionV1 {
        action_hash: [id; 32],
        mutation: MemoryMutationPayloadV1 {
            address_space: MemoryMutationAddressSpace::GuestPhysical,
            transform: MemoryMutationTransformKind::BitFlip,
            atomicity: MemoryMutationAtomicity::AllOrNothing,
            vcpu_index: MEMORY_MUTATION_NO_VCPU,
            address,
            mask: vec![0xff],
            values: Vec::new(),
            expected_translation_sha256: [0; 32],
        },
    }
}

#[test]
fn preparation_and_commit_batches_are_canonical_and_ordered() {
    let mut batch = MemoryMutationBatchV1 {
        actions: vec![action(1, 0x1000), action(2, 0x1000)],
        expected_precondition_sha256: [0; 32],
    };
    let preparation = batch
        .encode_preparation()
        .unwrap_or_else(|error| panic!("encode batch preparation: {error}"));
    assert_eq!(
        MemoryMutationBatchV1::decode(&preparation, true),
        Ok(batch.clone())
    );
    assert_eq!(
        MemoryMutationBatchV1::decode(&preparation, false),
        Err(MemoryMutationBatchError::Precondition)
    );

    batch.expected_precondition_sha256 = [9; 32];
    let commit = batch
        .encode()
        .unwrap_or_else(|error| panic!("encode batch commit: {error}"));
    assert_eq!(MemoryMutationBatchV1::decode(&commit, false), Ok(batch));
}

#[test]
fn batch_rejects_duplicate_identity_and_cumulative_overflow() {
    let duplicate = MemoryMutationBatchV1 {
        actions: vec![action(1, 0), action(1, 1)],
        expected_precondition_sha256: [0; 32],
    };
    assert_eq!(
        duplicate.encode_preparation(),
        Err(MemoryMutationBatchError::ActionIdentity)
    );
}

#[test]
fn transport_envelopes_include_worst_case_batch_overhead() {
    let per_action_overhead =
        MEMORY_MUTATION_BATCH_RECORD_V1_BYTES + crate::MEMORY_MUTATION_PAYLOAD_HEADER_V1_BYTES;
    let hard = MEMORY_MUTATION_BATCH_HEADER_V1_BYTES
        + MEMORY_MUTATION_BATCH_MAX_ACTIONS as usize * per_action_overhead
        + 2 * HARD_MEMORY_MUTATION_BYTES as usize;
    let default = MEMORY_MUTATION_BATCH_HEADER_V1_BYTES
        + MEMORY_MUTATION_BATCH_MAX_ACTIONS as usize * per_action_overhead
        + 2 * crate::DEFAULT_MEMORY_MUTATION_BYTES as usize;

    assert_eq!(hard, HARD_FAULT_PAYLOAD_BYTES as usize);
    assert_eq!(default, crate::DEFAULT_FAULT_PAYLOAD_BYTES as usize);
}
