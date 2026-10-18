//! Memory-mutation batch codec tests.

use super::*;
use crate::{
    MEMORY_MUTATION_NO_VCPU, MemoryMutationAddressSpace, MemoryMutationAtomicity,
    MemoryMutationTransformKind,
};

fn whole_ram_root(bytes: &[u8]) -> [u8; 32] {
    use crucible_ram::{
        Limits, MetadataBudget, PageDigest, RegionClass, RegionDescriptor, RegionTree, RootRecord,
        Scope, Topology,
    };

    let budget = MetadataBudget::new(1 << 20);
    let digests = bytes
        .chunks(4096)
        .map(|page| {
            PageDigest::hash(page).unwrap_or_else(|error| panic!("memory batch fixture: {error}"))
        })
        .collect::<Vec<_>>();
    let tree = RegionTree::from_page_digests(bytes.len() as u64, &digests, &budget)
        .unwrap_or_else(|error| panic!("memory batch fixture: {error}"));
    let region = RegionDescriptor::new("pc.ram", RegionClass::MutableMain, bytes.len() as u64)
        .unwrap_or_else(|error| panic!("memory batch fixture: {error}"));
    let topology = Topology::new(vec![region], Limits::default())
        .unwrap_or_else(|error| panic!("memory batch fixture: {error}"));
    *RootRecord::new(topology, Scope::Execution, vec![tree.digest()])
        .unwrap_or_else(|error| panic!("memory batch fixture: {error}"))
        .digest()
        .as_bytes()
}

fn evidence(before: &[u8], after: &[u8]) -> MemoryMutationEvidenceV2 {
    use crate::{
        MemoryMappingRecordV1, MemoryMutationFragmentV1, memory_dirty_ranges_for_fragments,
        memory_dirty_ranges_sha256, memory_mapping_sha256, memory_ram_block_identity_sha256,
        memory_region_identity_sha256,
    };

    let region = memory_region_identity_sha256("/machine/system-memory", "ram")
        .unwrap_or_else(|error| panic!("memory batch fixture: {error}"));
    let block = memory_ram_block_identity_sha256("pc.ram")
        .unwrap_or_else(|error| panic!("memory batch fixture: {error}"));
    let mappings = vec![MemoryMappingRecordV1 {
        guest_physical_start: 0,
        length: before.len() as u64,
        memory_region_offset: 0,
        ram_block_offset: 0,
        flags: 0,
        memory_region_identity_sha256: region,
        ram_block_identity_sha256: block,
    }];
    let fragments = vec![MemoryMutationFragmentV1 {
        guest_physical_start: 0,
        request_offset: 0,
        length: 1,
        flags: crate::MEMORY_MUTATION_FRAGMENT_TB_INVALIDATED,
        memory_region_offset: 0,
        ram_block_offset: 0,
        memory_region_identity_sha256: region,
        ram_block_identity_sha256: block,
    }];
    let dirty_ranges = memory_dirty_ranges_for_fragments(&fragments)
        .unwrap_or_else(|error| panic!("memory batch fixture: {error}"));
    let mut result = MemoryMutationEvidenceV2 {
        address_space: MemoryMutationAddressSpace::GuestPhysical,
        transform: MemoryMutationTransformKind::BitFlip,
        vcpu_index: MEMORY_MUTATION_NO_VCPU,
        address: 0,
        length: 1,
        observed_icount: 11,
        translations: Vec::new(),
        before_sha256: Sha256::digest(&before[..1]).into(),
        after_sha256: Sha256::digest(&after[..1]).into(),
        mapping_generation_sha256: memory_mapping_sha256(&mappings)
            .unwrap_or_else(|error| panic!("memory batch fixture: {error}")),
        dirty_pages_sha256: memory_dirty_ranges_sha256(&dirty_ranges)
            .unwrap_or_else(|error| panic!("memory batch fixture: {error}")),
        fragments,
        mappings,
        dirty_ranges,
        invalidated_start: Some(0),
        invalidated_end: Some(0),
        target_node_hash: [5; 32],
        node_fingerprint: [0; 32],
        before_ram_blake3: whole_ram_root(before),
        after_ram_blake3: whole_ram_root(after),
        before_ram_bytes: before.len() as u64,
        after_ram_bytes: after.len() as u64,
        before_bytes: before[..1].to_vec(),
        after_bytes: after[..1].to_vec(),
    };
    result.node_fingerprint = result
        .expected_node_fingerprint()
        .unwrap_or_else(|error| panic!("memory batch fixture: {error}"));
    result
        .validate()
        .unwrap_or_else(|error| panic!("memory batch fixture: {error}"));
    result
}

fn ordered_evidence() -> MemoryMutationBatchEvidenceV1 {
    let first = vec![0; 4096];
    let mut middle = first.clone();
    middle[0] = 1;
    let mut value = MemoryMutationBatchEvidenceV1 {
        actions: vec![
            MemoryMutationBatchEvidenceActionV1 {
                action_hash: [1; 32],
                evidence: evidence(&first, &middle),
            },
            MemoryMutationBatchEvidenceActionV1 {
                action_hash: [2; 32],
                evidence: evidence(&middle, &first),
            },
        ],
        precondition_sha256: [0; 32],
    };
    value.precondition_sha256 = value
        .expected_precondition_sha256()
        .unwrap_or_else(|error| panic!("memory batch fixture: {error}"));
    value
}

// Models an untrusted producer that recomputes valid per-record and aggregate
// digests but omits the cross-record transaction checks performed by the decoder.
fn encode_untrusted_batch(actions: &[MemoryMutationBatchEvidenceActionV1]) -> Vec<u8> {
    let mut aggregate = Sha256::new();
    aggregate.update(MEMORY_MUTATION_BATCH_PRECONDITION_SHA256_DOMAIN_V2);
    aggregate.update((actions.len() as u32).to_le_bytes());
    let mut records = Vec::new();
    for action in actions {
        let value = &action.evidence;
        let precondition = memory_mutation_precondition_sha256(MemoryMutationPreconditionBinding {
            before_sha256: value.before_sha256,
            after_sha256: value.after_sha256,
            translation_sha256: value
                .translation_sha256()
                .unwrap_or_else(|error| panic!("memory batch fixture: {error}")),
            mapping_generation_sha256: value.mapping_generation_sha256,
            before_ram_blake3: value.before_ram_blake3,
            after_ram_blake3: value.after_ram_blake3,
            before_ram_bytes: value.before_ram_bytes,
            after_ram_bytes: value.after_ram_bytes,
        });
        aggregate.update(action.action_hash);
        aggregate.update(precondition);
        let nested = value
            .encode()
            .unwrap_or_else(|error| panic!("memory batch fixture: {error}"));
        records.extend_from_slice(&action.action_hash);
        records.extend_from_slice(&(nested.len() as u32).to_le_bytes());
        records.extend_from_slice(&[0; 4]);
        records.extend_from_slice(&nested);
    }
    let mut bytes = vec![0; MEMORY_MUTATION_BATCH_EVIDENCE_HEADER_V1_BYTES];
    bytes[..8].copy_from_slice(&MEMORY_MUTATION_BATCH_EVIDENCE_MAGIC_V1);
    put_u16(&mut bytes, 8, MEMORY_MUTATION_BATCH_EVIDENCE_VERSION_V1);
    put_u32(&mut bytes, 12, actions.len() as u32);
    bytes[16..48].copy_from_slice(&aggregate.finalize());
    put_u32(&mut bytes, 48, records.len() as u32);
    bytes.extend_from_slice(&records);
    bytes
}

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

#[test]
fn complete_ram_transaction_evidence_round_trips_real_prefix_roots() {
    let batch = ordered_evidence();
    let bytes = batch
        .encode()
        .unwrap_or_else(|error| panic!("memory batch fixture: {error}"));
    assert_eq!(MemoryMutationBatchEvidenceV1::decode(&bytes), Ok(batch));
}

#[test]
fn complete_ram_transaction_rejects_individually_valid_discontinuous_actions() {
    let baseline = ordered_evidence();
    for field in 0..4 {
        let mut value = baseline.clone();
        let second = &mut value.actions[1].evidence;
        match field {
            0 => {
                let mut before = vec![0; 4096];
                before[0] = 1;
                before[1024] = 9;
                let mut after = before.clone();
                after[0] = 0;
                *second = evidence(&before, &after);
            }
            1 => {
                let mut before = vec![0; 8192];
                before[0] = 1;
                let after = vec![0; 8192];
                *second = evidence(&before, &after);
            }
            2 => second.target_node_hash = [8; 32],
            3 => second.observed_icount += 1,
            _ => unreachable!(),
        }
        second.node_fingerprint = second
            .expected_node_fingerprint()
            .unwrap_or_else(|error| panic!("memory batch fixture: {error}"));
        assert!(second.validate().is_ok());
        assert_eq!(
            value.expected_precondition_sha256(),
            Err(MemoryMutationBatchError::Continuity)
        );
        assert_eq!(value.encode(), Err(MemoryMutationBatchError::Continuity));
        let wire = encode_untrusted_batch(&value.actions);
        assert_eq!(
            MemoryMutationBatchEvidenceV1::decode(&wire),
            Err(MemoryMutationBatchError::Continuity)
        );
    }
}

#[test]
fn prepared_authorization_rejects_changed_unselected_ram_with_identical_range() {
    let baseline = ordered_evidence();
    let selected = &baseline.actions[0].evidence;
    let mut before = vec![0; 4096];
    before[1024] = 9;
    let mut after = before.clone();
    after[0] = 1;
    let changed = evidence(&before, &after);
    assert_eq!(selected.before_sha256, changed.before_sha256);
    assert_eq!(selected.after_sha256, changed.after_sha256);
    assert_eq!(
        selected.mapping_generation_sha256,
        changed.mapping_generation_sha256
    );
    let precondition = |value: &MemoryMutationEvidenceV2| {
        memory_mutation_precondition_sha256(MemoryMutationPreconditionBinding {
            before_sha256: value.before_sha256,
            after_sha256: value.after_sha256,
            translation_sha256: value
                .translation_sha256()
                .unwrap_or_else(|error| panic!("memory batch fixture: {error}")),
            mapping_generation_sha256: value.mapping_generation_sha256,
            before_ram_blake3: value.before_ram_blake3,
            after_ram_blake3: value.after_ram_blake3,
            before_ram_bytes: value.before_ram_bytes,
            after_ram_bytes: value.after_ram_bytes,
        })
    };
    assert_ne!(precondition(selected), precondition(&changed));
}
