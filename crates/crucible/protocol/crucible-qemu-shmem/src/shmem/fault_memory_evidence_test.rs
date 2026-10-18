//! Memory-mutation evidence codec tests.

use super::*;

#[test]
fn prepared_precondition_binds_every_boundary_digest() {
    let baseline = memory_mutation_precondition_sha256([1; 32], [2; 32], [3; 32], [4; 32]);
    assert_ne!(
        baseline,
        memory_mutation_precondition_sha256([9; 32], [2; 32], [3; 32], [4; 32])
    );
    assert_ne!(
        baseline,
        memory_mutation_precondition_sha256([1; 32], [9; 32], [3; 32], [4; 32])
    );
    assert_ne!(
        baseline,
        memory_mutation_precondition_sha256([1; 32], [2; 32], [9; 32], [4; 32])
    );
    assert_ne!(
        baseline,
        memory_mutation_precondition_sha256([1; 32], [2; 32], [3; 32], [9; 32])
    );
}

#[test]
fn translation_digest_and_evidence_round_trip() {
    let records = vec![MemoryTranslationRecordV1 {
        virtual_page_start: 0x4000,
        physical_page_start: 0x8000,
        page_size: 4096,
        permissions: MEMORY_TRANSLATION_PERMISSION_READ
            | MEMORY_TRANSLATION_PERMISSION_WRITE
            | MEMORY_TRANSLATION_PERMISSION_EXECUTE,
        attributes: MEMORY_TRANSLATION_ATTRIBUTE_USER,
        covered_bytes: 3,
    }];
    let before = vec![1, 2, 3];
    let after = vec![0, 2, 7];
    let region_identity = memory_region_identity_sha256("/machine/unattached/system-memory", "ram")
        .unwrap_or_else(|error| panic!("region identity: {error}"));
    let ram_block_identity = memory_ram_block_identity_sha256("pc.ram")
        .unwrap_or_else(|error| panic!("RAMBlock identity: {error}"));
    let mappings = vec![MemoryMappingRecordV1 {
        guest_physical_start: 0,
        length: 0x1_0000,
        memory_region_offset: 0,
        ram_block_offset: 0,
        flags: 0,
        memory_region_identity_sha256: region_identity,
        ram_block_identity_sha256: ram_block_identity,
    }];
    let dirty_ranges = vec![MemoryDirtyRangeV1 {
        ram_block_identity_sha256: ram_block_identity,
        ram_block_offset: 0x8000,
        page_count: 1,
        page_size: MEMORY_DIRTY_PAGE_BYTES_V1,
    }];
    let mapping_generation_sha256 =
        memory_mapping_sha256(&mappings).unwrap_or_else(|error| panic!("mapping digest: {error}"));
    let dirty_pages_sha256 = memory_dirty_ranges_sha256(&dirty_ranges)
        .unwrap_or_else(|error| panic!("dirty digest: {error}"));
    let mut evidence = MemoryMutationEvidenceV1 {
        address_space: MemoryMutationAddressSpace::GuestVirtual,
        transform: MemoryMutationTransformKind::BitFlip,
        vcpu_index: 0,
        address: 0x4001,
        length: 3,
        observed_icount: 11,
        translations: records,
        fragments: vec![MemoryMutationFragmentV1 {
            guest_physical_start: 0x8001,
            request_offset: 0,
            length: 3,
            flags: MEMORY_MUTATION_FRAGMENT_TB_INVALIDATED,
            memory_region_offset: 0x8001,
            ram_block_offset: 0x8001,
            memory_region_identity_sha256: region_identity,
            ram_block_identity_sha256: ram_block_identity,
        }],
        mappings,
        dirty_ranges,
        before_sha256: Sha256::digest(&before).into(),
        after_sha256: Sha256::digest(&after).into(),
        mapping_generation_sha256,
        dirty_pages_sha256,
        invalidated_start: Some(0x8001),
        invalidated_end: Some(0x8003),
        target_node_hash: [5; 32],
        node_fingerprint: [0; 32],
        before_bytes: before,
        after_bytes: after,
    };
    evidence.node_fingerprint = evidence
        .expected_node_fingerprint()
        .unwrap_or_else(|error| panic!("node fingerprint: {error}"));
    let bytes = evidence
        .encode()
        .unwrap_or_else(|error| panic!("encode evidence: {error}"));
    assert_eq!(
        MemoryMutationEvidenceV1::decode(&bytes),
        Ok(evidence.clone())
    );

    let mut wrong_interval = evidence.clone();
    wrong_interval.invalidated_start = Some(0x8000);
    wrong_interval.node_fingerprint = wrong_interval
        .expected_node_fingerprint()
        .unwrap_or_else(|error| panic!("wrong-interval fingerprint: {error}"));
    assert_eq!(
        wrong_interval.validate(),
        Err(MemoryMutationEvidenceError::Invalidation)
    );

    let mut missing_executable_invalidation = evidence.clone();
    missing_executable_invalidation.fragments[0].flags = 0;
    missing_executable_invalidation.invalidated_start = None;
    missing_executable_invalidation.invalidated_end = None;
    missing_executable_invalidation.node_fingerprint = missing_executable_invalidation
        .expected_node_fingerprint()
        .unwrap_or_else(|error| panic!("missing-invalidation fingerprint: {error}"));
    assert_eq!(
        missing_executable_invalidation.validate(),
        Err(MemoryMutationEvidenceError::Invalidation)
    );

    let mut missing_physical_invalidation = evidence.clone();
    missing_physical_invalidation.address_space = MemoryMutationAddressSpace::GuestPhysical;
    missing_physical_invalidation.vcpu_index = u32::MAX;
    missing_physical_invalidation.address = 0x8001;
    missing_physical_invalidation.translations.clear();
    missing_physical_invalidation.fragments[0].flags = 0;
    missing_physical_invalidation.invalidated_start = None;
    missing_physical_invalidation.invalidated_end = None;
    missing_physical_invalidation.node_fingerprint = missing_physical_invalidation
        .expected_node_fingerprint()
        .unwrap_or_else(|error| panic!("physical-invalidation fingerprint: {error}"));
    assert_eq!(
        missing_physical_invalidation.validate(),
        Err(MemoryMutationEvidenceError::Invalidation)
    );

    let mut hidden_interval = bytes;
    let flags = read_u16(&hidden_interval, MEMORY_MUTATION_EVIDENCE_FLAGS_OFFSET)
        & !MEMORY_MUTATION_EVIDENCE_FLAG_TB_INVALIDATED;
    put_u16(
        &mut hidden_interval,
        MEMORY_MUTATION_EVIDENCE_FLAGS_OFFSET,
        flags,
    );
    assert_eq!(
        MemoryMutationEvidenceV1::decode(&hidden_interval),
        Err(MemoryMutationEvidenceError::Invalidation)
    );
}
