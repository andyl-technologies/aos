//! Memory-mutation evidence codec tests.

use super::*;

#[test]
fn prepared_precondition_binds_every_boundary_digest() {
    let hash = |digests: [[u8; 32]; 6], before_bytes, after_bytes| {
        memory_mutation_precondition_sha256(MemoryMutationPreconditionBinding {
            before_sha256: digests[0],
            after_sha256: digests[1],
            translation_sha256: digests[2],
            mapping_generation_sha256: digests[3],
            before_ram_blake3: digests[4],
            after_ram_blake3: digests[5],
            before_ram_bytes: before_bytes,
            after_ram_bytes: after_bytes,
        })
    };
    let digests = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]];
    let baseline = hash(digests, 4096, 4096);
    // Pins the v2 domain, six-digest order, and little-endian byte counts.
    assert_eq!(
        baseline,
        [
            36, 213, 225, 181, 179, 232, 32, 204, 162, 41, 52, 140, 22, 2, 221, 65, 87, 107, 161,
            90, 54, 196, 229, 246, 43, 70, 253, 19, 23, 188, 249, 217,
        ]
    );

    for index in 0..digests.len() {
        let mut changed = digests;
        changed[index] = [9; 32];
        assert_ne!(baseline, hash(changed, 4096, 4096));
    }
    assert_ne!(baseline, hash(digests, 8192, 4096),);
    assert_ne!(baseline, hash(digests, 4096, 8192),);
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
    let mut evidence = MemoryMutationEvidenceV2 {
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
        before_ram_blake3: [6; 32],
        after_ram_blake3: [7; 32],
        before_ram_bytes: 0x1_0000,
        after_ram_bytes: 0x1_0000,
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
        MemoryMutationEvidenceV2::decode(&bytes),
        Ok(evidence.clone())
    );

    for offset in [304, 336, 368, 376, 384, 388] {
        let mut substituted = bytes.clone();
        substituted[offset] ^= 1;
        assert!(MemoryMutationEvidenceV2::decode(&substituted).is_err());
    }

    let mut predecessor = bytes.clone();
    predecessor[..8].copy_from_slice(b"CRUCMER1");
    predecessor[8..10].copy_from_slice(&1_u16.to_le_bytes());
    assert!(MemoryMutationEvidenceV2::decode(&predecessor).is_err());

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
        MemoryMutationEvidenceV2::decode(&hidden_interval),
        Err(MemoryMutationEvidenceError::Invalidation)
    );
}
