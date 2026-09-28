//! Native V3 topology/profile vectors using the shared cryptographic fixture.

use super::*;

#[test]
fn native_v3_rejects_old_positive_framing_and_noncanonical_topology() {
    let fixture = Fixture::new();
    let unsigned = fixture.acceptance.acceptance().to_canonical_bytes();
    let signed = fixture.acceptance.to_canonical_bytes();
    let reply = fixture.reply().to_canonical_bytes();
    assert_eq!(&unsigned[..10], b"AOSZNA03\0\x03");
    assert_eq!(&reply[..10], b"AOSZNP03\0\x03");
    assert_eq!(
        StorageNativeAcceptanceV3::from_canonical_bytes(&unsigned).unwrap(),
        *fixture.acceptance.acceptance()
    );
    assert_eq!(
        SignedStorageNativeAcceptanceV3::from_canonical_bytes(&signed).unwrap(),
        fixture.acceptance
    );
    assert_eq!(
        fixture.acceptance.acceptance().digest(),
        digest(
            b"aos.sandbox.storage.native-acceptance.digest.v3\0",
            &unsigned
        )
    );
    assert_eq!(
        fixture.acceptance.digest(),
        digest(
            b"aos.sandbox.storage.native-acceptance.signed-digest.v3\0",
            &signed
        )
    );
    assert_ne!(
        fixture.acceptance.acceptance().digest(),
        digest(
            b"aos.sandbox.storage.native-acceptance.digest.v2\0",
            &unsigned
        )
    );
    assert_ne!(
        fixture.acceptance.digest(),
        digest(
            b"aos.sandbox.storage.native-acceptance.signed-digest.v2\0",
            &signed
        )
    );

    for offset in [0, 7, 8, 9, 10, 15] {
        let mut changed = unsigned;
        changed[offset] ^= 1;
        assert!(StorageNativeAcceptanceV3::from_canonical_bytes(&changed).is_err());
    }
    assert!(StorageNativeAcceptanceV3::from_canonical_bytes(&unsigned[..215]).is_err());
    let mut trailing = unsigned.to_vec();
    trailing.push(0);
    assert!(StorageNativeAcceptanceV3::from_canonical_bytes(&trailing).is_err());
    assert!(SignedStorageNativeAcceptanceV3::from_canonical_bytes(&signed[..367]).is_err());
    let mut trailing = signed.clone();
    trailing.push(0);
    assert!(SignedStorageNativeAcceptanceV3::from_canonical_bytes(&trailing).is_err());
    assert!(StorageNativeAcquireReplyV3::from_canonical_bytes(&reply[..1191]).is_err());
    let mut trailing = reply.clone();
    trailing.push(0);
    assert!(StorageNativeAcquireReplyV3::from_canonical_bytes(&trailing).is_err());

    // Both historical compact V2 and padded V3-sized records with V2 framing
    // are rejected. A length change cannot silently upgrade unsigned claims.
    let mut old_unsigned = unsigned[..136].to_vec();
    old_unsigned[..10].copy_from_slice(b"AOSZNA02\0\x02");
    let mut old_signed = old_unsigned.clone();
    old_signed.extend_from_slice(&signed[216..]);
    let mut old_reply = reply[..24].to_vec();
    old_reply[..10].copy_from_slice(b"AOSZNP02\0\x02");
    old_reply.extend_from_slice(&old_signed);
    old_reply.extend_from_slice(&fixture.receipt.encode());
    assert_eq!(old_unsigned.len(), 136);
    assert_eq!(old_signed.len(), 288);
    assert_eq!(old_reply.len(), 1112);
    assert!(StorageNativeAcceptanceV3::from_canonical_bytes(&old_unsigned).is_err());
    assert!(SignedStorageNativeAcceptanceV3::from_canonical_bytes(&old_signed).is_err());
    assert!(StorageNativeAcquireReplyV3::from_canonical_bytes(&old_reply).is_err());
    for magic in [b"AOSZNA02\0\x02", b"AOSZNA03\0\x02", b"AOSZNA02\0\x03"] {
        let mut changed = unsigned;
        changed[..10].copy_from_slice(magic);
        assert!(StorageNativeAcceptanceV3::from_canonical_bytes(&changed).is_err());
    }
    for magic in [b"AOSZNP02\0\x02", b"AOSZNP03\0\x02", b"AOSZNP02\0\x03"] {
        let mut changed = reply.clone();
        changed[..10].copy_from_slice(magic);
        assert!(StorageNativeAcquireReplyV3::from_canonical_bytes(&changed).is_err());
    }

    for (start, width) in [(136, 16), (152, 8), (160, 32), (192, 8), (208, 4)] {
        let mut changed = unsigned;
        changed[start..start + width].fill(0);
        assert!(StorageNativeAcceptanceV3::from_canonical_bytes(&changed).is_err());
    }
    let mut with_submount = unsigned;
    with_submount[212..216].copy_from_slice(&1_u32.to_be_bytes());
    assert!(StorageNativeAcceptanceV3::from_canonical_bytes(&with_submount).is_err());
    let mut recursive_mounts = with_submount;
    recursive_mounts[208..212].copy_from_slice(&2_u32.to_be_bytes());
    assert!(StorageNativeAcceptanceV3::from_canonical_bytes(&recursive_mounts).is_err());

    // Other message families do not inherit the positive version change.
    assert_eq!(
        &fixture.request.to_canonical_bytes()[..10],
        b"AOSZNQ02\0\x02"
    );
    let cleanup = StorageNativeCleanupRequestV2::new(
        1,
        d(64),
        [65; 32],
        StorageNativeCleanupReasonV2::CustodyLost,
        &fixture.request,
        fixture.acceptance.acceptance(),
    )
    .unwrap();
    let cleanup = SignedStorageNativeCleanupRequestV2::sign(
        cleanup,
        fixture.request.signer().clone(),
        &fixture.provider_key,
    )
    .unwrap();
    assert_eq!(&cleanup.to_canonical_bytes()[..10], b"AOSZNC02\0\x02");
    assert_eq!(
        SignedStorageNativeCleanupRequestV2::from_canonical_bytes(&cleanup.to_canonical_bytes())
            .unwrap(),
        cleanup
    );
}

#[test]
fn native_topology_has_exact_preimage_and_reuses_the_existing_eighty_byte_codec() {
    let fixture = Fixture::new();
    let topology = fixture.acceptance.acceptance().topology();
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&fixture.receipt.signer().authority().0);
    preimage.extend_from_slice(&fixture.receipt.receipt().head().journal().0.to_be_bytes());
    preimage.extend_from_slice(fixture.request.digest().as_bytes());
    preimage.extend_from_slice(fixture.receipt.digest().as_bytes());
    preimage
        .extend_from_slice(source_root_descriptor_commitment_v1(&fixture.descriptor).as_bytes());
    preimage.extend_from_slice(
        fixture
            .receipt
            .receipt()
            .snapshot()
            .read_only_content_digest()
            .as_bytes(),
    );
    preimage.extend_from_slice(&2_u64.to_be_bytes());
    preimage.extend_from_slice(&55_u64.to_be_bytes());
    preimage.extend_from_slice(&1_u32.to_be_bytes());
    preimage.extend_from_slice(&0_u32.to_be_bytes());
    assert_eq!(preimage.len(), 176);
    // The documented fixed-field preimage was independently SHA-256 hashed
    // with AOS OpenSSL 4.0.2, not frozen from this helper's digest output.
    let golden_preimage = hex::decode(concat!(
        "2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e000000000000002b",
        "df7644deba326b0089a20c2b9bcfa910df1b09194b981154aaafcea86b9bc3bf",
        "444ce4a96eb0716b16d879a5347991d0534ab40c3ad9417a688f84f281f676f1",
        "f468c44bb447bdda2f569ea8b0e9ceec07a549fcc3ebff62280f0c2c0599d9e5",
        "1616161616161616161616161616161616161616161616161616161616161616",
        "000000000000000200000000000000370000000100000000",
    ))
    .unwrap();
    assert_eq!(preimage, golden_preimage);
    let golden_digest =
        hex::decode("d8b774995d867979eee96b9e746346c2c8abd6250343b26e710041f1c253ee38").unwrap();
    assert_eq!(
        topology.topology_digest().as_bytes(),
        golden_digest.as_slice()
    );
    assert_eq!(
        topology.topology_digest(),
        digest(
            b"aos.sandbox.storage.native-nonrecursive-topology.v1\0",
            &preimage
        )
    );
    assert_eq!(topology.authority_id(), [46; 16]);
    assert_eq!(topology.generation(), 43);
    assert_ne!(
        topology.generation(),
        fixture.receipt.signer().authority().1
    );

    let encoded = encode_recursive_topology_proof_v1(topology);
    assert_eq!(encoded.len(), 80);
    assert_eq!(
        decode_recursive_topology_proof_v1(&encoded).unwrap(),
        *topology
    );
    assert!(decode_recursive_topology_proof_v1(&encoded[..79]).is_err());
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(decode_recursive_topology_proof_v1(&trailing).is_err());
    let proof = SourceProviderProofV1::ZfsHeldSnapshot {
        proof: fixture.receipt.receipt().snapshot().clone(),
        topology: topology.clone(),
    };
    let encoded_proof = encode_provider_proof(&proof);
    assert_eq!(&encoded_proof[encoded_proof.len() - 80..], &encoded);
    assert_eq!(decode_provider_proof(&encoded_proof).unwrap(), proof);
}

#[test]
fn native_topology_enforces_measured_producer_boundaries_not_directory_depth() {
    let fixture = Fixture::new();
    for (nodes, bytes) in [(1, 0), (2, 0), (4096, 64 * 1024 * 1024)] {
        let topology = storage_native_nonrecursive_topology_v1(
            &fixture.request,
            &fixture.receipt,
            &fixture.descriptor,
            nodes,
            bytes,
        )
        .unwrap();
        assert_eq!(topology.maximum_depth(), 1);
        assert_eq!(topology.observed_submounts(), 0);
        let acceptance = StorageNativeAcceptanceV3::new(
            [54; 16],
            fixture.request.digest(),
            fixture.receipt.digest(),
            fixture.descriptor.clone(),
            topology,
        )
        .unwrap();
        assert_eq!(
            StorageNativeAcceptanceV3::from_canonical_bytes(&acceptance.to_canonical_bytes())
                .unwrap(),
            acceptance
        );
    }
    for (nodes, bytes) in [
        (0, 0),
        (1, 1),
        (4097, 0),
        (u64::MAX, 0),
        (2, 64 * 1024 * 1024 + 1),
        (2, u64::MAX),
    ] {
        assert_eq!(
            storage_native_nonrecursive_topology_v1(
                &fixture.request,
                &fixture.receipt,
                &fixture.descriptor,
                nodes,
                bytes,
            ),
            Err(StorageNativeAcquireErrorV2::Noncanonical)
        );
    }
    let original = fixture.acceptance.acceptance();
    for (offset, value) in [
        (192, 4097_u64),
        (200, 64 * 1024 * 1024 + 1),
        (192, u64::MAX),
        (200, u64::MAX),
    ] {
        let mut wire = original.to_canonical_bytes();
        wire[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        assert!(StorageNativeAcceptanceV3::from_canonical_bytes(&wire).is_err());
    }
    let mut root_only_with_bytes = original.to_canonical_bytes();
    root_only_with_bytes[192..200].copy_from_slice(&1_u64.to_be_bytes());
    assert!(StorageNativeAcceptanceV3::from_canonical_bytes(&root_only_with_bytes).is_err());
}

#[test]
fn native_topology_crosslinks_reject_mutation_even_with_a_valid_storage_signature() {
    let fixture = Fixture::new();
    let original = fixture.acceptance.acceptance();
    for offset in [32, 96, 119, 127, 135, 136, 159, 160, 199, 207] {
        let mut changed = original.to_canonical_bytes();
        changed[offset] ^= 1;
        let changed = StorageNativeAcceptanceV3::from_canonical_bytes(&changed).unwrap();
        let signed = SignedStorageNativeAcceptanceV3::sign(
            changed,
            fixture.receipt.signer(),
            &fixture.storage_key,
        );
        signed.verify(fixture.verifier).unwrap();
        assert_eq!(
            StorageNativeAcquireReplyV3::new(signed, fixture.receipt.clone()),
            Err(StorageNativeAcquireErrorV2::Mismatch),
            "acceptance offset {offset}"
        );
    }

    // Changing a primary cut, content commitment, or receipt signer changes
    // the profile even when every replacement has a valid dedicated signature.
    let receipt = fixture.receipt.receipt();
    let head = receipt.head();
    let changed_head = StorageZfsHoldHeadV1::new(
        head.catalog().0,
        head.catalog().1,
        head.authority().0,
        head.authority().1,
        head.journal().0 + 1,
        head.journal().1,
        head.physical_observation_digest(),
    )
    .unwrap();
    let changed_receipt = StorageZfsHoldReceiptV1::new(
        receipt.attempt().0,
        receipt.attempt().1,
        receipt.binding_digest(),
        receipt.resource().clone(),
        receipt.snapshot().clone(),
        changed_head,
        receipt.validity().0,
        receipt.validity().1,
    )
    .unwrap();
    let changed_receipt = sign_receipt(
        changed_receipt,
        fixture.receipt.signer(),
        &fixture.storage_key,
    );
    let foreign_signer = StorageZfsHoldSignerV1::new(
        [76; 16],
        head.authority().0,
        head.authority().1,
        [47; 16],
        48,
    )
    .unwrap();
    let foreign_receipt = sign_receipt(receipt.clone(), foreign_signer, &fixture.storage_key);
    let snapshot = receipt.snapshot();
    let changed_content = ZfsHeldSnapshotProofV1::new(
        snapshot.storage_handle(),
        snapshot.storage_version(),
        snapshot.pool_guid(),
        snapshot.dataset_guid(),
        snapshot.snapshot_guid(),
        snapshot.hold_id(),
        snapshot.hold_generation(),
        snapshot.active_hold_digest(),
        snapshot.root_policy_digest(),
        d(77),
    )
    .unwrap();
    let changed_content = StorageZfsHoldReceiptV1::new(
        receipt.attempt().0,
        receipt.attempt().1,
        receipt.binding_digest(),
        receipt.resource().clone(),
        changed_content,
        head,
        receipt.validity().0,
        receipt.validity().1,
    )
    .unwrap();
    let changed_content = sign_receipt(
        changed_content,
        fixture.receipt.signer(),
        &fixture.storage_key,
    );
    for replacement in [changed_receipt, changed_content, foreign_receipt.clone()] {
        let unchanged_topology = StorageNativeAcceptanceV3::new(
            original.issuance_id(),
            original.request_digest(),
            replacement.digest(),
            fixture.descriptor.clone(),
            original.topology().clone(),
        )
        .unwrap();
        let signed = SignedStorageNativeAcceptanceV3::sign(
            unchanged_topology,
            replacement.signer(),
            &fixture.storage_key,
        );
        assert_eq!(
            StorageNativeAcquireReplyV3::new(signed, replacement),
            Err(StorageNativeAcquireErrorV2::Mismatch)
        );
    }

    let valid_foreign_topology = storage_native_nonrecursive_topology_v1(
        &fixture.request,
        &foreign_receipt,
        &fixture.descriptor,
        2,
        55,
    )
    .unwrap();
    let foreign_acceptance = StorageNativeAcceptanceV3::new(
        original.issuance_id(),
        original.request_digest(),
        foreign_receipt.digest(),
        fixture.descriptor.clone(),
        valid_foreign_topology,
    )
    .unwrap();
    let foreign_reply = StorageNativeAcquireReplyV3::new(
        SignedStorageNativeAcceptanceV3::sign(
            foreign_acceptance,
            foreign_signer,
            &fixture.storage_key,
        ),
        foreign_receipt,
    )
    .unwrap();
    assert_eq!(
        fixture.verify(
            &foreign_reply,
            &fixture.descriptor,
            &[SourceProviderDescriptorRole::SourceRoot]
        ),
        Err(StorageNativeAcquireErrorV2::Authority)
    );
}
