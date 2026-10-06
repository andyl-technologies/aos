//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Exercises canonical format, persistent ownership, independent oracles, and epochs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crucible_ram::{
    Consumer, DirtyTracker, Geometry, Limits, MetadataBudget, PageCoordinate, PageDigest,
    PageProof, RamError, RamSnapshot, RegionClass, RegionDescriptor, RegionTree, RootRecord, Scope,
    Topology, TrackingIncarnation, TrackingLimits, empty_leaf_digest, leaf_digest, oracle,
};

fn topology(length: u64) -> Topology {
    Topology::new(
        vec![RegionDescriptor::new("machine.ram", RegionClass::MutableMain, length).unwrap()],
        Limits::default(),
    )
    .unwrap()
}

fn coordinate(page_index: u64) -> PageCoordinate {
    PageCoordinate {
        region_index: 0,
        page_index,
    }
}

fn golden_snapshot(budget: &MetadataBudget) -> (RamSnapshot, Vec<Vec<u8>>) {
    let pages = vec![
        vec![0; 4096],
        (0..4096).map(|value| (value % 256) as u8).collect(),
        b"xyz".to_vec(),
    ];
    let topology = Topology::new(
        vec![
            RegionDescriptor::new("machine.ram", RegionClass::MutableMain, 8195).unwrap(),
            RegionDescriptor::new("firmware.rom", RegionClass::ImmutableImage, 3).unwrap(),
        ],
        Limits::default(),
    )
    .unwrap();
    let firmware =
        RegionTree::from_page_digests(3, &[PageDigest::hash(b"abc").unwrap()], budget).unwrap();
    let page_digests: Vec<_> = pages
        .iter()
        .map(|page| PageDigest::hash(page).unwrap())
        .collect();
    let machine = RegionTree::from_page_digests(8195, &page_digests, budget).unwrap();
    (
        RamSnapshot::new(topology, vec![firmware, machine], budget).unwrap(),
        pages,
    )
}

#[test]
fn canonical_golden_vectors() {
    // Frozen expected bytes from the former RFC JSON, not a generated fixture.
    assert_eq!(
        empty_leaf_digest().to_string(),
        "2b7e8057318c1fbf33948150119a2e19b00e062bda2696f772766f9d119bf89a"
    );
    let abc = PageDigest::hash(b"abc").unwrap();
    assert_eq!(
        abc.to_string(),
        "cef06d81ee7f2cd3627186a68ec50e368a5e9b9adbd6f06a00ca3118154db3bc"
    );
    assert_eq!(
        leaf_digest(abc).to_string(),
        "5d1644fc5810f07e0652edc0824fce3c1326f1664258092d0d3e14ae8762f054"
    );
    assert_eq!(
        PageDigest::hash(&[0; 4096]).unwrap().to_string(),
        "38342d59e3bbfc7d08d016242833a358693b56c3cb16c8798430b9fa08efc645"
    );

    let budget = MetadataBudget::new(1_000_000);
    let (snapshot, pages) = golden_snapshot(&budget);
    assert_eq!(
        PageDigest::hash(&pages[1]).unwrap().to_string(),
        "1a784196802d209f925c32e9f80b4a325daf89c47a1edf35d3173ea07d8650e0"
    );
    assert_eq!(
        PageDigest::hash(&pages[2]).unwrap().to_string(),
        "aedeb64c0c98fb3588c0bdf13ccd6d236c0be8c1a74a2efed0300c041101b27e"
    );
    assert_eq!(
        snapshot
            .region_tree("firmware.rom")
            .unwrap()
            .digest()
            .to_string(),
        "134cfd09553b0ea3c9231a1d1c013c1a663a82fb8cf911c8d54f837caf2df2c7"
    );
    assert_eq!(
        snapshot
            .region_tree("machine.ram")
            .unwrap()
            .digest()
            .to_string(),
        "6dd0dafc7231f7732579b0a5c7907aa3c27fca63d04812ef87d510a5fbd60368"
    );
    assert_eq!(
        snapshot.topology().digest().to_string(),
        "c0ed536e8f7f7437192fda3f503dd0aa92b920d7e3f297e46b6196362c655fce"
    );
    for (scope, expected) in [
        (
            Scope::Execution,
            "22aa6d280fb0d6227e69774a41d01b133859800e8d2651cc52b12c587628f09f",
        ),
        (
            Scope::Exact,
            "446b6ef414cf9002e2c7a1e6a9d8aff914407090c7eb73667e1ecfbfe84a631c",
        ),
        (
            Scope::Lifecycle,
            "3330483a2fd835779b9af138da298c5608f50051ddc7a9424ce2ed7a37b912bd",
        ),
    ] {
        let record = snapshot.root_record(scope).unwrap();
        assert_eq!(record.digest().to_string(), expected);
        assert_eq!(record.try_encode().unwrap().len(), record.encoded_len());
        assert_eq!(
            RootRecord::decode(&record.encode(), Limits::default()).unwrap(),
            record
        );
        assert_eq!(
            oracle::recompute(snapshot.topology(), scope, 4, |region, index, output| {
                if region.id() == "firmware.rom" {
                    output.copy_from_slice(b"abc");
                } else {
                    output.copy_from_slice(&pages[index as usize]);
                }
                Ok(())
            })
            .unwrap(),
            record.digest()
        );
    }
}

#[test]
fn primitive_mode_and_output_are_fixed() {
    assert_eq!(
        blake3::hash(b"").to_hex().as_str(),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    // Official unkeyed vectors use the repeating byte sequence modulo 251.
    for (length, expected) in [
        (
            1,
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        ),
        (
            1023,
            "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        ),
        (
            1024,
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        ),
        (
            1025,
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
        ),
        (
            2048,
            "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
        ),
        (
            2049,
            "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
        ),
    ] {
        let input: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
        assert_eq!(blake3::hash(&input).to_hex().as_str(), expected);
        let mut split = blake3::Hasher::new();
        for chunk in input.chunks(17) {
            split.update(chunk);
        }
        assert_eq!(split.finalize().to_hex().as_str(), expected);
    }
    let preimage = b"crucible.ram.page.v1\0\0\0\0\x03abc";
    let ordinary = blake3::hash(preimage);
    assert_eq!(
        PageDigest::hash(b"abc").unwrap().as_bytes(),
        ordinary.as_bytes()
    );
    assert_ne!(blake3::keyed_hash(&[1; 32], preimage), ordinary);
    assert_ne!(
        blake3::derive_key("crucible incorrect mode", preimage),
        *ordinary.as_bytes()
    );
    let mut split = blake3::Hasher::new();
    for byte in preimage {
        split.update(&[*byte]);
    }
    assert_eq!(split.finalize(), ordinary);
    assert!(PageDigest::hash(&[]).is_err());
    assert!(PageDigest::hash(&[0; 4097]).is_err());
    assert_ne!(
        PageDigest::hash(b"abc").unwrap(),
        PageDigest::hash(&[b'a', b'b', b'c', 0]).unwrap()
    );
}

#[test]
fn canonical_codec_adversarial() {
    let budget = MetadataBudget::new(1_000_000);
    let (snapshot, _) = golden_snapshot(&budget);
    let record = snapshot.root_record(Scope::Execution).unwrap();
    let bytes = record.encode();
    for length in 0..bytes.len() {
        assert!(
            RootRecord::decode(&bytes[..length], Limits::default()).is_err(),
            "accepted prefix {length}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(RootRecord::decode(&trailing, Limits::default()).is_err());
    for offset in [0, 11, 15, 20] {
        let mut bad = bytes.clone();
        bad[offset] ^= 0xff;
        assert!(RootRecord::decode(&bad, Limits::default()).is_err());
    }
    let mut wrong_mask = bytes.clone();
    let inventory_offset = 16 + 4 + "execution".len();
    let first_mask_offset = inventory_offset + 4 + 4 + "firmware.rom".len() + 1;
    wrong_mask[first_mask_offset] = 7;
    assert!(RootRecord::decode(&wrong_mask, Limits::default()).is_err());
    assert!(
        RootRecord::decode(
            &bytes,
            Limits {
                max_record_bytes: bytes.len() - 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        RootRecord::decode(
            &bytes,
            Limits {
                max_regions: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        RootRecord::decode(
            &bytes,
            Limits {
                max_logical_bytes: 8197,
                ..Limits::default()
            }
        )
        .is_err()
    );

    let mut inventory = snapshot.topology().encode_inventory();
    let first_descriptor_size = 4 + "firmware.rom".len() + 1 + 1 + 8;
    let first = inventory[4..4 + first_descriptor_size].to_vec();
    let second = inventory[4 + first_descriptor_size..].to_vec();
    inventory.truncate(4);
    inventory.extend_from_slice(&second);
    inventory.extend_from_slice(&first);
    assert_eq!(
        Topology::decode_inventory(&inventory, Limits::default()),
        Err(RamError::InvalidOrder)
    );
    assert!(RegionDescriptor::new("bad\0id", RegionClass::MutableMain, 1).is_err());
    assert!(RegionDescriptor::new("bad\u{7f}id", RegionClass::MutableMain, 1).is_err());
    assert!(RegionDescriptor::new("", RegionClass::MutableMain, 1).is_err());
    assert!(RegionDescriptor::new("r", RegionClass::MutableMain, 0).is_err());
    assert!(
        Topology::new(
            vec![
                RegionDescriptor::new("same", RegionClass::MutableMain, 1).unwrap(),
                RegionDescriptor::new("same", RegionClass::MutableDevice, 1).unwrap(),
            ],
            Limits::default()
        )
        .is_err()
    );
    assert!(
        Topology::new(
            vec![
                RegionDescriptor::new("a", RegionClass::MutableMain, u64::MAX).unwrap(),
                RegionDescriptor::new("b", RegionClass::MutableMain, 1).unwrap(),
            ],
            Limits::default()
        )
        .is_err()
    );
    assert!(
        RootRecord::new(
            snapshot.topology().clone(),
            Scope::Exact,
            vec![record.region_roots()[0]]
        )
        .is_err()
    );
}

#[test]
fn proof_rejects_position_length_padding_and_root() {
    let budget = MetadataBudget::new(1_000_000);
    let (snapshot, pages) = golden_snapshot(&budget);
    let record = snapshot.root_record(Scope::Exact).unwrap();
    let tree = snapshot.region_tree("machine.ram").unwrap();
    for index in 0..3 {
        let proof = tree.proof("machine.ram", index).unwrap();
        assert_eq!(
            proof
                .verify(&pages[index as usize], &record, record.digest())
                .unwrap(),
            tree.page_digest(index).unwrap()
        );
        let encoded = proof.encode();
        assert_eq!(
            PageProof::decode(&encoded, Limits::default()).unwrap(),
            proof
        );
        assert!(PageProof::decode(&encoded[..encoded.len() - 1], Limits::default()).is_err());
    }
    let proof = tree.proof("machine.ram", 2).unwrap();
    assert!(proof.verify(b"xyq", &record, record.digest()).is_err());
    let wrong_scope = snapshot.root_record(Scope::Lifecycle).unwrap();
    assert!(proof.verify(b"xyz", &record, wrong_scope.digest()).is_err());
    let padding = PageProof::new(
        "machine.ram",
        3,
        3,
        proof.page_digest(),
        proof.siblings().to_vec(),
    )
    .unwrap();
    assert_eq!(
        padding.verify(b"xyz", &record, record.digest()),
        Err(RamError::OutOfRange)
    );
    let wrong_length = PageProof::new(
        "machine.ram",
        2,
        4,
        PageDigest::hash(b"xyz\0").unwrap(),
        proof.siblings().to_vec(),
    )
    .unwrap();
    assert!(
        wrong_length
            .verify(b"xyz\0", &record, record.digest())
            .is_err()
    );
    let wrong_position = PageProof::new(
        "machine.ram",
        1,
        3,
        proof.page_digest(),
        proof.siblings().to_vec(),
    )
    .unwrap();
    assert!(
        wrong_position
            .verify(b"xyz", &record, record.digest())
            .is_err()
    );
    let missing_path = PageProof::new("machine.ram", 2, 3, proof.page_digest(), vec![]).unwrap();
    assert!(
        missing_path
            .verify(b"xyz", &record, record.digest())
            .is_err()
    );
    assert!(tree.proof("machine.ram", 3).is_err());
    assert!(
        PageProof::new(
            "machine.ram",
            0,
            4096,
            proof.page_digest(),
            vec![empty_leaf_digest(); 53]
        )
        .is_err()
    );
}

#[test]
fn persistent_tree_sparse_extreme_geometry() {
    let budget = MetadataBudget::new(50_000);
    let geometry = Geometry::new(u64::MAX).unwrap();
    assert_eq!(geometry.page_count(), 1_u64 << 52);
    assert_eq!(geometry.height(), 52);
    assert_eq!(
        geometry.valid_length(geometry.page_count() - 1).unwrap(),
        4095
    );
    assert!(geometry.valid_length(geometry.page_count()).is_err());
    let tree = RegionTree::zeroed(u64::MAX, &budget).unwrap();
    assert!(budget.used_bytes() < 20_000, "uniform sparse tree expanded");
    assert_eq!(
        tree.page_digest(0).unwrap(),
        PageDigest::hash(&[0; 4096]).unwrap()
    );
    assert_eq!(
        tree.page_digest(geometry.page_count() - 1).unwrap(),
        PageDigest::hash(&[0; 4095]).unwrap()
    );
    let proof = tree
        .proof("machine.ram", geometry.page_count() - 1)
        .unwrap();
    let record = RootRecord::new(topology(u64::MAX), Scope::Exact, vec![tree.digest()]).unwrap();
    proof.verify(&[0; 4095], &record, record.digest()).unwrap();
    let cloned = tree.clone();
    assert!(cloned.shares_root_with(&tree));
    drop(cloned);
    drop(tree);
    assert_eq!(budget.used_bytes(), 0);
}

#[test]
fn persistent_updates_fork_isolation_and_budget_rollback() {
    let budget = MetadataBudget::new(1_000_000);
    let tree = RegionTree::zeroed(4096 * 8, &budget).unwrap();
    let used = budget.used_bytes();
    let zero = tree.page_digest(0).unwrap();
    let unchanged = tree.updated(&[(0, zero), (7, zero)]).unwrap();
    assert!(unchanged.shares_root_with(&tree));
    assert_eq!(budget.used_bytes(), used);

    let change = PageDigest::hash(&[7; 4096]).unwrap();
    let child = tree.updated(&[(7, change), (1, change)]).unwrap();
    assert_ne!(child.digest(), tree.digest());
    assert_eq!(tree.page_digest(1).unwrap(), zero);
    assert_eq!(child.page_digest(1).unwrap(), change);
    assert_eq!(
        child.updated(&[(1, zero), (7, zero)]).unwrap().digest(),
        tree.digest()
    );
    assert!(tree.updated(&[(1, change), (1, zero)]).is_err());
    assert!(tree.updated(&[(8, change)]).is_err());

    let constrained = MetadataBudget::new(1500);
    let original = RegionTree::zeroed(4096 * 8, &constrained).unwrap();
    let original_digest = original.digest();
    let original_charge = constrained.used_bytes();
    let changes: Vec<_> = (0..8)
        .map(|index| {
            (
                index,
                PageDigest::hash(&vec![index as u8 + 1; 4096]).unwrap(),
            )
        })
        .collect();
    assert_eq!(
        original.updated(&changes).unwrap_err(),
        RamError::ResourceLimit
    );
    assert_eq!(original.digest(), original_digest);
    assert_eq!(constrained.used_bytes(), original_charge);
    drop(original);
    assert_eq!(constrained.used_bytes(), 0);
}

#[test]
fn oracle_independent_full_recompute_detects_suppressed_dirty() {
    let budget = MetadataBudget::new(1_000_000);
    let topology = topology(8193);
    let cached = RamSnapshot::new(
        topology.clone(),
        vec![RegionTree::zeroed(8193, &budget).unwrap()],
        &budget,
    )
    .unwrap();
    let mut actual = vec![0_u8; 8193];
    let recompute = |actual: &[u8]| {
        oracle::recompute(&topology, Scope::Execution, 3, |_, index, output| {
            let start = index as usize * 4096;
            output.copy_from_slice(&actual[start..start + output.len()]);
            Ok(())
        })
        .unwrap()
    };
    assert_eq!(
        recompute(&actual),
        cached.scoped_root(Scope::Execution).unwrap()
    );

    // Deliberately omit both dirty notification and production tree update.
    actual[4096] = 0x80;
    assert_ne!(
        recompute(&actual),
        cached.scoped_root(Scope::Execution).unwrap()
    );
    let corrected = cached
        .updated(
            "machine.ram",
            &[(1, PageDigest::hash(&actual[4096..8192]).unwrap())],
        )
        .unwrap();
    assert_eq!(
        recompute(&actual),
        corrected.scoped_root(Scope::Execution).unwrap()
    );
    let mut reads = 0;
    assert_eq!(
        oracle::recompute(&topology, Scope::Execution, 2, |_, _, _| {
            reads += 1;
            Ok(())
        }),
        Err(RamError::ResourceLimit)
    );
    assert_eq!(reads, 0);
    assert!(
        oracle::recompute(&topology, Scope::Execution, 3, |_, _, _| Err(
            RamError::Read("short source".into())
        ))
        .is_err()
    );
}

#[test]
fn dirty_consumers_preserve_races_and_cancel() {
    let budget = MetadataBudget::new(1_000_000);
    let mut tracker = DirtyTracker::new(
        topology(8192),
        TrackingIncarnation::new([1; 16]),
        TrackingLimits::default(),
        &budget,
    )
    .unwrap();
    tracker.mark_range("machine.ram", 4095, 2).unwrap();
    assert_eq!(tracker.page_version(coordinate(0)).unwrap().get(), 1);
    let fingerprint = tracker.capture(Consumer::Fingerprint).unwrap();
    let checkpoint = tracker.capture(Consumer::Checkpoint).unwrap();
    let cancelled = tracker.capture(Consumer::Transfer).unwrap();
    drop(cancelled);
    assert_eq!(tracker.pending_pages(Consumer::Transfer), 2);

    tracker.mark_page(coordinate(0)).unwrap();
    tracker.acknowledge(&fingerprint).unwrap();
    assert_eq!(tracker.pending_pages(Consumer::Fingerprint), 1);
    assert_eq!(tracker.pending_pages(Consumer::Checkpoint), 2);
    assert_eq!(tracker.pending_pages(Consumer::Paging), 2);
    tracker.acknowledge(&checkpoint).unwrap();
    assert_eq!(tracker.pending_pages(Consumer::Checkpoint), 1);
    assert_eq!(tracker.pending_pages(Consumer::Transfer), 2);
    assert!(tracker.acknowledge(&fingerprint).is_err());
    let paging = tracker.capture(Consumer::Paging).unwrap();
    tracker.acknowledge(&paging).unwrap();
    assert_eq!(tracker.pending_pages(Consumer::Paging), 0);
    assert_eq!(tracker.pending_pages(Consumer::Fingerprint), 1);
    assert_eq!(tracker.page_version(coordinate(0)).unwrap().get(), 2);
    drop(fingerprint);
    drop(checkpoint);
    drop(paging);
    drop(tracker);
    assert_eq!(budget.used_bytes(), 0);
}

#[test]
fn dirty_fork_and_restore_reject_stale_receipts() {
    let budget = MetadataBudget::new(1_000_000);
    let mut parent = DirtyTracker::new(
        topology(4096),
        TrackingIncarnation::new([1; 16]),
        TrackingLimits::default(),
        &budget,
    )
    .unwrap();
    parent.mark_page(coordinate(0)).unwrap();
    let parent_receipt = parent.capture(Consumer::Checkpoint).unwrap();
    let mut child = parent.fork(TrackingIncarnation::new([2; 16])).unwrap();
    assert_eq!(
        child.acknowledge(&parent_receipt),
        Err(RamError::StaleReceipt)
    );
    child.mark_page(coordinate(0)).unwrap();
    assert_eq!(parent.page_version(coordinate(0)).unwrap().get(), 1);
    assert_eq!(child.page_version(coordinate(0)).unwrap().get(), 2);
    let child_receipt = child.capture(Consumer::Checkpoint).unwrap();
    child.acknowledge(&child_receipt).unwrap();
    assert_eq!(parent.pending_pages(Consumer::Checkpoint), 1);
    assert!(parent.fork(parent.incarnation()).is_err());

    let mut restored = DirtyTracker::new(
        parent.topology().clone(),
        parent.incarnation(),
        TrackingLimits::default(),
        &budget,
    )
    .unwrap();
    assert_eq!(
        restored.acknowledge(&parent_receipt),
        Err(RamError::StaleReceipt)
    );
    assert_eq!(restored.page_version(coordinate(0)).unwrap().get(), 0);
}

#[test]
fn dirty_limits_reject_atomically() {
    let budget = MetadataBudget::new(1_000_000);
    let limits = TrackingLimits {
        max_versioned_pages: 2,
        max_dirty_entries: 4,
        max_capture_pages: 1,
    };
    let mut tracker = DirtyTracker::new(
        topology(8192),
        TrackingIncarnation::new([3; 16]),
        limits,
        &budget,
    )
    .unwrap();
    tracker.mark_page(coordinate(0)).unwrap();
    let used = budget.used_bytes();
    assert_eq!(
        tracker.mark_page(coordinate(1)),
        Err(RamError::ResourceLimit)
    );
    assert_eq!(tracker.page_version(coordinate(1)).unwrap().get(), 0);
    assert_eq!(budget.used_bytes(), used);
    assert!(tracker.mark_pages(&[coordinate(0), coordinate(0)]).is_err());
    assert!(tracker.mark_range("machine.ram", u64::MAX, 2).is_err());
    assert_eq!(tracker.page_version(coordinate(0)).unwrap().get(), 1);

    let immutable = Topology::new(
        vec![RegionDescriptor::new("firmware.rom", RegionClass::ImmutableImage, 1).unwrap()],
        Limits::default(),
    )
    .unwrap();
    let mut tracker = DirtyTracker::new(
        immutable,
        TrackingIncarnation::new([4; 16]),
        TrackingLimits::default(),
        &budget,
    )
    .unwrap();
    assert_eq!(
        tracker.mark_page(coordinate(0)),
        Err(RamError::InvalidEncoding)
    );
}

#[test]
fn persistent_batches_match_independent_oracle_across_geometry() {
    let budget = MetadataBudget::new(10_000_000);
    for count in 1_u64..=40 {
        let length = (count - 1) * 4096 + (count * 17 % 4096) + 1;
        let topology = topology(length);
        let mut contents = vec![0; length as usize];
        let initial = RegionTree::zeroed(length, &budget).unwrap();
        let mut updates = Vec::new();
        for page in (0..count).rev() {
            if page % 3 == 0 {
                let start = page as usize * 4096;
                let end = (start + 4096).min(contents.len());
                contents[start..end].fill((page % 11) as u8 + 1);
                updates.push((page, PageDigest::hash(&contents[start..end]).unwrap()));
            }
        }
        let tree = initial.updated(&updates).unwrap();
        let snapshot = RamSnapshot::new(topology.clone(), vec![tree.clone()], &budget).unwrap();
        let record = snapshot.root_record(Scope::Exact).unwrap();
        let recomputed = oracle::recompute(&topology, Scope::Exact, count, |_, index, output| {
            let start = index as usize * 4096;
            output.copy_from_slice(&contents[start..start + output.len()]);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            record.digest(),
            recomputed,
            "geometry with {count} pages diverged"
        );
        for index in 0..count {
            let proof = tree.proof("machine.ram", index).unwrap();
            let start = index as usize * 4096;
            proof
                .verify(
                    &contents[start..start + proof.valid_length() as usize],
                    &record,
                    record.digest(),
                )
                .unwrap();
        }
    }
    assert_eq!(budget.used_bytes(), 0);
}

#[test]
fn dirty_chunks_bound_dense_metadata_and_private_forks() {
    let budget = MetadataBudget::new(24_000);
    let limits = TrackingLimits {
        max_versioned_pages: 256,
        max_dirty_entries: 1024,
        max_capture_pages: 256,
    };
    let mut tracker = DirtyTracker::new(
        topology(256 * 4096),
        TrackingIncarnation::new([1; 16]),
        limits,
        &budget,
    )
    .unwrap();
    tracker.mark_range("machine.ram", 0, 256 * 4096).unwrap();
    assert!(
        budget.used_bytes() < 8192,
        "dense ledger did not amortize sparse chunk storage"
    );
    let mut child = tracker.fork(TrackingIncarnation::new([2; 16])).unwrap();
    let earlier = tracker.capture(Consumer::Paging).unwrap();
    tracker.mark_page(coordinate(127)).unwrap();
    let later = tracker.capture(Consumer::Paging).unwrap();
    tracker.acknowledge(&later).unwrap();
    assert_eq!(tracker.acknowledge(&earlier), Err(RamError::StaleReceipt));
    assert_eq!(tracker.pending_pages(Consumer::Paging), 0);
    assert_eq!(child.pending_pages(Consumer::Paging), 256);
    assert!(
        tracker
            .capture(Consumer::Paging)
            .unwrap()
            .entries()
            .is_empty()
    );
    child.mark_page(coordinate(128)).unwrap();
    assert_eq!(tracker.page_version(coordinate(128)).unwrap().get(), 1);
    assert_eq!(child.page_version(coordinate(128)).unwrap().get(), 2);
}

#[test]
fn owned_metadata_reservations_release_and_refuse_excess() {
    let budget = MetadataBudget::new(1000);
    let first = budget.reserve_bytes(900).unwrap();
    assert_eq!(first.bytes(), 900);
    assert_eq!(budget.used_bytes(), 900);
    assert!(matches!(
        budget.reserve_bytes(101),
        Err(RamError::ResourceLimit)
    ));
    let last = budget.reserve_bytes(100).unwrap();
    assert_eq!(budget.used_bytes(), 1000);
    drop(first);
    assert_eq!(budget.used_bytes(), 100);
    drop(last);
    assert_eq!(budget.used_bytes(), 0);
}
