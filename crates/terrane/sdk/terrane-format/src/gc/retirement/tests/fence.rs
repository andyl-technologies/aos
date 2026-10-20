//! Checks exact embedded fence schemas and represented catalog relationships.

use super::*;

fn capabilities_bytes() -> Vec<u8> {
    let mut bytes = vec![
        0xab, 1, 2, 2, 0xf5, 3, 0xf5, 4, 0xf5, 5, 0xf4, 6, 1, 7, 4, 8, 0xa4, 1,
    ];
    write_text(&mut bytes, "terrane-v1");
    write_uint(&mut bytes, 2);
    write_text(&mut bytes, "blake3");
    write_uint(&mut bytes, 3);
    write_text(&mut bytes, "cdc-1m");
    write_uint(&mut bytes, 4);
    write_bytes(&mut bytes, &[0; 32]);
    bytes.extend_from_slice(&[9, 1, 10, 0x80, 11, 1]);
    bytes
}

fn manifest_bytes(copy: bool) -> Vec<u8> {
    let mut bytes = vec![0xa7, 1, 1, 2, 0x80, 3, 4, 4, 3, 5, 0x80, 6, 0x81];
    exclusion_bytes(&mut bytes);
    write_uint(&mut bytes, 7);
    write_array(&mut bytes, usize::from(copy));
    if copy {
        write_bytes(&mut bytes, &PACK);
    }
    bytes
}

fn fence_state_bytes(copy: bool, local: bool) -> Vec<u8> {
    let mut bytes = vec![0xa8, 0, 1, 1, 2, 2, 0, 3, 0x80, 4];
    bytes.extend(if local { local_bytes() } else { remote_bytes() });
    bytes.extend_from_slice(&[5, 0x80, 6]);
    write_bytes(&mut bytes, &[17; 32]);
    bytes.push(7);
    write_array(&mut bytes, usize::from(copy));
    if copy {
        write_array(&mut bytes, 2);
        write_bytes(&mut bytes, &PACK);
        bytes.extend_from_slice(&[0x81, 0]);
    }
    bytes
}

fn fence_bytes(copy: bool, local: bool) -> Vec<u8> {
    fence_bytes_at_cycle(copy, local, 3)
}

fn fence_bytes_at_cycle(copy: bool, local: bool, cycle: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_map(&mut bytes, if copy { 12 } else { 10 });
    field(&mut bytes, 0, if copy { 2 } else { 1 });
    write_uint(&mut bytes, 1);
    write_bytes(&mut bytes, &capabilities_bytes());
    write_uint(&mut bytes, 2);
    write_bytes(&mut bytes, &manifest_bytes(copy));
    bytes.extend_from_slice(&[3, 0x80, 4]);
    write_bytes(&mut bytes, &[17; 32]);
    write_uint(&mut bytes, 5);
    write_bytes(&mut bytes, &fence_state_bytes(copy, local));
    write_uint(&mut bytes, 6);
    pointer(&mut bytes, &format!("gc/{cycle}/roots"), [18; 32]);
    write_uint(&mut bytes, 7);
    pointer(&mut bytes, &format!("gc/{cycle}/state"), [19; 32]);
    write_uint(&mut bytes, 8);
    bytes.extend(if local { local_bytes() } else { remote_bytes() });
    bytes.extend_from_slice(&[9, 0x80]);
    if copy {
        write_uint(&mut bytes, 10);
        slot(&mut bytes, 0, [9; 32]);
        write_uint(&mut bytes, 11);
        pointer(
            &mut bytes,
            &format!("publication/snapshots/2:{}", "00".repeat(32)),
            [20; 32],
        );
    }
    bytes
}

fn ref_inventory_prefix(copied: bool) -> Vec<u8> {
    let bytes = fence_bytes(copied, false);
    let mut decoder = crate::cbor::Decoder::new(&bytes);
    decoder.map(12).unwrap();
    for key in 0..=3 {
        assert_eq!(decoder.uint().unwrap(), key);
        if key != 3 {
            decoder.skip_value(MAX_RECORD_BYTES).unwrap();
        }
    }
    bytes[..decoder.position()].to_vec()
}

fn ref_row_bytes(name: &str, current: Option<&[u8]>) -> Vec<u8> {
    let mut row = vec![0x84];
    write_text(&mut row, name);
    if let Some(current) = current {
        write_bytes(&mut row, current);
    } else {
        row.push(0xf6);
    }
    row.extend_from_slice(&[0x81, 0, 0xf6]);
    row
}

#[test]
fn permanent_fences_match_independent_bytes_and_keep_copy_data_separate() {
    let bytes = fence_bytes(false, false);
    let current = CurrentCollectionFence::decode(&bytes).unwrap();
    assert_eq!(current.encode().unwrap(), bytes);
    assert!(CopiedPlacementFence::decode(&bytes).is_err());
    let mut authorization =
        RemoteSweepDeleteAuthorization::decode(&auth_bytes(false, false)).unwrap();
    authorization.fence.digest = *blake3::hash(&bytes).as_bytes();
    PermanentDeleteAuthorization::Sweep(authorization)
        .check_fence(&bytes)
        .unwrap();
    for local in [false, true] {
        let bytes = fence_bytes(true, local);
        let fence = CopiedPlacementFence::decode(&bytes).unwrap();
        assert_eq!(fence.encode().unwrap(), bytes);
        assert!(CurrentCollectionFence::decode(&bytes).is_err());
        let mut authorization =
            CopiedRetirementAuthorization::decode(&auth_bytes(true, local)).unwrap();
        authorization.fence.digest = *blake3::hash(&bytes).as_bytes();
        PermanentDeleteAuthorization::Copied(authorization)
            .check_fence(&bytes)
            .unwrap();
        for cut in 0..bytes.len() {
            assert!(CopiedPlacementFence::decode(&bytes[..cut]).is_err());
        }
    }
}

#[test]
fn copied_authorization_keeps_its_barrier_with_a_fresh_current_checkpoint() {
    for local in [false, true] {
        let bytes = fence_bytes_at_cycle(true, local, 9);
        let fence = CopiedPlacementFence::decode(&bytes).unwrap();
        assert_eq!(fence.encode().unwrap(), bytes);
        assert_eq!(fence.roots.key, "gc/9/roots");
        assert_eq!(fence.marks.key, "gc/9/state");

        let mut authorization =
            CopiedRetirementAuthorization::decode(&auth_bytes(true, local)).unwrap();
        let original = authorization.clone();
        authorization.fence = RecordPointer {
            key: "gc/9/fence/2".into(),
            digest: *blake3::hash(&bytes).as_bytes(),
        };
        let checked = PermanentDeleteAuthorization::Copied(authorization.clone());
        checked.check_fence(&bytes).unwrap();
        checked.check_predecessor(&fence.state).unwrap();
        checked.check_key(&key()).unwrap();
        let mut lineage = authorization.clone();
        lineage.lineage_fence = Some(RecordPointer {
            key: "gc/11/fence/2".into(),
            digest: [12; 32],
        });
        PermanentDeleteAuthorization::Copied(lineage.clone())
            .check_predecessor(&fence.state)
            .unwrap();
        lineage.lineage_fence.as_mut().unwrap().key = "gc/11/fence/3".into();
        assert!(
            PermanentDeleteAuthorization::Copied(lineage)
                .check_predecessor(&fence.state)
                .is_err()
        );
        assert_eq!(authorization.exclusion, original.exclusion);
        assert_eq!(authorization.barrier, original.barrier);
        assert_eq!(authorization.tombstone, original.tombstone);
        assert_eq!(authorization.preparation, original.preparation);
        assert_eq!(
            authorization.grace_elapsed_nanos,
            original.grace_elapsed_nanos
        );
        assert_eq!(
            authorization.deletion_elapsed_nanos,
            original.deletion_elapsed_nanos
        );

        for invalid in ["gc/3/fence/2", "gc/9/fence/1", "gc/9/fence/3"] {
            let mut mismatch = authorization.clone();
            mismatch.fence.key = invalid.into();
            assert!(
                PermanentDeleteAuthorization::Copied(mismatch)
                    .check_fence(&bytes)
                    .is_err()
            );
        }
        let mut wrong_digest = authorization;
        wrong_digest.fence.digest[0] ^= 1;
        assert!(
            PermanentDeleteAuthorization::Copied(wrong_digest)
                .check_fence(&bytes)
                .is_err()
        );
    }

    // Ordinary sweep remains tied to its original collection cycle.
    let mut sweep = RemoteSweepDeleteAuthorization::decode(&auth_bytes(false, false)).unwrap();
    sweep.fence.key = "gc/9/fence/2".into();
    assert!(sweep.encode().is_err());
}

#[test]
fn copied_fence_rejects_unknown_inventory_burn_disagreement_and_wrong_stamps() {
    let value = CopiedPlacementFence::decode(&fence_bytes(true, false)).unwrap();
    let mut invalid = value.clone();
    let mut manifest = crate::bucket::GenerationManifest::decode(&invalid.manifest).unwrap();
    manifest.burns = None;
    invalid.manifest = manifest.encode().unwrap();
    assert!(invalid.encode().is_err());
    invalid = value.clone();
    invalid.state.burn_owners = Some(vec![]);
    assert!(invalid.encode().is_err());
    invalid = value.clone();
    invalid.genesis.revision = 1;
    assert!(invalid.encode().is_err());
    invalid = value.clone();
    invalid.guard[0] ^= 1;
    assert!(invalid.encode().is_err());
    invalid = value.clone();
    invalid.marks.key = "gc/4/state".into();
    assert!(invalid.encode().is_err());
    invalid = value.clone();
    invalid.projection.key = format!("publication/snapshots/3:{}", "00".repeat(32));
    assert!(invalid.encode().is_err());
    invalid = value;
    invalid.capabilities = vec![0xa0];
    assert!(invalid.encode().is_err());
}

#[test]
fn fence_pointer_checks_raw_bytes_and_predecessor_not_future_selecting_slot() {
    let bytes = fence_bytes(true, false);
    let fence = CopiedPlacementFence::decode(&bytes).unwrap();
    let pointer = RecordPointer {
        key: "gc/3/fence/2".into(),
        digest: *blake3::hash(&bytes).as_bytes(),
    };
    fence.check_pointer(&pointer).unwrap();
    for key in [
        "gc/3/fence/3",
        "gc/4/fence/2",
        "gc/03/fence/2",
        "gc/3/fence/02",
        "gc/3/fence/2/extra",
    ] {
        let mut invalid = pointer.clone();
        invalid.key = key.into();
        assert!(fence.check_pointer(&invalid).is_err());
    }
    let mut invalid = pointer;
    invalid.digest[0] ^= 1;
    assert!(fence.check_pointer(&invalid).is_err());
}

#[test]
fn fence_inventory_headers_do_not_reserve_storage_before_validating_rows() {
    for copied in [false, true] {
        let valid = fence_bytes(copied, false);
        for field in [3, 9] {
            let mut decoder = crate::cbor::Decoder::new(&valid);
            decoder.map(12).unwrap();
            for key in 0..=field {
                assert_eq!(decoder.uint().unwrap(), key);
                if key != field {
                    decoder.skip_value(MAX_RECORD_BYTES).unwrap();
                }
            }

            // The declared count fits the remaining encoded bytes but would
            // reserve gigabytes of typed rows if used as a capacity hint.
            // A uint first row is invalid for both represented inventories.
            let mut malformed = valid[..decoder.position()].to_vec();
            write_array(&mut malformed, 10_000_000);
            malformed.resize(MAX_RECORD_BYTES, 0);
            let result = if copied {
                CopiedPlacementFence::decode(&malformed).map(|_| ())
            } else {
                CurrentCollectionFence::decode(&malformed).map(|_| ())
            };
            if field == 3 {
                assert_eq!(
                    result,
                    Err(RetirementError::Cbor(crate::cbor::Error::Malformed))
                );
            } else {
                assert_eq!(
                    result,
                    Err(RetirementError::Evidence(
                        crate::gc::publication::evidence::EvidenceError::Cbor(
                            crate::cbor::Error::Malformed
                        ),
                    ))
                );
            }
        }

        if copied {
            let decoded = CopiedPlacementFence::decode(&valid).unwrap();
            assert_eq!(decoded.encode().unwrap(), valid);
        } else {
            let decoded = CurrentCollectionFence::decode(&valid).unwrap();
            assert_eq!(decoded.encode().unwrap(), valid);
        }
    }

    let mut value = CopiedPlacementFence::decode(&fence_bytes(true, false)).unwrap();
    let mut capabilities = crate::bucket::BucketCapabilities::decode(&value.capabilities).unwrap();
    let name = "refs/heads/_/main";
    capabilities.ref_names = Some(vec![name.into()]);
    value.capabilities = capabilities.encode().unwrap();
    value.refs = vec![FenceRef {
        name: name.into(),
        current: None,
        selection: crate::gc::publication::CommittedSelection::Never,
        log: None,
    }];
    value.state.branches = vec![crate::gc::publication::HistoryEntry {
        name: name.into(),
        selection: crate::gc::publication::CommittedSelection::Never,
    }];
    value.controls = vec![crate::gc::publication::evidence::RequiredControlPin {
        kind: crate::gc::publication::evidence::ControlKind::Registration,
        owner: crate::gc::publication::evidence::PhysicalRegistration::Local(
            crate::gc::publication::evidence::LocalOriginalRegistration {
                original_id: [1; 32],
                root: b"/r".to_vec(),
                domain: "public".into(),
                root_device: 1,
                root_inode: 2,
                coordination_device: 3,
                coordination_inode: 4,
                control: b"/c".to_vec(),
            },
        ),
        key: "registration.cbor".into(),
        digest: [2; 32],
    }];
    let bytes = value.encode().unwrap();
    assert_eq!(CopiedPlacementFence::decode(&bytes).unwrap(), value);
    let current = value.current_fields();
    let bytes = current.encode().unwrap();
    assert_eq!(CurrentCollectionFence::decode(&bytes).unwrap(), current);
}

#[test]
fn fence_ref_rows_validate_names_order_and_current_records_before_growing_inventory() {
    for copied in [false, true] {
        for (name, count) in [("", 1), ("refs/notes/memos/_/a", 2), ("refs/notes/a", 1)] {
            let row = ref_row_bytes(name, None);
            let mut malformed = ref_inventory_prefix(copied);
            write_array(&mut malformed, count);
            for _ in 0..count {
                malformed.extend_from_slice(&row);
            }

            // These inputs end immediately after structurally complete rows.
            // The row error must be reported before missing later fence fields.
            let result = if copied {
                CopiedPlacementFence::decode(&malformed).map(|_| ())
            } else {
                CurrentCollectionFence::decode(&malformed).map(|_| ())
            };
            assert_eq!(result, Err(RetirementError::Schema));
        }

        let mut reversed = ref_inventory_prefix(copied);
        write_array(&mut reversed, 2);
        reversed.extend_from_slice(&ref_row_bytes("refs/notes/memos/_/z", None));
        reversed.extend_from_slice(&ref_row_bytes("refs/notes/memos/_/a", None));
        let result = if copied {
            CopiedPlacementFence::decode(&reversed).map(|_| ())
        } else {
            CurrentCollectionFence::decode(&reversed).map(|_| ())
        };
        assert_eq!(result, Err(RetirementError::Schema));

        let mut invalid_current = ref_inventory_prefix(copied);
        write_array(&mut invalid_current, 1);
        invalid_current.extend_from_slice(&ref_row_bytes("refs/heads/_/main", Some(&[0])));
        let result = if copied {
            CopiedPlacementFence::decode(&invalid_current).map(|_| ())
        } else {
            CurrentCollectionFence::decode(&invalid_current).map(|_| ())
        };
        assert_eq!(
            result,
            Err(RetirementError::Publication(PublicationError::Ref(
                crate::refs::RecordError::Cbor(crate::cbor::Error::Malformed),
            )))
        );
    }

    // Notes preserve their existing opaque current bytes; their row does not
    // acquire RefRecord interpretation or source authority from this decoder.
    let mut value = CopiedPlacementFence::decode(&fence_bytes(true, false)).unwrap();
    let mut capabilities = crate::bucket::BucketCapabilities::decode(&value.capabilities).unwrap();
    capabilities.ref_names = Some(vec!["refs/notes/memos/_/a".into()]);
    value.capabilities = capabilities.encode().unwrap();
    value.refs = vec![FenceRef {
        name: "refs/notes/memos/_/a".into(),
        current: Some(vec![0]),
        selection: crate::gc::publication::CommittedSelection::Never,
        log: None,
    }];
    let bytes = value.encode().unwrap();
    assert_eq!(CopiedPlacementFence::decode(&bytes).unwrap(), value);
    let current = value.current_fields();
    let bytes = current.encode().unwrap();
    assert_eq!(CurrentCollectionFence::decode(&bytes).unwrap(), current);
}
