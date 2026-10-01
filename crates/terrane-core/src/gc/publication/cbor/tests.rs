//! Exercises independently assembled canonical witnesses and contradictions.
//!
//! Fixtures below are hand-transcribed from CDDL diagnostic shapes. Changes
//! require byte-level schema review; production codecs do not regenerate them.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod retirement;

use super::*;
use crate::cbor;
use crate::refs::Locality;
use alloc::{format, vec};

fn local() -> BackendBinding {
    BackendBinding::Local {
        root: b"/a".to_vec(),
        root_device: 1,
        root_inode: 2,
        coordination_device: 3,
        coordination_inode: 4,
    }
}

fn state(revision: u64) -> PublicationState {
    PublicationState {
        revision,
        loss_generation: 0,
        sources: vec![],
        binding: local(),
        branches: vec![],
        guard: None,
        burn_owners: None,
    }
}

fn pointer(revision: u64) -> PortableCurrent {
    PortableCurrent {
        key: format!("publication/snapshots/{revision}:{}", "00".repeat(32)),
        digest: [7; 32],
    }
}

fn head(seq: u64) -> RefRecord {
    RefRecord {
        commit: [8; 32],
        seq,
        writer_epoch: 1,
        home: Locality::default(),
        policy: None,
        candidate_id: Some([9; 32]),
    }
}

fn history_value(branches: Vec<HistoryEntry>) -> Vec<u8> {
    SelectedHistory {
        branches,
        origin: local(),
    }
    .encode()
    .expect("selected history")
}

fn transaction() -> PublicationTransaction {
    PublicationTransaction {
        nonce: [0; 32],
        old: Some(state(0)),
        new: state(1),
        changes: vec![],
        proof: PublicationProof::Raw,
        predecessor: Some(PredecessorSlot {
            revision: 0,
            digest: [3; 32],
        }),
        snapshot: pointer(1),
    }
}

#[test]
fn local_binding_and_registration_match_independent_bytes() {
    let binding = [0x86, 0, 0x42, b'/', b'a', 1, 2, 3, 4];
    assert_eq!(local().encode().unwrap(), binding);
    assert_eq!(BackendBinding::decode(&binding).unwrap(), local());

    let pending = [
        0xa4, 0, 1, 1, 0x86, 0, 0x42, b'/', b'a', 1, 2, 3, 4, 2, 0, 3, 0xf6,
    ];
    assert_eq!(
        BackendRegistration::decode(&pending).unwrap(),
        BackendRegistration {
            binding: local(),
            activation: Activation::Pending,
            genesis: None
        }
    );
    assert_eq!(
        BackendRegistration::decode(&pending)
            .unwrap()
            .encode()
            .unwrap(),
        pending
    );

    let mut active = pending[..pending.len() - 1].to_vec();
    active[14] = 1;
    active.extend_from_slice(&[0x58, 0x20]);
    active.extend_from_slice(&[5; 32]);
    let decoded = BackendRegistration::decode(&active).unwrap();
    assert_eq!(decoded.activation, Activation::Active);
    assert_eq!(decoded.genesis, Some([5; 32]));
    assert_eq!(decoded.encode().unwrap(), active);
}

#[test]
fn remote_binding_keeps_exact_resource_and_nonce_bytes() {
    let mut fixture = vec![
        0x84, 1, 0x62, b's', b'3', 0x84, 0x61, b'e', 0x61, b'b', 0x40, 0x58, 0x20,
    ];
    fixture.extend_from_slice(&[1; 32]);
    fixture.extend_from_slice(&[0x82, 0x41, b'k', 0x58, 0x20]);
    fixture.extend_from_slice(&[2; 32]);

    let value = BackendBinding::Remote {
        provider: RemoteProvider::S3,
        endpoint: "e".into(),
        bucket: "b".into(),
        prefix: vec![],
        resource_nonce: [1; 32],
        coordination_key: b"k".to_vec(),
        coordination_nonce: [2; 32],
    };
    assert_eq!(BackendBinding::decode(&fixture).unwrap(), value);
    assert_eq!(value.encode().unwrap(), fixture);
}

#[test]
fn never_and_unknown_are_distinct_and_exact() {
    assert_eq!(CommittedSelection::Never.encode().unwrap(), [0x81, 0]);
    assert_eq!(CommittedSelection::Unknown.encode().unwrap(), [0x81, 2]);
    assert_eq!(
        CommittedSelection::decode(&[0x81, 0]).unwrap(),
        CommittedSelection::Never
    );
    assert_eq!(
        CommittedSelection::decode(&[0x81, 2]).unwrap(),
        CommittedSelection::Unknown
    );

    let fixture = [
        0xa3, 0, 1, 1, 0x80, 2, 0x86, 0, 0x42, b'/', b'a', 1, 2, 3, 4,
    ];
    let value = SelectedHistory {
        branches: vec![],
        origin: local(),
    };
    assert_eq!(value.encode().unwrap(), fixture);
    assert_eq!(SelectedHistory::decode(&fixture).unwrap(), value);
}

#[test]
fn retained_whole_ref_uses_unchanged_existing_bytes() {
    let mut fixture = vec![0x82, 1, 0xa4, 1, 0x58, 0x20];
    fixture.extend_from_slice(&[8; 32]);
    fixture.extend_from_slice(&[2, 1, 3, 1, 4, 0xa0]);
    let mut record = head(1);
    record.candidate_id = None;
    assert_eq!(
        CommittedSelection::Selected(record.clone().into())
            .encode()
            .unwrap(),
        fixture
    );
    assert_eq!(
        CommittedSelection::decode(&fixture).unwrap(),
        CommittedSelection::Selected(record.into())
    );
}

#[test]
fn selected_state_and_current_have_exact_map_fields() {
    let fixture = [
        0xa7, 0, 1, 1, 0, 2, 0, 3, 0x80, 4, 0x86, 0, 0x42, b'/', b'a', 1, 2, 3, 4, 5, 0x80, 6, 0xf6,
    ];
    assert_eq!(state(0).encode().unwrap(), fixture);
    assert_eq!(PublicationState::decode(&fixture).unwrap(), state(0));

    let mut current = vec![0xa3, 0, 1, 1, 0, 2, 0x58, 0x20];
    current.extend_from_slice(&[6; 32]);
    let value = PublicationCurrent {
        revision: 0,
        digest: [6; 32],
    };
    assert_eq!(value.encode().unwrap(), current);
    assert_eq!(PublicationCurrent::decode(&current).unwrap(), value);
}

#[test]
fn proof_cases_match_independent_small_fixtures() {
    assert_eq!(PublicationProof::Raw.encode().unwrap(), [0x81, 0]);
    for (case, value) in [
        (1, PublicationProof::Candidate([3; 32])),
        (4, PublicationProof::Guard([3; 32])),
    ] {
        let mut fixture = vec![0x82, case, 0x58, 0x20];
        fixture.extend_from_slice(&[3; 32]);
        assert_eq!(value.encode().unwrap(), fixture);
        assert_eq!(PublicationProof::decode(&fixture).unwrap(), value);
    }
    let mut fixture = vec![0x85, 2, 0x6c];
    fixture.extend_from_slice(b"gc/0/fence/0");
    // The key is twelve bytes including its separators.
    fixture[2] = 0x6c;
    fixture.extend_from_slice(&[0x58, 0x20]);
    fixture.extend_from_slice(&[4; 32]);
    fixture.extend_from_slice(&[0x80, 0x80]);
    let value = PublicationProof::Collection {
        fence_key: "gc/0/fence/0".into(),
        fence_digest: [4; 32],
        removed: vec![],
        carried: vec![],
    };
    assert_eq!(value.encode().unwrap(), fixture);
    assert_eq!(PublicationProof::decode(&fixture).unwrap(), value);
}

#[test]
fn portable_pointer_and_commit_match_independent_key_witnesses() {
    let pointer = pointer(0);
    let mut fixture = vec![0xa3, 0, 1, 1, 0x78, 0x58];
    fixture.extend_from_slice(b"publication/snapshots/0:");
    fixture.extend_from_slice("00".repeat(32).as_bytes());
    fixture.extend_from_slice(&[2, 0x58, 0x20]);
    fixture.extend_from_slice(&[7; 32]);
    assert_eq!(pointer.encode().unwrap(), fixture);
    assert_eq!(PortableCurrent::decode(&fixture).unwrap(), pointer);

    let key = format!("publication/transactions/{}", "00".repeat(32));
    let mut fixture = vec![0xa5, 0, 1, 1, 0, 2, 0xf6, 3, 0x78, 0x59];
    fixture.extend_from_slice(key.as_bytes());
    fixture.extend_from_slice(&[4, 0x58, 0x20]);
    fixture.extend_from_slice(&[1; 32]);
    let value = PublicationCommit {
        revision: 0,
        predecessor: None,
        transaction_key: key,
        transaction_digest: [1; 32],
    };
    assert_eq!(value.encode().unwrap(), fixture);
    assert_eq!(PublicationCommit::decode(&fixture).unwrap(), value);
}

#[test]
fn delta_snapshot_has_independent_empty_projection_fixture() {
    let mut fixture = vec![
        0xa5, 0, 1, 1, 1, 2, 0x86, 0, 0x42, b'/', b'a', 1, 2, 3, 4, 3, 0x80, 4, 0x82, 0x78, 0x58,
    ];
    fixture.extend_from_slice(b"publication/snapshots/0:");
    fixture.extend_from_slice("00".repeat(32).as_bytes());
    fixture.extend_from_slice(&[0x58, 0x20]);
    fixture.extend_from_slice(&[7; 32]);
    let value = PortableSnapshot {
        revision: 1,
        origin: local(),
        projection: vec![],
        predecessor: Some(pointer(0)),
    };
    assert_eq!(value.encode().unwrap(), fixture);
    assert_eq!(PortableSnapshot::decode(&fixture).unwrap(), value);
}

#[test]
fn transaction_has_independently_assembled_exact_embedded_state_fixture() {
    let old = [
        0xa7, 0, 1, 1, 0, 2, 0, 3, 0x80, 4, 0x86, 0, 0x42, b'/', b'a', 1, 2, 3, 4, 5, 0x80, 6, 0xf6,
    ];
    let mut next = old;
    next[4] = 1;
    let mut fixture = vec![0xa8, 0, 1, 1, 0x58, 0x20];
    fixture.extend_from_slice(&[0; 32]);
    fixture.extend_from_slice(&[2, 0x57]);
    fixture.extend_from_slice(&old);
    fixture.extend_from_slice(&[3, 0x57]);
    fixture.extend_from_slice(&next);
    fixture.extend_from_slice(&[4, 0x80, 5, 0x81, 0, 6, 0x82, 0, 0x58, 0x20]);
    fixture.extend_from_slice(&[3; 32]);
    fixture.extend_from_slice(&[7, 0x82, 0x78, 0x58]);
    fixture.extend_from_slice(b"publication/snapshots/1:");
    fixture.extend_from_slice("00".repeat(32).as_bytes());
    fixture.extend_from_slice(&[0x58, 0x20]);
    fixture.extend_from_slice(&[7; 32]);
    assert_eq!(transaction().encode().unwrap(), fixture);
    assert_eq!(
        PublicationTransaction::decode(&fixture).unwrap(),
        transaction()
    );
}

#[test]
fn rejects_noncanonical_missing_unknown_and_trailing_fields() {
    let fixtures: &[(&str, &[u8])] = &[
        ("nonminimal", &[0x81, 0x18, 0]),
        ("indefinite", &[0x9f, 0, 0xff]),
        ("wrong arity", &[0x82, 0, 0]),
        ("unregistered selection", &[0x81, 3]),
        ("trailing", &[0x81, 0, 0]),
        ("tag", &[0xc0, 0x81, 0]),
        ("float", &[0x81, 0xf9, 0, 0]),
        ("oversized", &[0x9a, 0xff, 0xff, 0xff, 0xff]),
    ];
    for (name, bytes) in fixtures {
        assert!(CommittedSelection::decode(bytes).is_err(), "{name}");
    }
    let bytes = state(0).encode().unwrap();
    for cut in 0..bytes.len() {
        assert!(
            PublicationState::decode(&bytes[..cut]).is_err(),
            "cut {cut}"
        );
    }
    let mut bytes = bytes;
    bytes[2] = 2;
    assert!(PublicationState::decode(&bytes).is_err());
    bytes[2] = 1;
    bytes[3] = 0;
    assert!(PublicationState::decode(&bytes).is_err());
}

#[test]
fn rejects_non_normalized_local_roots_and_remote_lengths() {
    for root in [
        b"relative".as_slice(),
        b"//a",
        b"/a/",
        b"/a/./b",
        b"/a/../b",
        b"/a\0",
    ] {
        let binding = BackendBinding::Local {
            root: root.to_vec(),
            root_device: 0,
            root_inode: 0,
            coordination_device: 0,
            coordination_inode: 0,
        };
        assert!(binding.encode().is_err(), "{root:?}");
    }
    let mut binding = local();
    if let BackendBinding::Local { root, .. } = &mut binding {
        *root = b"/".to_vec();
    }
    assert!(binding.encode().is_ok());
    let mut fixture = vec![0x84, 1, 0x62, b's', b'3', 0x84, 0x79, 0x10, 0x01];
    fixture.extend_from_slice(&[b'e'; 4097]);
    assert_eq!(
        BackendBinding::decode(&fixture),
        Err(PublicationError::Cbor(cbor::Error::Limit))
    );
}

#[test]
fn registration_cannot_regress_or_replace_binding_or_genesis() {
    let pending = BackendRegistration {
        binding: local(),
        activation: Activation::Pending,
        genesis: None,
    };
    let active = BackendRegistration {
        binding: local(),
        activation: Activation::Active,
        genesis: Some([1; 32]),
    };
    pending.check_successor(&active).unwrap();
    assert!(active.check_successor(&pending).is_err());
    let mut changed = active.clone();
    changed.genesis = Some([2; 32]);
    assert!(active.check_successor(&changed).is_err());
    changed.genesis = None;
    assert!(changed.encode().is_err());
}

#[test]
fn rejects_unsorted_duplicate_and_nonbranch_history() {
    for names in [
        vec!["refs/heads/_/b", "refs/heads/_/a"],
        vec!["refs/heads/_/a", "refs/heads/_/a"],
        vec!["refs/tags/_/a"],
    ] {
        let value = SelectedHistory {
            branches: names
                .iter()
                .map(|name| HistoryEntry {
                    name: (*name).into(),
                    selection: CommittedSelection::Never,
                })
                .collect(),
            origin: local(),
        };
        assert!(value.encode().is_err(), "{names:?}");
    }
}

#[test]
fn snapshot_rejects_lease_private_control_pointer_and_wrong_predecessor() {
    let mut snapshot = PortableSnapshot {
        revision: 1,
        origin: local(),
        projection: vec![],
        predecessor: Some(pointer(0)),
    };
    for key in [
        "publication/PORTABLE",
        "publication/guards/a",
        "gc/0/state",
        "objects/pack/aa/a",
        "refs/heads/_/main",
    ] {
        snapshot.projection = vec![ProjectionEntry {
            key: key.into(),
            value: None,
        }];
        assert!(snapshot.encode().is_err(), "{key}");
    }
    snapshot.projection = vec![ProjectionEntry {
        key: "gc/lease".into(),
        value: Some(vec![0]),
    }];
    assert!(snapshot.encode().is_err());
    snapshot.projection.clear();
    snapshot.revision = 2;
    assert!(snapshot.encode().is_err());
    snapshot.predecessor = None;
    assert!(snapshot.encode().is_err());
}

#[test]
fn checkpoint_requires_complete_history_origin_and_current_ref_consistency() {
    let mut snapshot = PortableSnapshot {
        revision: 0,
        origin: local(),
        predecessor: None,
        projection: vec![
            ProjectionEntry {
                key: "CAPABILITIES".into(),
                value: Some(vec![0xa0]),
            },
            ProjectionEntry {
                key: "gc/lease".into(),
                value: None,
            },
            ProjectionEntry {
                key: "publication/SELECTED-HISTORY".into(),
                value: Some(history_value(vec![])),
            },
        ],
    };
    snapshot.encode().unwrap();
    let branches = vec![HistoryEntry {
        name: "refs/heads/_/main".into(),
        selection: CommittedSelection::Selected(head(1).into()),
    }];
    snapshot.projection[2].value = Some(history_value(branches));
    assert!(snapshot.encode().is_err());
    snapshot.projection.push(ProjectionEntry {
        key: "refs/heads/_/main:record".into(),
        value: Some(head(2).encode().unwrap()),
    });
    assert!(snapshot.encode().is_err());
    snapshot.projection[3].value = Some(head(1).encode().unwrap());
    snapshot.encode().unwrap();
}

#[test]
fn transaction_rejects_revision_binding_predecessor_and_nonce_contradictions() {
    let original = transaction();
    let mut changed = original.clone();
    changed.new.revision = 2;
    assert!(changed.encode().is_err());
    changed = original.clone();
    changed.predecessor = None;
    assert!(changed.encode().is_err());
    changed = original.clone();
    changed.nonce[0] = 1;
    assert!(changed.encode().is_err());
    changed = original.clone();
    changed.new.loss_generation = 1;
    changed.old.as_mut().unwrap().loss_generation = 2;
    assert!(changed.encode().is_err());
    changed = original;
    changed.old.as_mut().unwrap().revision = u64::MAX;
    assert_eq!(changed.encode(), Err(PublicationError::Exhausted));
}

#[test]
fn raw_mutation_cannot_install_guard_or_lineage() {
    let mut value = transaction();
    value.new.guard = Some([1; 32]);
    assert!(value.encode().is_err());
    value.old.as_mut().unwrap().guard = Some([1; 32]);
    value.new.sources = vec![SourceLineage {
        name: "refs/tags/_/v1".into(),
        digest: [2; 32],
    }];
    assert!(value.encode().is_err());
    value.old.as_mut().unwrap().sources = value.new.sources.clone();
    value.encode().unwrap();
    value.new.loss_generation = 1;
    assert!(value.encode().is_err());
}

#[test]
fn retained_history_cannot_disappear_reset_or_skip_sequence() {
    let name = "refs/heads/_/main";
    let old_branch = HistoryEntry {
        name: name.into(),
        selection: CommittedSelection::Selected(head(1).into()),
    };
    let mut value = transaction();
    value.old.as_mut().unwrap().branches = vec![old_branch.clone()];
    assert!(value.encode().is_err());
    value.new.branches = vec![HistoryEntry {
        name: name.into(),
        selection: CommittedSelection::Never,
    }];
    assert!(value.encode().is_err());
    value.new.branches = vec![HistoryEntry {
        name: name.into(),
        selection: CommittedSelection::Selected(head(3).into()),
    }];
    assert!(value.encode().is_err());
    value.new.branches = vec![old_branch];
    value.changes = vec![LogicalChange {
        key: format!("{name}:record"),
        expected: Some(head(1).encode().unwrap()),
        new: None,
    }];
    assert!(value.encode().is_err());
    let history = history_value(value.new.branches.clone());
    value.changes.insert(
        0,
        LogicalChange {
            key: "publication/SELECTED-HISTORY".into(),
            expected: Some(history.clone()),
            new: Some(history),
        },
    );
    value.encode().unwrap();
}

#[test]
fn proof_checks_guard_selector_and_exact_carried_sources() {
    let mut value = transaction();
    value.proof = PublicationProof::Guard([3; 32]);
    assert!(value.encode().is_err());
    value.new.guard = Some([3; 32]);
    value.encode().unwrap();
    value.proof = PublicationProof::Collection {
        fence_key: "gc/0/fence/0".into(),
        fence_digest: [4; 32],
        removed: vec![RemovedPack {
            pack: [1; 16],
            index: [5; 32],
        }],
        carried: vec![],
    };
    value.old.as_mut().unwrap().guard = value.new.guard;
    assert!(value.encode().is_err());
    value.new.loss_generation = 1;
    value.encode().unwrap();
    if let PublicationProof::Collection { removed, .. } = &mut value.proof {
        let mut contradictory = removed[0].clone();
        contradictory.index = [6; 32];
        removed.push(contradictory);
    }
    assert!(value.encode().is_err());
}

#[test]
fn commit_and_snapshot_associations_require_exact_bytes_and_selectors() {
    let transaction = transaction();
    let bytes = transaction.encode().unwrap();
    let key = format!("publication/transactions/{}", "00".repeat(32));
    transaction.check_key(&key).unwrap();
    assert!(transaction.check_key(&key.replace('0', "A")).is_err());
    let mut commit = PublicationCommit {
        revision: 1,
        predecessor: Some([3; 32]),
        transaction_key: key,
        transaction_digest: *blake3::hash(&bytes).as_bytes(),
    };
    commit
        .check_transaction("publication/commits/1", &bytes)
        .unwrap();
    assert!(
        commit
            .check_transaction("publication/commits/01", &bytes)
            .is_err()
    );
    commit.predecessor = Some([4; 32]);
    assert!(
        commit
            .check_transaction("publication/commits/1", &bytes)
            .is_err()
    );
}

#[test]
fn exact_snapshot_predecessor_checks_digest_revision_and_origin() {
    let previous = PortableSnapshot {
        revision: 0,
        origin: local(),
        predecessor: None,
        projection: vec![
            ProjectionEntry {
                key: "CAPABILITIES".into(),
                value: Some(vec![0xa0]),
            },
            ProjectionEntry {
                key: "gc/lease".into(),
                value: None,
            },
            ProjectionEntry {
                key: "publication/SELECTED-HISTORY".into(),
                value: Some(history_value(vec![])),
            },
        ],
    };
    let bytes = previous.encode().unwrap();
    let mut pointer = pointer(0);
    pointer.digest = *blake3::hash(&bytes).as_bytes();
    let next = PortableSnapshot {
        revision: 1,
        origin: local(),
        projection: vec![],
        predecessor: Some(pointer.clone()),
    };
    next.check_predecessor(&pointer, &bytes).unwrap();
    pointer.check_snapshot(&bytes).unwrap();

    let mut changed = pointer.clone();
    changed.digest[0] ^= 1;
    assert!(next.check_predecessor(&changed, &bytes).is_err());
    changed = pointer;
    changed.key = changed.key.replace("/0:", "/1:");
    assert!(changed.check_snapshot(&bytes).is_err());
}

#[test]
fn staged_delta_cannot_add_unrepresented_logical_changes() {
    let mut value = transaction();
    let mut snapshot = PortableSnapshot {
        revision: 1,
        origin: local(),
        projection: vec![],
        predecessor: Some(pointer(0)),
    };
    let bytes = snapshot.encode().unwrap();
    value.snapshot.digest = *blake3::hash(&bytes).as_bytes();
    value.check_snapshot(&bytes).unwrap();
    let mut wrong_nonce = value.clone();
    wrong_nonce.nonce[0] = 1;
    assert!(wrong_nonce.check_snapshot(&bytes).is_err());

    snapshot.projection.push(ProjectionEntry {
        key: "refs/tags/_/v1:record".into(),
        value: Some(head(1).encode().unwrap()),
    });
    let bytes = snapshot.encode().unwrap();
    value.snapshot.digest = *blake3::hash(&bytes).as_bytes();
    assert!(value.check_snapshot(&bytes).is_err());
    value.changes.push(LogicalChange {
        key: "refs/tags/_/v1:record".into(),
        expected: None,
        new: snapshot.projection[0].value.clone(),
    });
    value.check_snapshot(&bytes).unwrap();
}

#[test]
fn genesis_requires_explicit_complete_structural_checkpoint_expectations() {
    let mut value = transaction();
    value.old = None;
    value.predecessor = None;
    value.new.revision = 0;
    value.snapshot = pointer(0);
    assert!(value.encode().is_err());
    value.changes = vec![
        LogicalChange {
            key: "CAPABILITIES".into(),
            expected: None,
            new: Some(vec![0xa0]),
        },
        LogicalChange {
            key: "gc/lease".into(),
            expected: None,
            new: None,
        },
        LogicalChange {
            key: "publication/SELECTED-HISTORY".into(),
            expected: None,
            new: Some(history_value(vec![])),
        },
    ];
    value.encode().unwrap();
    value.changes[0].expected = Some(vec![0xa0]);
    assert!(value.encode().is_err());
}

#[test]
fn removed_witness_order_is_preserved_but_contradictions_fail() {
    let mut proof = PublicationProof::Collection {
        fence_key: "gc/0/fence/0".into(),
        fence_digest: [4; 32],
        removed: vec![
            RemovedPack {
                pack: [2; 16],
                index: [5; 32],
            },
            RemovedPack {
                pack: [1; 16],
                index: [6; 32],
            },
        ],
        carried: vec![],
    };
    let bytes = proof.encode().unwrap();
    assert_eq!(PublicationProof::decode(&bytes).unwrap(), proof);
    if let PublicationProof::Collection { removed, .. } = &mut proof {
        removed.push(removed[0].clone());
    }
    proof.encode().unwrap();
    if let PublicationProof::Collection { removed, .. } = &mut proof {
        removed[2].index = [7; 32];
    }
    assert!(proof.encode().is_err());
}

#[test]
fn staged_full_checkpoint_cannot_omit_selected_catalog_change() {
    let mut value = transaction();
    value.changes.push(LogicalChange {
        key: "objects/index/1/MANIFEST".into(),
        expected: None,
        new: Some(vec![0xa0]),
    });

    // Independent diagnostic witness: revision one, local /a origin, a full
    // checkpoint with CAPABILITIES, absent lease, and empty selected history.
    // Its omitted catalog change is contradictory even though opaque payload
    // validation and complete prior selected state remain external obligations.
    let mut omitted = vec![
        0xa5, 0, 1, 1, 1, 2, 0x86, 0, 0x42, b'/', b'a', 1, 2, 3, 4, 3, 0x83, 0x82, 0x6c,
    ];
    omitted.extend_from_slice(b"CAPABILITIES");
    omitted.extend_from_slice(&[0x41, 0xa0, 0x82, 0x68]);
    omitted.extend_from_slice(b"gc/lease");
    omitted.extend_from_slice(&[0xf6, 0x82, 0x78, 0x1c]);
    omitted.extend_from_slice(b"publication/SELECTED-HISTORY");
    omitted.extend_from_slice(&[
        0x4f, 0xa3, 0, 1, 1, 0x80, 2, 0x86, 0, 0x42, b'/', b'a', 1, 2, 3, 4, 4, 0xf6,
    ]);
    let mut checkpoint = PortableSnapshot::decode(&omitted).unwrap();
    assert_eq!(checkpoint.encode().unwrap(), omitted);
    value.snapshot.digest = *blake3::hash(&omitted).as_bytes();
    assert_eq!(
        value.check_snapshot(&omitted),
        Err(PublicationError::Contradiction)
    );

    checkpoint.projection.insert(
        2,
        ProjectionEntry {
            key: "objects/index/1/MANIFEST".into(),
            value: Some(vec![0xa0]),
        },
    );
    let complete = checkpoint.encode().unwrap();
    value.snapshot.digest = *blake3::hash(&complete).as_bytes();
    value.check_snapshot(&complete).unwrap();
}
