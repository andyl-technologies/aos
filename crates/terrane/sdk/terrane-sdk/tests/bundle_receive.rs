//! Checks private bundle framing, resource bounds and configured schema validation.
//!
//! These representation fixtures establish no repository authority or graph closure.

#![allow(
    clippy::unwrap_used,
    reason = "Malformed fixtures intentionally panic."
)]

use std::collections::BTreeMap;

use terrane_format::{
    chunking::ChunkProfile,
    manifest::{ChunkRef, Manifest},
    refs::{Commit, CommitSource, PrincipalKind, ProfilePair, Provenance},
};
use terrane_sdk::{
    pack::{BundleObject, EntryKind},
    repository::MetadataValidator,
    wire::{
        bundle::{BundleError, BundleLimits, BundleReceiver},
        v1::{self, bundle_frame::Frame},
    },
};

fn limits() -> BundleLimits {
    BundleLimits::new(8, 4096, 8192, 4096).unwrap()
}

fn validator() -> MetadataValidator {
    MetadataValidator::new(ChunkProfile::cdc_1m([42; 32]))
}

fn node() -> BundleObject {
    // An empty root leaf, assembled without the Node encoder.
    BundleObject::new(EntryKind::Node, vec![0xa2, 1, 0, 2, 0x80]).unwrap()
}

fn manifest() -> BundleObject {
    let manifest = Manifest {
        size: 1,
        chunks: vec![ChunkRef {
            digest: [1; 32],
            length: 1,
        }],
        hashes: BTreeMap::from([("blake3".into(), vec![2; 32])]),
        media_type: None,
    };
    BundleObject::new(
        EntryKind::Manifest,
        manifest.encode(&ChunkProfile::cdc_1m([42; 32])).unwrap(),
    )
    .unwrap()
}

fn commit() -> BundleObject {
    let commit = Commit {
        tree: *node().hash(),
        parents: Vec::new(),
        provenance: Provenance {
            issuer: "fixture-issuer".into(),
            token_id: [2; 16],
            subject: "fixture-principal".into(),
            kind: PrincipalKind::Workload,
            workload_identity: None,
            process: "fixture".into(),
            observed_at: 1,
            writer_epoch: 1,
            source: CommitSource::Uploaded,
            embedded_token: None,
        },
        timestamp: 1,
        message: String::new(),
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "cdc-1m".into(),
            recipe: None,
            conflicted: None,
            lease: None,
            required_properties: None,
            entry_receipts: None,
            commit_context: None,
        },
        packs: None,
        signature: None,
    };
    BundleObject::new(EntryKind::Commit, commit.encode().unwrap()).unwrap()
}

fn frame(frame: Frame) -> v1::BundleFrame {
    v1::BundleFrame {
        frame: Some(frame),
        ..Default::default()
    }
}

fn object(value: &BundleObject) -> v1::MetaObject {
    v1::MetaObject {
        kind: value.kind() as u32,
        hash: v1::Hash {
            value: value.hash().to_vec(),
            ..Default::default()
        }
        .into(),
        encoded: value.bytes().to_vec(),
        ..Default::default()
    }
}

fn metadata(value: &BundleObject) -> v1::BundleFrame {
    frame(Frame::Object(Box::new(object(value))))
}

fn rejected(frame: v1::BundleFrame) {
    let mut receiver = BundleReceiver::new(limits(), false);
    receiver.push(metadata(&node())).unwrap();
    assert!(receiver.push(frame).is_err());

    assert_eq!(receiver.buffered_bytes(), 0);
    assert!(matches!(
        receiver.push(metadata(&manifest())),
        Err(BundleError::Terminated)
    ));
    assert!(matches!(
        receiver.finish(&validator()),
        Err(BundleError::Terminated)
    ));
}

#[test]
fn registered_metadata_and_requested_opaque_profile_preserve_received_order() {
    let expected = [commit(), node(), manifest()];
    let mut receiver = BundleReceiver::new(limits(), true);
    for value in &expected {
        receiver.push(metadata(value)).unwrap();
    }
    receiver
        .push(frame(Frame::AccessProfile(vec![0xff, 0x00])))
        .unwrap();
    assert_eq!(
        receiver.buffered_bytes(),
        expected
            .iter()
            .map(|value| value.bytes().len())
            .sum::<usize>()
            + 2
    );

    let received = receiver.finish(&validator()).unwrap();

    assert_eq!(received.objects(), expected);
    assert_eq!(received.access_profile(), Some([0xff, 0x00].as_slice()));
}

#[test]
fn all_held_empty_stream_and_omitted_optional_profile_are_valid() {
    for requested in [false, true] {
        let received = BundleReceiver::new(limits(), requested)
            .finish(&validator())
            .unwrap();
        assert!(received.objects().is_empty());
        assert!(received.access_profile().is_none());
    }
}

#[test]
fn chunks_unknown_and_wide_kinds_are_terminal_refusals() {
    for kind in [
        EntryKind::Chunk as u32,
        EntryKind::Bundle as u32,
        0,
        255,
        256,
        u32::MAX,
    ] {
        let mut value = object(&manifest());
        value.kind = kind;
        rejected(frame(Frame::Object(Box::new(value))));
    }
}

#[test]
fn absent_wrong_width_and_mismatching_hashes_release_prior_objects() {
    for hash in [
        None,
        Some(vec![]),
        Some(vec![1; 31]),
        Some(vec![1; 33]),
        Some(vec![0; 32]),
    ] {
        let mut value = object(&manifest());
        value.hash = hash
            .map(|value| v1::Hash {
                value,
                ..Default::default()
            })
            .into();
        rejected(frame(Frame::Object(Box::new(value))));
    }
}

#[test]
fn malformed_and_noncanonical_cbor_fail_before_completion() {
    for encoded in [vec![], vec![0x18, 0], vec![0xa1], vec![0, 0]] {
        let mut value = object(&manifest());
        value.encoded = encoded;
        rejected(frame(Frame::Object(Box::new(value))));
    }
}

#[test]
fn canonical_cbor_is_insufficient_without_registered_metadata_schema() {
    for kind in [EntryKind::Node, EntryKind::Manifest, EntryKind::Commit] {
        let opaque = BundleObject::new(kind, vec![0xa1, 1, 0]).unwrap();
        let mut receiver = BundleReceiver::new(limits(), false);
        receiver.push(metadata(&node())).unwrap();
        receiver.push(metadata(&opaque)).unwrap();

        assert!(matches!(
            receiver.finish(&validator()),
            Err(BundleError::Validation(_))
        ));
    }
}

#[test]
fn duplicates_and_missing_variants_latch_rejection() {
    rejected(metadata(&node()));
    rejected(v1::BundleFrame::default());
}

#[test]
fn count_body_aggregate_and_profile_limits_are_enforced() {
    let node = node();
    let manifest = manifest();
    let cases = [
        (
            BundleLimits::new(1, 4096, 8192, 4096).unwrap(),
            vec![metadata(&node), metadata(&manifest)],
        ),
        (
            BundleLimits::new(8, node.bytes().len() - 1, 8192, 4096).unwrap(),
            vec![metadata(&node)],
        ),
        (
            BundleLimits::new(
                8,
                manifest.bytes().len(),
                manifest.bytes().len() + node.bytes().len() - 1,
                1,
            )
            .unwrap(),
            vec![metadata(&node), metadata(&manifest)],
        ),
        (
            BundleLimits::new(8, 4096, 8192, 1).unwrap(),
            vec![frame(Frame::AccessProfile(vec![1, 2]))],
        ),
        (
            BundleLimits::new(
                8,
                node.bytes().len(),
                node.bytes().len(),
                node.bytes().len(),
            )
            .unwrap(),
            vec![metadata(&node), frame(Frame::AccessProfile(vec![1]))],
        ),
    ];
    for (bounds, frames) in cases {
        let mut receiver = BundleReceiver::new(bounds, true);
        let mut refused = false;
        for frame in frames {
            if matches!(receiver.push(frame), Err(BundleError::Limit)) {
                refused = true;
                break;
            }
        }
        assert!(refused);
        assert_eq!(receiver.buffered_bytes(), 0);
        assert!(matches!(
            receiver.finish(&validator()),
            Err(BundleError::Terminated)
        ));
    }
    for bounds in [
        (0, 1, 1, 1),
        (1, 0, 1, 1),
        (1, 1, 0, 1),
        (1, 1, 1, 0),
        (1, 2, 1, 1),
        (1, 1, 1, 2),
        (usize::MAX, 1, 1, 1),
        (1, 1, usize::MAX, 1),
    ] {
        assert!(matches!(
            BundleLimits::new(bounds.0, bounds.1, bounds.2, bounds.3),
            Err(BundleError::Limits)
        ));
    }
}

#[test]
fn unrequested_and_nonfinal_profiles_release_all_retained_bytes() {
    rejected(frame(Frame::AccessProfile(Vec::new())));
    for trailing in [
        metadata(&manifest()),
        frame(Frame::AccessProfile(vec![])),
        v1::BundleFrame::default(),
    ] {
        let mut receiver = BundleReceiver::new(limits(), true);
        receiver.push(metadata(&node())).unwrap();
        receiver.push(frame(Frame::AccessProfile(vec![]))).unwrap();

        assert!(matches!(receiver.push(trailing), Err(BundleError::Order)));
        assert_eq!(receiver.buffered_bytes(), 0);
        assert!(matches!(
            receiver.finish(&validator()),
            Err(BundleError::Terminated)
        ));
    }
}
