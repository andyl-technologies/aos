//! Format, packing, and lazy-storage tests for version 2 replay closures.
//!
//! Selection provenance needs real campaign records and is covered by the
//! guarded campaign-run tests; these tests use opaque synthetic records.

// crucible-lint: allow panic-shortcut -- fixture construction failures must name the broken step.
#![allow(clippy::expect_used)]

use super::format::{FrameKind, decode_bundle};
use super::*;

fn frame_kinds(closure: &GuardedCampaignReplayClosure) -> Vec<(FrameKind, u32)> {
    closure
        .root
        .frames
        .iter()
        .map(|frame| (frame.kind, frame.count))
        .collect()
}

fn frames(closure: &GuardedCampaignReplayClosure) -> Vec<Arc<[u8]>> {
    (0..closure.frames.len())
        .map(|index| closure.frame_bytes(index).expect("read frame"))
        .collect()
}

#[test]
fn builder_closes_record_frames_before_the_entry_frames_that_reference_them() {
    let closure = GuardedCampaignReplayClosure::synthetic_for_test(5_000).expect("build closure");

    // One shared domain and declaration plus one opportunity per entry.
    assert_eq!(closure.root.entry_count, 5_000);
    assert_eq!(closure.root.record_count, 5_002);
    assert_eq!(
        frame_kinds(&closure),
        [
            (FrameKind::Records, 4_096),
            (FrameKind::Records, 2),
            (FrameKind::Entries, 4_096),
            (FrameKind::Records, 904),
            (FrameKind::Entries, 904),
        ]
    );

    assert_eq!(closure.root.record_frame(4_095), Some(0));
    assert_eq!(closure.root.record_frame(4_096), Some(1));
    assert_eq!(closure.root.record_frame(4_098), Some(3));
    assert_eq!(closure.root.record_frame(5_002), None);
    assert_eq!(closure.root.entry_frame(4_095), Some(2));
    assert_eq!(closure.root.entry_frame(4_096), Some(4));
    assert_eq!(closure.root.entry_frame(5_000), None);
}

#[test]
fn reader_serves_entries_and_records_by_ordinal_and_kind() {
    let closure = GuardedCampaignReplayClosure::synthetic_for_test(5_000).expect("build closure");
    let mut reader = FrameReader::new(&closure);

    let entry = reader.entry(4_097).expect("read entry");
    assert_eq!(entry.selection[..8], 4_097_u64.to_le_bytes());
    assert_eq!((entry.domain, entry.declaration), (0, 1));
    assert_eq!(entry.opportunity, 4_099);

    let (bytes, range) = reader
        .record_bytes(RecordKind::Opportunity, entry.opportunity)
        .expect("read opportunity");
    assert_eq!(bytes[range], 4_097_u64.to_le_bytes());
    assert!(matches!(
        reader.record_bytes(RecordKind::Domain, entry.opportunity),
        Err(GuardedCampaignReplayClosureError::Invalid {
            reason: "replay closure record has another kind"
        })
    ));
    assert!(reader.entry(5_000).is_err());
}

#[test]
fn bundle_and_frame_objects_carry_the_root_and_every_frame() {
    let closure = GuardedCampaignReplayClosure::synthetic_for_test(5_000).expect("build closure");
    let bundle = closure.to_canonical_bytes().expect("encode bundle");

    let (root, decoded) = decode_bundle(&bundle).expect("decode bundle");
    assert_eq!(&root[..], closure.root_bytes());
    assert_eq!(decoded, frames(&closure));

    let objects = closure.to_frame_objects().expect("split frame objects");
    assert_eq!(objects.len(), 6);
    assert!(
        objects
            .iter()
            .all(|object| object.len() <= MAX_REPLAY_CLOSURE_FRAME_BYTES)
    );

    let mut trailing = bundle;
    trailing.push(0);
    assert!(decode_bundle(&trailing).is_err());
}

#[test]
fn empty_closure_round_trips_through_every_carrier() {
    let empty = GuardedCampaignReplayClosure::empty();

    let bundle = empty.to_canonical_bytes().expect("encode empty bundle");
    assert_eq!(
        GuardedCampaignReplayClosure::from_canonical_bytes(&bundle).expect("decode empty bundle"),
        empty
    );
    let objects = empty.to_frame_objects().expect("split empty closure");
    assert_eq!(objects.len(), 1);
    assert_eq!(
        GuardedCampaignReplayClosure::from_frame_objects(&objects).expect("decode empty objects"),
        empty
    );
    assert!(GuardedCampaignReplayClosure::from_frame_objects::<Vec<u8>>(&[]).is_err());
}

#[test]
fn roots_reject_partial_entry_frames_and_unreferenced_records() {
    let frame = [0_u8; 32];

    let partial = ClosureRoot::encode(&[
        (FrameKind::Entries, 10, 64, frame),
        (FrameKind::Entries, 10, 64, frame),
    ]);
    assert!(matches!(
        partial,
        Err(GuardedCampaignReplayClosureError::Invalid {
            reason: "replay closure entry frame is not full"
        })
    ));

    let unreferenced = ClosureRoot::encode(&[(FrameKind::Records, 1, 64, frame)]);
    assert!(matches!(
        unreferenced,
        Err(GuardedCampaignReplayClosureError::Invalid {
            reason: "replay closure ends with unreferenced records"
        })
    ));
}

#[test]
fn stored_frames_are_read_lazily_and_authenticated_against_the_root() {
    let closure = GuardedCampaignReplayClosure::synthetic_for_test(10).expect("build closure");
    let originals = frames(&closure);
    let handles = |bytes: &[Arc<[u8]>]| {
        bytes
            .iter()
            .map(|frame| BlobHandle::from_bytes(frame.to_vec()))
            .collect::<Vec<_>>()
    };

    let stored = GuardedCampaignReplayClosure::from_stored(
        closure.root_bytes().to_vec(),
        handles(&originals),
    )
    .expect("open stored closure");
    assert_eq!(stored, closure);
    assert_eq!(
        stored.to_canonical_bytes().expect("read stored frames"),
        closure.to_canonical_bytes().expect("read memory frames")
    );

    // Same length, different bytes: accepted at open, refused when read.
    let mut tampered = originals.clone();
    let mut frame = tampered[0].to_vec();
    if let Some(last) = frame.last_mut() {
        *last ^= 1;
    }
    tampered[0] = frame.into();
    let tampered = GuardedCampaignReplayClosure::from_stored(
        closure.root_bytes().to_vec(),
        handles(&tampered),
    )
    .expect("open tampered closure");
    assert!(matches!(
        tampered.frame_bytes(0),
        Err(GuardedCampaignReplayClosureError::Invalid {
            reason: "stored replay closure frame digest differs"
        })
    ));

    let mut truncated = originals;
    truncated[0] = Arc::from(&truncated[0][1..]);
    assert!(
        GuardedCampaignReplayClosure::from_stored(
            closure.root_bytes().to_vec(),
            handles(&truncated)
        )
        .is_err()
    );
}

#[test]
fn frame_identities_match_the_root_digests() {
    let closure = GuardedCampaignReplayClosure::synthetic_for_test(5_000).expect("build closure");

    let derived = frames(&closure)
        .iter()
        .map(|frame| closure_object_id(frame))
        .collect::<Vec<_>>();
    assert_eq!(closure.frame_ids().collect::<Vec<_>>(), derived);
    assert_eq!(closure.root_id(), closure_object_id(closure.root_bytes()));
}
