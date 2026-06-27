//! Checks T-IO-5 block snapshot/restore and materialization behavior.

#![forbid(unsafe_code)]

use crucible::{
    BLOCK_OVERLAY_PAGE_SIZE, BlockBaseImage, BlockSnapshotError, BlockSubNodeOverlay, ContentHash,
    DeviceRngState, Icount, IoSubNodeCompletion, NodeId, RngStreamId, RngStreamPosition,
    SchedulerNodeId, SchedulingNodeKind, SimDuration,
};
use std::collections::BTreeMap;

#[test]
fn snapshot_captures_dirty_delta_rng_inflight_clock_and_length_without_base_bytes() {
    let base_bytes = patterned_base(BLOCK_OVERLAY_PAGE_SIZE * 2 + 11);
    let base = BlockBaseImage::from_bytes(base_bytes.clone()).expect("base should build");
    let mut overlay = BlockSubNodeOverlay::new(base.clone());
    let rng = rng_state(&[("block/read", 7), ("block/write", 11)]);

    overlay
        .write(9, b"dirty")
        .expect("write should dirty one page");
    let snapshot = overlay.capture_snapshot(
        rng.clone(),
        vec![
            completion(4, "disk-b", "vm-a", 9, b"later"),
            completion(2, "disk-a", "vm-a", 9, b"earlier-source"),
            completion(1, "disk-a", "vm-a", 8, b"earlier-time"),
        ],
        Icount { retired: 123 },
    );

    assert_eq!(snapshot.delta.base, base.content_ref());
    assert_eq!(snapshot.delta.pages.len(), 1);
    assert_eq!(snapshot.delta.pages[0].page_base, 0);
    assert_eq!(&snapshot.delta.pages[0].bytes[9..14], b"dirty");
    assert_eq!(snapshot.device_rng, rng);
    assert_eq!(snapshot.clock_icount, Icount { retired: 123 });
    assert_eq!(snapshot.length, base.len());
    assert_eq!(
        snapshot
            .in_flight
            .iter()
            .map(|response| {
                (
                    response.delivery_icount.retired,
                    response.sub_node.node.name.as_str(),
                    response.sequence,
                )
            })
            .collect::<Vec<_>>(),
        vec![(8, "disk-a", 1), (9, "disk-a", 2), (9, "disk-b", 4)]
    );
    assert_eq!(overlay.dirty_page_count(), 0);
    assert_eq!(base.bytes(), base_bytes.as_slice());
}

#[test]
fn restore_stacks_delta_over_parent_overlay_and_returns_runtime_state() {
    let base = BlockBaseImage::from_bytes(patterned_base(BLOCK_OVERLAY_PAGE_SIZE * 3))
        .expect("base should build");
    let mut parent = BlockSubNodeOverlay::new(base.clone());
    parent
        .write(2, b"parent")
        .expect("parent write should succeed");
    assert_eq!(parent.capture_dirty_delta().pages.len(), 1);

    let mut child = parent.clone();
    child
        .write((BLOCK_OVERLAY_PAGE_SIZE + 5) as u64, b"child")
        .expect("child write should succeed");
    let rng = rng_state(&[("block/read", 3)]);
    let in_flight = vec![
        completion(8, "disk-b", "vm-a", 33, b"later"),
        completion(7, "disk-a", "vm-a", 32, b"pending"),
    ];
    let mut snapshot =
        child.capture_snapshot(rng.clone(), in_flight.clone(), Icount { retired: 44 });
    snapshot.in_flight.reverse();

    let mut restored = parent.clone();
    let runtime = restored
        .restore_snapshot(&snapshot)
        .expect("snapshot should restore");

    assert_eq!(runtime.device_rng, rng);
    assert_eq!(
        runtime
            .in_flight
            .iter()
            .map(|response| (response.delivery_icount.retired, response.sequence))
            .collect::<Vec<_>>(),
        vec![(32, 7), (33, 8)]
    );
    assert_eq!(runtime.clock_icount, Icount { retired: 44 });
    assert_eq!(
        restored.read(2, 6).expect("parent bytes should read"),
        b"parent".as_slice()
    );
    assert_eq!(
        restored
            .read((BLOCK_OVERLAY_PAGE_SIZE + 5) as u64, 5)
            .expect("child bytes should read"),
        b"child".as_slice()
    );
    assert_eq!(restored.dirty_page_count(), 0);
    assert_eq!(restored.materialize_image(), child.materialize_image());
    assert_eq!(
        restored.materialized_content_hash(),
        child.materialized_content_hash()
    );
    assert_eq!(
        base.bytes(),
        patterned_base(BLOCK_OVERLAY_PAGE_SIZE * 3).as_slice()
    );
}

#[test]
fn materialize_image_writes_base_then_live_overlay_pages_without_mutating_base() {
    let base_bytes = patterned_base(BLOCK_OVERLAY_PAGE_SIZE + 3);
    let base = BlockBaseImage::from_bytes(base_bytes.clone()).expect("base should build");
    let mut overlay = BlockSubNodeOverlay::new(base.clone());

    overlay
        .write(0, b"boot")
        .expect("first write should succeed");
    overlay
        .write(BLOCK_OVERLAY_PAGE_SIZE as u64 + 1, b"xy")
        .expect("final partial page write should succeed");

    let image = overlay.materialize_image();

    assert_eq!(image.len(), base_bytes.len());
    assert_eq!(&image[..4], b"boot");
    assert_eq!(&image[BLOCK_OVERLAY_PAGE_SIZE + 1..], b"xy");
    assert_eq!(base.bytes(), base_bytes.as_slice());
    assert_ne!(
        ContentHash::from_bytes(&base_bytes),
        overlay.materialized_content_hash()
    );
}

#[test]
fn snapshot_content_hash_tracks_delta_rng_inflight_clock_and_length() {
    let base = BlockBaseImage::from_bytes(patterned_base(BLOCK_OVERLAY_PAGE_SIZE))
        .expect("base should build");
    let mut overlay = BlockSubNodeOverlay::new(base);
    overlay.write(0, b"x").expect("write should succeed");
    let snapshot = overlay.capture_snapshot(
        rng_state(&[("block/read", 1)]),
        vec![completion(1, "disk-a", "vm-a", 5, b"pending")],
        Icount { retired: 6 },
    );

    assert_eq!(snapshot.content_hash(), snapshot.clone().content_hash());

    let mut reordered = snapshot.clone();
    reordered.in_flight.reverse();
    assert_eq!(snapshot.content_hash(), reordered.content_hash());

    let mut changed_rng = snapshot.clone();
    changed_rng.device_rng = rng_state(&[("block/read", 2)]);
    assert_ne!(snapshot.content_hash(), changed_rng.content_hash());

    let mut changed_response = snapshot.clone();
    changed_response.in_flight[0].delivery_icount = Icount { retired: 7 };
    assert_ne!(snapshot.content_hash(), changed_response.content_hash());

    let mut changed_clock = snapshot.clone();
    changed_clock.clock_icount = Icount { retired: 7 };
    assert_ne!(snapshot.content_hash(), changed_clock.content_hash());

    let mut changed_length = snapshot.clone();
    changed_length.length += 1;
    assert_ne!(snapshot.content_hash(), changed_length.content_hash());
}

#[test]
fn restore_rejects_forged_base_length_and_delta_pages() {
    let base = BlockBaseImage::from_bytes(patterned_base(BLOCK_OVERLAY_PAGE_SIZE * 2))
        .expect("base should build");
    let mut overlay = BlockSubNodeOverlay::new(base.clone());
    overlay.write(0, b"a").expect("first write should succeed");
    overlay
        .write(BLOCK_OVERLAY_PAGE_SIZE as u64, b"b")
        .expect("second write should succeed");
    let snapshot =
        overlay.capture_snapshot(DeviceRngState::empty(), Vec::new(), Icount { retired: 1 });

    let other_base = BlockBaseImage::from_bytes(patterned_base(BLOCK_OVERLAY_PAGE_SIZE * 2 + 1))
        .expect("other base should build");
    let mut wrong_base = BlockSubNodeOverlay::new(other_base);
    assert!(matches!(
        wrong_base.restore_snapshot(&snapshot),
        Err(BlockSnapshotError::BaseImageMismatch { .. })
    ));

    let mut wrong_length = snapshot.clone();
    wrong_length.length += 1;
    let mut target = BlockSubNodeOverlay::new(base.clone());
    assert!(matches!(
        target.restore_snapshot(&wrong_length),
        Err(BlockSnapshotError::LengthMismatch { .. })
    ));

    let mut short_page = snapshot.clone();
    short_page.delta.pages[0].bytes.pop();
    let mut target = BlockSubNodeOverlay::new(base.clone());
    assert!(matches!(
        target.restore_snapshot(&short_page),
        Err(BlockSnapshotError::InvalidDeltaPageSize { .. })
    ));

    let mut misaligned = snapshot.clone();
    misaligned.delta.pages[0].page_base = 1;
    let mut target = BlockSubNodeOverlay::new(base.clone());
    assert!(matches!(
        target.restore_snapshot(&misaligned),
        Err(BlockSnapshotError::DeltaPageMisaligned { page_base: 1 })
    ));

    let mut out_of_bounds = snapshot.clone();
    out_of_bounds.delta.pages[0].page_base = base.len();
    let mut target = BlockSubNodeOverlay::new(base.clone());
    assert!(matches!(
        target.restore_snapshot(&out_of_bounds),
        Err(BlockSnapshotError::DeltaPageOutOfBounds { page_base, length })
            if page_base == base.len() && length == base.len()
    ));

    let mut unordered = snapshot.clone();
    unordered.delta.pages.swap(0, 1);
    let mut target = BlockSubNodeOverlay::new(base);
    assert!(matches!(
        target.restore_snapshot(&unordered),
        Err(BlockSnapshotError::DeltaPageOutOfOrder {
            previous: Some(_),
            current: 0,
        })
    ));
}

#[test]
fn restore_rejects_invalid_delta_without_partial_overlay_mutation() {
    let base_bytes = patterned_base(BLOCK_OVERLAY_PAGE_SIZE * 2);
    let base = BlockBaseImage::from_bytes(base_bytes.clone()).expect("base should build");
    let mut overlay = BlockSubNodeOverlay::new(base.clone());
    overlay.write(0, b"a").expect("first write should succeed");
    overlay
        .write(BLOCK_OVERLAY_PAGE_SIZE as u64, b"b")
        .expect("second write should succeed");
    let mut snapshot =
        overlay.capture_snapshot(DeviceRngState::empty(), Vec::new(), Icount { retired: 1 });
    snapshot.delta.pages[1].bytes.pop();

    let mut target = BlockSubNodeOverlay::new(base);
    let error = target
        .restore_snapshot(&snapshot)
        .expect_err("invalid second page should reject whole restore");

    assert!(matches!(
        error,
        BlockSnapshotError::InvalidDeltaPageSize { .. }
    ));
    assert_eq!(target.overlay_page_count(), 0);
    assert_eq!(target.dirty_page_count(), 0);
    assert_eq!(target.materialize_image(), base_bytes);
}

#[test]
fn apply_delta_stacks_without_marking_restored_pages_dirty() {
    let base = BlockBaseImage::from_bytes(patterned_base(BLOCK_OVERLAY_PAGE_SIZE * 2))
        .expect("base should build");
    let mut parent = BlockSubNodeOverlay::new(base.clone());
    parent
        .write(3, b"parent")
        .expect("parent write should succeed");
    let parent_delta = parent.capture_dirty_delta();

    let mut child = BlockSubNodeOverlay::new(base.clone());
    child
        .apply_delta(&parent_delta, base.len())
        .expect("parent delta should apply");
    child
        .write((BLOCK_OVERLAY_PAGE_SIZE + 1) as u64, b"child")
        .expect("child write should succeed");
    let child_delta = child.capture_dirty_delta();

    let mut restored = BlockSubNodeOverlay::new(base);
    restored
        .apply_delta(&parent_delta, parent.get_length())
        .expect("parent delta should restore");
    restored
        .apply_delta(&child_delta, parent.get_length())
        .expect("child delta should restore");

    assert_eq!(
        restored.read(3, 6).expect("parent bytes should read"),
        b"parent".as_slice()
    );
    assert_eq!(
        restored
            .read((BLOCK_OVERLAY_PAGE_SIZE + 1) as u64, 5)
            .expect("child bytes should read"),
        b"child".as_slice()
    );
    assert_eq!(restored.dirty_page_count(), 0);
}

fn completion(
    sequence: u64,
    sub_node: &str,
    requester: &str,
    delivery_icount: u64,
    payload: &[u8],
) -> IoSubNodeCompletion {
    IoSubNodeCompletion {
        sequence,
        sub_node: scheduler_node(sub_node, SchedulingNodeKind::Disk),
        requester: scheduler_node(requester, SchedulingNodeKind::Vm),
        request_icount: Icount { retired: 1 },
        delivery_icount: Icount {
            retired: delivery_icount,
        },
        modeled_latency: SimDuration { nanos: 10 },
        rng_draw: None,
        payload: payload.to_vec(),
    }
}

fn rng_state(entries: &[(&str, u64)]) -> DeviceRngState {
    DeviceRngState {
        streams: entries
            .iter()
            .map(|(name, draws)| {
                (
                    RngStreamId::new("crucible.block-test", *name),
                    RngStreamPosition::new(*draws),
                )
            })
            .collect::<BTreeMap<_, _>>(),
    }
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind,
    }
}

fn patterned_base(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}
