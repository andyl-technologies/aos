//! Per-device tests for the in-process device test harness (CS-IO-6).
//!
//! These exercise the harness of spec §15.7 / §15.8 against all three I/O
//! sub-nodes — block, 9p, and the network link — proving, per device:
//!
//! - **run-twice determinism** ([IO-28]): two independent constructions driven
//!   through the same script yield byte-identical responses + delivery icounts;
//! - **divergence localization** ([IO-28], [INV-10]): a deliberately perturbed
//!   run is localized to its FIRST differing record/field deterministically;
//! - **device-visible state** ([IO-27]): the harness lets a test assert the
//!   overlay/dirty set (block), the fid table (9p), and the in-flight count
//!   (link) after a run;
//! - **idle-vs-busy-poll equivalence** ([IO-29]): one big `advance_to` and many
//!   single-icount advances produce identical deliveries at identical icounts.
//!
//! The §15.8 busy-poll spike conclusion is asserted from the documented
//! [`BUSY_POLL_SPIKE`] constant ([IO-30]).

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test fixture construction must fail loudly.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::fmt::Debug;

use crucible_device::block::codec::BlockRequest;
use crucible_device::harness::adapters::LinkRequest;
use crucible_device::netlink::fault::{LinkCorruptionStrategy, LinkFaults, Probability};
use crucible_device::netlink::link::{Frame, FrameDraws, NetLink, PastDeliveryPolicy};
use crucible_device::ninep::codec;
use crucible_device::{
    BUSY_POLL_SPIKE, BaseImage, BlockDevice, BlockHarness, BlockLatency, BusyPollSpike,
    DivergedField, FsTree, IoCore, NetLinkHarness, NinepDevice, NinepHarness, NinepLatency, Node,
    Script, compare_logs, idle_busy_poll_equivalence, localize_divergence, run_twice,
};

/// Unwraps a result in tests, panicking with the error on failure.
fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("expected Ok, got {error:?}"))
}

// =========================================================================
// Block device
// =========================================================================

const BLOCK_SHIFT: u8 = 8;

/// Builds a fresh block harness over a 3-page base image with a fixed latency.
fn block_harness() -> BlockHarness {
    let src = crucible_shmem::SLOT_BLK_IO as u32;
    let core = ok(IoCore::new(BLOCK_SHIFT, src, 64, 64));
    // A 12 KiB base whose bytes are their offset modulo 251 (a deterministic,
    // non-trivial pattern), so reads return distinctive content.
    let base_bytes: Vec<u8> = (0..12_288u32).map(|i| (i % 251) as u8).collect();
    let base = BaseImage::new(base_bytes);
    BlockHarness::new(BlockDevice::new(core, base, BlockLatency::default()))
}

/// A representative block script: a write that dirties a page, a read of it
/// back, a flush, and a get-length — with interleaved advances.
fn block_script() -> Script<BlockRequest> {
    Script::new()
        .request(0, BlockRequest::write(1, 4096, vec![0xAB; 256]))
        .request(0, BlockRequest::read(2, 4096, 256))
        .advance_to(50)
        .request(50, BlockRequest::flush(3))
        .request(50, BlockRequest::get_length(4))
        .advance_to(2_000)
}

#[test]
fn block_run_twice_is_byte_identical() {
    let comparison = ok(run_twice::<BlockHarness, _>(block_harness, &block_script()));
    assert!(
        comparison.is_identical(),
        "block run-twice diverged: {:?}",
        comparison.divergence()
    );
}

#[test]
fn block_harness_exposes_device_visible_state() {
    // Drive the script once through a single harness and assert the overlay and
    // dirty set the write produced ([IO-27]).
    let mut h = block_harness();
    use crucible_device::HarnessDevice;
    h.apply_request(0, &BlockRequest::write(1, 4096, vec![0xAB; 256]))
        .map(|_| ())
        .unwrap_or_else(|e| panic!("write failed: {e:?}"));
    ok(h.advance_to(2_000));
    let _ = ok(h.drain_records());
    // Exactly one page (the page at base 4096) was copied up and dirtied.
    let overlay = h.device().overlay();
    assert_eq!(
        overlay.page_count(),
        1,
        "write must copy up exactly one page"
    );
    assert!(
        overlay.dirty_pages().contains(&4096),
        "the written page must be dirty ([IO-7])"
    );
    assert_eq!(h.device().length(), 12_288, "get-length is the base size");
}

#[test]
fn block_divergence_localizes_first_differing_payload_byte() {
    // A baseline run reads the written page (all 0xAB at offset 4096); the
    // perturbed run reads the untouched base page at offset 0 (whose first byte
    // is 0x00 from the base pattern). Their read-back payloads differ at byte 0,
    // and the divergence must localize to the read record's first byte ([IO-28]).
    //
    // The read (read_base 1000 ns -> 5 icounts) delivers before the write ack
    // (write_base 1500 ns -> 7 icounts), so the read is record index 0.
    let baseline = block_script();
    let perturbed = Script::new()
        .request(0, BlockRequest::write(1, 4096, vec![0xAB; 256]))
        // Perturb: read the untouched base page instead of the written one.
        .request(0, BlockRequest::read(2, 0, 256))
        .advance_to(50)
        .request(50, BlockRequest::flush(3))
        .request(50, BlockRequest::get_length(4))
        .advance_to(2_000);

    let left = ok(crucible_device::run_script::<BlockHarness, _>(
        block_harness,
        &baseline,
    ));
    let right = ok(crucible_device::run_script::<BlockHarness, _>(
        block_harness,
        &perturbed,
    ));

    let divergence = localize_divergence(&left, &right)
        .unwrap_or_else(|| panic!("expected the perturbed run to diverge"));
    // The read delivers first (lower latency), so it is record index 0. A block
    // record's payload is the full encoded `BlockResponse` wire frame, whose
    // 20-byte header (status, version, reserved, epoch, request_id, count) is
    // identical for both reads; the first data byte at wire offset 20 is where the read
    // content differs (0xAB written page vs 0x00 base page).
    assert_eq!(divergence.record_index, 0, "the read delivers first");
    const RESPONSE_HEADER_LEN: usize = 20;
    match divergence.field {
        DivergedField::PayloadByte {
            offset,
            left,
            right,
        } => {
            assert_eq!(
                offset, RESPONSE_HEADER_LEN,
                "first differing byte is the first data byte after the header"
            );
            assert_eq!((left, right), (0xAB, 0x00), "written page vs base page");
        }
        other => panic!("expected a payload-byte divergence, got {other:?}"),
    }
    // Localization is deterministic: repeating it yields the identical point.
    assert_eq!(localize_divergence(&left, &right), Some(divergence));
}

#[test]
fn block_idle_equals_busy_poll() {
    let result = ok(idle_busy_poll_equivalence::<BlockHarness, _>(
        block_harness,
        &block_script(),
    ));
    assert!(
        result.is_equivalent(),
        "block idle vs busy-poll diverged: {:?}",
        result.comparison.divergence()
    );
    // The proof is non-trivial: it delivered responses.
    assert!(!result.idle_log.is_empty(), "block proof delivered nothing");
}

#[test]
fn block_idle_equals_busy_poll_with_bounded_outbox_under_coincident_deliveries() {
    // REGRESSION (MAJOR): the idle path used to do ONE advance + ONE drain, so a
    // bounded outbox capped the idle log at `outbox_capacity` records while the
    // busy-poll path (which drains every step) emitted all of them — a false
    // divergence on a perfectly deterministic device. Here five `get_length`
    // requests all complete at the SAME icount (latency 100 ns -> 1 icount at
    // shift 8), and the outbox capacity is only 2 (< 5 coincident deliveries).
    // With the drain-to-quiescent fix both paths must report all five.
    let factory = || {
        let src = crucible_shmem::SLOT_BLK_IO as u32;
        // Outbox capacity 2 (a power of two), strictly below the 5 coincident
        // deliveries. Inbox is roomy so all five COMPUTE up front.
        let core = ok(IoCore::new(BLOCK_SHIFT, src, 8, 2));
        let base = BaseImage::new(vec![0u8; 4096]);
        BlockHarness::new(BlockDevice::new(core, base, BlockLatency::default()))
    };
    // Five get-length requests at icount 0; all deliver coincidentally at icount 1.
    let script = Script::new()
        .request(0, BlockRequest::get_length(1))
        .request(0, BlockRequest::get_length(2))
        .request(0, BlockRequest::get_length(3))
        .request(0, BlockRequest::get_length(4))
        .request(0, BlockRequest::get_length(5))
        .advance_to(100);

    let result = ok(idle_busy_poll_equivalence::<BlockHarness, _>(
        factory, &script,
    ));
    assert!(
        result.is_equivalent(),
        "bounded-outbox idle vs busy-poll diverged: {:?}",
        result.comparison.divergence()
    );
    // Both paths report ALL FIVE coincident deliveries despite the capacity-2
    // outbox — the under-drain is gone.
    assert_eq!(
        result.idle_log.len(),
        5,
        "idle path must drain all coincident deliveries past a bounded outbox"
    );
    assert_eq!(result.busy_poll_log.len(), 5);
    // All five land at the same icount, in deterministic (icount, src, seq) order.
    assert!(
        result.idle_log.iter().all(|r| r.delivery_icount == 1),
        "all five get-length deliveries are coincident at icount 1"
    );
    let seqs: Vec<u32> = result.idle_log.iter().map(|r| r.seq).collect();
    assert_eq!(seqs, vec![0, 1, 2, 3, 4], "seq order is deterministic");
}

// =========================================================================
// 9p device
// =========================================================================

const NINEP_SHIFT: u8 = 8;

/// Builds the sample 9p tree: a root with a subdir, files, and a symlink.
fn ninep_tree() -> FsTree {
    let mut bin = BTreeMap::new();
    bin.insert(
        "tool".to_string(),
        Node::File {
            content: b"TOOL".to_vec(),
        },
    );
    let mut root = BTreeMap::new();
    root.insert(
        "alpha".to_string(),
        Node::File {
            content: b"alpha-content".to_vec(),
        },
    );
    root.insert("bin".to_string(), Node::Directory { children: bin });
    root.insert(
        "zeta".to_string(),
        Node::File {
            content: b"z".to_vec(),
        },
    );
    FsTree::try_new(Node::Directory { children: root }).expect("test 9p tree components are valid")
}

/// Builds a fresh 9p harness over the sample tree with a default latency.
fn ninep_harness() -> NinepHarness {
    let src = crucible_shmem::SLOT_9P_IO as u32;
    let core = ok(IoCore::new(NINEP_SHIFT, src, 64, 64));
    NinepHarness::new(NinepDevice::new(
        core,
        ninep_tree(),
        NinepLatency::default(),
    ))
}

// ---- 9p frame builders (the request side) -------------------------------

fn frame(msg_type: u8, tag: u16, body: &[u8]) -> Vec<u8> {
    let size = (codec::HEADER_LEN + body.len()) as u32;
    let mut f = Vec::new();
    f.extend_from_slice(&size.to_le_bytes());
    f.push(msg_type);
    f.extend_from_slice(&tag.to_le_bytes());
    f.extend_from_slice(body);
    f
}

fn string_bytes(s: &str) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(s.len() as u16).to_le_bytes());
    b.extend_from_slice(s.as_bytes());
    b
}

fn tversion(tag: u16, msize: u32, version: &str) -> Vec<u8> {
    let mut body = msize.to_le_bytes().to_vec();
    body.extend_from_slice(&string_bytes(version));
    frame(codec::TVERSION, tag, &body)
}

fn tattach(tag: u16, fid: u32) -> Vec<u8> {
    let mut body = fid.to_le_bytes().to_vec();
    body.extend_from_slice(&u32::MAX.to_le_bytes());
    body.extend_from_slice(&string_bytes("user"));
    body.extend_from_slice(&string_bytes(""));
    body.extend_from_slice(&0u32.to_le_bytes());
    frame(codec::TATTACH, tag, &body)
}

fn twalk(tag: u16, fid: u32, newfid: u32, names: &[&str]) -> Vec<u8> {
    let mut body = fid.to_le_bytes().to_vec();
    body.extend_from_slice(&newfid.to_le_bytes());
    body.extend_from_slice(&(names.len() as u16).to_le_bytes());
    for n in names {
        body.extend_from_slice(&string_bytes(n));
    }
    frame(codec::TWALK, tag, &body)
}

fn tlopen(tag: u16, fid: u32, flags: u32) -> Vec<u8> {
    let mut body = fid.to_le_bytes().to_vec();
    body.extend_from_slice(&flags.to_le_bytes());
    frame(codec::TLOPEN, tag, &body)
}

fn tread(tag: u16, fid: u32, offset: u64, count: u32) -> Vec<u8> {
    let mut body = fid.to_le_bytes().to_vec();
    body.extend_from_slice(&offset.to_le_bytes());
    body.extend_from_slice(&count.to_le_bytes());
    frame(codec::TREAD, tag, &body)
}

/// A representative 9p script: negotiate, attach, walk into a subdir, open,
/// and read a file's content — with interleaved advances.
fn ninep_script() -> Script<Vec<u8>> {
    Script::new()
        .request(0, tversion(1, 4096, codec::PROTOCOL_VERSION))
        .advance_to(20_000)
        .request(20_000, tattach(2, 1))
        .request(20_000, twalk(3, 1, 2, &["bin", "tool"]))
        .advance_to(60_000)
        .request(60_000, tlopen(4, 2, 0))
        .request(60_000, tread(5, 2, 0, 64))
        .advance_to(120_000)
}

#[test]
fn ninep_run_twice_is_byte_identical() {
    let comparison = ok(run_twice::<NinepHarness, _>(ninep_harness, &ninep_script()));
    assert!(
        comparison.is_identical(),
        "9p run-twice diverged: {:?}",
        comparison.divergence()
    );
}

#[test]
fn ninep_harness_exposes_fid_table_state() {
    use crucible_device::HarnessDevice;
    let mut h = ninep_harness();
    for step in ninep_script().steps() {
        match step {
            crucible_device::Step::Request { at_icount, request } => {
                ok(h.apply_request(*at_icount, request));
            }
            crucible_device::Step::AdvanceTo { limit } => {
                ok(h.advance_to(*limit));
                let _ = ok(h.drain_records());
            }
        }
    }
    // After version+attach+walk, the fid table holds fid 1 (root) and fid 2
    // (bin/tool), and the negotiated msize is the clamped 4096 ([IO-27], [IO-19]).
    let fids: Vec<u32> = h.device().server().fids().keys().copied().collect();
    assert_eq!(fids, vec![1, 2], "fid table must hold the walked fids");
    assert_eq!(h.device().server().msize(), 4096);
}

#[test]
fn ninep_divergence_localizes_first_differing_record() {
    // Perturb the read: read a file with different content (zeta vs bin/tool) so
    // the read reply frame differs. Localization points at the read record.
    let baseline = ninep_script();
    let perturbed = Script::new()
        .request(0, tversion(1, 4096, codec::PROTOCOL_VERSION))
        .advance_to(20_000)
        .request(20_000, tattach(2, 1))
        // Walk to a different file (zeta) so the opened+read content differs.
        .request(20_000, twalk(3, 1, 2, &["zeta"]))
        .advance_to(60_000)
        .request(60_000, tlopen(4, 2, 0))
        .request(60_000, tread(5, 2, 0, 64))
        .advance_to(120_000);

    let left = ok(crucible_device::run_script::<NinepHarness, _>(
        ninep_harness,
        &baseline,
    ));
    let right = ok(crucible_device::run_script::<NinepHarness, _>(
        ninep_harness,
        &perturbed,
    ));
    let divergence = localize_divergence(&left, &right)
        .unwrap_or_else(|| panic!("expected the perturbed 9p run to diverge"));
    // Records in delivery order: [Rversion, Rattach, Rwalk, Rlopen, Rread].
    // The Rwalk (record 2) already differs because the walked QID differs.
    assert_eq!(
        divergence.record_index, 2,
        "the differing walk is the third record"
    );
    // Determinism of localization.
    assert_eq!(localize_divergence(&left, &right), Some(divergence));
}

#[test]
fn ninep_idle_equals_busy_poll() {
    let result = ok(idle_busy_poll_equivalence::<NinepHarness, _>(
        ninep_harness,
        &ninep_script(),
    ));
    assert!(
        result.is_equivalent(),
        "9p idle vs busy-poll diverged: {:?}",
        result.comparison.divergence()
    );
    assert!(!result.idle_log.is_empty(), "9p proof delivered nothing");
}

// =========================================================================
// Network link
// =========================================================================

const LINK_SHIFT: u8 = 8;
const LINK_FLOOR_NS: u64 = 1_000;
const LINK_BASE_NS: u64 = 2_560; // exactly 10 icounts at shift 8

/// Builds a fresh link harness with a fixed fault table that exercises jitter,
/// reorder, duplicate, and corrupt (all seeded by injected draws).
fn link_harness() -> NetLinkHarness {
    let src = crucible_shmem::SLOT_NET_ROUTER as u32;
    let mut faults = LinkFaults::none();
    faults.jitter_window_ns = 1_024;
    faults.reorder_window_ns = 2_048;
    faults.duplicate = Probability::new(1, 2);
    faults.duplicate_gap_ns = 512;
    faults.corrupt = Probability::new(1, 2);
    faults.corruption_strategies = vec![LinkCorruptionStrategy::BitFlip { max_bits: 1 }];
    let link = ok(NetLink::new(
        LINK_SHIFT,
        src,
        LINK_BASE_NS,
        LINK_FLOOR_NS,
        faults,
    ));
    NetLinkHarness::new(link, PastDeliveryPolicy::ClampToFuture)
}

/// A representative link script: three frames with distinct injected draws,
/// then advance well past every delivery icount.
fn link_script() -> Script<LinkRequest> {
    Script::new()
        .request(
            0,
            LinkRequest::new(
                Frame::new(0, 10, vec![1, 2, 3, 4]),
                FrameDraws {
                    jitter: 300,
                    reorder: 700,
                    loss: 5,
                    additional_loss: Vec::new(),
                    duplicate: 0,
                    corrupt: 0,
                    corrupt_bits: vec![3],
                },
            ),
        )
        .request(
            0,
            LinkRequest::new(
                Frame::new(0, 11, vec![5, 6, 7, 8]),
                FrameDraws {
                    jitter: 100,
                    reorder: 50,
                    loss: 9,
                    additional_loss: Vec::new(),
                    duplicate: 1,
                    corrupt: 1,
                    corrupt_bits: vec![17],
                },
            ),
        )
        .request(
            0,
            LinkRequest::new(
                Frame::new(1, 12, vec![9, 9, 9, 9]),
                FrameDraws {
                    jitter: 1_000,
                    reorder: 0,
                    loss: 1,
                    additional_loss: Vec::new(),
                    duplicate: 1,
                    corrupt: 0,
                    corrupt_bits: vec![0],
                },
            ),
        )
        .advance_to(100_000)
}

#[test]
fn link_run_twice_is_byte_identical() {
    let comparison = ok(run_twice::<NetLinkHarness, _>(link_harness, &link_script()));
    assert!(
        comparison.is_identical(),
        "link run-twice diverged: {:?}",
        comparison.divergence()
    );
    // The seeded faults produced a non-trivial delivery stream.
    let log = ok(crucible_device::run_script::<NetLinkHarness, _>(
        link_harness,
        &link_script(),
    ));
    assert!(!log.is_empty(), "link script delivered nothing");
}

#[test]
fn link_divergence_localizes_first_differing_payload() {
    // The baseline corrupts frame 10 at bit position 3 (its corrupt draw 0 fires
    // the 1/2 probability, since 0 % 2 < 1). The perturbed run is identical
    // except frame 10's corrupt bit position is 4, so frame 10's delivered
    // payload differs by exactly that one flipped bit. Every other frame and
    // draw is byte-identical, so the divergence localizes to frame 10's record.
    let baseline = link_script();
    let perturbed = Script::new()
        .request(
            0,
            LinkRequest::new(
                Frame::new(0, 10, vec![1, 2, 3, 4]),
                FrameDraws {
                    jitter: 300,
                    reorder: 700,
                    loss: 5,
                    additional_loss: Vec::new(),
                    duplicate: 0,
                    corrupt: 0,
                    // Perturb only the corrupt bit position (3 -> 4).
                    corrupt_bits: vec![4],
                },
            ),
        )
        .request(
            0,
            LinkRequest::new(
                Frame::new(0, 11, vec![5, 6, 7, 8]),
                FrameDraws {
                    jitter: 100,
                    reorder: 50,
                    loss: 9,
                    additional_loss: Vec::new(),
                    duplicate: 1,
                    corrupt: 1,
                    corrupt_bits: vec![17],
                },
            ),
        )
        .request(
            0,
            LinkRequest::new(
                Frame::new(1, 12, vec![9, 9, 9, 9]),
                FrameDraws {
                    jitter: 1_000,
                    reorder: 0,
                    loss: 1,
                    additional_loss: Vec::new(),
                    duplicate: 1,
                    corrupt: 0,
                    corrupt_bits: vec![0],
                },
            ),
        )
        .advance_to(100_000);

    let left = ok(crucible_device::run_script::<NetLinkHarness, _>(
        link_harness,
        &baseline,
    ));
    let right = ok(crucible_device::run_script::<NetLinkHarness, _>(
        link_harness,
        &perturbed,
    ));
    // The two runs differ (the perturbed corrupt bit flips a different bit).
    let divergence = localize_divergence(&left, &right)
        .unwrap_or_else(|| panic!("expected the perturbed link run to diverge"));
    // Localization is deterministic and points at a concrete payload byte.
    assert!(matches!(
        divergence.field,
        DivergedField::PayloadByte { .. }
    ));
    assert_eq!(localize_divergence(&left, &right), Some(divergence));
}

#[test]
fn link_idle_equals_busy_poll() {
    let result = ok(idle_busy_poll_equivalence::<NetLinkHarness, _>(
        link_harness,
        &link_script(),
    ));
    assert!(
        result.is_equivalent(),
        "link idle vs busy-poll diverged: {:?}",
        result.comparison.divergence()
    );
    assert!(!result.idle_log.is_empty(), "link proof delivered nothing");
}

// =========================================================================
// Cross-cutting: divergence helper sanity + the §15.8 spike conclusion
// =========================================================================

#[test]
fn compare_logs_identical_when_equal_and_localizes_length_mismatch() {
    let log = ok(crucible_device::run_script::<BlockHarness, _>(
        block_harness,
        &block_script(),
    ));
    assert!(compare_logs(&log, &log).is_identical());
    // A truncated log diverges at the first missing record with `Missing`.
    let mut shorter = log.clone();
    shorter.pop();
    let divergence = localize_divergence(&log, &shorter)
        .unwrap_or_else(|| panic!("a length mismatch must diverge"));
    assert_eq!(divergence.record_index, shorter.len());
    assert!(matches!(divergence.field, DivergedField::Missing { .. }));
}

#[test]
fn busy_poll_spike_conclusion_is_recorded() {
    // The §15.8 spike result ([IO-30]): completion exactness holds under both
    // idle and busy-poll, busy-poll is a performance concern only, and any
    // mitigation must preserve exactness. Assert the recorded conclusion matches
    // the documented finding field-for-field.
    assert_eq!(
        BUSY_POLL_SPIKE,
        BusyPollSpike {
            correctness_independent_of_poll_mode: true,
            busy_poll_is_performance_only: true,
            mitigation_must_preserve_exactness: true,
        }
    );
}
