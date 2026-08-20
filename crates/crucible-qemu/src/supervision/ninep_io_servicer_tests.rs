//! Unit tests for the production host-I/O checkpoint boundary.

use std::fs;
use std::io::Write;
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_shmem::{RegionAllocation, RegionConfig};

use super::*;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn transaction_fixture() -> (fs::File, QemuLive9pIoServicer) {
    let allocation = RegionAllocation::new_model(RegionConfig::new(1, 4, 0))
        .unwrap_or_else(|error| panic!("allocate test region: {error}"));
    let layout = allocation.layout();
    let bytes = allocation
        .setup_region_bytes()
        .unwrap_or_else(|error| panic!("serialize test region: {error}"));
    let mut path = std::env::temp_dir();
    path.push(format!(
        "crucible-ninep-servicer-transaction-{}-{}",
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap_or_else(|error| panic!("create test region: {error}"));
    fs::remove_file(&path).unwrap_or_else(|error| panic!("unlink test region: {error}"));
    file.set_len(layout.region_size)
        .unwrap_or_else(|error| panic!("size test region: {error}"));
    file.write_all(&bytes)
        .unwrap_or_else(|error| panic!("write test region: {error}"));
    let servicer = QemuLive9pIoServicer::from_shmem_fd(file.as_fd(), layout.region_size, 0, 0)
        .unwrap_or_else(|error| panic!("map test servicer: {error}"));
    (file, servicer)
}

#[test]
fn host_private_transaction_rollback_restores_exact_state() {
    let (_file, mut servicer) = transaction_fixture();
    let before = servicer
        .begin_transaction()
        .unwrap_or_else(|error| panic!("capture transaction: {error}"));
    servicer
        .commit_visibility_update(
            [7; 32],
            NinepObjectVersion {
                path: String::from("/created"),
                version: 1,
                mode: 0o100_644,
                data: b"created".to_vec(),
                deleted: false,
            },
            NinepVisibilityPolicy {
                scope: crucible_device::NinepVisibilityScope::Global,
                atomic_metadata_and_data: true,
                retain_deleted_objects: false,
            },
            NinepVisibilityRelease::AtNanos(10),
            0,
        )
        .unwrap_or_else(|error| panic!("mutate visibility: {error}"));
    assert_ne!(servicer.visibility_state().committed_frontier(), 0);
    servicer
        .rollback_transaction(before.clone())
        .unwrap_or_else(|error| panic!("rollback transaction: {error}"));
    let restored = servicer
        .begin_transaction()
        .unwrap_or_else(|error| panic!("capture restored transaction: {error}"));
    assert_eq!(restored, before);
}

#[test]
fn authorized_due_reply_remains_retryable_after_backpressure() {
    let (_file, mut servicer) = transaction_fixture();
    let mut frame = Vec::new();
    let version = b"9P2000.L";
    let size = 7 + 4 + 2 + version.len();
    frame.extend_from_slice(&(size as u32).to_le_bytes());
    frame.push(crucible_device::ninep::codec::TVERSION);
    frame.extend_from_slice(&9_u16.to_le_bytes());
    frame.extend_from_slice(&4096_u32.to_le_bytes());
    frame.extend_from_slice(&(version.len() as u16).to_le_bytes());
    frame.extend_from_slice(version);
    let opportunity = NinepRequestOpportunity::from_frame(5, 7, frame)
        .unwrap_or_else(|error| panic!("construct opportunity: {error}"));
    servicer
        .pending_fault_opportunities
        .insert((10, opportunity.identity), (opportunity.clone(), true));

    assert!(servicer.due_fault_opportunities(10).is_empty());
    assert!(servicer.has_authorized_due(10));
    assert!(!servicer.has_authorized_due(9));
}

/// The fixed 9p tree is a pure constant: two independent constructions are
/// byte-for-byte equal. Device-level icount purity (a request's delivery
/// icount is a function of its request icount, never of host work) is proven
/// in `crucible-device`'s ninep `run_sequence(skew)` test; the servicer only
/// plumbs that already-deterministic device onto the shmem rings.
#[test]
fn deterministic_fs_tree_is_reproducible() {
    let (Ok(first), Ok(second)) = (deterministic_fs_tree(), deterministic_fs_tree()) else {
        panic!("fixed 9p tree is well-formed");
    };
    assert_eq!(first, second);
}

/// The diagnostics sink is a pure function of the observation sequence:
/// replaying identical `(icount, service step)` observations into two sinks
/// yields byte-identical snapshots, and the first-request horizon, max
/// icount, and cumulative counts accumulate as specified.
#[test]
fn diagnostics_accumulate_as_a_pure_function_of_observations() {
    let observations = [
        (10_u64, false, 0_u64, step(0, 0, None, None)),
        (10, true, 1, step(1, 0, Some(1512), Some(1512))),
        (900, true, 1512, step(0, 0, None, Some(1512))),
        (1512, true, 1512, step(0, 1, None, None)),
    ];

    let replay = || {
        let diag = NinepIoDiagnostics::default();
        for (icount, active, idle_wake, serviced) in &observations {
            diag.record(*icount, *active, *idle_wake, serviced);
        }
        diag.snapshot()
    };

    let a = replay();
    let b = replay();
    assert_eq!(a, b, "same observations must yield the same snapshot");

    assert_eq!(a.frames_processed, 1);
    assert_eq!(a.frames_delivered, 1);
    assert_eq!(a.service_calls, 4);
    assert_eq!(a.first_request_icount, Some(10));
    assert_eq!(a.first_completion_horizon, Some(1512));
    assert_eq!(a.max_current_icount, 1512);
    assert_eq!(a.last_current_icount, 1512);
    assert!(a.last_device_io_active);
}

fn step(
    processed: usize,
    delivered: usize,
    computed: Option<u64>,
    next: Option<u64>,
) -> QemuLive9pIoServiceStep {
    QemuLive9pIoServiceStep {
        processed,
        delivered,
        first_request_icount: (processed > 0).then_some(10),
        computed_completion_icount: computed,
        next_completion_icount: next,
    }
}
