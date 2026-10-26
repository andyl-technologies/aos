//! Bounded live trace of slot publications that leave an earlier advance's marker.
//!
//! A settled clamp leaves the node idle with its wake at its own coordinate.
//! Under console custody the host holds a pause at that coordinate for the
//! next advance until a fresh publication releases it. A publication that
//! keeps the slot in that shape while the newer advance has not settled looks,
//! from the host, exactly like a report for the newer advance. This trace
//! names the writer of each such publication, so a stall at that marker shows
//! which path republished it:
//!
//! ```text
//! CRUCIBLE-SLOT-WRITER-V1 pid=4242 writer=timer-witness gen=1974616 logical_ps=572604210200 idle_wake_ps=572604210200 advance=9320 settled=9318 control=4671 count=1
//! ```
//!
//! A process prints at most [`MAXIMUM_ROWS`] rows. The rows are diagnostic
//! only and never feed a guest-visible value.

use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_shmem::{NodeSlot, NodeSlotSnapshot, STATUS_IDLE};

/// Rows one process may print before the trace goes quiet.
const MAXIMUM_ROWS: u64 = 64;

static COUNT: AtomicU64 = AtomicU64::new(0);

/// Plugin writer that published the slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlotWriter {
    ReachedIcount,
    ReachedIcountRetainingIdle,
    Settled,
    TimerWitness,
    IdleWait,
    PauseQuiesced,
    ControlBoundary,
    MarkRunning,
    DeviceIoActive,
    DeviceIoCleared,
}

impl SlotWriter {
    const fn label(self) -> &'static str {
        match self {
            Self::ReachedIcount => "reached",
            Self::ReachedIcountRetainingIdle => "reached-retaining-idle",
            Self::Settled => "settled",
            Self::TimerWitness => "timer-witness",
            Self::IdleWait => "idle-wait",
            Self::PauseQuiesced => "pause-quiesced",
            Self::ControlBoundary => "control-boundary",
            Self::MarkRunning => "mark-running",
            Self::DeviceIoActive => "device-io-active",
            Self::DeviceIoCleared => "device-io-cleared",
        }
    }
}

/// Prints one row when `writer` left an earlier advance's marker in the slot,
/// until the per-process allowance is spent.
pub(crate) fn note(slot: &NodeSlot, writer: SlotWriter) {
    if COUNT.load(Ordering::Relaxed) >= MAXIMUM_ROWS {
        return;
    }
    // A contended snapshot belongs to another writer, whose own row covers it.
    let Some(snapshot) = slot.try_snapshot() else {
        return;
    };
    if !stale_marker(&snapshot) {
        return;
    }
    let count = COUNT.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    if count > MAXIMUM_ROWS {
        return;
    }
    let _ = writeln!(
        io_target(),
        "{}",
        row(std::process::id(), writer, &snapshot, count)
    );
}

/// Reports whether the slot reads as the quiesced boundary at its own
/// coordinate while a newer advance than the settled one is published.
fn stale_marker(snapshot: &NodeSlotSnapshot) -> bool {
    snapshot.status == STATUS_IDLE
        && snapshot.idle_wake_icount <= snapshot.current_icount
        && snapshot.settled_publication_sequence != 0
        && snapshot.settled_publication_sequence < snapshot.advance_publication_sequence
}

fn row(process_id: u32, writer: SlotWriter, snapshot: &NodeSlotSnapshot, count: u64) -> String {
    format!(
        "CRUCIBLE-SLOT-WRITER-V1 pid={process_id} writer={} gen={} logical_ps={} idle_wake_ps={} advance={} settled={} control={} count={count}",
        writer.label(),
        snapshot.publish_gen,
        snapshot.current_icount,
        snapshot.idle_wake_icount,
        snapshot.advance_publication_sequence,
        snapshot.settled_publication_sequence,
        snapshot.control_boundary_ack,
    )
}

#[cfg(not(test))]
fn io_target() -> std::io::StderrLock<'static> {
    std::io::stderr().lock()
}

#[cfg(test)]
fn io_target() -> std::io::Sink {
    std::io::sink()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(advance: u64, settled: u64) -> NodeSlotSnapshot {
        let slot = NodeSlot::new(crucible_shmem::KIND_VM);
        let mut snapshot = slot.snapshot();
        snapshot.status = STATUS_IDLE;
        snapshot.current_icount = 1100;
        snapshot.idle_wake_icount = 1100;
        snapshot.advance_publication_sequence = advance;
        snapshot.settled_publication_sequence = settled;
        snapshot
    }

    #[test]
    fn only_a_marker_left_under_a_newer_advance_is_reported() {
        assert!(stale_marker(&marker(9320, 9318)));
        assert!(!stale_marker(&marker(9318, 9318)));
        assert!(!stale_marker(&marker(9320, 0)));

        let mut future_wake = marker(9320, 9318);
        future_wake.idle_wake_icount = 1200;
        assert!(!stale_marker(&future_wake));
    }

    #[test]
    fn a_row_names_the_writer_and_both_advances() {
        let mut snapshot = marker(9320, 9318);
        snapshot.publish_gen = 16;
        snapshot.control_boundary_ack = 4671;

        assert_eq!(
            row(42, SlotWriter::TimerWitness, &snapshot, 1),
            "CRUCIBLE-SLOT-WRITER-V1 pid=42 writer=timer-witness gen=16 logical_ps=1100 idle_wake_ps=1100 advance=9320 settled=9318 control=4671 count=1"
        );
    }
}
