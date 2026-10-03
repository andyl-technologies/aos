//! Bounded observations from the admitted owner of a pending quantum wait.
//!
//! The existing diagnostic opt-in admits 1..=256 records per runtime. An
//! advance phase must remain pending for five seconds before its first record.
//! A clamp first reports after the smaller of five seconds and half its original
//! budget, so a one-second failed ACK wait remains observable. Follow-up records
//! are at least five seconds apart within each phase. Waits that complete before
//! their first sample spend no budget. The original host deadline supplies
//! sampling time; no additional clock is read. Renewed advance slices retain
//! only consumption established by the original remaining-budget reads. This
//! conservatively omits time after the last read rather than inventing elapsed
//! time when a caller renews early.
//! Snapshots and independently acquire-read ring cursors are advisory, never a
//! coherent cross-transport state or input to a control decision.
//! Fixed phases and scalar fields keep each record below 2048 bytes, for at most
//! 512 KiB per runtime. Unavailable views and failed writes remain nonfatal.

use std::cell::Cell;
use std::io::Write;
use std::os::fd::BorrowedFd;
use std::time::Duration;

use crucible_shmem::NodeSlotSnapshot;

use super::QemuLiveHostIoRuntime;
use super::control::PendingControlBoundary;

const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

/// Copies the exact existing settlement requirements without publishing them.
#[derive(Clone, Copy)]
pub(super) struct ClampExpectation {
    pub(super) request: PendingControlBoundary,
    pub(super) current_ps: u64,
    pub(super) idle_ps: u64,
    pub(super) acknowledgement_seen: bool,
    pub(super) device_progress: bool,
}

/// Keeps diagnostic-only state outside checkpoints and runtime counters.
pub(super) struct WaitObservation {
    remaining: u16,
    slice_timeout: Duration,
    slice_remaining: Duration,
    consumed_slices: Duration,
    next_elapsed: Option<Duration>,
    region_inode: Option<u64>,
    /// Last deadline computed by the original host publication, without rereading it.
    pub(super) host_published_device_deadline: Cell<Option<u64>>,
}

impl WaitObservation {
    pub(super) fn from_environment(fd: BorrowedFd<'_>) -> Self {
        let maximum = std::env::var("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or_default();
        let mut observation = Self::with_budget(maximum);
        if observation.remaining != 0 {
            observation.region_inode = rustix::fs::fstat(fd).ok().map(|stat| stat.st_ino);
        }
        observation
    }

    fn with_budget(maximum: u16) -> Self {
        Self {
            remaining: if (1..=256).contains(&maximum) {
                maximum
            } else {
                0
            },
            slice_timeout: Duration::ZERO,
            slice_remaining: Duration::ZERO,
            consumed_slices: Duration::ZERO,
            next_elapsed: None,
            region_inode: None,
            host_published_device_deadline: Cell::new(None),
        }
    }

    pub(super) fn begin(&mut self, timeout: Duration) {
        self.slice_timeout = timeout;
        self.slice_remaining = timeout;
        self.consumed_slices = Duration::ZERO;
        self.next_elapsed = Some(SAMPLE_INTERVAL);
    }

    pub(super) fn observe_remaining(&mut self, remaining: Duration) {
        if self.remaining != 0 {
            self.slice_remaining = self.slice_remaining.min(remaining);
        }
    }

    /// Carries observed consumption across an original successful renewal.
    pub(super) fn renew(&mut self, timeout: Duration) {
        if self.remaining == 0 {
            return;
        }
        self.consumed_slices = self
            .consumed_slices
            .saturating_add(self.slice_timeout.saturating_sub(self.slice_remaining));
        self.slice_timeout = timeout;
        self.slice_remaining = timeout;
    }

    pub(super) fn begin_clamp(&mut self, timeout: Duration) {
        let first_sample_after = SAMPLE_INTERVAL.min(timeout / 2);
        self.begin(timeout);
        self.next_elapsed = if first_sample_after.is_zero() {
            None
        } else {
            Some(first_sample_after)
        };
    }

    /// Reserves a record before acquiring any diagnostic transport views.
    fn due(&mut self, remaining: Duration) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.observe_remaining(remaining);
        let elapsed = self
            .consumed_slices
            .saturating_add(self.slice_timeout.saturating_sub(self.slice_remaining));
        if !self.next_elapsed.is_some_and(|next| elapsed >= next) {
            return false;
        }
        self.remaining -= 1;
        self.next_elapsed = elapsed.checked_add(SAMPLE_INTERVAL);
        true
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RingIndices {
    tx: Option<(u64, u64)>,
    rx: Option<(u64, u64)>,
    fault_command: Option<(u64, u64)>,
    fault_event: Option<(u64, u64)>,
    fault_result: Option<(u64, u64)>,
}

impl QemuLiveHostIoRuntime {
    /// Emits the original snapshot before sleeping, without servicing payloads.
    pub(super) fn observe_pending_wait(
        &mut self,
        phase: &'static str,
        snapshot: &NodeSlotSnapshot,
        clamp: Option<ClampExpectation>,
        remaining: Duration,
    ) {
        if !self.wait_observation.due(remaining) {
            return;
        }
        self.emit_pending_wait_to(
            phase,
            snapshot,
            clamp,
            remaining,
            &mut std::io::stderr().lock(),
        );
    }

    fn emit_pending_wait_to(
        &mut self,
        phase: &'static str,
        snapshot: &NodeSlotSnapshot,
        clamp: Option<ClampExpectation>,
        remaining: Duration,
        sink: &mut impl Write,
    ) {
        let indices = self.wait_ring_indices();
        // A closed diagnostic sink cannot replace the original wait result.
        let _ = write_observation(sink, self, phase, snapshot, clamp, remaining, &indices);
    }

    fn wait_ring_indices(&mut self) -> RingIndices {
        // These existing accessors validate the owned mapping before exposing
        // headers. Only cursors are read; no peek/dequeue or payload inspection.
        let network = self
            .region
            .node_directed_ring_pair_mut(
                self.vm_slot,
                self.vm_slot,
                crucible_shmem::SLOT_NET_ROUTER as u32,
                crucible_shmem::SLOT_NET_ROUTER as u32,
                self.vm_slot,
            )
            .ok()
            .map(|rings| {
                (
                    (
                        rings.first.header.read_index(),
                        rings.first.header.write_index(),
                    ),
                    (
                        rings.second.header.read_index(),
                        rings.second.header.write_index(),
                    ),
                )
            });
        let fault_command = self
            .region
            .fault_command_transport_mut(self.vm_slot)
            .ok()
            .map(|transport| (transport.ring.read_index(), transport.ring.write_index()));
        let fault_event = self
            .region
            .fault_event_transport_mut(self.vm_slot)
            .ok()
            .map(|transport| (transport.ring.read_index(), transport.ring.write_index()));
        let fault_result = self
            .region
            .fault_result_transport_mut(self.vm_slot)
            .ok()
            .map(|transport| (transport.ring.read_index(), transport.ring.write_index()));
        RingIndices {
            tx: network.map(|indices| indices.0),
            rx: network.map(|indices| indices.1),
            fault_command,
            fault_event,
            fault_result,
        }
    }
}

fn write_observation(
    sink: &mut impl Write,
    runtime: &QemuLiveHostIoRuntime,
    phase: &str,
    snapshot: &NodeSlotSnapshot,
    clamp: Option<ClampExpectation>,
    remaining: Duration,
    indices: &RingIndices,
) -> std::io::Result<()> {
    let request = clamp.map(|clamp| clamp.request);
    // Legacy *_icount slot coordinates are picosecond ticks; only the raw
    // logical-time partner counts retired instructions (shmem::TICKS_PER_NS).
    // None explicitly means unavailable, including advance's absent ACK fence.
    writeln!(
        sink,
        "CRUCIBLE-HOST-WAIT-V1 phase={phase} slot={} region_inode={:?} current_ps={} max_ps={} idle_ps={} raw_instructions={} status={} device_active={} publish_gen={} wake={} observed_ack={} expected_ack={:?} request={:?} request_fault_frontier={:?} observed_fault_frontier={} request_capture={:?} observed_capture={} expected_current_ps={:?} expected_idle_ps={:?} acknowledgement_seen={:?} device_progress={:?} scheduler_pending_gen={:?} device_pending_gen={:?} host_remaining_ms={} host_published_device_deadline_ps={:?} tx_read_write={:?} rx_read_write={:?} fault_command_read_write={:?} fault_event_read_write={:?} fault_result_read_write={:?}",
        runtime.vm_slot,
        runtime.wait_observation.region_inode,
        snapshot.current_icount,
        snapshot.max_advance_icount,
        snapshot.idle_wake_icount,
        snapshot.logical_time_raw_icount,
        snapshot.status,
        snapshot.device_io_active,
        snapshot.publish_gen,
        snapshot.wake_signal,
        snapshot.control_boundary_ack,
        request.map(|request| request.generation.wrapping_add(1)),
        request.map(|request| request.generation),
        request.map(|request| request.fault_command_frontier),
        snapshot.control_boundary_fault_command_frontier,
        request.and_then(|request| request.fingerprint_capture_request),
        snapshot.control_boundary_capture_request,
        clamp.map(|clamp| clamp.current_ps),
        clamp.map(|clamp| clamp.idle_ps),
        clamp.map(|clamp| clamp.acknowledgement_seen),
        clamp.map(|clamp| clamp.device_progress),
        runtime.scheduler_input_publish_generation,
        runtime.device_wake_publish_generation,
        remaining.as_millis(),
        runtime
            .wait_observation
            .host_published_device_deadline
            .get(),
        indices.tx,
        indices.rx,
        indices.fault_command,
        indices.fault_event,
        indices.fault_result,
    )
}

#[cfg(test)]
#[path = "wait_observation_tests.rs"]
mod tests;
