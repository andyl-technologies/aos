//! Existing block waiter decisions with optional original-value observations.

use super::*;

impl LiveVcpuTimeCallbackState {
    pub(super) fn on_block_wait(&self, request_id: u32) -> Result<(), LiveVcpuTimeCallbackError> {
        let resumed = self.note_block_wait(request_id);
        let mut observation = self.device_wait_witness.request(
            request_id,
            self.control_stage_identity,
            self.last_icount.load(Ordering::Acquire),
        );
        self.device_wait_witness.emit(
            observation,
            "entered",
            (None, None, None),
            (None, None),
            "pending",
        );
        let result = (|| {
            if self.idle_advance_is_pending() {
                self.device_wait_witness.emit(
                    observation,
                    "pending",
                    (None, None, None),
                    (None, None),
                    "deferred",
                );
                return Ok(());
            }
            let dispatch = self.device_wait_dispatch(resumed)?;
            if dispatch == DeviceWaitDispatch::Dispatchable {
                self.device_wait_witness.emit(
                    observation,
                    "vcpu-running",
                    (None, None, None),
                    (None, None),
                    "retry",
                );
                // The guest still owns time: it advances by retiring
                // instructions until the device deadline or until every vCPU
                // halts, when the all-halted idle path plans the same wake.
                return Ok(());
            }

            // Keep the one live sample: the jump below may arm only there.
            let raw_icount_at_entry = self.last_raw_icount.load(Ordering::Acquire);
            let sampled_raw_icount = (self.icount_raw)();
            let current_icount = self.publish_callback_icount_without_pause(
                raw_icount_at_entry,
                sampled_raw_icount,
                "device-current",
            )?;
            let device_deadline =
                PluginShmemOrdering::device_completion_deadline_tick(self.slot.get());
            if let Some(observation) = observation.as_mut() {
                observation.current = Some(current_icount);
                observation.deadline = Some(device_deadline);
            }
            if device_deadline == 0 {
                self.device_wait_witness.emit(
                    observation,
                    "no-deadline",
                    (None, None, None),
                    (None, None),
                    "retry",
                );
                // The host publishes the deterministic deadline before signalling
                // the wake fd. QEMU re-fires this callback after that wake, so this
                // wall-time race changes only how long the coroutine stays parked.
                return Ok(());
            }
            let ceiling_icount = self.scheduler_idle_ceiling(device_deadline)?;
            let exact_deadline = self
                .exact_deadline
                .read_next_deadline()
                .map_err(|source| LiveVcpuTimeCallbackError::ExactDeadlineRead { source })?;
            if let Some(observation) = observation.as_mut() {
                observation.exact_deadline = Some(exact_deadline);
            }
            let exact_deadline = dispatch.serviceable_timer(exact_deadline, current_icount);
            let plan = compute_idle_wake_plan(
                current_icount,
                exact_deadline,
                None,
                SchedulerCeiling::new(ceiling_icount),
                true,
                Some(device_deadline),
            )
            .map_err(|source| LiveVcpuTimeCallbackError::IdleHotLoop { source })?;
            // A block coroutine can park before the vCPU gets another opportunity
            // to query `max_advance_icount`. A wake beyond the current ceiling
            // leaves the clock where it is: the ceiling is a bound, not a target
            // (RFC-0010 SCHED-12). The idle path settles the parked node, and the
            // host wake after publishing a later ceiling re-fires this hook.
            let target_icount = plan.desired_wake_icount();
            if target_icount > ceiling_icount {
                self.device_wait_witness.emit(
                    observation,
                    "beyond-ceiling",
                    (None, Some(target_icount), None),
                    (None, None),
                    "retry",
                );
                return Ok(());
            }
            if target_icount <= current_icount {
                self.device_wait_witness.emit(
                    observation,
                    "already-due",
                    (None, Some(target_icount), None),
                    (None, None),
                    "retry",
                );
                // Virtual time already admits the response. If its ring write is
                // still physically pending, the next host wake retries the poll at
                // this same icount without exposing host timing to the guest.
                return Ok(());
            }
            // Arm only at the live raw coordinate. A sample that was not
            // committed (a preserved output stop, a superseded publication)
            // leaves the published raw count apart from QEMU's, and a jump
            // pinned there would fail the pending-jump invariant on the next
            // read.
            let raw_icount = self.last_raw_icount.load(Ordering::Acquire);
            if raw_icount != sampled_raw_icount {
                self.device_wait_witness.emit(
                    observation,
                    "stale-raw",
                    (Some(raw_icount), Some(target_icount), None),
                    (None, None),
                    "retry",
                );
                return Ok(());
            }
            self.arm_and_enqueue_idle_advance_observed(
                raw_icount,
                target_icount,
                None,
                observation,
            )?;
            Ok(())
        })();
        if result.is_err() {
            self.device_wait_witness.emit(
                observation,
                "error",
                (None, None, None),
                (None, None),
                "error",
            );
        }
        result
    }

    /// Records the calling thread as the RR vCPU thread.
    ///
    /// Crucible requires single-threaded RR, so every vCPU callback runs on
    /// one thread. Recording on each vCPU callback, not only at init, keeps
    /// the identity current in a forked hot-fork child.
    pub(super) fn record_rr_vcpu_thread(&self) {
        self.rr_vcpu_thread
            .store(current_thread_identity(), Ordering::Release);
    }

    /// Records a block wait and returns whether its request had parked before.
    fn note_block_wait(&self, request_id: u32) -> bool {
        self.parked_block_waits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .note_wait(request_id)
    }

    /// Records a block poll result for the parked-wait bookkeeping.
    pub(super) fn note_block_poll(&self, epoch: u64, request_id: u32, completed: bool) {
        self.parked_block_waits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .note_poll(epoch, request_id, completed);
    }

    /// Classifies whether QEMU can dispatch guest code while this wait runs.
    ///
    /// Only a resumed request on the RR thread proves that thread is blocked;
    /// see [`ParkedBlockWaits`]. Every other wait, including a first pass on
    /// the RR thread, uses the parked check. An unrecorded RR identity never
    /// matches. A borrowed halt tracker counts as dispatchable: the waiter
    /// retries and no time moves.
    fn device_wait_dispatch(
        &self,
        resumed: bool,
    ) -> Result<DeviceWaitDispatch, LiveVcpuTimeCallbackError> {
        let rr_vcpu_thread = self.rr_vcpu_thread.load(Ordering::Acquire);
        if resumed && rr_vcpu_thread != 0 && rr_vcpu_thread == current_thread_identity() {
            return Ok(DeviceWaitDispatch::IoBlockedOnRrThread);
        }
        let parked = match self.try_halted_vcpus() {
            Ok(halted_vcpus) => halted_vcpus.all_halted_and_parked(),
            Err(LiveVcpuTimeCallbackError::HaltStateBorrowed) => false,
            Err(error) => return Err(error),
        };
        Ok(if parked {
            DeviceWaitDispatch::AllParked
        } else {
            DeviceWaitDispatch::Dispatchable
        })
    }
}

/// Whether guest dispatch is frozen while a block wait runs, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeviceWaitDispatch {
    /// A parked request resumed on the RR vCPU thread itself.
    ///
    /// A nested poll in a vCPU's synchronous device emulation resumed the
    /// coroutine there, mid-instruction, and blocks until the request
    /// completes. That vCPU is not halted, but the single RR thread that runs
    /// every vCPU is blocked, so no guest code can run.
    IoBlockedOnRrThread,
    /// The wait runs on QEMU's main loop and every vCPU is halted and parked.
    ///
    /// The RR thread executes guest code with the BQL released, so an idle
    /// advance armed while a vCPU can run pins a raw coordinate the vCPU
    /// keeps retiring past. A vCPU whose resume deferred its wake publication
    /// keeps its halt bit but is dispatchable, so halt bits alone are not
    /// enough. Halt tracking changes only in BQL-held RR callbacks and this
    /// callback holds the BQL, so the answer stays true until QEMU's advance
    /// barrier freezes dispatch.
    AllParked,
    /// A vCPU can still execute guest code; the wait must not move time.
    Dispatchable,
}

impl DeviceWaitDispatch {
    /// Drops a timer that only an idle advance can no longer service.
    ///
    /// On the main loop an already-due timer belongs to the RR idle path,
    /// which dispatches it at the current coordinate, so the wait retries.
    /// On a blocked RR thread nothing else can run it: QEMU services virtual
    /// timers on that same thread, so a plan that retried on it would park
    /// forever. The device deadline is then the next real event, and the
    /// advance to it runs the overdue timer. A timer still ahead of the
    /// current coordinate remains a real wake in both cases.
    fn serviceable_timer(
        self,
        exact_deadline: ExactDeadlineReport,
        current_icount: u64,
    ) -> ExactDeadlineReport {
        match (self, exact_deadline) {
            (Self::IoBlockedOnRrThread, ExactDeadlineReport::Armed { deadline_ps })
                if deadline_ps <= current_icount =>
            {
                ExactDeadlineReport::NoArmedTimer
            }
            _ => exact_deadline,
        }
    }
}

/// Bound on recorded parked requests; beyond it a wait counts as a first pass.
///
/// A virtqueue holds far fewer requests. Failing closed only withholds the
/// RR-thread jump, so the wait retries without moving time.
const MAX_PARKED_BLOCK_WAITS: usize = 4096;

/// Block requests whose wait callback has already run at least once.
///
/// A crucible-shmem request coroutine fires the wait callback on every
/// pending poll and then yields. Its first pass runs where the request was
/// submitted. With `ioeventfd=off` that is the RR vCPU thread, inside the
/// guest's queue kick, and the yield returns to that vCPU, which keeps
/// retiring instructions. An idle jump armed there pins a raw coordinate the
/// running vCPU passes. A later pass runs where the parked coroutine is
/// resumed: on the main loop, or in a nested poll on the RR thread that holds
/// the vCPU until the request completes. Only that resumption proves the RR
/// thread cannot dispatch guest code.
///
/// Request identifiers are unique within a transport epoch. A completed
/// request is forgotten, and a poll from another epoch forgets them all.
#[derive(Debug, Default)]
pub(super) struct ParkedBlockWaits {
    epoch: Option<u64>,
    requests: std::collections::BTreeSet<u32>,
}

impl ParkedBlockWaits {
    /// Records a wait and returns whether its request had parked before.
    fn note_wait(&mut self, request_id: u32) -> bool {
        if self.requests.contains(&request_id) {
            return true;
        }
        if self.requests.len() < MAX_PARKED_BLOCK_WAITS {
            self.requests.insert(request_id);
        }
        false
    }

    /// Forgets a completed request, or every request of an earlier epoch.
    fn note_poll(&mut self, epoch: u64, request_id: u32, completed: bool) {
        if self.epoch != Some(epoch) {
            self.requests.clear();
            self.epoch = Some(epoch);
        }
        if completed {
            self.requests.remove(&request_id);
        }
    }
}

/// Returns a process-unique, nonzero identity for the calling thread.
///
/// Zero is reserved for "unrecorded". A forked child keeps the forking
/// thread's identity, as it keeps that thread.
pub(super) fn current_thread_identity() -> u64 {
    static NEXT_THREAD_IDENTITY: AtomicU64 = AtomicU64::new(1);
    thread_local! {
        static THREAD_IDENTITY: u64 = NEXT_THREAD_IDENTITY.fetch_add(1, Ordering::Relaxed);
    }
    THREAD_IDENTITY.with(|identity| *identity)
}
