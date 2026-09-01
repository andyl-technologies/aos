//! Result records emitted by the live node-step and lifecycle gates.

use super::*;

/// Raw-versus-logical accounting for one bounded node step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLiveNodeStepQuantum {
    /// Scheduler-requested ceiling for this step (the raw target).
    pub target_icount: u64,
    /// Node-published completion icount at the boundary (the logical value).
    pub completion_icount: u64,
    /// `completion_icount - target_icount`; must be zero in a busy window.
    pub logical_offset: u64,
    /// Times the ceiling was re-issued before the boundary was reached.
    pub reissue_count: u32,
    /// Whether the step reached the horizon rather than parking idle early.
    pub reached_horizon: bool,
}

/// The outcome of one full node-step run (bring-up, steps, teardown).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NodeStepOutcome {
    pub(super) quanta: Vec<QemuLiveNodeStepQuantum>,
    pub(super) fingerprint: ExecutionFingerprint,
    pub(super) orderly_child_exit: bool,
}

/// Successful evidence from the live [`QemuNode`] bounded-step gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveNodeStepReport {
    /// Per-step raw-versus-logical accounting from the reference (first) run.
    pub quanta: Vec<QemuLiveNodeStepQuantum>,
    /// Execution fingerprint the node published at the final boundary.
    pub execution_fingerprint: ExecutionFingerprint,
    /// The QEMU child exited cleanly after the node's shutdown escalation.
    pub orderly_child_exit: bool,
    /// The second run, under bounded scheduler preemption, matched the first byte for byte.
    pub deterministic_under_scheduler_preemption: bool,
    /// Bounded scheduler preemption was actually applied during the second run.
    pub scheduler_preemption_applied: bool,
    /// Every busy-window step's logical offset was zero.
    pub busy_window_logical_offset_zero: bool,
}

/// Evidence from a real QEMU save, process crash, load, and continuation run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveExactSnapshotReport {
    /// Number of serialized round-robin vCPUs exercised by the restore.
    pub smp_vcpus: u16,
    /// Raw node icount at the captured completed quantum boundary.
    pub capture_icount: u64,
    /// Raw node icount observed immediately after restore.
    pub restored_icount: u64,
    /// Serialized RR vCPU selected at the captured boundary.
    pub capture_rr_current_vcpu: u32,
    /// Nonzero instruction offset within the captured RR turn.
    pub capture_rr_position_in_quantum: u64,
    /// Fixed RR turn length serialized with the captured cursor.
    pub capture_rr_switch_quantum: u64,
    /// Raw node icount reached by the restored and independently replayed suffix.
    pub suffix_icount: u64,
    /// Captured logical icount minus QEMU's raw icount at the save boundary.
    pub capture_logical_time_offset: u64,
    /// Execution fingerprint at capture and immediately after restore.
    pub capture_fingerprint: ContentHash,
    /// Execution fingerprint after the post-restore suffix.
    pub suffix_fingerprint: ContentHash,
    /// Aggregate VMState, host-I/O, and wrapper identity matched independent replay.
    pub replay_oracle_pair_match: bool,
    /// The old QEMU process was force-killed and reaped before artifact staging.
    pub old_process_force_crashed: bool,
    /// The captured block continuation contained pending work.
    pub pending_block_io_captured: bool,
    /// Production admission rejected an otherwise identical fingerprint whose
    /// RR position was reset to zero.
    pub rr_cursor_negative_control_rejected: bool,
}

/// Evidence from one signal-driven lifecycle effect applied by live patched QEMU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveNodeLifecycleFaultReport {
    /// QEMU instruction coordinate at which the command was committed.
    pub observed_icount: u64,
    /// Authenticated action identity carried by command and occurrence evidence.
    pub action: ContentHash,
    /// Authenticated typed evidence identity returned by QEMU.
    pub evidence: ContentHash,
    /// Transition-specific QEMU process exit status.
    pub exit_code: i32,
    /// The signal runtime committed exactly one node-lifecycle impulse.
    pub lifecycle_impulse_committed: bool,
    /// A separately launched QEMU process reproduced every discovered target
    /// manifest and derived capability row exactly before the fault ran.
    pub exact_manifest_replay_admitted: bool,
    /// A real guest-state change between PREPARE and APPLY produced the typed
    /// precondition-mismatch status while the QEMU process remained live.
    pub changed_state_precondition_rejected: bool,
    /// Corrupting the authentic command result was rejected while the authentic
    /// occurrence event remained independently valid.
    pub corrupt_result_rejected_with_valid_event: bool,
    /// Corrupting the authentic occurrence event was rejected while the
    /// authentic command result remained independently valid.
    pub corrupt_event_rejected_with_valid_result: bool,
    /// One event source atomically committed network, storage, and node actions
    /// into their production adapter ledgers.
    ///
    /// This is an adapter-routing and commit-order proof. The network and
    /// storage impulses still require exact device opportunities before their
    /// mutations become externally visible.
    pub cross_adapter_actions_committed: bool,
    /// A live QEMU precondition rejection left the prepared host adapter state
    /// byte-identical and empty.
    pub cross_adapter_rejection_rolled_back: bool,
}
