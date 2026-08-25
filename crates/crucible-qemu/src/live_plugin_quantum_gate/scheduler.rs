//! Multi-quantum scheduler that drives one boot/idle/idle-jump scenario.
//!
//! The scheduler raises the plugin-owned max-advance ceiling in fixed steps
//! while the guest is busy, detects the first parked-idle quantum (the idle
//! observation), then issues one wide quantum that lets the parked guest
//! idle-jump toward a far ceiling. Boot and idle-jump advancement are timed so
//! the emitted evidence can distinguish O(1) idle-jump from per-instruction
//! execution.

use std::thread;
use std::time::{Duration, Instant};

use crucible::{AdvanceOutcome, ExecutionHorizon, Icount, SimDoubleHostScheduleEvent};
use crucible_shmem::{FingerprintSample, STATUS_IDLE};

use crate::quantum_boundary::{QuantumBoundary, classify_quantum_boundary};
use crate::{
    QemuHostIoRuntime, QemuMappedQuantumShmemHotPath, QemuNodeChannelError, QemuNodeIdleState,
    QemuShmemHotPathChannel,
};

use super::{
    HostAdversary, LivePluginAdvancementRates, LivePluginIdleObservation,
    LivePluginQuantumGateConfig, LivePluginQuantumGateError,
};

/// Host poll interval while waiting on the plugin-owned boundary or teardown.
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Drives the boot, idle-observation, and idle-jump quanta for one run.
///
/// # Errors
///
/// Returns [`LivePluginQuantumGateError`] when a quantum times out, the guest
/// exits early, the guest never idles before the search bound, or the idle-jump
/// quantum fails to advance past the idle onset.
pub(super) fn drive_scenario(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    child: &mut crate::QemuNodeChild,
    setup: &crate::QemuHostPluginSetup,
    config: &LivePluginQuantumGateConfig,
    host_adversary: &mut Option<HostAdversary>,
) -> Result<
    (
        LivePluginIdleObservation,
        LivePluginAdvancementRates,
        Vec<SimDoubleHostScheduleEvent>,
    ),
    LivePluginQuantumGateError,
> {
    let schedule = config.schedule();
    let boot_started = wall_clock_start();
    let mut ceiling = schedule.ceiling_step_icount;
    let mut boot_quantum_count: u32 = 0;
    let mut host_observable_schedule = Vec::new();

    let idle = loop {
        let (stop, event) = run_quantum(hot_path, child, setup, ceiling, config, host_adversary)?;
        host_observable_schedule.push(event);
        match stop {
            QuantumStop::ReachedCeiling { .. } => {
                boot_quantum_count = boot_quantum_count.saturating_add(1);
                if ceiling >= schedule.max_search_icount {
                    return Err(LivePluginQuantumGateError::GuestNeverIdled {
                        ceiling_icount: ceiling,
                        max_search_icount: schedule.max_search_icount,
                    });
                }
                ceiling = ceiling.saturating_add(schedule.ceiling_step_icount);
            }
            QuantumStop::Paused { at, deadline } => {
                break LivePluginIdleObservation {
                    idle_onset_icount: at,
                    next_deadline_icount: deadline,
                    ceiling_icount: ceiling,
                    boot_quantum_count,
                };
            }
        }
    };
    let boot_wall_micros = wall_micros_since(boot_started);

    // Idle-jump: raise the ceiling far beyond the parked deadline in one quantum.
    // A time-owning plugin advances the idle guest by O(1) deadline jumps, so the
    // whole span collapses in wall time even though it spans a large icount range.
    let idle_horizon = idle
        .idle_onset_icount
        .saturating_add(schedule.idle_horizon_margin_icount)
        .max(
            idle.next_deadline_icount
                .saturating_add(schedule.ceiling_step_icount),
        );
    let idle_started = wall_clock_start();
    let (stop, event) = run_quantum(hot_path, child, setup, idle_horizon, config, host_adversary)?;
    host_observable_schedule.push(event);
    let terminal_icount = match stop {
        QuantumStop::ReachedCeiling { icount } => icount,
        QuantumStop::Paused { at, .. } => at,
    };
    let idle_wall_micros = wall_micros_since(idle_started);

    if terminal_icount <= idle.idle_onset_icount {
        return Err(LivePluginQuantumGateError::IdleJumpDidNotAdvance {
            idle_onset_icount: idle.idle_onset_icount,
        });
    }

    let rates = LivePluginAdvancementRates {
        boot_icount_span: idle.idle_onset_icount,
        boot_wall_micros,
        idle_icount_span: terminal_icount.saturating_sub(idle.idle_onset_icount),
        idle_wall_micros,
        terminal_icount,
    };
    Ok((idle, rates, host_observable_schedule))
}

/// A completed quantum's stopping condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum QuantumStop {
    /// The busy guest advanced to exactly the host-published ceiling.
    ReachedCeiling {
        /// Node icount observed at the ceiling.
        icount: u64,
    },
    /// The guest parked in an idle wait with a deadline beyond the ceiling.
    Paused {
        /// Node icount at which the guest parked.
        at: u64,
        /// Computed next virtual-timer deadline published while idle.
        deadline: u64,
    },
}

/// Publishes one scheduler ceiling, waits for the plugin-owned boundary, and
/// finishes the quantum, cross-checking the observed stop against the plugin's
/// reported advance outcome.
pub(super) fn run_quantum(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    child: &mut crate::QemuNodeChild,
    setup: &crate::QemuHostPluginSetup,
    ceiling: u64,
    config: &LivePluginQuantumGateConfig,
    host_adversary: &mut Option<HostAdversary>,
) -> Result<(QuantumStop, SimDoubleHostScheduleEvent), LivePluginQuantumGateError> {
    let from_icount = QemuShmemHotPathChannel::idle_state(hot_path)
        .map_err(|source| channel_error("read pre-quantum icount", source))?
        .current_icount
        .retired;
    let initial_publish_generation = hot_path
        .node_snapshot()
        .map_err(|source| channel_error("read pre-quantum publication", source))?
        .publish_gen;
    let mut pending = QemuShmemHotPathChannel::start_quantum(
        hot_path,
        ExecutionHorizon {
            icount: Icount { retired: ceiling },
        },
    )
    .map_err(|source| channel_error("start quantum", source))?;
    // Do not remove this wake: `start_quantum` futex-wakes the shared-memory
    // slot, which is sufficient to release the boot-barrier and single-quantum
    // install path, but it is NOT sufficient across a multi-quantum run. After the
    // guest first idles, QEMU parks the vCPU thread in its idle wait on the
    // inherited wake eventfd (fd 5), which a shared-memory futex wake does not
    // rouse. Signalling the eventfd once per quantum re-arms QEMU so the plugin
    // observes the raised ceiling. It is deliberately NOT signalled per poll:
    // constant waking destabilises the plugin's published idle state and prevents
    // the scheduler from observing a stable idle park. Advance targets are the
    // guest's exact virtual-timer deadlines, so the wake cadence never affects the
    // resulting icount.
    setup
        .signal_plugin_wake()
        .map_err(|source| channel_error("wake plugin for next quantum", source))?;
    HostAdversary::certify_mapped_quantum_pending(host_adversary, hot_path, &mut pending)
        .map_err(|source| LivePluginQuantumGateError::SchedulerPreemption { source })?;
    let stop =
        wait_for_quantum_boundary(hot_path, child, ceiling, initial_publish_generation, config)?;
    let completion = QemuShmemHotPathChannel::finish_quantum(hot_path, pending)
        .map_err(|source| channel_error("finish quantum", source))?;
    match (&stop, &completion.outcome) {
        (QuantumStop::ReachedCeiling { .. }, AdvanceOutcome::ReachedHorizon)
        | (QuantumStop::Paused { .. }, AdvanceOutcome::Paused { .. }) => {
            let reached_icount = match stop {
                QuantumStop::ReachedCeiling { icount } => icount,
                QuantumStop::Paused { at, .. } => at,
            };
            Ok((
                stop,
                SimDoubleHostScheduleEvent::HorizonAdvance {
                    from_icount,
                    requested_icount: ceiling,
                    reached_icount,
                    outcome: completion.outcome,
                },
            ))
        }
        (_, outcome) => Err(LivePluginQuantumGateError::SecondRunDiverged {
            reason: format!("quantum stop {stop:?} disagreed with plugin outcome {outcome:?}"),
        }),
    }
}

// crucible-lint: allow clippy-disallowed-method -- quantum-gate host timeout bounds QEMU liveness only.
#[allow(clippy::disallowed_methods)]
fn wait_for_quantum_boundary(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    child: &mut crate::QemuNodeChild,
    ceiling: u64,
    initial_publish_generation: u32,
    config: &LivePluginQuantumGateConfig,
) -> Result<QuantumStop, LivePluginQuantumGateError> {
    let started = Instant::now();
    loop {
        let snapshot = hot_path
            .node_snapshot()
            .map_err(|source| channel_error("poll idle state", source))?;
        let idle = QemuNodeIdleState {
            current_icount: Icount {
                retired: snapshot.current_icount,
            },
            next_deadline: (snapshot.status == STATUS_IDLE).then_some(Icount {
                retired: snapshot.idle_wake_icount,
            }),
        };
        match classify_quantum_boundary(&idle, ceiling) {
            QuantumBoundary::Reached { icount } => {
                return Ok(QuantumStop::ReachedCeiling { icount });
            }
            QuantumBoundary::Paused { at, deadline }
                if at != deadline || snapshot.publish_gen != initial_publish_generation =>
            {
                return Ok(QuantumStop::Paused { at, deadline });
            }
            QuantumBoundary::Paused { .. } => {}
            QuantumBoundary::Pending => {}
        }
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| LivePluginQuantumGateError::ChildWait { source })?
        {
            return Err(LivePluginQuantumGateError::ChildExitBeforeBoundary {
                ceiling_icount: ceiling,
                status: status.to_string(),
            });
        }
        if started.elapsed() >= config.completion_timeout() {
            return Err(LivePluginQuantumGateError::QuantumTimeout {
                ceiling_icount: ceiling,
                last_snapshot: hot_path
                    .node_snapshot()
                    .map_err(|source| channel_error("snapshot timed-out quantum", source))?,
                last_deadline_icount: idle.next_deadline.map(|deadline| deadline.retired),
                timeout: config.completion_timeout(),
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

// crucible-lint: allow clippy-disallowed-method -- host timeout bounds digest-worker liveness only.
#[allow(clippy::disallowed_methods)]
pub(super) fn wait_for_fingerprint_sample(
    hot_path: &QemuMappedQuantumShmemHotPath,
    child: &mut crate::QemuNodeChild,
    expected_icount: u64,
    config: &LivePluginQuantumGateConfig,
) -> Result<FingerprintSample, LivePluginQuantumGateError> {
    // crucible-lint: allow host-monotonic-time -- supervised liveness bound never enters guest or canonical state.
    let started = Instant::now();
    loop {
        if let Some(sample) = hot_path
            .fingerprint_sample()
            .map_err(|source| LivePluginQuantumGateError::MappedHotPath { source })?
        {
            if sample.sample_icount == expected_icount {
                return Ok(sample);
            }
            if sample.sample_icount > expected_icount {
                return Err(LivePluginQuantumGateError::FingerprintSampleAdvanced {
                    expected_icount,
                    sample_icount: sample.sample_icount,
                });
            }
        }
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| LivePluginQuantumGateError::ChildWait { source })?
        {
            return Err(LivePluginQuantumGateError::ChildExitBeforeBoundary {
                ceiling_icount: expected_icount,
                status: status.to_string(),
            });
        }
        if started.elapsed() >= config.completion_timeout() {
            return Err(LivePluginQuantumGateError::FingerprintSampleTimeout {
                expected_icount,
                timeout: config.completion_timeout(),
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Requests and waits for an exact BQL-held terminal fingerprint boundary.
///
/// # Errors
///
/// Returns [`LivePluginQuantumGateError`] when the request cannot be published,
/// QEMU exits, the acknowledgement does not arrive within the gate timeout, or
/// the digest worker does not publish the exact terminal sample.
pub(super) fn publish_terminal_fingerprint(
    runtime: &mut dyn QemuHostIoRuntime,
    hot_path: &QemuMappedQuantumShmemHotPath,
    child: &mut crate::QemuNodeChild,
    expected_icount: u64,
    config: &LivePluginQuantumGateConfig,
) -> Result<FingerprintSample, LivePluginQuantumGateError> {
    runtime
        .publish_current_execution_fingerprint(config.completion_timeout())
        .map_err(|source| {
            channel_error(
                "publish production terminal fingerprint boundary",
                QemuNodeChannelError::new("execution fingerprint boundary", source.to_string()),
            )
        })?;
    let snapshot = hot_path
        .node_snapshot()
        .map_err(|source| channel_error("read terminal fingerprint boundary", source))?;
    if snapshot.current_icount != expected_icount {
        return Err(channel_error(
            "verify terminal fingerprint boundary",
            QemuNodeChannelError::new(
                "terminal fingerprint boundary",
                format!(
                    "acknowledged at icount {} instead of {expected_icount}",
                    snapshot.current_icount
                ),
            ),
        ));
    }
    wait_for_fingerprint_sample(hot_path, child, expected_icount, config)
}

// crucible-lint: allow clippy-disallowed-method -- quantum-gate host timeout bounds plugin teardown only.
#[allow(clippy::disallowed_methods)]
pub(super) fn wait_for_plugin_teardown(
    hot_path: &QemuMappedQuantumShmemHotPath,
    config: &LivePluginQuantumGateConfig,
) -> Result<(), LivePluginQuantumGateError> {
    let started = Instant::now();
    loop {
        if hot_path
            .plugin_teardown_done()
            .map_err(|source| LivePluginQuantumGateError::MappedHotPath { source })?
        {
            return Ok(());
        }
        if started.elapsed() >= config.completion_timeout() {
            return Err(LivePluginQuantumGateError::PluginQuitTimeout {
                timeout: config.completion_timeout(),
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

// crucible-lint: allow clippy-disallowed-method -- quantum-gate host timeout bounds child reap only.
#[allow(clippy::disallowed_methods)]
pub(super) fn wait_for_natural_child_exit(
    child: &mut crate::QemuNodeChild,
    config: &LivePluginQuantumGateConfig,
) -> Result<std::process::ExitStatus, LivePluginQuantumGateError> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| LivePluginQuantumGateError::ChildWait { source })?
        {
            return Ok(status);
        }
        if started.elapsed() >= config.completion_timeout() {
            return Err(LivePluginQuantumGateError::ChildExitTimeout {
                timeout: config.completion_timeout(),
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Marks the start of a wall-clock advancement-rate measurement window.
///
/// The measured wall time is used only to distinguish idle-jump advancement
/// from per-instruction execution in the emitted diagnostics; it never enters
/// guest state, the execution fingerprint, or the cross-run determinism check.
// crucible-lint: allow clippy-disallowed-method -- diagnostic advancement-rate window only; never enters Crucible state.
#[allow(clippy::disallowed_methods)]
fn wall_clock_start() -> Instant {
    Instant::now()
}

/// Returns the wall-clock microseconds elapsed since [`wall_clock_start`].
// crucible-lint: allow clippy-disallowed-method -- diagnostic advancement-rate window only; never enters Crucible state.
#[allow(clippy::disallowed_methods)]
fn wall_micros_since(started: Instant) -> u128 {
    started.elapsed().as_micros()
}

fn channel_error(
    operation: &'static str,
    source: QemuNodeChannelError,
) -> LivePluginQuantumGateError {
    LivePluginQuantumGateError::channel(operation, source)
}
