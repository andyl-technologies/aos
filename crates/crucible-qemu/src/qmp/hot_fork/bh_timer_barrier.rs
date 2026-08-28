//! Retained QEMU-owned bottom-half and timer-source barrier.

use serde_json::Value;

use super::{QMP_HOT_FORK_BOTTOM_HALF_INVENTORY_MAX, QMP_HOT_FORK_TIMER_INVENTORY_MAX};
use crate::qmp::{QmpCommandKind, QmpError};

/// QMP command name used for the reversible bottom-half/timer barrier.
pub const QMP_HOT_FORK_BH_TIMER_BARRIER_COMMAND: &str = "crucible-hot-fork-bh-timer-barrier";
/// Version of the QEMU-owned bottom-half/timer barrier contract.
pub const QMP_HOT_FORK_BH_TIMER_BARRIER_SCHEMA_VERSION: u32 = 1;

/// Exact state of QEMU's retained bottom-half and timer-source barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkBhTimerBarrierState {
    generation: u64,
    owner_thread_id: i64,
    held: bool,
    complete: bool,
    bottom_halves_complete: bool,
    timers_complete: bool,
    admissions_in_flight: u64,
    bottom_half_count: u64,
    pending_bottom_halves: u64,
    scheduled_bottom_halves: u64,
    active_bottom_half_callbacks: u64,
    pending_timers: u64,
    active_timer_callbacks: u64,
    quiescent: bool,
}

impl QmpHotForkBhTimerBarrierState {
    /// Returns the process-local hold/release generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the coordinator thread that acquired the retained barrier.
    #[must_use]
    pub const fn owner_thread_id(self) -> i64 {
        self.owner_thread_id
    }

    /// Returns whether source producers and callback dispatch are parked.
    #[must_use]
    pub const fn held(self) -> bool {
        self.held
    }

    /// Returns whether both bounded source inventories were complete.
    #[must_use]
    pub const fn complete(self) -> bool {
        self.complete
    }

    /// Returns whether the bottom-half inventory was stable and complete.
    #[must_use]
    pub const fn bottom_halves_complete(self) -> bool {
        self.bottom_halves_complete
    }

    /// Returns whether the live-timer inventory was complete.
    #[must_use]
    pub const fn timers_complete(self) -> bool {
        self.timers_complete
    }

    /// Returns outer source operations admitted before the hold.
    #[must_use]
    pub const fn admissions_in_flight(self) -> u64 {
        self.admissions_in_flight
    }

    /// Returns the exact allocated bottom-half count.
    #[must_use]
    pub const fn bottom_half_count(self) -> u64 {
        self.bottom_half_count
    }

    /// Returns queued bottom halves retained as parked work.
    #[must_use]
    pub const fn pending_bottom_halves(self) -> u64 {
        self.pending_bottom_halves
    }

    /// Returns queued bottom halves whose callback remains scheduled.
    #[must_use]
    pub const fn scheduled_bottom_halves(self) -> u64 {
        self.scheduled_bottom_halves
    }

    /// Returns currently executing bottom-half callbacks.
    #[must_use]
    pub const fn active_bottom_half_callbacks(self) -> u64 {
        self.active_bottom_half_callbacks
    }

    /// Returns armed timers retained as parked work.
    #[must_use]
    pub const fn pending_timers(self) -> u64 {
        self.pending_timers
    }

    /// Returns currently executing timer callbacks.
    #[must_use]
    pub const fn active_timer_callbacks(self) -> u64 {
        self.active_timer_callbacks
    }

    /// Returns whether all admitted work drained under a complete held barrier.
    #[must_use]
    pub const fn quiescent(self) -> bool {
        self.quiescent
    }
}

pub(crate) fn parse_hot_fork_bh_timer_barrier_state(
    value: &Value,
) -> Result<QmpHotForkBhTimerBarrierState, QmpError> {
    parse_hot_fork_bh_timer_barrier_state_for(QmpCommandKind::HotForkBhTimerBarrier, value)
}

pub(super) fn parse_hot_fork_bh_timer_barrier_state_for(
    command: QmpCommandKind,
    value: &Value,
) -> Result<QmpHotForkBhTimerBarrierState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "owner-thread-id",
        "held",
        "complete",
        "bottom-halves-complete",
        "timers-complete",
        "admissions-in-flight",
        "bottom-half-count",
        "pending-bottom-halves",
        "scheduled-bottom-halves",
        "active-bottom-half-callbacks",
        "pending-timers",
        "active-timer-callbacks",
        "quiescent",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let schema_version = object
        .get("schema-version")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let owner_thread_id = object
        .get("owner-thread-id")
        .and_then(Value::as_i64)
        .ok_or_else(&malformed)?;
    let held = object
        .get("held")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let bottom_halves_complete = object
        .get("bottom-halves-complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let timers_complete = object
        .get("timers-complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let admissions_in_flight = object
        .get("admissions-in-flight")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let bottom_half_count = object
        .get("bottom-half-count")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let pending_bottom_halves = object
        .get("pending-bottom-halves")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let scheduled_bottom_halves = object
        .get("scheduled-bottom-halves")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let active_bottom_half_callbacks = object
        .get("active-bottom-half-callbacks")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let pending_timers = object
        .get("pending-timers")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let active_timer_callbacks = object
        .get("active-timer-callbacks")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let quiescent = object
        .get("quiescent")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;

    let expected_complete = bottom_halves_complete && timers_complete;
    let expected_quiescent = held
        && complete
        && admissions_in_flight == 0
        && active_bottom_half_callbacks == 0
        && active_timer_callbacks == 0;
    let valid = schema_version == u64::from(QMP_HOT_FORK_BH_TIMER_BARRIER_SCHEMA_VERSION)
        && complete == expected_complete
        && bottom_half_count <= QMP_HOT_FORK_BOTTOM_HALF_INVENTORY_MAX as u64
        && pending_bottom_halves <= bottom_half_count
        && scheduled_bottom_halves <= pending_bottom_halves
        && active_bottom_half_callbacks <= bottom_half_count
        && pending_timers <= QMP_HOT_FORK_TIMER_INVENTORY_MAX as u64
        && active_timer_callbacks <= QMP_HOT_FORK_TIMER_INVENTORY_MAX as u64
        && quiescent == expected_quiescent
        && if held {
            generation != 0 && owner_thread_id > 0
        } else {
            owner_thread_id == 0 && !quiescent
        };
    if !valid {
        return Err(malformed());
    }

    Ok(QmpHotForkBhTimerBarrierState {
        generation,
        owner_thread_id,
        held,
        complete,
        bottom_halves_complete,
        timers_complete,
        admissions_in_flight,
        bottom_half_count,
        pending_bottom_halves,
        scheduled_bottom_halves,
        active_bottom_half_callbacks,
        pending_timers,
        active_timer_callbacks,
        quiescent,
    })
}
