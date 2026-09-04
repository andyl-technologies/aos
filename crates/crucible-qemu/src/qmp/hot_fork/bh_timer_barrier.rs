//! Retained QEMU-owned asynchronous-source barrier.

use serde_json::Value;

use super::{
    QMP_HOT_FORK_AIO_HANDLER_INVENTORY_MAX, QMP_HOT_FORK_AIO_INVENTORY_MAX,
    QMP_HOT_FORK_BOTTOM_HALF_INVENTORY_MAX, QMP_HOT_FORK_TIMER_INVENTORY_MAX,
};
use crate::qmp::{QmpCommandKind, QmpError};

/// QMP command name used for the reversible asynchronous-source barrier.
///
/// The legacy command name is retained for wire compatibility after schema 2
/// expands the barrier across AioContexts, AioHandlers, and coroutines.
pub const QMP_HOT_FORK_BH_TIMER_BARRIER_COMMAND: &str = "crucible-hot-fork-bh-timer-barrier";
/// Version of the QEMU-owned asynchronous-source barrier contract.
pub const QMP_HOT_FORK_BH_TIMER_BARRIER_SCHEMA_VERSION: u32 = 2;

/// Exact state of QEMU's retained asynchronous-source barrier.
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
    aio_context_count: u64,
    active_aio_polls: u64,
    active_aio_dispatches: u64,
    queued_coroutines: u64,
    aio_handler_count: u64,
    active_aio_handler_callbacks: u64,
    aio_contexts_complete: bool,
    aio_handlers_complete: bool,
    quiescent: bool,
}

impl QmpHotForkBhTimerBarrierState {
    #[cfg(test)]
    pub(crate) const fn one_quiescent(generation: u64) -> Self {
        Self {
            generation,
            owner_thread_id: 1,
            held: true,
            complete: true,
            bottom_halves_complete: true,
            timers_complete: true,
            admissions_in_flight: 0,
            bottom_half_count: 0,
            pending_bottom_halves: 0,
            scheduled_bottom_halves: 0,
            active_bottom_half_callbacks: 0,
            pending_timers: 0,
            active_timer_callbacks: 0,
            aio_context_count: 0,
            active_aio_polls: 0,
            active_aio_dispatches: 0,
            queued_coroutines: 0,
            aio_handler_count: 0,
            active_aio_handler_callbacks: 0,
            aio_contexts_complete: true,
            aio_handlers_complete: true,
            quiescent: true,
        }
    }

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

    /// Returns whether every bounded asynchronous-source inventory was complete.
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

    /// Returns the exact registered AioContext count.
    #[must_use]
    pub const fn aio_context_count(self) -> u64 {
        self.aio_context_count
    }

    /// Returns active `aio_poll()` calls admitted before the hold.
    #[must_use]
    pub const fn active_aio_polls(self) -> u64 {
        self.active_aio_polls
    }

    /// Returns active GLib AioContext dispatch calls admitted before the hold.
    #[must_use]
    pub const fn active_aio_dispatches(self) -> u64 {
        self.active_aio_dispatches
    }

    /// Returns coroutines queued as retained parked work.
    #[must_use]
    pub const fn queued_coroutines(self) -> u64 {
        self.queued_coroutines
    }

    /// Returns the exact allocated POSIX AioHandler count.
    #[must_use]
    pub const fn aio_handler_count(self) -> u64 {
        self.aio_handler_count
    }

    /// Returns active AioHandler callbacks admitted before the hold.
    #[must_use]
    pub const fn active_aio_handler_callbacks(self) -> u64 {
        self.active_aio_handler_callbacks
    }

    /// Returns whether the bounded AioContext inventory was complete.
    #[must_use]
    pub const fn aio_contexts_complete(self) -> bool {
        self.aio_contexts_complete
    }

    /// Returns whether the bounded AioHandler inventory was complete.
    #[must_use]
    pub const fn aio_handlers_complete(self) -> bool {
        self.aio_handlers_complete
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
        "aio-context-count",
        "active-aio-polls",
        "active-aio-dispatches",
        "queued-coroutines",
        "aio-handler-count",
        "active-aio-handler-callbacks",
        "aio-contexts-complete",
        "aio-handlers-complete",
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
    let aio_context_count = object
        .get("aio-context-count")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let active_aio_polls = object
        .get("active-aio-polls")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let active_aio_dispatches = object
        .get("active-aio-dispatches")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let queued_coroutines = object
        .get("queued-coroutines")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let aio_handler_count = object
        .get("aio-handler-count")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let active_aio_handler_callbacks = object
        .get("active-aio-handler-callbacks")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let aio_contexts_complete = object
        .get("aio-contexts-complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let aio_handlers_complete = object
        .get("aio-handlers-complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let quiescent = object
        .get("quiescent")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;

    let expected_complete =
        aio_contexts_complete && bottom_halves_complete && aio_handlers_complete && timers_complete;
    let expected_quiescent = held
        && complete
        && admissions_in_flight == 0
        && active_aio_polls == 0
        && active_aio_dispatches == 0
        && active_bottom_half_callbacks == 0
        && active_aio_handler_callbacks == 0
        && active_timer_callbacks == 0;
    let valid = schema_version == u64::from(QMP_HOT_FORK_BH_TIMER_BARRIER_SCHEMA_VERSION)
        && complete == expected_complete
        && bottom_half_count <= QMP_HOT_FORK_BOTTOM_HALF_INVENTORY_MAX as u64
        && pending_bottom_halves <= bottom_half_count
        && scheduled_bottom_halves <= pending_bottom_halves
        && active_bottom_half_callbacks <= bottom_half_count
        && pending_timers <= QMP_HOT_FORK_TIMER_INVENTORY_MAX as u64
        && active_timer_callbacks <= QMP_HOT_FORK_TIMER_INVENTORY_MAX as u64
        && aio_context_count <= QMP_HOT_FORK_AIO_INVENTORY_MAX as u64
        && active_aio_polls <= aio_context_count
        && active_aio_dispatches <= aio_context_count
        && queued_coroutines <= aio_context_count * u64::from(u32::MAX)
        && aio_handler_count <= QMP_HOT_FORK_AIO_HANDLER_INVENTORY_MAX as u64
        && active_aio_handler_callbacks <= aio_handler_count * u64::from(u32::MAX)
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
        aio_context_count,
        active_aio_polls,
        active_aio_dispatches,
        queued_coroutines,
        aio_handler_count,
        active_aio_handler_callbacks,
        aio_contexts_complete,
        aio_handlers_complete,
        quiescent,
    })
}
