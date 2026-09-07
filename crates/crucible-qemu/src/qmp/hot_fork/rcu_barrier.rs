//! Retained QEMU-owned RCU admission and drain barrier.

use serde_json::Value;

use super::QMP_HOT_FORK_RCU_INVENTORY_MAX;
use crate::qmp::{QmpCommandKind, QmpError};

/// QMP command name used for QEMU's reversible RCU barrier.
pub const QMP_HOT_FORK_RCU_BARRIER_COMMAND: &str = "crucible-hot-fork-rcu-barrier";
/// Version of the QEMU-owned RCU barrier contract.
pub const QMP_HOT_FORK_RCU_BARRIER_SCHEMA_VERSION: u32 = 1;

/// Exact state of QEMU's retained RCU admission and drain barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkRcuBarrierState {
    generation: u64,
    owner_thread_id: i64,
    held: bool,
    complete: bool,
    registered_readers: u64,
    active_readers: u64,
    admissions_in_flight: u64,
    pending_callbacks: u64,
    drain_active: bool,
    quiescent: bool,
}

impl QmpHotForkRcuBarrierState {
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) const fn one_quiescent(generation: u64) -> Self {
        Self {
            generation,
            owner_thread_id: 1,
            held: true,
            complete: true,
            registered_readers: 1,
            active_readers: 0,
            admissions_in_flight: 0,
            pending_callbacks: 0,
            drain_active: false,
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

    /// Returns whether new RCU admissions are currently parked.
    #[must_use]
    pub const fn held(self) -> bool {
        self.held
    }

    /// Returns whether QEMU observed the complete bounded reader registry.
    #[must_use]
    pub const fn complete(self) -> bool {
        self.complete
    }

    /// Returns the exact retained registered-reader count.
    #[must_use]
    pub const fn registered_readers(self) -> u64 {
        self.registered_readers
    }

    /// Returns readers still inside an outer read-side critical section.
    #[must_use]
    pub const fn active_readers(self) -> u64 {
        self.active_readers
    }

    /// Returns entries between admission and publication into RCU state.
    #[must_use]
    pub const fn admissions_in_flight(self) -> u64 {
        self.admissions_in_flight
    }

    /// Returns callbacks submitted but not yet completed.
    #[must_use]
    pub const fn pending_callbacks(self) -> u64 {
        self.pending_callbacks
    }

    /// Returns whether a synchronous callback drain is active.
    #[must_use]
    pub const fn drain_active(self) -> bool {
        self.drain_active
    }

    /// Returns whether the complete held barrier has fully drained.
    #[must_use]
    pub const fn quiescent(self) -> bool {
        self.quiescent
    }
}

pub(crate) fn parse_hot_fork_rcu_barrier_state(
    value: &Value,
) -> Result<QmpHotForkRcuBarrierState, QmpError> {
    parse_hot_fork_rcu_barrier_state_for(QmpCommandKind::HotForkRcuBarrier, value)
}

pub(super) fn parse_hot_fork_rcu_barrier_state_for(
    command: QmpCommandKind,
    value: &Value,
) -> Result<QmpHotForkRcuBarrierState, QmpError> {
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
        "registered-readers",
        "active-readers",
        "admissions-in-flight",
        "pending-callbacks",
        "drain-active",
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
    let registered_readers = object
        .get("registered-readers")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let active_readers = object
        .get("active-readers")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let admissions_in_flight = object
        .get("admissions-in-flight")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let pending_callbacks = object
        .get("pending-callbacks")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let drain_active = object
        .get("drain-active")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let quiescent = object
        .get("quiescent")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;

    let expected_quiescent = held
        && complete
        && active_readers == 0
        && admissions_in_flight == 0
        && pending_callbacks == 0
        && !drain_active;
    let valid = schema_version == u64::from(QMP_HOT_FORK_RCU_BARRIER_SCHEMA_VERSION)
        && registered_readers <= QMP_HOT_FORK_RCU_INVENTORY_MAX as u64
        && active_readers <= registered_readers
        && quiescent == expected_quiescent
        && if held {
            generation != 0 && owner_thread_id > 0
        } else {
            owner_thread_id == 0 && !quiescent
        };
    if !valid {
        return Err(malformed());
    }

    Ok(QmpHotForkRcuBarrierState {
        generation,
        owner_thread_id,
        held,
        complete,
        registered_readers,
        active_readers,
        admissions_in_flight,
        pending_callbacks,
        drain_active,
        quiescent,
    })
}
