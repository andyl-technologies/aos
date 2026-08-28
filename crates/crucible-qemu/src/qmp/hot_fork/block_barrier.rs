//! Retained QEMU-owned block-graph writer and all-block drain barrier.

use serde_json::Value;

use super::QMP_HOT_FORK_BLOCK_BACKEND_INVENTORY_MAX;
use crate::qmp::{QmpCommandKind, QmpError};

/// QMP command name used for QEMU's reversible graph and block-drain barrier.
pub const QMP_HOT_FORK_BLOCK_BARRIER_COMMAND: &str = "crucible-hot-fork-block-barrier";
/// Version of the QEMU-owned graph-writer and block-drain barrier contract.
pub const QMP_HOT_FORK_BLOCK_BARRIER_SCHEMA_VERSION: u32 = 2;

/// Exact state of QEMU's retained graph-writer and all-block drain barriers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkBlockBarrierState {
    generation: u64,
    owner_thread_id: i64,
    graph_barrier_generation: u64,
    graph_mutation_generation: u64,
    held_graph_mutation_generation: u64,
    graph_owner_thread_id: i64,
    held: bool,
    graph_held: bool,
    graph_writer_active: bool,
    graph_waiting_writers: u32,
    graph_stable: bool,
    complete: bool,
    backend_count: u64,
    rooted_backends: u64,
    writable_backends: u64,
    quiesced_rooted_backends: u64,
    in_flight: u64,
    quiescent: bool,
}

impl QmpHotForkBlockBarrierState {
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

    /// Returns the process-local graph-barrier state generation.
    #[must_use]
    pub const fn graph_barrier_generation(self) -> u64 {
        self.graph_barrier_generation
    }

    /// Returns the generation of the latest completed block-graph mutation.
    #[must_use]
    pub const fn graph_mutation_generation(self) -> u64 {
        self.graph_mutation_generation
    }

    /// Returns the graph-mutation generation captured by the retained hold.
    #[must_use]
    pub const fn held_graph_mutation_generation(self) -> u64 {
        self.held_graph_mutation_generation
    }

    /// Returns the coordinator thread retaining block-graph writer exclusion.
    #[must_use]
    pub const fn graph_owner_thread_id(self) -> i64 {
        self.graph_owner_thread_id
    }

    /// Returns whether the native all-block drain section remains retained.
    #[must_use]
    pub const fn held(self) -> bool {
        self.held
    }

    /// Returns whether block-graph writer admission remains closed.
    #[must_use]
    pub const fn graph_held(self) -> bool {
        self.graph_held
    }

    /// Returns whether a graph writer is inside its critical section.
    #[must_use]
    pub const fn graph_writer_active(self) -> bool {
        self.graph_writer_active
    }

    /// Returns writers admitted but not yet inside their critical section.
    #[must_use]
    pub const fn graph_waiting_writers(self) -> u32 {
        self.graph_waiting_writers
    }

    /// Returns whether the retained graph generation remains unchanged.
    #[must_use]
    pub const fn graph_stable(self) -> bool {
        self.graph_stable
    }

    /// Returns whether QEMU observed the complete bounded backend registry.
    #[must_use]
    pub const fn complete(self) -> bool {
        self.complete
    }

    /// Returns the exact allocated BlockBackend count.
    #[must_use]
    pub const fn backend_count(self) -> u64 {
        self.backend_count
    }

    /// Returns the exact count of backends with a block root.
    #[must_use]
    pub const fn rooted_backends(self) -> u64 {
        self.rooted_backends
    }

    /// Returns the exact count of backends requesting write permission.
    #[must_use]
    pub const fn writable_backends(self) -> u64 {
        self.writable_backends
    }

    /// Returns rooted backends retained inside a native drain section.
    #[must_use]
    pub const fn quiesced_rooted_backends(self) -> u64 {
        self.quiesced_rooted_backends
    }

    /// Returns the checked aggregate BlockBackend in-flight I/O count.
    #[must_use]
    pub const fn in_flight(self) -> u64 {
        self.in_flight
    }

    /// Returns whether every rooted backend is quiesced with no in-flight I/O.
    #[must_use]
    pub const fn quiescent(self) -> bool {
        self.quiescent
    }
}

pub(crate) fn parse_hot_fork_block_barrier_state(
    value: &Value,
) -> Result<QmpHotForkBlockBarrierState, QmpError> {
    parse_hot_fork_block_barrier_state_for(QmpCommandKind::HotForkBlockBarrier, value)
}

pub(crate) fn parse_hot_fork_block_barrier_state_for(
    command: QmpCommandKind,
    value: &Value,
) -> Result<QmpHotForkBlockBarrierState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "owner-thread-id",
        "graph-barrier-generation",
        "graph-mutation-generation",
        "held-graph-mutation-generation",
        "graph-owner-thread-id",
        "held",
        "graph-held",
        "graph-writer-active",
        "graph-waiting-writers",
        "graph-stable",
        "complete",
        "backend-count",
        "rooted-backends",
        "writable-backends",
        "quiesced-rooted-backends",
        "in-flight",
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
    let graph_barrier_generation = object
        .get("graph-barrier-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let graph_mutation_generation = object
        .get("graph-mutation-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let held_graph_mutation_generation = object
        .get("held-graph-mutation-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let graph_owner_thread_id = object
        .get("graph-owner-thread-id")
        .and_then(Value::as_i64)
        .ok_or_else(&malformed)?;
    let held = object
        .get("held")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let graph_held = object
        .get("graph-held")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let graph_writer_active = object
        .get("graph-writer-active")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let graph_waiting_writers = object
        .get("graph-waiting-writers")
        .and_then(Value::as_u64)
        .and_then(|count| u32::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let graph_stable = object
        .get("graph-stable")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let backend_count = object
        .get("backend-count")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let rooted_backends = object
        .get("rooted-backends")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let writable_backends = object
        .get("writable-backends")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let quiesced_rooted_backends = object
        .get("quiesced-rooted-backends")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let in_flight = object
        .get("in-flight")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let quiescent = object
        .get("quiescent")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;

    let expected_graph_stable = graph_held
        && !graph_writer_active
        && graph_mutation_generation == held_graph_mutation_generation;
    let expected_quiescent = held
        && graph_stable
        && complete
        && in_flight == 0
        && quiesced_rooted_backends == rooted_backends;
    let valid = schema_version == u64::from(QMP_HOT_FORK_BLOCK_BARRIER_SCHEMA_VERSION)
        && backend_count <= QMP_HOT_FORK_BLOCK_BACKEND_INVENTORY_MAX as u64
        && rooted_backends <= backend_count
        && writable_backends <= backend_count
        && quiesced_rooted_backends <= rooted_backends
        && graph_stable == expected_graph_stable
        && quiescent == expected_quiescent
        && if held {
            generation != 0
                && owner_thread_id > 0
                && graph_barrier_generation != 0
                && graph_held
                && graph_owner_thread_id == owner_thread_id
                && graph_stable
        } else {
            owner_thread_id == 0
                && !graph_held
                && graph_owner_thread_id == 0
                && held_graph_mutation_generation == 0
                && !graph_stable
                && !quiescent
        };
    if !valid {
        return Err(malformed());
    }

    Ok(QmpHotForkBlockBarrierState {
        generation,
        owner_thread_id,
        graph_barrier_generation,
        graph_mutation_generation,
        held_graph_mutation_generation,
        graph_owner_thread_id,
        held,
        graph_held,
        graph_writer_active,
        graph_waiting_writers,
        graph_stable,
        complete,
        backend_count,
        rooted_backends,
        writable_backends,
        quiesced_rooted_backends,
        in_flight,
        quiescent,
    })
}
