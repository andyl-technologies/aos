//! Typed observation of QEMU's registered fork-child runtime.

use serde_json::Value;

use super::{
    QMP_HOT_FORK_CHILD_RUNTIME_SCHEMA_VERSION, QMP_HOT_FORK_PLUGIN_WORKER_ALL,
    QMP_HOT_FORK_PLUGIN_WORKER_REQUIRED, QmpCommandKind, QmpError,
};

/// Process-local phase of the registered fork-child runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmpHotForkChildRuntimePhase {
    /// The template process has not installed a child resource plan.
    Template,
    /// Child reconstruction started but has not completed.
    Initializing,
    /// Private resources and replacement workers are installed behind holds.
    WorkersHeld,
    /// Child admission was released into ordinary execution.
    Active,
    /// Child reconstruction failed closed.
    Failed,
}

/// Exact QEMU-owned state of the registered plugin child-runtime operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkChildRuntimeState {
    generation: u64,
    registered: bool,
    manifest_consistent: bool,
    plugin_id: u64,
    process_generation: u64,
    phase: QmpHotForkChildRuntimePhase,
    callbacks_held: bool,
    mapping_installed: bool,
    workers_ready: bool,
    active: bool,
    failed: bool,
    parent_process_generation: u64,
    child_process_generation: u64,
    template_generation: u64,
    private_ring_generation: u64,
    plugin_endpoint_generation: u64,
    plugin_barrier_generation: u64,
    control_socket_cookie: u64,
    wake_eventfd_id: u64,
    source_mapping_start: u64,
    source_mapping_length: u64,
    source_mapping_offset: u64,
    worker_mask: u64,
    parked_worker_mask: u64,
    pending_worker_mask: u64,
    worker_operations_in_flight: u64,
}

impl QmpHotForkChildRuntimeState {
    /// Returns the process-local registration or status-mutation generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns whether one process-lifetime child-runtime callback is installed.
    #[must_use]
    pub const fn registered(self) -> bool {
        self.registered
    }

    /// Returns whether the callback and complete manifest name one plugin.
    #[must_use]
    pub const fn manifest_consistent(self) -> bool {
        self.manifest_consistent
    }

    /// Returns the registering plugin identity, or zero when unregistered.
    #[must_use]
    pub const fn plugin_id(self) -> u64 {
        self.plugin_id
    }

    /// Returns the exact current plugin process generation.
    #[must_use]
    pub const fn process_generation(self) -> u64 {
        self.process_generation
    }

    /// Returns the current child-runtime phase.
    #[must_use]
    pub const fn phase(self) -> QmpHotForkChildRuntimePhase {
        self.phase
    }

    /// Returns whether inherited callback admission remains held.
    #[must_use]
    pub const fn callbacks_held(self) -> bool {
        self.callbacks_held
    }

    /// Returns whether the branch-private setup mapping is installed.
    #[must_use]
    pub const fn mapping_installed(self) -> bool {
        self.mapping_installed
    }

    /// Returns whether every sealed replacement worker is recreated and held.
    #[must_use]
    pub const fn workers_ready(self) -> bool {
        self.workers_ready
    }

    /// Returns whether child admission was released.
    #[must_use]
    pub const fn active(self) -> bool {
        self.active
    }

    /// Returns whether reconstruction failed closed.
    #[must_use]
    pub const fn failed(self) -> bool {
        self.failed
    }

    /// Returns the exact parent process generation accepted by this child.
    #[must_use]
    pub const fn parent_process_generation(self) -> u64 {
        self.parent_process_generation
    }

    /// Returns the checked immediate child process generation.
    #[must_use]
    pub const fn child_process_generation(self) -> u64 {
        self.child_process_generation
    }

    /// Returns the source template generation, or zero before initialization.
    #[must_use]
    pub const fn template_generation(self) -> u64 {
        self.template_generation
    }

    /// Returns the installed private-ring generation, or zero before initialization.
    #[must_use]
    pub const fn private_ring_generation(self) -> u64 {
        self.private_ring_generation
    }

    /// Returns the installed endpoint-pair generation, or zero before initialization.
    #[must_use]
    pub const fn plugin_endpoint_generation(self) -> u64 {
        self.plugin_endpoint_generation
    }

    /// Returns the inherited plugin-barrier generation, or zero before initialization.
    #[must_use]
    pub const fn plugin_barrier_generation(self) -> u64 {
        self.plugin_barrier_generation
    }

    /// Returns the authenticated replacement control-socket identity.
    #[must_use]
    pub const fn control_socket_cookie(self) -> u64 {
        self.control_socket_cookie
    }

    /// Returns the authenticated replacement wake-eventfd identity.
    #[must_use]
    pub const fn wake_eventfd_id(self) -> u64 {
        self.wake_eventfd_id
    }

    /// Returns the authenticated template setup-region VMA start.
    #[must_use]
    pub const fn source_mapping_start(self) -> u64 {
        self.source_mapping_start
    }

    /// Returns the exact authenticated template setup-region VMA length.
    #[must_use]
    pub const fn source_mapping_length(self) -> u64 {
        self.source_mapping_length
    }

    /// Returns the exact authenticated template setup-region file offset.
    #[must_use]
    pub const fn source_mapping_offset(self) -> u64 {
        self.source_mapping_offset
    }

    /// Returns the complete sealed process-worker mask.
    #[must_use]
    pub const fn worker_mask(self) -> u64 {
        self.worker_mask
    }

    /// Returns worker classes parked at an operation boundary.
    #[must_use]
    pub const fn parked_worker_mask(self) -> u64 {
        self.parked_worker_mask
    }

    /// Returns parked worker classes retaining one pre-admission item.
    #[must_use]
    pub const fn pending_worker_mask(self) -> u64 {
        self.pending_worker_mask
    }

    /// Returns admitted worker operations that have not returned.
    #[must_use]
    pub const fn worker_operations_in_flight(self) -> u64 {
        self.worker_operations_in_flight
    }
}

pub(crate) fn parse_hot_fork_child_runtime_state(
    value: &Value,
) -> Result<QmpHotForkChildRuntimeState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkChildRuntime,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "registered",
        "manifest-consistent",
        "plugin-id",
        "process-generation",
        "phase",
        "callbacks-held",
        "mapping-installed",
        "workers-ready",
        "active",
        "failed",
        "parent-process-generation",
        "child-process-generation",
        "template-generation",
        "private-ring-generation",
        "plugin-endpoint-generation",
        "plugin-barrier-generation",
        "control-socket-cookie",
        "wake-eventfd-id",
        "source-mapping-start",
        "source-mapping-length",
        "source-mapping-offset",
        "worker-mask",
        "parked-worker-mask",
        "pending-worker-mask",
        "worker-operations-in-flight",
        "readiness-proof-acknowledged",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let unsigned = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)
    };
    let boolean = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)
    };
    let schema_version = unsigned("schema-version")?;
    let generation = unsigned("generation")?;
    let registered = boolean("registered")?;
    let manifest_consistent = boolean("manifest-consistent")?;
    let plugin_id = unsigned("plugin-id")?;
    let process_generation = unsigned("process-generation")?;
    let phase = match object.get("phase").and_then(Value::as_str) {
        Some("template") => QmpHotForkChildRuntimePhase::Template,
        Some("initializing") => QmpHotForkChildRuntimePhase::Initializing,
        Some("workers-held") => QmpHotForkChildRuntimePhase::WorkersHeld,
        Some("active") => QmpHotForkChildRuntimePhase::Active,
        Some("failed") => QmpHotForkChildRuntimePhase::Failed,
        _ => return Err(malformed()),
    };
    let callbacks_held = boolean("callbacks-held")?;
    let mapping_installed = boolean("mapping-installed")?;
    let workers_ready = boolean("workers-ready")?;
    let active = boolean("active")?;
    let failed = boolean("failed")?;
    let parent_process_generation = unsigned("parent-process-generation")?;
    let child_process_generation = unsigned("child-process-generation")?;
    let template_generation = unsigned("template-generation")?;
    let private_ring_generation = unsigned("private-ring-generation")?;
    let plugin_endpoint_generation = unsigned("plugin-endpoint-generation")?;
    let plugin_barrier_generation = unsigned("plugin-barrier-generation")?;
    let control_socket_cookie = unsigned("control-socket-cookie")?;
    let wake_eventfd_id = unsigned("wake-eventfd-id")?;
    let source_mapping_start = unsigned("source-mapping-start")?;
    let source_mapping_length = unsigned("source-mapping-length")?;
    let source_mapping_offset = unsigned("source-mapping-offset")?;
    let worker_mask = unsigned("worker-mask")?;
    let parked_worker_mask = unsigned("parked-worker-mask")?;
    let pending_worker_mask = unsigned("pending-worker-mask")?;
    let worker_operations_in_flight = unsigned("worker-operations-in-flight")?;
    let readiness_proof_acknowledged = boolean("readiness-proof-acknowledged")?;

    let worker_shape = worker_mask & !QMP_HOT_FORK_PLUGIN_WORKER_ALL == 0
        && worker_mask & QMP_HOT_FORK_PLUGIN_WORKER_REQUIRED == QMP_HOT_FORK_PLUGIN_WORKER_REQUIRED
        && parked_worker_mask & !worker_mask == 0
        && pending_worker_mask & !parked_worker_mask == 0
        && u64::from(parked_worker_mask.count_ones()) + worker_operations_in_flight
            <= u64::from(worker_mask.count_ones());
    let child_basis_present = parent_process_generation != 0
        && parent_process_generation != u64::MAX
        && child_process_generation == parent_process_generation + 1
        && template_generation != 0
        && private_ring_generation != 0
        && plugin_endpoint_generation != 0
        && plugin_barrier_generation != 0
        && control_socket_cookie != 0
        && wake_eventfd_id != 0
        && source_mapping_start != 0
        && source_mapping_length != 0
        && source_mapping_offset == 0
        && source_mapping_start
            .checked_add(source_mapping_length)
            .is_some();
    let child_basis_absent = parent_process_generation == 0
        && child_process_generation == 0
        && template_generation == 0
        && private_ring_generation == 0
        && plugin_endpoint_generation == 0
        && plugin_barrier_generation == 0
        && control_socket_cookie == 0
        && wake_eventfd_id == 0
        && source_mapping_start == 0
        && source_mapping_length == 0
        && source_mapping_offset == 0;
    let phase_shape = match phase {
        QmpHotForkChildRuntimePhase::Template => {
            child_basis_absent
                && !callbacks_held
                && !mapping_installed
                && !workers_ready
                && !active
                && !failed
        }
        QmpHotForkChildRuntimePhase::Initializing => !active && !failed && !workers_ready,
        QmpHotForkChildRuntimePhase::WorkersHeld => {
            child_basis_present
                && callbacks_held
                && mapping_installed
                && workers_ready
                && !active
                && !failed
        }
        QmpHotForkChildRuntimePhase::Active => {
            child_basis_present
                && !callbacks_held
                && mapping_installed
                && !workers_ready
                && active
                && !failed
        }
        QmpHotForkChildRuntimePhase::Failed => child_basis_present && !active && failed,
    };
    let unregistered_shape = generation == 0
        && !manifest_consistent
        && plugin_id == 0
        && process_generation == 0
        && phase == QmpHotForkChildRuntimePhase::Template
        && worker_mask == 0
        && parked_worker_mask == 0
        && pending_worker_mask == 0
        && worker_operations_in_flight == 0
        && phase_shape;
    if schema_version != u64::from(QMP_HOT_FORK_CHILD_RUNTIME_SCHEMA_VERSION)
        || readiness_proof_acknowledged
        || active != (phase == QmpHotForkChildRuntimePhase::Active)
        || failed != (phase == QmpHotForkChildRuntimePhase::Failed)
        || (registered
            && (generation == 0
                || !manifest_consistent
                || plugin_id == 0
                || process_generation == 0
                || !worker_shape
                || !phase_shape))
        || (!registered && !unregistered_shape)
    {
        return Err(malformed());
    }

    Ok(QmpHotForkChildRuntimeState {
        generation,
        registered,
        manifest_consistent,
        plugin_id,
        process_generation,
        phase,
        callbacks_held,
        mapping_installed,
        workers_ready,
        active,
        failed,
        parent_process_generation,
        child_process_generation,
        template_generation,
        private_ring_generation,
        plugin_endpoint_generation,
        plugin_barrier_generation,
        control_socket_cookie,
        wake_eventfd_id,
        source_mapping_start,
        source_mapping_length,
        source_mapping_offset,
        worker_mask,
        parked_worker_mask,
        pending_worker_mask,
        worker_operations_in_flight,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn template_state() -> Value {
        json!({
            "schema-version": 3,
            "generation": 2,
            "registered": true,
            "manifest-consistent": true,
            "plugin-id": 7,
            "process-generation": 11,
            "phase": "template",
            "callbacks-held": false,
            "mapping-installed": false,
            "workers-ready": false,
            "active": false,
            "failed": false,
            "parent-process-generation": 0,
            "child-process-generation": 0,
            "template-generation": 0,
            "private-ring-generation": 0,
            "plugin-endpoint-generation": 0,
            "plugin-barrier-generation": 0,
            "control-socket-cookie": 0,
            "wake-eventfd-id": 0,
            "source-mapping-start": 0,
            "source-mapping-length": 0,
            "source-mapping-offset": 0,
            "worker-mask": 3,
            "parked-worker-mask": 0,
            "pending-worker-mask": 0,
            "worker-operations-in-flight": 0,
            "readiness-proof-acknowledged": false
        })
    }

    #[test]
    fn child_runtime_parser_binds_registration_and_process_generation() {
        let exact = match parse_hot_fork_child_runtime_state(&template_state()) {
            Ok(state) => state,
            Err(error) => panic!("exact template runtime should decode: {error}"),
        };
        assert!(exact.registered());
        assert!(exact.manifest_consistent());
        assert_eq!(exact.process_generation(), 11);
        assert_eq!(exact.phase(), QmpHotForkChildRuntimePhase::Template);

        let mut workers_held = template_state();
        workers_held["phase"] = json!("workers-held");
        workers_held["callbacks-held"] = json!(true);
        workers_held["mapping-installed"] = json!(true);
        workers_held["workers-ready"] = json!(true);
        workers_held["parent-process-generation"] = json!(11);
        workers_held["child-process-generation"] = json!(12);
        workers_held["template-generation"] = json!(1);
        workers_held["private-ring-generation"] = json!(2);
        workers_held["plugin-endpoint-generation"] = json!(3);
        workers_held["plugin-barrier-generation"] = json!(4);
        workers_held["control-socket-cookie"] = json!(5);
        workers_held["wake-eventfd-id"] = json!(6);
        workers_held["source-mapping-start"] = json!(4096);
        workers_held["source-mapping-length"] = json!(8192);
        workers_held["source-mapping-offset"] = json!(0);
        workers_held["parked-worker-mask"] = json!(3);
        let installed = match parse_hot_fork_child_runtime_state(&workers_held) {
            Ok(state) => state,
            Err(error) => panic!("exact installed mapping basis should decode: {error}"),
        };
        assert_eq!(installed.source_mapping_start(), 4096);
        assert_eq!(installed.source_mapping_length(), 8192);
        assert_eq!(installed.source_mapping_offset(), 0);

        let mut skipped = workers_held.clone();
        skipped["child-process-generation"] = json!(13);
        assert!(parse_hot_fork_child_runtime_state(&skipped).is_err());

        let mut unbound_mapping = workers_held.clone();
        unbound_mapping["source-mapping-start"] = json!(0);
        assert!(parse_hot_fork_child_runtime_state(&unbound_mapping).is_err());

        let mut nonzero_offset = workers_held;
        nonzero_offset["source-mapping-offset"] = json!(4096);
        assert!(parse_hot_fork_child_runtime_state(&nonzero_offset).is_err());

        let mut promoted = template_state();
        promoted["readiness-proof-acknowledged"] = json!(true);
        assert!(parse_hot_fork_child_runtime_state(&promoted).is_err());
    }
}
