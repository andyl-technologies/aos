//! Typed plugin-resource and callback-barrier hot-fork QMP responses.

use serde_json::Value;

use super::{
    QMP_HOT_FORK_PLUGIN_BARRIER_SCHEMA_VERSION, QMP_HOT_FORK_PLUGIN_CALLBACK_ALL,
    QMP_HOT_FORK_PLUGIN_CALLBACK_FLUSH, QMP_HOT_FORK_PLUGIN_CALLBACK_REQUIRED,
    QMP_HOT_FORK_PLUGIN_CALLBACK_TB_TRANSLATION, QMP_HOT_FORK_PLUGIN_RESOURCE_ALL,
    QMP_HOT_FORK_PLUGIN_RESOURCE_APP_RANDOM, QMP_HOT_FORK_PLUGIN_RESOURCE_COVERAGE,
    QMP_HOT_FORK_PLUGIN_RESOURCE_FINGERPRINT,
    QMP_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_SCHEMA_VERSION, QMP_HOT_FORK_PLUGIN_RESOURCE_REQUIRED,
    QMP_HOT_FORK_PLUGIN_RESOURCE_STATE_DUMP, QMP_HOT_FORK_PLUGIN_RESOURCE_WHITEBOX,
    QMP_HOT_FORK_PLUGIN_WORKER_ALL, QMP_HOT_FORK_PLUGIN_WORKER_FINGERPRINT,
    QMP_HOT_FORK_PLUGIN_WORKER_REQUIRED, QMP_HOT_FORK_PLUGIN_WORKER_RUN_CONTROL,
    QMP_HOT_FORK_PLUGIN_WORKER_TEARDOWN, QmpCommandKind, QmpError,
};

/// Exact scalar inventory of the installed Crucible plugin resources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkPluginResourceInventory {
    generation: u64,
    registered: bool,
    complete: bool,
    process_generation: u64,
    plugin_id: u64,
    resource_mask: u64,
    callback_mask: u64,
    worker_mask: u64,
    observed_callback_mask: u64,
    shmem_device: u64,
    shmem_inode: u64,
    shmem_length: u64,
    slot_index: u32,
    node_count: u32,
    control_fd: i32,
    wake_fd: i32,
    coverage: bool,
    whitebox: bool,
    fingerprint: bool,
    run_control_worker: bool,
    teardown_worker: bool,
    fingerprint_worker: bool,
    state_dump: bool,
    app_random: bool,
}

impl QmpHotForkPluginResourceInventory {
    #[cfg(test)]
    pub(crate) fn one_complete(process_generation: u64) -> Self {
        Self::one_complete_with_bindings(process_generation, 1, 2, 4096, 3, 4)
    }

    #[cfg(test)]
    pub(crate) const fn one_complete_with_bindings(
        process_generation: u64,
        shmem_device: u64,
        shmem_inode: u64,
        shmem_length: u64,
        control_fd: i32,
        wake_fd: i32,
    ) -> Self {
        Self {
            generation: 1,
            registered: true,
            complete: true,
            process_generation,
            plugin_id: 1,
            resource_mask: QMP_HOT_FORK_PLUGIN_RESOURCE_REQUIRED,
            callback_mask: QMP_HOT_FORK_PLUGIN_CALLBACK_REQUIRED,
            worker_mask: QMP_HOT_FORK_PLUGIN_WORKER_REQUIRED,
            observed_callback_mask: QMP_HOT_FORK_PLUGIN_CALLBACK_REQUIRED,
            shmem_device,
            shmem_inode,
            shmem_length,
            slot_index: 0,
            node_count: 1,
            control_fd,
            wake_fd,
            coverage: false,
            whitebox: false,
            fingerprint: false,
            run_control_worker: true,
            teardown_worker: true,
            fingerprint_worker: false,
            state_dump: false,
            app_random: false,
        }
    }

    /// Returns the process-local registration generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether the plugin sealed one manifest.
    #[must_use]
    pub const fn registered(&self) -> bool {
        self.registered
    }

    /// Returns whether QEMU found the sealed manifest internally consistent.
    ///
    /// Completeness remains observational and cannot authorize a fork.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns the exact host-supervised process generation.
    #[must_use]
    pub const fn process_generation(&self) -> u64 {
        self.process_generation
    }

    /// Returns the nonzero QEMU plugin identity.
    #[must_use]
    pub const fn plugin_id(&self) -> u64 {
        self.plugin_id
    }

    /// Returns the closed plugin-owned resource-class mask.
    #[must_use]
    pub const fn resource_mask(&self) -> u64 {
        self.resource_mask
    }

    /// Returns the callback mask sealed by the plugin.
    #[must_use]
    pub const fn callback_mask(&self) -> u64 {
        self.callback_mask
    }

    /// Returns the closed process-lifetime plugin worker-class mask.
    #[must_use]
    pub const fn worker_mask(&self) -> u64 {
        self.worker_mask
    }

    /// Returns the callback mask independently observed by QEMU.
    #[must_use]
    pub const fn observed_callback_mask(&self) -> u64 {
        self.observed_callback_mask
    }

    /// Returns the mapped shared-memory backing device number.
    #[must_use]
    pub const fn shmem_device(&self) -> u64 {
        self.shmem_device
    }

    /// Returns the mapped shared-memory backing inode.
    #[must_use]
    pub const fn shmem_inode(&self) -> u64 {
        self.shmem_inode
    }

    /// Returns the mapped shared-memory byte length.
    #[must_use]
    pub const fn shmem_length(&self) -> u64 {
        self.shmem_length
    }

    /// Returns the assigned VM slot index.
    #[must_use]
    pub const fn slot_index(&self) -> u32 {
        self.slot_index
    }

    /// Returns the shared-memory topology node count.
    #[must_use]
    pub const fn node_count(&self) -> u32 {
        self.node_count
    }

    /// Returns the plugin control-socket descriptor number.
    #[must_use]
    pub const fn control_fd(&self) -> i32 {
        self.control_fd
    }

    /// Returns the QEMU-registered wake descriptor number.
    #[must_use]
    pub const fn wake_fd(&self) -> i32 {
        self.wake_fd
    }

    /// Returns whether coverage resources are installed.
    #[must_use]
    pub const fn coverage(&self) -> bool {
        self.coverage
    }

    /// Returns whether white-box resources are installed.
    #[must_use]
    pub const fn whitebox(&self) -> bool {
        self.whitebox
    }

    /// Returns whether fingerprint resources are installed.
    #[must_use]
    pub const fn fingerprint(&self) -> bool {
        self.fingerprint
    }

    /// Returns whether the mandatory RUN control reader is sealed.
    #[must_use]
    pub const fn run_control_worker(&self) -> bool {
        self.run_control_worker
    }

    /// Returns whether the mandatory teardown worker is sealed.
    #[must_use]
    pub const fn teardown_worker(&self) -> bool {
        self.teardown_worker
    }

    /// Returns whether the optional fingerprint digest worker is sealed.
    #[must_use]
    pub const fn fingerprint_worker(&self) -> bool {
        self.fingerprint_worker
    }

    /// Returns whether raw-state-dump resources are installed.
    #[must_use]
    pub const fn state_dump(&self) -> bool {
        self.state_dump
    }

    /// Returns whether app-random resources are installed.
    #[must_use]
    pub const fn app_random(&self) -> bool {
        self.app_random
    }
}

/// Exact plugin-owned callback and shared-ring producer barrier state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkPluginBarrierState {
    generation: u64,
    registered: bool,
    manifest_consistent: bool,
    held: bool,
    teardown_closed: bool,
    in_flight: u64,
    ring_count: u64,
    rings_held: u64,
    ring_producers_in_flight: u64,
    worker_mask: u64,
    parked_worker_mask: u64,
    worker_operations_in_flight: u64,
    quiescent: bool,
}

impl QmpHotForkPluginBarrierState {
    /// Returns the process-local barrier registration/hold generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns whether the plugin registered a process-lifetime barrier callback.
    #[must_use]
    pub const fn registered(self) -> bool {
        self.registered
    }

    /// Returns whether the barrier and sealed resource manifest name one plugin.
    #[must_use]
    pub const fn manifest_consistent(self) -> bool {
        self.manifest_consistent
    }

    /// Returns whether new covered callbacks are currently rejected.
    #[must_use]
    pub const fn held(self) -> bool {
        self.held
    }

    /// Returns whether permanent teardown closure superseded the barrier.
    #[must_use]
    pub const fn teardown_closed(self) -> bool {
        self.teardown_closed
    }

    /// Returns callbacks admitted before the hold that have not yet returned.
    #[must_use]
    pub const fn in_flight(self) -> u64 {
        self.in_flight
    }

    /// Returns the exact ring count from the validated shared-memory layout.
    #[must_use]
    pub const fn ring_count(self) -> u64 {
        self.ring_count
    }

    /// Returns the number of rings whose producer barrier is held.
    #[must_use]
    pub const fn rings_held(self) -> u64 {
        self.rings_held
    }

    /// Returns producer publications admitted before the ring hold.
    #[must_use]
    pub const fn ring_producers_in_flight(self) -> u64 {
        self.ring_producers_in_flight
    }

    /// Returns the exact sealed process-lifetime worker-class mask.
    #[must_use]
    pub const fn worker_mask(self) -> u64 {
        self.worker_mask
    }

    /// Returns worker classes parked at a process-safe operation boundary.
    #[must_use]
    pub const fn parked_worker_mask(self) -> u64 {
        self.parked_worker_mask
    }

    /// Returns worker operations admitted before the hold and still running.
    #[must_use]
    pub const fn worker_operations_in_flight(self) -> u64 {
        self.worker_operations_in_flight
    }

    /// Returns whether the registered, manifest-consistent hold has drained.
    ///
    /// This proves callback, ring-producer, and sealed-worker parking. Queued
    /// ring/worker cloning and child reconstruction remain outside it.
    #[must_use]
    pub const fn quiescent(self) -> bool {
        self.quiescent
    }
}
pub(crate) fn parse_hot_fork_plugin_resource_inventory(
    value: &Value,
) -> Result<QmpHotForkPluginResourceInventory, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkPluginResourceInventory,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "registered",
        "complete",
        "process-generation",
        "plugin-id",
        "resource-mask",
        "callback-mask",
        "worker-mask",
        "observed-callback-mask",
        "callback-mask-consistent",
        "shmem-device",
        "shmem-inode",
        "shmem-length",
        "slot-index",
        "node-count",
        "control-fd",
        "wake-fd",
        "coverage",
        "whitebox",
        "fingerprint",
        "run-control-worker",
        "teardown-worker",
        "fingerprint-worker",
        "state-dump",
        "app-random",
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
    let registered = object
        .get("registered")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let process_generation = object
        .get("process-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let plugin_id = object
        .get("plugin-id")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let resource_mask = object
        .get("resource-mask")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let callback_mask = object
        .get("callback-mask")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let worker_mask = object
        .get("worker-mask")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let observed_callback_mask = object
        .get("observed-callback-mask")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let callback_mask_consistent = object
        .get("callback-mask-consistent")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let shmem_device = object
        .get("shmem-device")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let shmem_inode = object
        .get("shmem-inode")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let shmem_length = object
        .get("shmem-length")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let slot_index = object
        .get("slot-index")
        .and_then(Value::as_u64)
        .and_then(|index| u32::try_from(index).ok())
        .ok_or_else(&malformed)?;
    let node_count = object
        .get("node-count")
        .and_then(Value::as_u64)
        .and_then(|count| u32::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let control_fd = object
        .get("control-fd")
        .and_then(Value::as_i64)
        .and_then(|fd| i32::try_from(fd).ok())
        .ok_or_else(&malformed)?;
    let wake_fd = object
        .get("wake-fd")
        .and_then(Value::as_i64)
        .and_then(|fd| i32::try_from(fd).ok())
        .ok_or_else(&malformed)?;
    let coverage = object
        .get("coverage")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let whitebox = object
        .get("whitebox")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let fingerprint = object
        .get("fingerprint")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let run_control_worker = object
        .get("run-control-worker")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let teardown_worker = object
        .get("teardown-worker")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let fingerprint_worker = object
        .get("fingerprint-worker")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let state_dump = object
        .get("state-dump")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let app_random = object
        .get("app-random")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;

    let known_masks = resource_mask & !QMP_HOT_FORK_PLUGIN_RESOURCE_ALL == 0
        && callback_mask & !QMP_HOT_FORK_PLUGIN_CALLBACK_ALL == 0
        && observed_callback_mask & !QMP_HOT_FORK_PLUGIN_CALLBACK_ALL == 0
        && worker_mask & !QMP_HOT_FORK_PLUGIN_WORKER_ALL == 0;
    let callback_consistent = callback_mask == observed_callback_mask;
    let derived_modes = coverage == (resource_mask & QMP_HOT_FORK_PLUGIN_RESOURCE_COVERAGE != 0)
        && whitebox == (resource_mask & QMP_HOT_FORK_PLUGIN_RESOURCE_WHITEBOX != 0)
        && fingerprint == (resource_mask & QMP_HOT_FORK_PLUGIN_RESOURCE_FINGERPRINT != 0)
        && state_dump == (resource_mask & QMP_HOT_FORK_PLUGIN_RESOURCE_STATE_DUMP != 0)
        && app_random == (resource_mask & QMP_HOT_FORK_PLUGIN_RESOURCE_APP_RANDOM != 0);
    let optional_callbacks = callback_mask & !QMP_HOT_FORK_PLUGIN_CALLBACK_REQUIRED;
    let optional_consistent = (coverage || whitebox)
        == (optional_callbacks & QMP_HOT_FORK_PLUGIN_CALLBACK_TB_TRANSLATION != 0)
        && coverage == (optional_callbacks & QMP_HOT_FORK_PLUGIN_CALLBACK_FLUSH != 0);
    let derived_workers = run_control_worker
        == (worker_mask & QMP_HOT_FORK_PLUGIN_WORKER_RUN_CONTROL != 0)
        && teardown_worker == (worker_mask & QMP_HOT_FORK_PLUGIN_WORKER_TEARDOWN != 0)
        && fingerprint_worker == (worker_mask & QMP_HOT_FORK_PLUGIN_WORKER_FINGERPRINT != 0)
        && fingerprint == fingerprint_worker;
    let registered_shape = process_generation != 0
        && plugin_id != 0
        && resource_mask & QMP_HOT_FORK_PLUGIN_RESOURCE_REQUIRED
            == QMP_HOT_FORK_PLUGIN_RESOURCE_REQUIRED
        && callback_mask & QMP_HOT_FORK_PLUGIN_CALLBACK_REQUIRED
            == QMP_HOT_FORK_PLUGIN_CALLBACK_REQUIRED
        && worker_mask & QMP_HOT_FORK_PLUGIN_WORKER_REQUIRED == QMP_HOT_FORK_PLUGIN_WORKER_REQUIRED
        && shmem_inode != 0
        && shmem_length != 0
        && node_count != 0
        && slot_index < node_count
        && control_fd >= 0
        && wake_fd >= 0
        && control_fd != wake_fd;
    let unregistered_shape = process_generation == 0
        && plugin_id == 0
        && resource_mask == 0
        && callback_mask == 0
        && worker_mask == 0
        && shmem_device == 0
        && shmem_inode == 0
        && shmem_length == 0
        && slot_index == 0
        && node_count == 0
        && control_fd == 0
        && wake_fd == 0
        && !coverage
        && !whitebox
        && !fingerprint
        && !run_control_worker
        && !teardown_worker
        && !fingerprint_worker
        && !state_dump
        && !app_random;
    let expected_complete = registered
        && registered_shape
        && callback_consistent
        && known_masks
        && derived_modes
        && derived_workers
        && optional_consistent;
    if schema_version != u64::from(QMP_HOT_FORK_PLUGIN_RESOURCE_INVENTORY_SCHEMA_VERSION)
        || callback_mask_consistent != callback_consistent
        || complete != expected_complete
        || !known_masks
        || !derived_modes
        || !derived_workers
        || !optional_consistent
        || (registered && !registered_shape)
        || (!registered && !unregistered_shape)
    {
        return Err(malformed());
    }

    Ok(QmpHotForkPluginResourceInventory {
        generation,
        registered,
        complete,
        process_generation,
        plugin_id,
        resource_mask,
        callback_mask,
        worker_mask,
        observed_callback_mask,
        shmem_device,
        shmem_inode,
        shmem_length,
        slot_index,
        node_count,
        control_fd,
        wake_fd,
        coverage,
        whitebox,
        fingerprint,
        run_control_worker,
        teardown_worker,
        fingerprint_worker,
        state_dump,
        app_random,
    })
}

pub(crate) fn parse_hot_fork_plugin_barrier_state(
    value: &Value,
) -> Result<QmpHotForkPluginBarrierState, QmpError> {
    parse_hot_fork_plugin_barrier_state_for(QmpCommandKind::HotForkPluginBarrier, value)
}

pub(super) fn parse_hot_fork_plugin_barrier_state_for(
    command: QmpCommandKind,
    value: &Value,
) -> Result<QmpHotForkPluginBarrierState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "registered",
        "manifest-consistent",
        "held",
        "teardown-closed",
        "in-flight",
        "ring-count",
        "rings-held",
        "ring-producers-in-flight",
        "worker-mask",
        "parked-worker-mask",
        "worker-operations-in-flight",
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
    let registered = object
        .get("registered")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let manifest_consistent = object
        .get("manifest-consistent")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let held = object
        .get("held")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let teardown_closed = object
        .get("teardown-closed")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let in_flight = object
        .get("in-flight")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let ring_count = object
        .get("ring-count")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let rings_held = object
        .get("rings-held")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let ring_producers_in_flight = object
        .get("ring-producers-in-flight")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let worker_mask = object
        .get("worker-mask")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let parked_worker_mask = object
        .get("parked-worker-mask")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let worker_operations_in_flight = object
        .get("worker-operations-in-flight")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let quiescent = object
        .get("quiescent")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let ring_shape = ring_count != 0
        && rings_held <= ring_count
        && (rings_held == 0 || rings_held == ring_count)
        && held == (rings_held == ring_count);
    let expected_quiescent = registered
        && manifest_consistent
        && held
        && !teardown_closed
        && in_flight == 0
        && ring_shape
        && ring_producers_in_flight == 0
        && parked_worker_mask == worker_mask
        && worker_operations_in_flight == 0;
    let worker_shape = worker_mask & !QMP_HOT_FORK_PLUGIN_WORKER_ALL == 0
        && worker_mask & QMP_HOT_FORK_PLUGIN_WORKER_REQUIRED == QMP_HOT_FORK_PLUGIN_WORKER_REQUIRED
        && parked_worker_mask & !worker_mask == 0
        && u64::from(parked_worker_mask.count_ones()) + worker_operations_in_flight
            <= u64::from(worker_mask.count_ones());
    let unregistered_shape = generation == 0
        && !manifest_consistent
        && !held
        && !teardown_closed
        && in_flight == 0
        && ring_count == 0
        && rings_held == 0
        && ring_producers_in_flight == 0
        && worker_mask == 0
        && parked_worker_mask == 0
        && worker_operations_in_flight == 0
        && !quiescent;
    if schema_version != u64::from(QMP_HOT_FORK_PLUGIN_BARRIER_SCHEMA_VERSION)
        || quiescent != expected_quiescent
        || (registered && generation == 0)
        || (!registered && !unregistered_shape)
        || (manifest_consistent && !registered)
        || (registered && !ring_shape)
        || (registered && !worker_shape)
        || ((held
            || teardown_closed
            || in_flight != 0
            || ring_count != 0
            || rings_held != 0
            || ring_producers_in_flight != 0
            || worker_mask != 0
            || parked_worker_mask != 0
            || worker_operations_in_flight != 0)
            && !registered)
    {
        return Err(malformed());
    }

    Ok(QmpHotForkPluginBarrierState {
        generation,
        registered,
        manifest_consistent,
        held,
        teardown_closed,
        in_flight,
        ring_count,
        rings_held,
        ring_producers_in_flight,
        worker_mask,
        parked_worker_mask,
        worker_operations_in_flight,
        quiescent,
    })
}
