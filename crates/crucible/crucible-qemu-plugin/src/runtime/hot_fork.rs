//! Held hot-fork callback barriers and fork-child runtime identity checks.
//!
//! The adapters operate on the original pinned runtime. Child reconstruction
//! stays unavailable until a separately issued startup Source is supplied;
//! copied parent custody cannot authorize child resources or worker effects.

use super::*;

impl OwnedCallbackRuntimeState {
    /// Validates the held fork-child cut before fresh startup custody is required.
    ///
    /// The separately issued child Source is unavailable, so reconstruction
    /// refuses before resource or worker effects. The copied parent Source
    /// cannot authorize child allocations or descriptor aliases.
    fn prepare_hot_fork_child(
        mut self: Pin<&mut Self>,
        private_ring_fd: BorrowedFd<'_>,
        expected_identity: crucible_qemu_shmem::SetupRegionBackingIdentity,
        binding: HotForkChildResourceBinding,
    ) -> Result<HotForkChildRuntimeSnapshot, HotForkChildRuntimeError> {
        let state = self.as_ref().get_ref();
        if let Err(phase) = state.child_runtime_state.compare_exchange(
            CHILD_RUNTIME_TEMPLATE,
            CHILD_RUNTIME_INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            return Err(HotForkChildRuntimeError::WrongPhase { phase });
        }

        // SAFETY: the hot-fork barrier has excluded every callback and worker
        // operation before this method is invoked. Mutating fields in place
        // does not move the pinned runtime or any callback allocation.
        let state = unsafe { self.as_mut().get_unchecked_mut() };
        let result =
            state.prepare_hot_fork_child_inner(private_ring_fd, expected_identity, binding);
        match result {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                state
                    .child_runtime_state
                    .store(CHILD_RUNTIME_FAILED, Ordering::Release);
                Err(error)
            }
        }
    }

    pub(super) fn prepare_hot_fork_child_inner(
        &mut self,
        _private_ring_fd: BorrowedFd<'_>,
        _expected_identity: crucible_qemu_shmem::SetupRegionBackingIdentity,
        binding: HotForkChildResourceBinding,
    ) -> Result<HotForkChildRuntimeSnapshot, HotForkChildRuntimeError> {
        let callbacks = self.quiescence.snapshot();
        let workers = self.workers.snapshot();
        if !callbacks.hot_fork_held
            || callbacks.teardown_closed
            || callbacks.in_flight != 0
            || !workers.held
            || workers.parked_mask != workers.worker_mask
            || workers.pending_mask != 0
            || workers.operations_in_flight != 0
            || !self.mapping_excluded_from_child.load(Ordering::Acquire)
        {
            return Err(HotForkChildRuntimeError::TemplateNotQuiescent);
        }
        if binding.parent_process_generation != self.process_generation
            || binding.parent_process_generation == 0
            || binding.parent_process_generation.checked_add(1)
                != Some(binding.child_process_generation)
        {
            return Err(HotForkChildRuntimeError::ProcessGeneration);
        }
        if !self.workspace_disarmed || self.owner_process == std::process::id() {
            return Err(HotForkChildRuntimeError::TemplateNotQuiescent);
        }

        // Fresh reconstruction requires a separately issued child Source.
        // The copied parent Source cannot authorize any child allocation or alias.
        Err(Self::child_startup_source_unavailable())
    }

    /// Returns one exact snapshot of fork-child mapping and worker readiness.
    fn hot_fork_child_snapshot(&self) -> HotForkChildRuntimeSnapshot {
        let callbacks = self.quiescence.snapshot();
        HotForkChildRuntimeSnapshot {
            phase: self.child_runtime_state.load(Ordering::Acquire),
            workers: self.workers.snapshot(),
            callbacks_held: callbacks.hot_fork_held,
            mapping_installed: self.child_mapping_installed.load(Ordering::Acquire),
            binding: HotForkChildResourceBinding::default(),
        }
    }

    /// Releases a fully reconstructed child runtime into ordinary execution.
    fn release_hot_fork_child(
        &mut self,
    ) -> Result<HotForkChildRuntimeSnapshot, HotForkChildRuntimeError> {
        let phase = self.child_runtime_state.load(Ordering::Acquire);
        if phase != CHILD_RUNTIME_WORKERS_HELD {
            return Err(HotForkChildRuntimeError::WrongPhase { phase });
        }
        if !self.workers.fork_child_workers_ready() {
            return Err(HotForkChildRuntimeError::WorkersNotReady);
        }
        let rings = self
            .setup
            .mapped_region()
            .hot_fork_ring_io_snapshot()
            .map_err(|_source| HotForkChildRuntimeError::RingBarrier)?;
        if !rings.quiescent() {
            return Err(HotForkChildRuntimeError::RingBarrier);
        }

        Err(Self::child_startup_source_unavailable())
    }
}

/// Rejects checkpoint handoff when guest RX ownership is ambiguous.
pub(super) fn check_hot_fork_network_rx(
    live: Option<&live_callbacks::LiveVcpuTimeCallbackState>,
    action: u32,
) -> Result<(), std::os::raw::c_int> {
    if matches!(
        action,
        crate::QEMU_PLUGIN_HOT_FORK_BARRIER_HOLD | crate::QEMU_PLUGIN_HOT_FORK_BARRIER_QUERY
    ) && live.is_some_and(live_callbacks::LiveVcpuTimeCallbackState::network_rx_commit_uncertain)
    {
        return Err(-libc::EPROTO);
    }

    Ok(())
}

/// Checks RX ownership before and after acquiring the barrier's factual state.
pub(super) fn collect_hot_fork_state_with_network_rx_check<T>(
    live: Option<&live_callbacks::LiveVcpuTimeCallbackState>,
    action: u32,
    collect: impl FnOnce() -> Result<T, std::os::raw::c_int>,
) -> Result<T, std::os::raw::c_int> {
    check_hot_fork_network_rx(live, action)?;
    let snapshot = collect()?;

    // An RX callback may fail after the entry check but before the acquired
    // quiescence snapshot. Recheck after observing in-flight work.
    check_hot_fork_network_rx(live, action)?;
    Ok(snapshot)
}

pub(super) extern "C" fn crucible_qemu_plugin_hot_fork_barrier(
    action: u32,
    status: *mut crate::QemuPluginHotForkBarrierStatus,
    userdata: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
    if status.is_null() || userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: registration passes the stable pinned runtime-owner address, and
    // production retains that allocation for the QEMU process lifetime.
    let state = unsafe { &*userdata.cast::<OwnedCallbackRuntimeState>() };
    // Arbitrate the entire legacy operation against companion acquisition and
    // disposition. An entry snapshot alone cannot exclude a later workspace or
    // ring release racing the new owner.
    let Ok(_parent_park_arbitration) = state.parent_park.try_lock() else {
        return -libc::EBUSY;
    };
    if state.checkpoint_owner_retained.load(Ordering::Acquire)
        || state.parent_park_retained.load(Ordering::Acquire)
        || state.quiescence.parent_hold_owned()
    {
        // Legacy QUERY also transfers workspace custody on its ordinary path.
        // A retained companion is observed only through its own CHECK operation.
        return -libc::EBUSY;
    }
    if action != crate::QEMU_PLUGIN_HOT_FORK_BARRIER_RELEASE
        && state.workers.identity_snapshot().is_err()
    {
        return -libc::EPROTO;
    }
    let snapshot = collect_hot_fork_state_with_network_rx_check(
        state
            .live_vcpu_time
            .as_ref()
            .map(|live| live.as_ref().get_ref()),
        action,
        || {
            let snapshot = match action {
                crate::QEMU_PLUGIN_HOT_FORK_BARRIER_HOLD => {
                    let snapshot = state.quiescence.hold_hot_fork();
                    let Ok(rings) = state.setup.mapped_region().hold_hot_fork_ring_io() else {
                        state.quiescence.release_hot_fork();
                        return Err(-libc::EPROTO);
                    };
                    let workers = state.workers.hold();
                    if !state.mapping_excluded_from_child.load(Ordering::Acquire) {
                        if let Err(error) = state.setup.exclude_setup_mapping_from_child() {
                            state.workers.release();
                            let _released_rings =
                                state.setup.mapped_region().release_hot_fork_ring_io();
                            state.quiescence.release_hot_fork();
                            return Err(error);
                        }
                        state
                            .mapping_excluded_from_child
                            .store(true, Ordering::Release);
                    }
                    if snapshot.in_flight == 0
                        && workers.parked_mask == workers.worker_mask
                        && workers.pending_mask == 0
                        && workers.operations_in_flight == 0
                        && let Some(live) = state.live_vcpu_time.as_ref()
                    {
                        // SAFETY: the complete held callback/worker snapshots
                        // exclude all access to the transferred workspace.
                        unsafe { live.hold_fingerprint_workspace() }.map_err(|_| -libc::EPROTO)?;
                    }
                    (snapshot, rings, workers)
                }
                crate::QEMU_PLUGIN_HOT_FORK_BARRIER_QUERY => {
                    let snapshot = state.quiescence.snapshot();
                    let Ok(rings) = state.setup.mapped_region().hot_fork_ring_io_snapshot() else {
                        return Err(-libc::EPROTO);
                    };
                    let workers = state.workers.snapshot();
                    if snapshot.hot_fork_held
                        && snapshot.in_flight == 0
                        && workers.held
                        && workers.parked_mask == workers.worker_mask
                        && workers.pending_mask == 0
                        && workers.operations_in_flight == 0
                        && let Some(live) = state.live_vcpu_time.as_ref()
                    {
                        // SAFETY: this is the same complete held/parked cut.
                        unsafe { live.hold_fingerprint_workspace() }.map_err(|_| -libc::EPROTO)?;
                    }
                    (snapshot, rings, workers)
                }
                crate::QEMU_PLUGIN_HOT_FORK_BARRIER_RELEASE => {
                    if let Some(live) = state.live_vcpu_time.as_ref() {
                        // SAFETY: callbacks/workers remain excluded until the
                        // same parent workspace has been restored successfully.
                        unsafe { live.restore_fingerprint_workspace() }
                            .map_err(|_| -libc::EPROTO)?;
                    }
                    if state.mapping_excluded_from_child.load(Ordering::Acquire) {
                        if let Err(error) = state.setup.restore_setup_mapping_parent() {
                            return Err(error);
                        }
                        state
                            .mapping_excluded_from_child
                            .store(false, Ordering::Release);
                    }
                    let Ok(rings) = state.setup.mapped_region().release_hot_fork_ring_io() else {
                        return Err(-libc::EPROTO);
                    };
                    let snapshot = state.quiescence.release_hot_fork();
                    let workers = state.workers.release();
                    (snapshot, rings, workers)
                }
                _ => return Err(-libc::EINVAL),
            };
            Ok(snapshot)
        },
    );
    let (snapshot, rings, workers) = match snapshot {
        Ok(snapshot) => snapshot,
        Err(status) => return status,
    };
    if snapshot.hot_fork_held != workers.held || workers.identity_failed {
        return -libc::EPROTO;
    }
    let Ok(struct_size) =
        u32::try_from(std::mem::size_of::<crate::QemuPluginHotForkBarrierStatus>())
    else {
        return -libc::EOVERFLOW;
    };
    let flags = (u32::from(snapshot.hot_fork_held) * crate::QEMU_PLUGIN_HOT_FORK_BARRIER_FLAG_HELD)
        | (u32::from(snapshot.teardown_closed) * crate::QEMU_PLUGIN_HOT_FORK_BARRIER_FLAG_TEARDOWN)
        | (u32::from(state.mapping_excluded_from_child.load(Ordering::Acquire))
            * crate::QEMU_PLUGIN_HOT_FORK_BARRIER_FLAG_MAPPING_DONTFORK);
    // SAFETY: the caller supplied a non-null out pointer for this synchronous
    // callback. The fixed C/Rust ABI layouts are checked by QEMU before use.
    unsafe {
        status.write(crate::QemuPluginHotForkBarrierStatus {
            schema_version: crate::QEMU_PLUGIN_HOT_FORK_BARRIER_STATUS_VERSION,
            struct_size,
            flags,
            reserved: 0,
            in_flight: snapshot.in_flight,
            ring_count: rings.ring_count(),
            rings_held: rings.held_rings(),
            ring_producers_in_flight: rings.producers_in_flight(),
            ring_consumers_in_flight: rings.consumers_in_flight(),
            worker_mask: workers.worker_mask,
            parked_worker_mask: workers.parked_mask,
            pending_worker_mask: workers.pending_mask,
            worker_operations_in_flight: workers.operations_in_flight,
            worker_process_id: workers.process_id,
            worker_membership_generation: workers.membership_generation,
            worker_thread_ids: workers.thread_ids,
        });
    }
    0
}

pub(super) extern "C" fn crucible_qemu_plugin_hot_fork_child_runtime(
    action: u32,
    plan: *const crate::QemuPluginHotForkChildPlan,
    status: *mut crate::QemuPluginHotForkChildStatus,
    userdata: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
    if status.is_null() || userdata.is_null() {
        return -libc::EINVAL;
    }

    // SAFETY: registration passes the stable pinned runtime-owner address.
    // QEMU invokes initialization/release only while the complete plugin
    // barrier excludes every callback and inherited worker operation.
    let retained = unsafe { &*userdata.cast::<OwnedCallbackRuntimeState>() };
    if retained.checkpoint_owner_retained.load(Ordering::Acquire)
        || retained.parent_park_retained.load(Ordering::Acquire)
        || retained.quiescence.parent_hold_owned()
    {
        // The genuine staged-child companion has not lent this parent borrow.
        // Refuse before forming a mutable runtime projection or touching a
        // copied worker mutex/mapping owner.
        return -libc::EBUSY;
    }
    // SAFETY: the existing native child barrier excludes all borrowed runtime
    // access, and no retained parent companion borrow remains.
    let state = unsafe { &mut *userdata.cast::<OwnedCallbackRuntimeState>() };
    if action == crate::QEMU_PLUGIN_HOT_FORK_CHILD_DISARM {
        if plan.is_null() {
            return -libc::EINVAL;
        }
        // SAFETY: native code retains this fixed synchronous early-entry plan.
        let plan = unsafe { *plan };
        let disarmed = match state.disarm_child_device_workspace(&plan) {
            Ok(disarmed) => disarmed,
            Err(status) => return status,
        };
        // SAFETY: native code retains the non-null fixed output through return.
        unsafe { status.write(disarmed) };
        return 0;
    }

    let result = match action {
        crate::QEMU_PLUGIN_HOT_FORK_CHILD_INITIALIZE => {
            if plan.is_null() {
                return -libc::EINVAL;
            }
            // SAFETY: QEMU retains the fixed-layout plan for this synchronous
            // callback invocation, and the non-null pointer is read only once.
            let plan = unsafe { *plan };
            if let Some(rejected) = hot_fork_child_plan_rejection(&plan, state) {
                // The child's stderr is its branch-private diagnostics stream
                // by now, so the host learns which check failed.
                emit_control_worker_diagnostic(&format!(
                    "hot-fork child plan rejected: {rejected}"
                ));
                return -libc::EPROTO;
            }
            let Some(identity) = crucible_qemu_shmem::SetupRegionBackingIdentity::from_parts(
                plan.shmem_device,
                plan.shmem_inode,
                plan.shmem_length,
            ) else {
                return -libc::EPROTO;
            };
            // SAFETY: the plan guarantees that QEMU owns this descriptor for
            // the synchronous callback. Installation duplicates the mapping,
            // not descriptor ownership, before the callback returns.
            let private_ring_fd = unsafe { BorrowedFd::borrow_raw(plan.private_ring_fd) };
            // SAFETY: the process-lifetime owner was pinned before registration
            // and the mutable reference is not used to move it.
            let state = unsafe { Pin::new_unchecked(&mut *state) };
            state.prepare_hot_fork_child(private_ring_fd, identity, plan.into())
        }
        crate::QEMU_PLUGIN_HOT_FORK_CHILD_QUERY => Ok(state.hot_fork_child_snapshot()),
        crate::QEMU_PLUGIN_HOT_FORK_CHILD_RELEASE => state.release_hot_fork_child(),
        _ => return -libc::EINVAL,
    };
    let snapshot = match result {
        Ok(snapshot) => snapshot,
        Err(error) => {
            emit_control_worker_diagnostic(&format!(
                "hot-fork child runtime action {action} failed: {error}"
            ));
            return hot_fork_child_runtime_status(error);
        }
    };

    let Ok(struct_size) = u32::try_from(std::mem::size_of::<crate::QemuPluginHotForkChildStatus>())
    else {
        return -libc::EOVERFLOW;
    };
    let workers_ready = snapshot.phase == CHILD_RUNTIME_WORKERS_HELD
        && state.workers.snapshot_ready(&snapshot.workers);
    let flags = (u32::from(snapshot.callbacks_held)
        * crate::QEMU_PLUGIN_HOT_FORK_CHILD_FLAG_CALLBACKS_HELD)
        | (u32::from(snapshot.mapping_installed)
            * crate::QEMU_PLUGIN_HOT_FORK_CHILD_FLAG_MAPPING_INSTALLED)
        | (u32::from(workers_ready) * crate::QEMU_PLUGIN_HOT_FORK_CHILD_FLAG_WORKERS_READY)
        | (u32::from(snapshot.phase == CHILD_RUNTIME_ACTIVE)
            * crate::QEMU_PLUGIN_HOT_FORK_CHILD_FLAG_ACTIVE)
        | (u32::from(snapshot.phase == CHILD_RUNTIME_FAILED)
            * crate::QEMU_PLUGIN_HOT_FORK_CHILD_FLAG_FAILED)
        | (u32::from(state.workspace_disarmed)
            * crate::QEMU_PLUGIN_HOT_FORK_CHILD_FLAG_WORKSPACE_DISARMED);
    // SAFETY: the caller supplied a non-null out pointer for this synchronous
    // callback. QEMU validates the exact fixed layout before using the result.
    unsafe {
        status.write(crate::QemuPluginHotForkChildStatus {
            schema_version: crate::QEMU_PLUGIN_HOT_FORK_CHILD_STATUS_VERSION,
            struct_size,
            flags,
            phase: u32::from(snapshot.phase),
            parent_process_generation: snapshot.binding.parent_process_generation,
            child_process_generation: snapshot.binding.child_process_generation,
            template_generation: snapshot.binding.template_generation,
            private_ring_generation: snapshot.binding.private_ring_generation,
            plugin_endpoint_generation: snapshot.binding.plugin_endpoint_generation,
            plugin_barrier_generation: snapshot.binding.plugin_barrier_generation,
            control_socket_cookie: snapshot.binding.control_socket_cookie,
            wake_eventfd_id: snapshot.binding.wake_eventfd_id,
            source_mapping_start: snapshot.binding.source_mapping_start,
            source_mapping_length: snapshot.binding.source_mapping_length,
            source_mapping_offset: snapshot.binding.source_mapping_offset,
            worker_mask: snapshot.workers.worker_mask,
            parked_worker_mask: snapshot.workers.parked_mask,
            pending_worker_mask: snapshot.workers.pending_mask,
            worker_operations_in_flight: snapshot.workers.operations_in_flight,
            account_generation: snapshot.binding.account_generation,
            workspace_generation: snapshot.binding.workspace_generation,
            workspace_device: snapshot.binding.workspace_device,
            workspace_inode: snapshot.binding.workspace_inode,
            workspace_length: snapshot.binding.workspace_length,
            workspace_fd: state.claimed_workspace_fd,
            workspace_reserved: 0,
        });
    }
    0
}

const HOT_FORK_ENDPOINT_FDINFO_MAX_BYTES: u64 = 4_096;

/// Returns the first check a fork-child plan fails, named for diagnostics.
///
/// Every check is a protocol invariant between QEMU's plan and the runtime
/// state the plugin sealed at registration; the first failure is reported
/// because later checks describe the same plan.
fn hot_fork_child_plan_rejection(
    plan: &crate::QemuPluginHotForkChildPlan,
    state: &OwnedCallbackRuntimeState,
) -> Option<&'static str> {
    let expected_size = std::mem::size_of::<crate::QemuPluginHotForkChildPlan>();
    let checks: [(&'static str, bool); 23] = [
        (
            "schema version",
            plan.schema_version == crate::QEMU_PLUGIN_HOT_FORK_CHILD_PLAN_VERSION,
        ),
        (
            "struct size",
            usize::try_from(plan.struct_size).ok() == Some(expected_size),
        ),
        ("flags", plan.flags == 0),
        ("reserved", plan.reserved == 0),
        (
            "process generation",
            hot_fork_child_process_generation_matches(plan, state.process_generation),
        ),
        ("template generation", plan.template_generation != 0),
        ("private ring generation", plan.private_ring_generation != 0),
        (
            "plugin endpoint generation",
            plan.plugin_endpoint_generation != 0,
        ),
        (
            "plugin barrier generation",
            plan.plugin_barrier_generation != 0,
        ),
        ("control socket cookie", plan.control_socket_cookie != 0),
        ("wake eventfd id", plan.wake_eventfd_id != 0),
        ("reserved fd", plan.reserved_fd == -1),
        ("private ring fd", plan.private_ring_fd >= 0),
        ("control fd", plan.control_fd == state.control_fd),
        ("wake fd", plan.wake_fd == state.setup.wake_fd().as_raw_fd()),
        (
            "private ring fd distinct from control fd",
            plan.private_ring_fd != plan.control_fd,
        ),
        (
            "private ring fd distinct from wake fd",
            plan.private_ring_fd != plan.wake_fd,
        ),
        (
            "worker mask",
            plan.worker_mask == state.workers.worker_mask(),
        ),
        (
            "endpoint identity",
            hot_fork_child_endpoint_identity_matches(plan),
        ),
        (
            "mapping basis",
            hot_fork_child_mapping_basis_matches(plan, &state.setup),
        ),
        ("workspace disarmed", state.workspace_disarmed),
        (
            "workspace fields",
            device_workspace::child_workspace_matches(plan, state),
        ),
        ("plan", true),
    ];
    checks
        .into_iter()
        .find_map(|(name, holds)| (!holds).then_some(name))
}

pub(super) fn hot_fork_child_endpoint_identity_matches(
    plan: &crate::QemuPluginHotForkChildPlan,
) -> bool {
    hot_fork_control_socket_cookie(plan.control_fd).ok() == Some(plan.control_socket_cookie)
        && hot_fork_wake_eventfd_id(plan.wake_fd).ok() == Some(plan.wake_eventfd_id)
}

/// Returns the whole-page VMA extent that a shared mapping of `length` spans.
///
/// The setup region length is an exact protocol value while QEMU binds and
/// reports the page-rounded mapping, so the plan is compared at page
/// granularity.
pub(super) fn host_mapping_extent(length: u64) -> u64 {
    // SAFETY: sysconf reads a process-constant kernel parameter and touches no
    // memory owned by this crate.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = u64::try_from(page).unwrap_or(4096).max(1);
    length
        .checked_add(page - 1)
        .map_or(u64::MAX, |rounded| rounded - rounded % page)
}

pub(super) fn hot_fork_child_mapping_basis_matches(
    plan: &crate::QemuPluginHotForkChildPlan,
    setup: &crate::setup::PluginSetupCompletion,
) -> bool {
    usize::try_from(plan.source_mapping_start).ok() == Some(setup.mapped_region().mapping_start())
        && plan.source_mapping_length == host_mapping_extent(setup.mapped_region().region_len())
        && plan.source_mapping_length == host_mapping_extent(plan.shmem_length)
        && plan.source_mapping_offset == 0
        && plan
            .source_mapping_start
            .checked_add(plan.source_mapping_length)
            .is_some()
}

pub(super) fn hot_fork_child_process_generation_matches(
    plan: &crate::QemuPluginHotForkChildPlan,
    current: u64,
) -> bool {
    current != 0
        && plan.parent_process_generation == current
        && current.checked_add(1) == Some(plan.child_process_generation)
}

pub(super) fn hot_fork_control_socket_cookie(descriptor: std::os::fd::RawFd) -> io::Result<u64> {
    let mut cookie = 0_u64;
    let mut length = std::mem::size_of::<u64>() as libc::socklen_t;
    let status =
        // SAFETY: `cookie` and `length` are valid output buffers for SO_COOKIE.
        unsafe {
            libc::getsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                std::ptr::from_mut(&mut cookie).cast(),
                &mut length,
            )
        };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<u64>() || cookie == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control socket returned an invalid SO_COOKIE",
        ));
    }
    Ok(cookie)
}

// The versioned child plan carries kernel eventfd-id plus one; zero is absent.
pub(super) fn hot_fork_wake_eventfd_id(descriptor: std::os::fd::RawFd) -> io::Result<u64> {
    let path = format!("/proc/self/fdinfo/{descriptor}");
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(HOT_FORK_ENDPOINT_FDINFO_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > HOT_FORK_ENDPOINT_FDINFO_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "eventfd fdinfo exceeds its fixed bound",
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("eventfd fdinfo is not UTF-8: {error}"),
        )
    })?;
    hot_fork_eventfd_identity_token_from_fdinfo(text)
}

pub(super) fn hot_fork_eventfd_identity_token_from_fdinfo(text: &str) -> io::Result<u64> {
    let mut identity = None;
    for line in text.lines() {
        let Some(value) = line.strip_prefix("eventfd-id:") else {
            continue;
        };
        if identity.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "eventfd fdinfo repeats eventfd-id",
            ));
        }
        let parsed = value.trim().parse::<u64>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("eventfd-id is invalid: {error}"),
            )
        })?;
        // Linux may allocate eventfd ID zero. The versioned plan uses a
        // one-based token so zero can keep denoting an absent identity.
        identity = Some(parsed.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "eventfd-id exceeds token range")
        })?);
    }
    identity.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "eventfd fdinfo omits eventfd-id",
        )
    })
}

fn hot_fork_child_runtime_status(error: HotForkChildRuntimeError) -> std::os::raw::c_int {
    match error {
        HotForkChildRuntimeError::WrongPhase { .. } => -libc::EALREADY,
        HotForkChildRuntimeError::Workspace { .. } => -libc::EPROTO,
        HotForkChildRuntimeError::WorkersNotReady => -libc::EAGAIN,
        HotForkChildRuntimeError::TemplateNotQuiescent
        | HotForkChildRuntimeError::ProcessGeneration
        | HotForkChildRuntimeError::RingBarrier => -libc::EPROTO,
    }
}
