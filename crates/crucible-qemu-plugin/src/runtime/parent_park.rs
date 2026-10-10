//! Retains exclusive parent callback, worker and mapped-runtime drain custody.
//!
//! A hold borrows the actual pinned runtime, including its setup mapping, Source
//! descriptor and live workspace. The native companion must retain that same
//! module/userdata lifetime and lend its later original only during invocation.
//! Neither a barrier snapshot nor completed startup registration creates a hold.
// SPDX-License-Identifier: GPL-2.0-only

use std::pin::Pin;

use super::OwnedCallbackRuntimeState;
use super::callback_quiescence::ParentCallbackHold;
use super::worker_quiescence::{ParentWorkerHold, WorkerQuiescenceSnapshot};

/// Noncopying custody of the existing pinned runtime and its exclusive gates.
///
/// There is deliberately no release-on-drop behavior. Native containment must
/// retain the runtime/module when an invocation or disposition is uncertain.
pub(super) struct ParentParkDrainOwner<'runtime> {
    runtime: Pin<&'runtime OwnedCallbackRuntimeState>,
    callbacks: Option<ParentCallbackHold>,
    workers: Option<ParentWorkerHold>,
    membership: Option<WorkerQuiescenceSnapshot>,
    first: i32,
    post: i32,
    terminal_containment: bool,
    acquisition_attempted: bool,
    disposed: bool,
}

impl<'runtime> ParentParkDrainOwner<'runtime> {
    /// Prepares inline custody before any hold effect or original query.
    pub(super) fn retain(runtime: Pin<&'runtime OwnedCallbackRuntimeState>) -> Self {
        Self {
            runtime,
            callbacks: None,
            workers: None,
            membership: None,
            first: 0,
            post: 0,
            terminal_containment: false,
            acquisition_attempted: false,
            disposed: false,
        }
    }

    /// Acquires actual resource holds under the callback's borrowed native original.
    pub(super) fn acquire(&mut self, mut original_check: impl FnMut() -> i32) -> i32 {
        if self.acquisition_attempted || self.disposed {
            return -libc::EALREADY;
        }
        self.acquisition_attempted = true;
        let original = original_check();
        if original != 0 {
            self.refuse(original);
            self.observe_post(original_check());
            return self.result();
        }

        let state = self.runtime.get_ref();
        self.callbacks = state.quiescence.reserve_parent_hold();
        if self.callbacks.is_none() {
            self.refuse(-libc::EBUSY);
            self.observe_post(original_check());
            return self.result();
        }
        match state.workers.reserve_parent_hold() {
            Ok(workers) => self.workers = Some(workers),
            Err(error) => {
                self.refuse(error.status());
                self.observe_post(original_check());
                return self.result();
            }
        }
        if state.setup.mapped_region().hold_hot_fork_ring_io().is_err() {
            self.refuse(-libc::EPROTO);
            self.observe_post(original_check());
            return self.result();
        }
        let Some(workers) = self.workers.as_ref() else {
            return self.refuse(-libc::EPROTO);
        };
        match workers.snapshot() {
            Ok(membership) => self.membership = Some(membership),
            Err(error) => {
                self.refuse(error.status());
                self.observe_post(original_check());
                return self.result();
            }
        }

        let local = self.check_resources();
        if local != 0 {
            self.refuse(local);
        } else if let Some(live) = &state.live_vcpu_time {
            // SAFETY: all actual callback/ring/worker admission is held and the
            // complete drained snapshots were verified immediately above.
            if let Err(status) = unsafe { live.hold_fingerprint_workspace_for_parent_park() } {
                self.refuse(status);
            }
        }
        self.observe_post(original_check());
        self.result()
    }

    /// Verifies the same actual retained membership and complete drain scope.
    pub(super) fn check(&mut self, mut original_check: impl FnMut() -> i32) -> i32 {
        if self.disposed || self.terminal_containment {
            return -libc::EALREADY;
        }
        let original = original_check();
        if original != 0 {
            self.refuse(original);
        } else {
            let local = self.check_resources();
            if local != 0 {
                self.refuse(local);
            }
        }
        self.observe_post(original_check());
        self.result()
    }

    /// Relinquishes gates only after native has closed the descendant/I-O scope.
    ///
    /// The caller's native context must prohibit parent execution, producers,
    /// unload and new births through the final release/publication cut. That
    /// native borrow is distinct from the installing Setup operation.
    pub(super) fn relinquish(&mut self, original_check: impl FnMut() -> i32) -> i32 {
        self.relinquish_after_check(original_check, || {})
    }

    // The fixture cut exposes an actual worker transition after the earlier
    // check; production supplies no hook and revalidates under the same loan.
    pub(super) fn relinquish_after_check(
        &mut self,
        original_check: impl FnMut() -> i32,
        after_check: impl FnOnce(),
    ) -> i32 {
        let status = self.check(original_check);
        if status != 0 {
            return status;
        }
        after_check();
        let state = self.runtime.get_ref();
        let release = match self
            .workers
            .as_ref()
            .map(ParentWorkerHold::prepare_relinquish)
        {
            Some(Ok(release)) => release,
            Some(Err(error)) => return Self::first_refusal(&mut self.first, error.status()),
            None => return Self::first_refusal(&mut self.first, -libc::EPROTO),
        };
        if !self.worker_scope_matches(&release.snapshot()) {
            drop(release);
            return self.refuse(-libc::EBUSY);
        }
        // The actual worker-state loan remains held through all local release
        // effects. A busy/poison refusal occurs before restoring either resource.
        let disposition = (|| {
            if let Some(live) = &state.live_vcpu_time {
                // SAFETY: check verified the same owned drained scope and native
                // retains producer/execution exclusion across this disposition.
                unsafe { live.restore_fingerprint_workspace_for_parent_park() }?;
            }
            if state
                .mapping_excluded_from_child
                .load(std::sync::atomic::Ordering::Acquire)
            {
                state
                    .setup
                    .mapped_region()
                    .restore_hot_fork_parent_inheritance()
                    .map_err(super::hot_fork_mapping_disposition_status)?;
                state
                    .mapping_excluded_from_child
                    .store(false, std::sync::atomic::Ordering::Release);
            }
            state
                .setup
                .mapped_region()
                .release_hot_fork_ring_io()
                .map_err(|_| -libc::EPROTO)?;
            Ok::<(), i32>(())
        })();
        if let Err(status) = disposition {
            drop(release);
            return self.refuse(status);
        }
        release.commit();
        self.workers = None;
        if let Some(callbacks) = self.callbacks.take() {
            callbacks.relinquish();
        }
        self.disposed = true;
        0
    }

    /// Records independent original refusal without replacing the initiating cause.
    pub(super) fn observe_post(&mut self, status: i32) {
        if status != 0 && self.post == 0 {
            self.post = status;
        }
    }

    pub(super) fn statuses(&self) -> (i32, i32) {
        (self.first, self.post)
    }

    fn refuse(&mut self, status: i32) -> i32 {
        Self::first_refusal(&mut self.first, status)
    }

    fn first_refusal(first: &mut i32, status: i32) -> i32 {
        if *first == 0 {
            *first = status;
        }
        *first
    }

    fn result(&self) -> i32 {
        if self.first != 0 {
            self.first
        } else {
            self.post
        }
    }

    fn worker_scope_matches(&self, worker: &WorkerQuiescenceSnapshot) -> bool {
        let Some(membership) = self.membership.as_ref() else {
            return false;
        };
        self.runtime.get_ref().workers.snapshot_ready(worker)
            && worker.process_id == membership.process_id
            && worker.membership_generation == membership.membership_generation
            && worker.thread_ids == membership.thread_ids
    }

    fn check_resources(&self) -> i32 {
        let state = self.runtime.get_ref();
        let (Some(callbacks), Some(workers), Some(_membership)) =
            (&self.callbacks, &self.workers, &self.membership)
        else {
            return -libc::EPROTO;
        };
        let callback = callbacks.snapshot();
        let worker = match workers.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return error.status(),
        };
        if !callback.hot_fork_held
            || callback.teardown_closed
            || callback.in_flight != 0
            || !self.worker_scope_matches(&worker)
        {
            return -libc::EBUSY;
        }
        let Ok(rings) = state.setup.mapped_region().hot_fork_ring_io_snapshot() else {
            return -libc::EPROTO;
        };
        if rings.ring_count() != rings.held_rings()
            || rings.producers_in_flight() != 0
            || rings.consumers_in_flight() != 0
        {
            return -libc::EBUSY;
        }
        super::check_hot_fork_network_rx(
            state
                .live_vcpu_time
                .as_ref()
                .map(|live| live.as_ref().get_ref()),
            crate::QEMU_PLUGIN_HOT_FORK_BARRIER_QUERY,
        )
        .err()
        .unwrap_or(0)
    }
}

/// Literal process-private counterpart of the reviewed native invocation.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub(super) struct Invocation {
    schema_version: u32,
    struct_size: u32,
    action: u32,
    disposition: u32,
    native_context_generation: u64,
    stopped_generation: u64,
    request_correlation: u64,
}

/// Process-private observation; it contains no permission or owned resource.
#[repr(C)]
pub(super) struct Status {
    schema_version: u32,
    struct_size: u32,
    action: u32,
    state: u32,
    native_context_generation: u64,
    plugin_owner_generation: u64,
    stopped_generation: u64,
    request_correlation: u64,
    first_status: i32,
    post_status: i32,
}

type Callback = extern "C" fn(u64, *const Invocation, *mut Status, *mut std::ffi::c_void) -> i32;
type Registrar = extern "C" fn(u64, Option<Callback>, *mut std::ffi::c_void) -> i32;
type Check = extern "C" fn(u64) -> i32;
type Slice = extern "C" fn(u64, *mut u64) -> i32;

#[derive(Clone, Copy)]
pub(super) struct NativeApi {
    register: Registrar,
    check: Check,
    query_slice: Slice,
}

impl NativeApi {
    fn check_original(self, plugin_id: u64) -> i32 {
        let status = (self.check)(plugin_id);
        if status != 0 {
            return status;
        }
        let mut bounded_ns = 0;
        let status = (self.query_slice)(plugin_id, &mut bounded_ns);
        if status != 0 {
            return status;
        }
        if bounded_ns == 0 {
            return -libc::EPROTO;
        }
        0
    }
}

/// Inline owner storage within the existing pinned callback allocation.
pub(super) struct Slot {
    owner: Option<ParentParkDrainOwner<'static>>,
    binding: Option<Invocation>,
}

impl Slot {
    pub(super) const fn new() -> Self {
        Self {
            owner: None,
            binding: None,
        }
    }
}

/// Registers only the exact installing callback owner when the joined SDK exists.
///
/// Absence leaves the new operation unavailable: native cannot accept a park
/// without this registered companion. It does not select an old barrier fallback.
pub(super) fn register(
    plugin_id: u64,
    runtime: Pin<&mut OwnedCallbackRuntimeState>,
) -> Result<(), i32> {
    // SAFETY: each resolved symbol has the literal reviewed process-private ABI;
    // no QEMU object or function pointer is exposed to the host process.
    let register = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_register_parent_park_drain_v1".as_ptr(),
        )
    };
    if register.is_null() {
        return Ok(());
    }
    // SAFETY: the static NUL-terminated name is borrowed only by dlsym, and the
    // returned address stays opaque until conversion to the reviewed function type.
    let check = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_parent_park_drain_original_check_v1".as_ptr(),
        )
    };
    // SAFETY: this static symbol name remains valid throughout dlsym; the
    // address is not called before non-null resolution and typed ABI conversion.
    let slice = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_parent_park_drain_original_query_slice_v1".as_ptr(),
        )
    };
    if check.is_null() || slice.is_null() {
        return Err(-libc::ENOSYS);
    }
    // SAFETY: non-null symbols are the exact declared registrar/check/slice
    // functions in the source-qualified matching native module.
    let api = unsafe {
        NativeApi {
            register: std::mem::transmute::<*mut std::ffi::c_void, Registrar>(register),
            check: std::mem::transmute::<*mut std::ffi::c_void, Check>(check),
            query_slice: std::mem::transmute::<*mut std::ffi::c_void, Slice>(slice),
        }
    };
    // SAFETY: assigning the inline table does not move the pinned allocation;
    // the real installing invocation precedes guest/callback execution.
    let state = unsafe { runtime.get_unchecked_mut() };
    state.parent_park_api = Some(api);
    // The registrar can retain userdata even on an ambiguous refusal. There is
    // no unregister in this SDK, so the pinned allocation remains process-owned
    // before the first acquire and after a healthy local relinquishment too.
    state
        .parent_park_registration_retained
        .store(true, std::sync::atomic::Ordering::Release);
    let status = (api.register)(
        plugin_id,
        Some(callback),
        std::ptr::from_mut(state).cast::<std::ffi::c_void>(),
    );
    if status == 0 { Ok(()) } else { Err(status) }
}

extern "C" fn callback(
    plugin_id: u64,
    invocation: *const Invocation,
    output: *mut Status,
    userdata: *mut std::ffi::c_void,
) -> i32 {
    if invocation.is_null() || output.is_null() || userdata.is_null() {
        return -libc::EINVAL;
    }
    let (state, invocation) = unsafe {
        // SAFETY: native dispatch retains this exact registered pinned allocation
        // and both fixed ABI objects for the complete synchronous invocation.
        (&*userdata.cast::<OwnedCallbackRuntimeState>(), *invocation)
    };
    if invocation.schema_version != 1
        || invocation.struct_size as usize != std::mem::size_of::<Invocation>()
        || !(1..=3).contains(&invocation.action)
        || invocation.native_context_generation == 0
        || invocation.stopped_generation == 0
        || invocation.request_correlation == 0
        || (invocation.action != 3 && invocation.disposition != 0)
        || (invocation.action == 3 && !(1..=2).contains(&invocation.disposition))
    {
        return -libc::EINVAL;
    }
    let Some(api) = state.parent_park_api else {
        return -libc::ENOSYS;
    };
    // Native refuses foreign/outside invocations before its lookups/locks. Its
    // actual later originals, not these coordinates, authorize the local borrow.
    let original = api.check_original(plugin_id);
    if original != 0 {
        return original;
    }
    if state.plugin_id != Some(plugin_id)
        || state.owner_process != std::process::id()
        || super::RUNTIME_STATE.load(std::sync::atomic::Ordering::Acquire) != super::RUNTIME_ACTIVE
    {
        return -libc::EPERM;
    }
    let Ok(mut slot) = state.parent_park.try_lock() else {
        return -libc::EBUSY;
    };
    if invocation.action == 1 {
        if slot.owner.is_some() {
            return -libc::EALREADY;
        }
        // This bit controls allocation retirement only; the owner below holds
        // the actual resource borrow and exclusion tokens before publication.
        state
            .parent_park_retained
            .store(true, std::sync::atomic::Ordering::Release);
        let retained = unsafe {
            // SAFETY: native pins the exact registered module/userdata and production
            // retains this allocation for process lifetime. Proof Drop also preserves
            // the allocation while this owner exists, including terminal refusal.
            Pin::new_unchecked(&*userdata.cast::<OwnedCallbackRuntimeState>())
        };
        slot.owner = Some(ParentParkDrainOwner::retain(retained));
        slot.binding = Some(invocation);
    }
    let Some(binding) = slot.binding else {
        return -libc::EPROTO;
    };
    if binding.native_context_generation != invocation.native_context_generation
        || binding.stopped_generation != invocation.stopped_generation
        || binding.request_correlation != invocation.request_correlation
    {
        return -libc::EPROTO;
    }
    let Some(owner) = slot.owner.as_mut() else {
        return -libc::EPROTO;
    };
    let status = match (invocation.action, invocation.disposition) {
        (1, 0) => owner.acquire(|| api.check_original(plugin_id)),
        (2, 0) => owner.check(|| api.check_original(plugin_id)),
        (3, 1) => owner.relinquish(|| api.check_original(plugin_id)),
        (3, 2) => {
            // A containment request is an ownership disposition, not evidence
            // that the original was canceled or another first cause occurred.
            owner.terminal_containment = true;
            0
        }
        _ => return -libc::EINVAL,
    };
    if status != 0 {
        return status;
    }
    let (first_status, post_status) = owner.statuses();
    let disposed = owner.disposed;
    let observation = Status {
        schema_version: 1,
        struct_size: std::mem::size_of::<Status>() as u32,
        action: invocation.action,
        state: if disposed {
            3
        } else if owner.terminal_containment || first_status != 0 || post_status != 0 {
            2
        } else {
            1
        },
        native_context_generation: invocation.native_context_generation,
        plugin_owner_generation: state.process_generation,
        stopped_generation: invocation.stopped_generation,
        request_correlation: invocation.request_correlation,
        first_status,
        post_status,
    };
    if disposed {
        slot.owner = None;
        // Drop the actual pinned borrow before allowing allocation retirement.
        state
            .parent_park_retained
            .store(false, std::sync::atomic::Ordering::Release);
    }
    // SAFETY: publish only the complete successful observation. Every refusal
    // above leaves the caller's fixed output sentinel untouched.
    unsafe { output.write(observation) };
    0
}
