//! Mirrors the frozen process-private required-worker SDK without issuing roles.
//!
//! Opaque claims and canonical workers remain Source-owned. Every signed return
//! is distinct from the copied physical journal; no address or readiness fact
//! supplies operation authority or Source activation.
// SPDX-License-Identifier: GPL-2.0-only

use crate::startup_source::runtime_purpose::RuntimePurpose;
#[cfg(not(test))]
use std::ffi::CStr;
use std::ffi::c_void;

macro_rules! opaque {
    ($($name:ident),+ $(,)?) => {$(
        /// Names one opaque Source-owned process-private identity.
        #[repr(C)]
        pub(crate) struct $name { _private: [u8; 0] }
    )+};
}
opaque!(Worker, Frame, RunClaim, TeardownClaim);

/// Projects the already-issued separate claims under their same containing Runtime.
#[derive(Clone, Copy)]
pub(crate) struct Material {
    pub(crate) id: u64,
    pub(crate) runtime: *mut RuntimePurpose,
    pub(crate) run: *mut RunClaim,
    pub(crate) teardown: *mut TeardownClaim,
}

/// Describes the actual whole ordinary Arc and separately planned stack.
#[repr(C)]
pub(super) struct LayoutDescriptor {
    pub(super) schema_version: u32,
    pub(super) struct_size: u32,
    pub(super) control_bytes: u64,
    pub(super) control_alignment: u64,
    pub(super) stack_bytes: u64,
}

/// Copies the exact Native journal independently of signed API failures.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Status {
    pub(super) schema_version: u32,
    pub(super) struct_size: u32,
    pub(super) first_status: i32,
    pub(super) post_status: i32,
    pub(super) entry_status: i32,
    pub(super) join_status: i32,
    pub(super) unmap_status: i32,
    pub(super) control_status: i32,
    pub(super) control_lifetime_status: i32,
    pub(super) destructor_status: i32,
    pub(super) destruction_first_status: i32,
    pub(super) funding_status: i32,
    pub(super) task_return_status: i32,
    pub(super) stack_retire_status: i32,
    pub(super) handoff_status: i32,
    pub(super) handoff_post_status: i32,
    pub(super) close_status: i32,
    pub(super) close_post_status: i32,
    pub(super) transfer_post_status: i32,
    pub(super) join_post_status: i32,
    pub(super) destruction_post_status: i32,
    pub(super) unmap_post_status: i32,
    pub(super) residual_bytes: u64,
    pub(super) control_users: u64,
    pub(super) destruction_calls: u64,
    pub(super) initialized: u32,
    pub(super) ready: u32,
    pub(super) closing: u32,
    pub(super) entry_entered: u32,
    pub(super) entry_returned: u32,
    pub(super) joined: u32,
    pub(super) destroyed: u32,
    pub(super) physical_returned: u32,
    pub(super) destruction_active: u32,
    pub(super) destruction_returned: u32,
    pub(super) destruction_uncertain: u32,
    pub(super) control_lifetime_uncertain: u32,
    pub(super) handoff_attempted: u32,
    pub(super) handoff_committed: u32,
    pub(super) handoff_returned: u32,
    pub(super) handoff_released: u32,
    pub(super) cancelled_before_handoff: u32,
    pub(super) task_reserved: u32,
    pub(super) born: u32,
    pub(super) birth_attempted: u32,
    pub(super) create_status: i32,
    pub(super) mask_restore_status: i32,
    pub(super) attr_destroy_status: i32,
    pub(super) allocation_attempted: u32,
    pub(super) allocation_returned: u32,
    pub(super) construction_returned: u32,
    pub(super) close_attempted: u32,
    pub(super) close_returned: u32,
    pub(super) destruction_begun: u32,
    pub(super) pins_held: u32,
    pub(super) stack_mapped: u32,
    pub(super) stack_charge_held: u32,
    pub(super) residual_charge_held: u32,
}

/// Holds the literal matched Native functions; none creates authority from data.
#[derive(Clone, Copy)]
pub(super) struct Api {
    pub(super) create_run: extern "C" fn(
        u64,
        *mut RuntimePurpose,
        *mut RunClaim,
        *mut c_void,
        *mut c_void,
        *mut *mut Worker,
    ) -> i32,
    pub(super) create_teardown: extern "C" fn(
        u64,
        *mut RuntimePurpose,
        *mut TeardownClaim,
        *mut c_void,
        *mut c_void,
        *mut *mut Worker,
    ) -> i32,
    pub(super) allocation_begin: extern "C" fn(*mut Frame) -> i32,
    pub(super) allocation_result: extern "C" fn(*mut Frame, *mut c_void, *mut c_void) -> i32,
    pub(super) initialized: extern "C" fn(*mut Frame) -> i32,
    pub(super) destroy_begin: extern "C" fn(*mut Frame) -> i32,
    pub(super) destroyed: extern "C" fn(*mut Frame) -> i32,
    pub(super) ready: extern "C" fn(*mut Worker) -> i32,
    pub(super) current: extern "C" fn(u64, *mut RuntimePurpose) -> i32,
    pub(super) handoff: extern "C" fn(u64, *mut Worker, *mut c_void) -> i32,
    pub(super) handoff_committed: extern "C" fn(*mut Frame) -> i32,
    pub(super) control_use: extern "C" fn(u64, *mut Worker, *mut c_void) -> i32,
    pub(super) control_retire: extern "C" fn(u64, *mut Worker, *mut c_void) -> i32,
    pub(super) close: extern "C" fn(u64, *mut Worker) -> i32,
    pub(super) tryjoin: extern "C" fn(u64, *mut Worker) -> i32,
    pub(super) transfer: extern "C" fn(u64, *mut *mut Worker, *mut *mut Worker) -> i32,
    pub(super) identity_return: extern "C" fn(u64, *mut *mut Worker) -> i32,
    pub(super) observe: extern "C" fn(u64, *mut Worker, *mut Status) -> i32,
}

#[cfg(not(test))]
impl Api {
    /// Resolves the complete literal SDK before either creator can be entered.
    ///
    /// # Errors
    /// Refuses a missing Native symbol without constructing a worker or claim.
    pub(super) fn resolve() -> Result<Self, i32> {
        macro_rules! resolve {
            ($name:literal, $ty:ty) => {{
                let address = symbol($name).ok_or(-libc::ENOSYS)?;
                // SAFETY: the frozen SDK declares this exact process-private ABI.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(address) }
            }};
        }
        Ok(Self {
            create_run: resolve!(
                c"qemu_plugin_crucible_run_worker_create_v1",
                extern "C" fn(
                    u64,
                    *mut RuntimePurpose,
                    *mut RunClaim,
                    *mut c_void,
                    *mut c_void,
                    *mut *mut Worker,
                ) -> i32
            ),
            create_teardown: resolve!(
                c"qemu_plugin_crucible_teardown_worker_create_v1",
                extern "C" fn(
                    u64,
                    *mut RuntimePurpose,
                    *mut TeardownClaim,
                    *mut c_void,
                    *mut c_void,
                    *mut *mut Worker,
                ) -> i32
            ),
            allocation_begin: resolve!(
                c"qemu_plugin_crucible_required_worker_allocation_begin_v1",
                extern "C" fn(*mut Frame) -> i32
            ),
            allocation_result: resolve!(
                c"qemu_plugin_crucible_required_worker_allocation_result_v1",
                extern "C" fn(*mut Frame, *mut c_void, *mut c_void) -> i32
            ),
            initialized: resolve!(
                c"qemu_plugin_crucible_required_worker_initialized_v1",
                extern "C" fn(*mut Frame) -> i32
            ),
            destroy_begin: resolve!(
                c"qemu_plugin_crucible_required_worker_destroy_begin_v1",
                extern "C" fn(*mut Frame) -> i32
            ),
            destroyed: resolve!(
                c"qemu_plugin_crucible_required_worker_destroyed_v1",
                extern "C" fn(*mut Frame) -> i32
            ),
            ready: resolve!(
                c"qemu_plugin_crucible_required_worker_ready_v1",
                extern "C" fn(*mut Worker) -> i32
            ),
            current: resolve!(
                c"qemu_plugin_crucible_required_workers_current_v1",
                extern "C" fn(u64, *mut RuntimePurpose) -> i32
            ),
            handoff: resolve!(
                c"qemu_plugin_crucible_run_worker_handoff_v1",
                extern "C" fn(u64, *mut Worker, *mut c_void) -> i32
            ),
            handoff_committed: resolve!(
                c"qemu_plugin_crucible_run_worker_handoff_committed_v1",
                extern "C" fn(*mut Frame) -> i32
            ),
            control_use: resolve!(
                c"qemu_plugin_crucible_required_worker_control_use_v1",
                extern "C" fn(u64, *mut Worker, *mut c_void) -> i32
            ),
            control_retire: resolve!(
                c"qemu_plugin_crucible_required_worker_control_retire_v1",
                extern "C" fn(u64, *mut Worker, *mut c_void) -> i32
            ),
            close: resolve!(
                c"qemu_plugin_crucible_required_worker_close_v1",
                extern "C" fn(u64, *mut Worker) -> i32
            ),
            tryjoin: resolve!(
                c"qemu_plugin_crucible_required_worker_tryjoin_v1",
                extern "C" fn(u64, *mut Worker) -> i32
            ),
            transfer: resolve!(
                c"qemu_plugin_crucible_required_worker_transfer_v1",
                extern "C" fn(u64, *mut *mut Worker, *mut *mut Worker) -> i32
            ),
            identity_return: resolve!(
                c"qemu_plugin_crucible_required_worker_identity_return_v1",
                extern "C" fn(u64, *mut *mut Worker) -> i32
            ),
            observe: resolve!(
                c"qemu_plugin_crucible_required_worker_observe_v1",
                extern "C" fn(u64, *mut Worker, *mut Status) -> i32
            ),
        })
    }
}

#[cfg(not(test))]
fn symbol(name: &CStr) -> Option<*mut c_void> {
    // SAFETY: this lookup borrows a constant NUL-terminated name and no owner.
    let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    (!pointer.is_null()).then_some(pointer)
}
