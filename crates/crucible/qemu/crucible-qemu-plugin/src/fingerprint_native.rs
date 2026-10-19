//! Process-private Source worker and detached-material ABI.
//!
//! Native owns the canonical worker, task, stack, workspace and material
//! journals. These opaque projections carry no Main or Root authority.
// SPDX-License-Identifier: GPL-2.0-only

use std::ffi::{c_void, CStr};
use crate::startup_source::runtime_purpose::{RuntimePurpose, WorkerClaim};

macro_rules! opaque {
    ($($name:ident),+ $(,)?) => {$ (
        #[doc = concat!("Names the process-private Source ", stringify!($name), " owner.")]
        #[repr(C)]
        pub(crate) struct $name { _private: [u8; 0] }
    )+};
}

opaque!(Worker, WorkerFrame, Material, Work);

/// Describes the ordinary complete shared allocation and independent stack.
#[repr(C)]
pub(crate) struct WorkerLayout {
    pub(crate) schema_version: u32,
    pub(crate) struct_size: u32,
    pub(crate) control_bytes: u64,
    pub(crate) control_alignment: u64,
    pub(crate) stack_bytes: u64,
}

/// Corroborates actual physical effects independently of signed posts.
#[repr(C)]
#[derive(Debug, Default)]
pub(crate) struct WorkerStatus {
    pub(crate) schema_version: u32,
    pub(crate) struct_size: u32,
    pub(crate) first_status: i32,
    pub(crate) post_status: i32,
    pub(crate) create_status: i32,
    pub(crate) mask_restore_status: i32,
    pub(crate) attr_destroy_status: i32,
    pub(crate) entry_status: i32,
    pub(crate) join_status: i32,
    pub(crate) unmap_status: i32,
    pub(crate) residual_bytes: u64,
    pub(crate) births_reserved: u64,
    pub(crate) born: u32,
    pub(crate) initialized: u32,
    pub(crate) closing: u32,
    pub(crate) entry_returned: u32,
    pub(crate) joined: u32,
    pub(crate) destroyed: u32,
    pub(crate) physical_returned: u32,
    pub(crate) material_held: u32,
    pub(crate) bytes_held: u32,
    pub(crate) control_users: u64,
    pub(crate) destruction_calls: u64,
    pub(crate) control_status: i32,
    pub(crate) destructor_status: i32,
    pub(crate) destruction_first_status: i32,
    pub(crate) destruction_active: u32,
    pub(crate) destruction_returned: u32,
    pub(crate) destruction_begun: u32,
    pub(crate) destruction_uncertain: u32,
}

pub(crate) use crate::fingerprint_sampler::read_receipt::MaterialRead;

/// Holds only the matched current process-private Source SDK functions.
#[derive(Clone, Copy)]
pub(crate) struct Api {
    pub(crate) create: extern "C" fn(
        u64,
        *mut RuntimePurpose,
        *mut WorkerClaim,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut *mut Worker,
    ) -> i32,
    pub(crate) control_use: extern "C" fn(u64, *mut Worker, *mut c_void) -> i32,
    pub(crate) control_retire: extern "C" fn(u64, *mut Worker, *mut c_void) -> i32,
    pub(crate) allocation_begin: extern "C" fn(*mut WorkerFrame) -> i32,
    pub(crate) allocation_result: extern "C" fn(*mut WorkerFrame, *mut c_void, *mut c_void) -> i32,
    pub(crate) initialized: extern "C" fn(*mut WorkerFrame) -> i32,
    pub(crate) destroy_begin: extern "C" fn(*mut WorkerFrame) -> i32,
    pub(crate) destroyed: extern "C" fn(*mut WorkerFrame) -> i32,
    pub(crate) transfer: extern "C" fn(u64, *mut *mut Worker, *mut *mut Worker) -> i32,
    pub(crate) observe: extern "C" fn(u64, *mut Worker, *mut WorkerStatus) -> i32,
    pub(crate) close: extern "C" fn(u64, *mut Worker) -> i32,
    pub(crate) tryjoin: extern "C" fn(u64, *mut Worker) -> i32,
    pub(crate) identity_return: extern "C" fn(u64, *mut *mut Worker) -> i32,
    pub(crate) submit: extern "C" fn(u64, *mut Worker, *mut Material, *mut *mut Work) -> i32,
    pub(crate) take:
        extern "C" fn(*mut Worker, *mut *mut Work, *mut *mut c_void, *mut usize) -> i32,
    pub(crate) complete: extern "C" fn(*mut Worker, *mut *mut Work, i32) -> i32,
    pub(crate) work_return: extern "C" fn(u64, *mut *mut Work, *mut i32) -> i32,
    pub(crate) material_current: extern "C" fn(u64, *mut Material, *mut u64) -> i32,
    pub(crate) worker_material_current: extern "C" fn(*mut Worker, *mut Work, *mut u64) -> i32,
    pub(crate) read: extern "C" fn(*mut Worker, *mut Work, usize, *mut MaterialRead) -> i32,
    pub(crate) material_return: extern "C" fn(u64, *mut *mut Material) -> i32,
}

impl Api {
    /// Resolves the complete current physical and material consumer interface.
    ///
    /// # Errors
    /// Refuses a missing symbol before any native worker or control birth.
    pub(crate) fn resolve() -> Result<Self, i32> {
        macro_rules! resolve {
            ($name:literal, $ty:ty) => {{
                let address = symbol($name).ok_or(-libc::ENOSYS)?;
                // SAFETY: each matched export has the exact declared private ABI.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(address) }
            }};
        }
        Ok(Self {
            create: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_create_v1",
                extern "C" fn(
                    u64,
                    *mut RuntimePurpose,
                    *mut WorkerClaim,
                    *mut c_void,
                    *mut c_void,
                    *mut c_void,
                    *mut *mut Worker,
                ) -> i32
            ),
            control_use: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_control_use_v1",
                extern "C" fn(u64, *mut Worker, *mut c_void) -> i32
            ),
            control_retire: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_control_retire_v1",
                extern "C" fn(u64, *mut Worker, *mut c_void) -> i32
            ),
            allocation_begin: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_allocation_begin_v1",
                extern "C" fn(*mut WorkerFrame) -> i32
            ),
            allocation_result: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_allocation_result_v1",
                extern "C" fn(*mut WorkerFrame, *mut c_void, *mut c_void) -> i32
            ),
            initialized: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_initialized_v1",
                extern "C" fn(*mut WorkerFrame) -> i32
            ),
            destroy_begin: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_destroy_begin_v1",
                extern "C" fn(*mut WorkerFrame) -> i32
            ),
            destroyed: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_destroyed_v1",
                extern "C" fn(*mut WorkerFrame) -> i32
            ),
            transfer: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_transfer_v1",
                extern "C" fn(u64, *mut *mut Worker, *mut *mut Worker) -> i32
            ),
            observe: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_observe_v1",
                extern "C" fn(u64, *mut Worker, *mut WorkerStatus) -> i32
            ),
            close: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_close_v1",
                extern "C" fn(u64, *mut Worker) -> i32
            ),
            tryjoin: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_tryjoin_v1",
                extern "C" fn(u64, *mut Worker) -> i32
            ),
            identity_return: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_identity_return_v1",
                extern "C" fn(u64, *mut *mut Worker) -> i32
            ),
            submit: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_submit_v1",
                extern "C" fn(u64, *mut Worker, *mut Material, *mut *mut Work) -> i32
            ),
            take: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_take_v1",
                extern "C" fn(*mut Worker, *mut *mut Work, *mut *mut c_void, *mut usize) -> i32
            ),
            complete: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_complete_v1",
                extern "C" fn(*mut Worker, *mut *mut Work, i32) -> i32
            ),
            work_return: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_work_return_v1",
                extern "C" fn(u64, *mut *mut Work, *mut i32) -> i32
            ),
            material_current: resolve!(
                c"qemu_plugin_crucible_fingerprint_material_current_v1",
                extern "C" fn(u64, *mut Material, *mut u64) -> i32
            ),
            worker_material_current: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_material_current_v1",
                extern "C" fn(*mut Worker, *mut Work, *mut u64) -> i32
            ),
            read: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_material_read_v1",
                extern "C" fn(*mut Worker, *mut Work, usize, *mut MaterialRead) -> i32
            ),
            material_return: resolve!(
                c"qemu_plugin_crucible_fingerprint_material_return_v1",
                extern "C" fn(u64, *mut *mut Material) -> i32
            ),
        })
    }
}

fn symbol(name: &CStr) -> Option<*mut c_void> {
    // SAFETY: the static C string is terminated and the query retains no borrow.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    (!address.is_null()).then_some(address)
}
