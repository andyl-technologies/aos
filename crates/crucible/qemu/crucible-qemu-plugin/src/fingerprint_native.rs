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

/// Carries one movable Source-issued material incarnation.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MaterialRef {
    /// Identifies canonical Source storage; Rust never dereferences this pointer.
    pub(crate) owner: *mut Material,
    /// Distinguishes this admitted incarnation from later reuse of the same slot.
    pub(crate) serial: u64,
}

impl MaterialRef {
    pub(crate) const fn empty() -> Self {
        Self {
            owner: std::ptr::null_mut(),
            serial: 0,
        }
    }

    pub(crate) fn is_empty(self) -> bool {
        self.owner.is_null() && self.serial == 0
    }

    pub(crate) fn is_live(self) -> bool {
        !self.owner.is_null() && self.serial != 0
    }
}

impl Default for MaterialRef {
    fn default() -> Self {
        Self::empty()
    }
}

/// Carries one movable Source-issued work incarnation.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WorkRef {
    /// Identifies canonical Source storage; Rust never dereferences this pointer.
    pub(crate) owner: *mut Work,
    /// Distinguishes this admitted incarnation from later reuse of the same cell.
    pub(crate) serial: u64,
}

impl WorkRef {
    pub(crate) const fn empty() -> Self {
        Self {
            owner: std::ptr::null_mut(),
            serial: 0,
        }
    }

    pub(crate) fn is_empty(self) -> bool {
        self.owner.is_null() && self.serial == 0
    }

    pub(crate) fn is_live(self) -> bool {
        !self.owner.is_null() && self.serial != 0
    }
}

impl Default for WorkRef {
    fn default() -> Self {
        Self::empty()
    }
}

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
#[derive(Debug)]
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
    pub(crate) control_lifetime_status: i32,
    pub(crate) control_lifetime_uncertain: u32,
}

impl Default for WorkerStatus {
    fn default() -> Self {
        Self {
            schema_version: 2,
            struct_size: size_of::<Self>() as u32,
            first_status: 0,
            post_status: 0,
            create_status: 0,
            mask_restore_status: 0,
            attr_destroy_status: 0,
            entry_status: 0,
            join_status: 0,
            unmap_status: 0,
            residual_bytes: 0,
            births_reserved: 0,
            born: 0,
            initialized: 0,
            closing: 0,
            entry_returned: 0,
            joined: 0,
            destroyed: 0,
            physical_returned: 0,
            material_held: 0,
            bytes_held: 0,
            control_users: 0,
            destruction_calls: 0,
            control_status: 0,
            destructor_status: 0,
            destruction_first_status: 0,
            destruction_active: 0,
            destruction_returned: 0,
            destruction_begun: 0,
            destruction_uncertain: 0,
            control_lifetime_status: 0,
            control_lifetime_uncertain: 0,
        }
    }
}

pub(crate) use crate::fingerprint_sampler::read_receipt::MaterialRead;

/// Copies durable native facts without reviving an ended Material owner.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct PipelineStatus {
    pub(crate) schema_version: u32,
    pub(crate) struct_size: u32,
    pub(crate) material_serial: u64,
    pub(crate) work_serial: u64,
    pub(crate) read_offset: u64,
    pub(crate) read: MaterialRead,
    pub(crate) material_first_status: i32,
    pub(crate) material_post_status: i32,
    pub(crate) submit_post_status: i32,
    pub(crate) complete_first_status: i32,
    pub(crate) complete_status: i32,
    pub(crate) work_result: i32,
    pub(crate) work_return_first_status: i32,
    pub(crate) work_return_status: i32,
    pub(crate) material_return_first_status: i32,
    pub(crate) material_return_status: i32,
    pub(crate) close_status: i32,
    pub(crate) submitted: u32,
    pub(crate) queued: u32,
    pub(crate) active: u32,
    pub(crate) completed: u32,
    pub(crate) bytes_held: u32,
    pub(crate) complete_attempted: u32,
    pub(crate) work_return_attempted: u32,
    pub(crate) work_returned: u32,
    pub(crate) cancelled: u32,
    pub(crate) material_return_attempted: u32,
    pub(crate) close_attempted: u32,
    pub(crate) close_uncertain: u32,
    pub(crate) physical_returned: u32,
}

impl Default for PipelineStatus {
    fn default() -> Self {
        Self {
            schema_version: 1,
            struct_size: size_of::<Self>() as u32,
            material_serial: 0,
            work_serial: 0,
            read_offset: 0,
            read: MaterialRead::default(),
            material_first_status: 0,
            material_post_status: 0,
            submit_post_status: 0,
            complete_first_status: 0,
            complete_status: 0,
            work_result: 0,
            work_return_first_status: 0,
            work_return_status: 0,
            material_return_first_status: 0,
            material_return_status: 0,
            close_status: 0,
            submitted: 0,
            queued: 0,
            active: 0,
            completed: 0,
            bytes_held: 0,
            complete_attempted: 0,
            work_return_attempted: 0,
            work_returned: 0,
            cancelled: 0,
            material_return_attempted: 0,
            close_attempted: 0,
            close_uncertain: 0,
            physical_returned: 0,
        }
    }
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(size_of::<WorkerStatus>() == 152);
    assert!(size_of::<PipelineStatus>() == 160);
    assert!(size_of::<MaterialRef>() == 16);
    assert!(size_of::<WorkRef>() == 16);
};

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
    pub(crate) submit: extern "C" fn(u64, *mut Worker, *const MaterialRef, *mut WorkRef) -> i32,
    pub(crate) take: extern "C" fn(*mut Worker, *mut WorkRef, *mut *mut c_void, *mut usize) -> i32,
    pub(crate) complete: extern "C" fn(*mut Worker, *mut WorkRef, i32) -> i32,
    pub(crate) work_return: extern "C" fn(u64, *mut WorkRef, *mut i32) -> i32,
    pub(crate) material_current: extern "C" fn(u64, *const MaterialRef, *mut u64) -> i32,
    pub(crate) worker_material_current: extern "C" fn(*mut Worker, *const WorkRef, *mut u64) -> i32,
    pub(crate) read: extern "C" fn(*mut Worker, *const WorkRef, usize, *mut MaterialRead) -> i32,
    pub(crate) material_return: extern "C" fn(u64, *mut MaterialRef) -> i32,
    pub(crate) pipeline_observe: extern "C" fn(u64, *const MaterialRef, *mut PipelineStatus) -> i32,
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
                c"qemu_plugin_crucible_fingerprint_worker_observe_v2",
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
                c"qemu_plugin_crucible_fingerprint_worker_submit_v2",
                extern "C" fn(u64, *mut Worker, *const MaterialRef, *mut WorkRef) -> i32
            ),
            take: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_take_v2",
                extern "C" fn(*mut Worker, *mut WorkRef, *mut *mut c_void, *mut usize) -> i32
            ),
            complete: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_complete_v2",
                extern "C" fn(*mut Worker, *mut WorkRef, i32) -> i32
            ),
            work_return: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_work_return_v2",
                extern "C" fn(u64, *mut WorkRef, *mut i32) -> i32
            ),
            material_current: resolve!(
                c"qemu_plugin_crucible_fingerprint_material_current_v2",
                extern "C" fn(u64, *const MaterialRef, *mut u64) -> i32
            ),
            worker_material_current: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_material_current_v2",
                extern "C" fn(*mut Worker, *const WorkRef, *mut u64) -> i32
            ),
            read: resolve!(
                c"qemu_plugin_crucible_fingerprint_worker_material_read_v2",
                extern "C" fn(*mut Worker, *const WorkRef, usize, *mut MaterialRead) -> i32
            ),
            material_return: resolve!(
                c"qemu_plugin_crucible_fingerprint_material_return_v2",
                extern "C" fn(u64, *mut MaterialRef) -> i32
            ),
            pipeline_observe: resolve!(
                c"qemu_plugin_crucible_fingerprint_material_pipeline_observe_v1",
                extern "C" fn(u64, *const MaterialRef, *mut PipelineStatus) -> i32
            ),
        })
    }
}

fn symbol(name: &CStr) -> Option<*mut c_void> {
    // SAFETY: the static C string is terminated and the query retains no borrow.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    (!address.is_null()).then_some(address)
}
