//! Binds the exact Source-owned callback-child physical SDK.
// SPDX-License-Identifier: GPL-2.0-only

use super::super::command_storage::NativeStorage as BridgeStorage;
use crate::StartupSourceError;
use crate::startup_source::runtime_purpose::{CallbackChildClaim, RuntimePurpose};
use std::ffi::c_void;

/// Names Source's opaque canonical child allocation owner.
#[repr(C)]
pub(in crate::runtime) struct Storage {
    _private: [u8; 0],
}

pub(super) type Initializer = extern "C" fn(
    u64,
    *mut Storage,
    *mut c_void,
    usize,
    usize,
    *mut BridgeStorage,
    *mut c_void,
) -> i32;

pub(super) type Destructor = extern "C" fn(u64, *mut Storage, *mut c_void, usize, usize) -> i32;

/// Copies journals after entered callbacks return; never lends a typed child.
#[repr(C)]
#[derive(Default)]
pub(super) struct Status {
    pub(super) schema_version: u32,
    pub(super) struct_size: u32,
    pub(super) extent_bytes: u64,
    pub(super) alignment_bytes: u64,
    pub(super) allocation_first_status: i32,
    pub(super) allocation_post_status: i32,
    pub(super) initialization_first_status: i32,
    pub(super) initialization_post_status: i32,
    pub(super) destructor_first_status: i32,
    pub(super) destructor_post_status: i32,
    pub(super) allocation_return_post_status: i32,
    pub(super) allocation_active: u32,
    pub(super) allocated: u32,
    pub(super) initialization_active: u32,
    pub(super) initialization_returned: u32,
    pub(super) placement_started: u32,
    pub(super) initialized: u32,
    pub(super) prefix_rollback_completed: u32,
    pub(super) placement_uncertain: u32,
    pub(super) destructor_attempted: u32,
    pub(super) destruction_active: u32,
    pub(super) destructor_returned: u32,
    pub(super) destroyed: u32,
    pub(super) destruction_uncertain: u32,
    pub(super) transferred: u32,
    pub(super) physical_returned: u32,
    pub(super) bridge_borrow_held: u32,
    pub(super) registration_retained: u32,
}

#[derive(Clone, Copy)]
pub(super) struct Api {
    pub(super) create: extern "C" fn(
        u64,
        *mut RuntimePurpose,
        *mut CallbackChildClaim,
        *mut BridgeStorage,
        *mut *mut Storage,
    ) -> i32,
    pub(super) initialize:
        extern "C" fn(u64, *mut Storage, Initializer, Destructor, *mut c_void) -> i32,
    pub(super) placement_begin: extern "C" fn(u64, *mut Storage) -> i32,
    pub(super) initialized: extern "C" fn(u64, *mut Storage) -> i32,
    pub(super) prefix_rollback: extern "C" fn(u64, *mut Storage) -> i32,
    pub(super) transfer:
        extern "C" fn(u64, *mut RuntimePurpose, *mut *mut Storage, *mut *mut Storage) -> i32,
    pub(super) current: extern "C" fn(u64, *mut Storage) -> i32,
    pub(super) destroyed: extern "C" fn(u64, *mut Storage) -> i32,
    pub(super) return_storage: extern "C" fn(u64, *mut *mut Storage) -> i32,
    pub(super) observe: extern "C" fn(u64, *mut Storage, *mut Status) -> i32,
    pub(super) holder_observe: extern "C" fn(u64, *mut *mut Storage, *mut *mut Storage) -> i32,
}

impl Api {
    /// Resolves only the literal owning SDK exports, without older fallbacks.
    ///
    /// # Errors
    /// Refuses any missing method before child creation can be attempted.
    pub(super) fn resolve() -> Result<Self, StartupSourceError> {
        macro_rules! entry {
            ($name:literal, $ty:ty) => {{
                // SAFETY: the immutable matched GPL SDK owns this exact C symbol.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(StartupSourceError::Unavailable {
                        symbol: $name.to_str().map_err(|_| StartupSourceError::Ownership {
                            reason: "callback-child symbol is not ASCII",
                        })?,
                    });
                }
                // SAFETY: the declared signature exactly matches the owning SDK.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(address) }
            }};
        }
        Ok(Self {
            create: entry!(
                c"qemu_plugin_crucible_callback_child_storage_create_v1",
                extern "C" fn(
                    u64,
                    *mut RuntimePurpose,
                    *mut CallbackChildClaim,
                    *mut BridgeStorage,
                    *mut *mut Storage,
                ) -> i32
            ),
            initialize: entry!(
                c"qemu_plugin_crucible_callback_child_storage_initialize_v1",
                extern "C" fn(u64, *mut Storage, Initializer, Destructor, *mut c_void) -> i32
            ),
            placement_begin: entry!(
                c"qemu_plugin_crucible_callback_child_storage_placement_begin_v1",
                extern "C" fn(u64, *mut Storage) -> i32
            ),
            initialized: entry!(
                c"qemu_plugin_crucible_callback_child_storage_initialized_v1",
                extern "C" fn(u64, *mut Storage) -> i32
            ),
            prefix_rollback: entry!(
                c"qemu_plugin_crucible_callback_child_storage_prefix_rollback_v1",
                extern "C" fn(u64, *mut Storage) -> i32
            ),
            transfer: entry!(
                c"qemu_plugin_crucible_callback_child_storage_transfer_v1",
                extern "C" fn(
                    u64,
                    *mut RuntimePurpose,
                    *mut *mut Storage,
                    *mut *mut Storage,
                ) -> i32
            ),
            current: entry!(
                c"qemu_plugin_crucible_callback_child_storage_current_v1",
                extern "C" fn(u64, *mut Storage) -> i32
            ),
            destroyed: entry!(
                c"qemu_plugin_crucible_callback_child_storage_destroyed_v1",
                extern "C" fn(u64, *mut Storage) -> i32
            ),
            return_storage: entry!(
                c"qemu_plugin_crucible_callback_child_storage_return_v1",
                extern "C" fn(u64, *mut *mut Storage) -> i32
            ),
            observe: entry!(
                c"qemu_plugin_crucible_callback_child_storage_observe_v1",
                extern "C" fn(u64, *mut Storage, *mut Status) -> i32
            ),
            holder_observe: entry!(
                c"qemu_plugin_crucible_callback_child_storage_holder_observe_v1",
                extern "C" fn(u64, *mut *mut Storage, *mut *mut Storage) -> i32
            ),
        })
    }
}
