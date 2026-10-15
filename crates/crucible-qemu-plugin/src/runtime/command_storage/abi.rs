//! Binds the exact Native physical command-storage SDK without a fallback.
// SPDX-License-Identifier: GPL-2.0-only

use crate::StartupSourceError;
use crate::startup_source::runtime_purpose::{CommandClaim, RuntimePurpose};
use std::ffi::c_void;

#[repr(C)]
pub(in crate::runtime) struct Storage {
    _private: [u8; 0],
}
#[repr(C)]
pub(super) struct PhysicalUse {
    _private: [u8; 0],
}

pub(super) type Initializer =
    extern "C" fn(*mut c_void, usize, usize, *mut c_void, *mut u32) -> i32;
pub(super) type Destructor = extern "C" fn(*mut c_void, usize, usize, *mut u32) -> i32;

/// Copies Native journals only; no getter reads a possibly destroyed Bridge.
#[repr(C)]
#[derive(Default)]
pub(super) struct Status {
    pub(super) schema_version: u32,
    pub(super) struct_size: u32,
    pub(super) extent_bytes: u64,
    pub(super) physical_alignment: u64,
    pub(super) allocation_first: i32,
    pub(super) allocation_post: i32,
    pub(super) initialization_first: i32,
    pub(super) initialization_post: i32,
    pub(super) destruction_first: i32,
    pub(super) destruction_post: i32,
    pub(super) allocation_return_post: i32,
    pub(super) allocated: u32,
    pub(super) initialization_attempted: u32,
    pub(super) placement_attempted: u32,
    pub(super) initialization_returned: u32,
    pub(super) initialized: u32,
    pub(super) initialization_uncertain: u32,
    pub(super) destruction_attempted: u32,
    pub(super) destruction_returned: u32,
    pub(super) destroyed: u32,
    pub(super) destruction_uncertain: u32,
    pub(super) free_attempted: u32,
    pub(super) physical_returned: u32,
    pub(super) held: u32,
    pub(super) transferred: u32,
    pub(super) use_held: u32,
}

#[derive(Clone, Copy)]
pub(super) struct Api {
    pub(super) create:
        extern "C" fn(u64, *mut RuntimePurpose, *mut CommandClaim, *mut *mut Storage) -> i32,
    pub(super) initialize:
        extern "C" fn(u64, *mut Storage, Initializer, Destructor, *mut c_void) -> i32,
    pub(super) placement_begin: extern "C" fn(u64, *mut Storage) -> i32,
    pub(super) transfer:
        extern "C" fn(u64, *mut RuntimePurpose, *mut *mut Storage, *mut *mut Storage) -> i32,
    pub(super) borrow: extern "C" fn(u64, *mut Storage, *mut *mut PhysicalUse, *mut u64) -> i32,
    pub(super) current:
        extern "C" fn(u64, *mut PhysicalUse, u64, *mut *mut c_void, *mut usize, *mut usize) -> i32,
    pub(super) return_use: extern "C" fn(u64, *mut *mut PhysicalUse, u64) -> i32,
    pub(super) observe: extern "C" fn(u64, *mut Storage, *mut Status) -> i32,
    pub(super) holder_observe: extern "C" fn(u64, *mut *mut Storage, *mut *mut Storage) -> i32,
    pub(super) return_storage: extern "C" fn(u64, *mut *mut Storage) -> i32,
}

impl Api {
    pub(super) fn resolve() -> Result<Self, StartupSourceError> {
        macro_rules! entry {
            ($name:literal, $ty:ty) => {{
                // SAFETY: the frozen GPL-private SDK owns this exact C export.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(StartupSourceError::Unavailable {
                        symbol: $name.to_str().map_err(|_| StartupSourceError::Ownership {
                            reason: "command storage symbol is not ASCII",
                        })?,
                    });
                }
                // SAFETY: the matched symbol has the literal declared signature.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(address) }
            }};
        }
        Ok(Self {
            create: entry!(
                c"qemu_plugin_crucible_command_consumer_storage_create_v1",
                extern "C" fn(
                    u64,
                    *mut RuntimePurpose,
                    *mut CommandClaim,
                    *mut *mut Storage,
                ) -> i32
            ),
            initialize: entry!(
                c"qemu_plugin_crucible_command_consumer_storage_initialize_v1",
                extern "C" fn(u64, *mut Storage, Initializer, Destructor, *mut c_void) -> i32
            ),
            placement_begin: entry!(
                c"qemu_plugin_crucible_command_consumer_storage_placement_begin_v1",
                extern "C" fn(u64, *mut Storage) -> i32
            ),
            transfer: entry!(
                c"qemu_plugin_crucible_command_consumer_storage_transfer_v1",
                extern "C" fn(
                    u64,
                    *mut RuntimePurpose,
                    *mut *mut Storage,
                    *mut *mut Storage,
                ) -> i32
            ),
            borrow: entry!(
                c"qemu_plugin_crucible_command_consumer_storage_use_borrow_v1",
                extern "C" fn(u64, *mut Storage, *mut *mut PhysicalUse, *mut u64) -> i32
            ),
            current: entry!(
                c"qemu_plugin_crucible_command_consumer_storage_use_current_v1",
                extern "C" fn(
                    u64,
                    *mut PhysicalUse,
                    u64,
                    *mut *mut c_void,
                    *mut usize,
                    *mut usize,
                ) -> i32
            ),
            return_use: entry!(
                c"qemu_plugin_crucible_command_consumer_storage_use_return_v1",
                extern "C" fn(u64, *mut *mut PhysicalUse, u64) -> i32
            ),
            observe: entry!(
                c"qemu_plugin_crucible_command_consumer_storage_observe_v1",
                extern "C" fn(u64, *mut Storage, *mut Status) -> i32
            ),
            holder_observe: entry!(
                c"qemu_plugin_crucible_command_consumer_storage_holder_observe_v1",
                extern "C" fn(u64, *mut *mut Storage, *mut *mut Storage) -> i32
            ),
            return_storage: entry!(
                c"qemu_plugin_crucible_command_consumer_storage_return_v1",
                extern "C" fn(u64, *mut *mut Storage) -> i32
            ),
        })
    }
}
