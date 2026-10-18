//! Binds the authentic Source-owned initial exchange and physical slot.
// SPDX-License-Identifier: GPL-2.0-only

use super::super::setup_mapping::NativeMapping;
use super::super::{StartupSourceError, runtime_purpose::RuntimePurpose};
use std::ffi::c_void;

/// Names Source's genuine opaque complete initial-exchange owner.
#[repr(C)]
pub(super) struct Handshake {
    _private: [u8; 0],
}

/// Names Source's genuine selected-slot owner, separate from reply facts.
#[repr(C)]
pub(super) struct Slot {
    _private: [u8; 0],
}

/// Copies physical byte progress; it issues no slot or operation authority.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(in crate::startup_source) struct Status {
    pub(in crate::startup_source) schema_version: u32,
    pub(in crate::startup_source) struct_size: u32,
    pub(in crate::startup_source) written_bytes: u64,
    pub(in crate::startup_source) read_bytes: u64,
    pub(in crate::startup_source) first_status: i32,
    pub(in crate::startup_source) write_post_status: i32,
    pub(in crate::startup_source) read_post_status: i32,
    pub(in crate::startup_source) io_post_status: i32,
    pub(in crate::startup_source) wait_post_status: i32,
    pub(in crate::startup_source) last_io_status: i32,
    pub(in crate::startup_source) last_wait_status: i32,
    pub(in crate::startup_source) write_completed: u32,
    pub(in crate::startup_source) read_completed: u32,
    pub(in crate::startup_source) reply_validated: u32,
    pub(in crate::startup_source) selected_slot: u32,
    pub(in crate::startup_source) node_count: u32,
}

/// Holds the nine actual owning exchange and physical-slot methods.
#[derive(Clone, Copy)]
pub(super) struct Api {
    pub(super) write: extern "C" fn(u64, *mut *mut Handshake) -> i32,
    pub(super) read: extern "C" fn(u64, *mut Handshake) -> i32,
    pub(super) observe: extern "C" fn(u64, *mut Handshake, *mut Status) -> i32,
    pub(super) transfer:
        extern "C" fn(u64, *mut RuntimePurpose, *mut *mut Handshake, *mut *mut Handshake) -> i32,
    pub(super) return_handshake: extern "C" fn(u64, *mut *mut Handshake) -> i32,
    pub(super) create_slot:
        extern "C" fn(u64, *mut Handshake, *mut NativeMapping, *mut *mut Slot) -> i32,
    pub(super) current_slot: extern "C" fn(u64, *mut Slot) -> i32,
    pub(super) transfer_slot:
        extern "C" fn(u64, *mut RuntimePurpose, *mut *mut Slot, *mut *mut Slot) -> i32,
    pub(super) return_slot: extern "C" fn(u64, *mut *mut Slot) -> i32,
}

impl Api {
    /// Resolves the complete actual Source ABI before framed I/O.
    ///
    /// # Errors
    /// Refuses missing methods or invalid literal names; no raw-I/O fallback exists.
    pub(super) fn resolve() -> Result<Self, StartupSourceError> {
        macro_rules! entry {
            ($name:literal, $ty:ty) => {{
                // SAFETY: the frozen owning SDK declares this process-private ABI.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(StartupSourceError::Unavailable {
                        symbol: $name.to_str().map_err(|_| StartupSourceError::Ownership {
                            reason: "setup exchange symbol is not ASCII",
                        })?,
                    });
                }
                // SAFETY: this is the exact annotated SDK function signature.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(address) }
            }};
        }
        Ok(Self {
            write: entry!(
                c"qemu_plugin_crucible_startup_hello_write_v1",
                extern "C" fn(u64, *mut *mut Handshake) -> i32
            ),
            read: entry!(
                c"qemu_plugin_crucible_startup_hello_ack_read_v1",
                extern "C" fn(u64, *mut Handshake) -> i32
            ),
            observe: entry!(
                c"qemu_plugin_crucible_startup_hello_observe_v1",
                extern "C" fn(u64, *mut Handshake, *mut Status) -> i32
            ),
            transfer: entry!(
                c"qemu_plugin_crucible_startup_hello_transfer_v1",
                extern "C" fn(
                    u64,
                    *mut RuntimePurpose,
                    *mut *mut Handshake,
                    *mut *mut Handshake,
                ) -> i32
            ),
            return_handshake: entry!(
                c"qemu_plugin_crucible_startup_hello_return_v1",
                extern "C" fn(u64, *mut *mut Handshake) -> i32
            ),
            create_slot: entry!(
                c"qemu_plugin_crucible_startup_setup_slot_create_v1",
                extern "C" fn(u64, *mut Handshake, *mut NativeMapping, *mut *mut Slot) -> i32
            ),
            current_slot: entry!(
                c"qemu_plugin_crucible_startup_setup_slot_current_v1",
                extern "C" fn(u64, *mut Slot) -> i32
            ),
            transfer_slot: entry!(
                c"qemu_plugin_crucible_startup_setup_slot_transfer_v1",
                extern "C" fn(u64, *mut RuntimePurpose, *mut *mut Slot, *mut *mut Slot) -> i32
            ),
            return_slot: entry!(
                c"qemu_plugin_crucible_startup_setup_slot_return_v1",
                extern "C" fn(u64, *mut *mut Slot) -> i32
            ),
        })
    }
}
