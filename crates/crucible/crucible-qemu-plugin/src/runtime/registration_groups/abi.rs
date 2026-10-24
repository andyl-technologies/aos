//! Mirrors the owning SDK's complete-group identity and factual receipt ABI.
//! This is GPL process-private registration plumbing, never a shared wire type.
// SPDX-License-Identifier: GPL-2.0-only

use super::super::callback_child::NativeStorage;
use super::Kind;
use crate::StartupSourceError;
use std::ffi::c_void;

/// Matches the true opaque QemuCrucibleCallbackRegistrationGroupOwner tag.
#[repr(C)]
pub(super) struct Owner {
    _private: [u8; 0],
}

/// Copies the exact owning SDK journal; no field grants registration or return.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Status {
    pub(super) publication_serial: u64,
    pub(super) registrar_serial: u64,
    pub(super) member_count: u64,
    pub(super) installed_members: u64,
    pub(super) attempted_mask: u32,
    pub(super) installed_mask: u32,
    pub(super) first_status: i32,
    pub(super) post_status: i32,
    pub(super) native_first_status: i32,
    pub(super) native_post_status: i32,
    pub(super) native_return_status: i32,
    pub(super) receipt_status: i32,
    pub(super) terminal_status: i32,
    pub(super) receipt_observed: u32,
    pub(super) native_debt: u32,
    pub(super) span_held: u32,
    pub(super) receipt_active: u32,
    pub(super) terminal_active: u32,
    pub(super) reserved: u32,
    pub(super) effect_started: u32,
    pub(super) effect_finished: u32,
    pub(super) complete: u32,
    pub(super) module_retained: u32,
    pub(super) borrow_retained: u32,
    pub(super) terminal: u32,
}

#[derive(Clone, Copy)]
pub(super) struct Api {
    pub(super) begin:
        extern "C" fn(u64, *mut NativeStorage, Kind, *mut *mut Owner, *mut u64) -> i32,
    pub(super) transfer: extern "C" fn(u64, *mut *mut Owner, u64, Kind, *mut *mut Owner) -> i32,
    pub(super) current:
        extern "C" fn(u64, *mut Owner, u64, Kind, *mut *mut c_void, *mut usize, *mut usize) -> i32,
    pub(super) span_return: extern "C" fn(u64, *mut *mut Owner, u64, Kind) -> i32,
    pub(super) owner_return: extern "C" fn(u64, *mut *mut Owner, u64, Kind) -> i32,
    pub(super) holder_observe:
        extern "C" fn(u64, *mut *mut Owner, Kind, *mut *mut Owner, *mut u64) -> i32,
    pub(super) postreceipt: extern "C" fn(u64, *mut Owner, u64, Kind) -> i32,
    pub(super) status_observe: extern "C" fn(u64, *mut Owner, u64, Kind, *mut Status) -> i32,
}

impl Api {
    /// Resolves all literal current methods before group entry.
    ///
    /// # Errors
    /// Refuses a missing SDK symbol without a single-family or legacy fallback.
    pub(super) fn resolve() -> Result<Self, StartupSourceError> {
        macro_rules! entry {
            ($name:literal, $ty:ty) => {{
                // SAFETY: the matched immutable SDK owns this exact GPL ABI.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(StartupSourceError::Unavailable {
                        symbol: $name.to_str().map_err(|_| StartupSourceError::Ownership {
                            reason: "group symbol is not ASCII",
                        })?,
                    });
                }
                // SAFETY: every signature matches the owning SDK's declaration.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(address) }
            }};
        }
        Ok(Self {
            begin: entry!(
                c"qemu_plugin_crucible_callback_group_begin_v1",
                extern "C" fn(u64, *mut NativeStorage, Kind, *mut *mut Owner, *mut u64) -> i32
            ),
            transfer: entry!(
                c"qemu_plugin_crucible_callback_group_transfer_v1",
                extern "C" fn(u64, *mut *mut Owner, u64, Kind, *mut *mut Owner) -> i32
            ),
            current: entry!(
                c"qemu_plugin_crucible_callback_group_current_v1",
                extern "C" fn(
                    u64,
                    *mut Owner,
                    u64,
                    Kind,
                    *mut *mut c_void,
                    *mut usize,
                    *mut usize,
                ) -> i32
            ),
            span_return: entry!(
                c"qemu_plugin_crucible_callback_group_span_return_v1",
                extern "C" fn(u64, *mut *mut Owner, u64, Kind) -> i32
            ),
            owner_return: entry!(
                c"qemu_plugin_crucible_callback_group_owner_return_v1",
                extern "C" fn(u64, *mut *mut Owner, u64, Kind) -> i32
            ),
            holder_observe: entry!(
                c"qemu_plugin_crucible_callback_group_holder_observe_v1",
                extern "C" fn(u64, *mut *mut Owner, Kind, *mut *mut Owner, *mut u64) -> i32
            ),
            postreceipt: entry!(
                c"qemu_plugin_crucible_callback_group_postreceipt_v1",
                extern "C" fn(u64, *mut Owner, u64, Kind) -> i32
            ),
            status_observe: entry!(
                c"qemu_plugin_crucible_callback_group_status_observe_v1",
                extern "C" fn(u64, *mut Owner, u64, Kind, *mut Status) -> i32
            ),
        })
    }
}
