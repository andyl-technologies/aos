//! Resolves the matched GPL-private Native received-delivery lifetime ABI.
// SPDX-License-Identifier: GPL-2.0-only

use super::super::abi::Receive;
use crate::StartupSourceError;
use std::ffi::c_void;

/// Names the opaque Source-owned delivery lifetime, never a module payload.
#[repr(C)]
pub(super) struct Owner {
    _private: [u8; 0],
}

/// Contains the actual delivery owner and physical payload entry points.
#[derive(Clone, Copy)]
pub(in crate::runtime::command_receive) struct Api {
    pub(super) create: extern "C" fn(u64, *mut Receive, u64, *mut *mut Owner, *mut u64) -> i32,
    pub(super) transfer: extern "C" fn(u64, *mut *mut Owner, u64, *mut *mut Owner) -> i32,
    pub(super) current: extern "C" fn(u64, *mut Owner, u64) -> i32,
    pub(super) identity_return: extern "C" fn(u64, *mut *mut Owner, u64) -> i32,
    pub(super) ready_return: extern "C" fn(u64, *mut Owner, u64, *mut u32) -> i32,
    pub(super) payload_claim: extern "C" fn(u64, *mut Owner, u64) -> i32,
    pub(super) payload_return: extern "C" fn(u64, *mut Owner, u64) -> i32,
}

impl Api {
    /// Resolves every owner operation before physical member birth.
    ///
    /// # Errors
    /// Refuses an absent matched symbol; there is no legacy or local substitute.
    pub(in crate::runtime::command_receive) fn resolve() -> Result<Self, StartupSourceError> {
        macro_rules! entry {
            ($name:literal, $ty:ty) => {{
                // SAFETY: the selected SDK defines this exact private signature.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(StartupSourceError::Unavailable {
                        symbol: $name.to_str().map_err(|_| StartupSourceError::Ownership {
                            reason: "delivery owner symbol is not ASCII",
                        })?,
                    });
                }
                // SAFETY: Source's matched declaration has the indicated type.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(address) }
            }};
        }

        Ok(Self {
            create: entry!(
                c"qemu_plugin_crucible_startup_source_received_delivery_create_v1",
                extern "C" fn(u64, *mut Receive, u64, *mut *mut Owner, *mut u64) -> i32
            ),
            transfer: entry!(
                c"qemu_plugin_crucible_startup_source_received_delivery_transfer_v1",
                extern "C" fn(u64, *mut *mut Owner, u64, *mut *mut Owner) -> i32
            ),
            current: entry!(
                c"qemu_plugin_crucible_startup_source_received_delivery_current_v1",
                extern "C" fn(u64, *mut Owner, u64) -> i32
            ),
            identity_return: entry!(
                c"qemu_plugin_crucible_startup_source_received_delivery_identity_return_v1",
                extern "C" fn(u64, *mut *mut Owner, u64) -> i32
            ),
            ready_return: entry!(
                c"qemu_plugin_crucible_startup_source_received_delivery_ready_return_v1",
                extern "C" fn(u64, *mut Owner, u64, *mut u32) -> i32
            ),
            payload_claim: entry!(
                c"qemu_plugin_crucible_startup_source_received_delivery_payload_claim_v1",
                extern "C" fn(u64, *mut Owner, u64) -> i32
            ),
            payload_return: entry!(
                c"qemu_plugin_crucible_startup_source_received_delivery_payload_return_v1",
                extern "C" fn(u64, *mut Owner, u64) -> i32
            ),
        })
    }
}
