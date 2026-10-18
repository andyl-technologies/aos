//! Binds only the four actual Source-owned completed-child SDK methods.
// SPDX-License-Identifier: GPL-2.0-only

use super::super::callback_child::NativeStorage;
use crate::StartupSourceError;
use std::ffi::c_void;

/// Matches the SDK's true opaque QemuCrucibleCallbackChildOwner tag.
#[repr(C)]
pub(super) struct Owner {
    _private: [u8; 0],
}

#[derive(Clone, Copy)]
pub(super) struct Api {
    pub(super) create: extern "C" fn(u64, *mut NativeStorage, *mut *mut Owner) -> i32,
    pub(super) transfer: extern "C" fn(u64, *mut *mut Owner, *mut *mut Owner) -> i32,
    pub(super) current: extern "C" fn(u64, *mut Owner) -> i32,
    pub(super) return_owner: extern "C" fn(u64, *mut *mut Owner) -> i32,
}

impl Api {
    /// Resolves the complete immutable Source owner ABI before any effect.
    ///
    /// # Errors
    /// Refuses missing or invalid symbols without an older constructor fallback.
    pub(super) fn resolve() -> Result<Self, StartupSourceError> {
        macro_rules! entry {
            ($name:literal, $ty:ty) => {{
                // SAFETY: the immutable matched SDK declares this actual GPL ABI.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(StartupSourceError::Unavailable {
                        symbol: $name.to_str().map_err(|_| StartupSourceError::Ownership {
                            reason: "registration-owner symbol is not ASCII",
                        })?,
                    });
                }
                // SAFETY: these exact signatures are copied from the owning SDK.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(address) }
            }};
        }
        Ok(Self {
            create: entry!(
                c"qemu_plugin_crucible_callback_registration_owner_create_v1",
                extern "C" fn(u64, *mut NativeStorage, *mut *mut Owner) -> i32
            ),
            transfer: entry!(
                c"qemu_plugin_crucible_callback_registration_owner_transfer_v1",
                extern "C" fn(u64, *mut *mut Owner, *mut *mut Owner) -> i32
            ),
            current: entry!(
                c"qemu_plugin_crucible_callback_registration_owner_current_v1",
                extern "C" fn(u64, *mut Owner) -> i32
            ),
            return_owner: entry!(
                c"qemu_plugin_crucible_callback_registration_owner_return_v1",
                extern "C" fn(u64, *mut *mut Owner) -> i32
            ),
        })
    }
}
