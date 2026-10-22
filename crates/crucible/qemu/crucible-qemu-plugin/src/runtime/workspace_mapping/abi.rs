//! Matches the four physical workspace mapping declarations in the owning SDK.
// SPDX-License-Identifier: GPL-2.0-only

use crate::StartupSourceError;
use crate::startup_source::runtime_purpose::RuntimePurpose;
use std::ffi::c_void;

/// Names the actual opaque Source mapping owner without exposing its layout.
#[repr(C)]
pub(super) struct Mapping {
    _private: [u8; 0],
}

#[derive(Clone, Copy)]
pub(super) struct Api {
    pub(super) create: extern "C" fn(u64, *mut *mut Mapping, *mut *mut c_void, *mut usize) -> i32,
    pub(super) transfer:
        extern "C" fn(u64, *mut RuntimePurpose, *mut *mut Mapping, *mut *mut Mapping) -> i32,
    pub(super) current: extern "C" fn(u64, *mut Mapping) -> i32,
    pub(super) identity_return: extern "C" fn(u64, *mut *mut Mapping) -> i32,
}

impl Api {
    /// Resolves the complete physical interface before its first constructor call.
    ///
    /// # Errors
    /// Refuses missing declarations without probing an obsolete interface.
    pub(super) fn resolve() -> Result<Self, StartupSourceError> {
        macro_rules! entry {
            ($name:literal, $signature:ty) => {{
                // SAFETY: the matched owning SDK declares this literal C symbol.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(StartupSourceError::Unavailable {
                        symbol: $name.to_str().map_err(|_| StartupSourceError::Ownership {
                            reason: "workspace mapping symbol is not ASCII",
                        })?,
                    });
                }
                // SAFETY: the signature matches the genuine four-method SDK.
                unsafe { std::mem::transmute::<*mut c_void, $signature>(address) }
            }};
        }
        Ok(Self {
            create: entry!(
                c"qemu_plugin_crucible_startup_workspace_mapping_create_v1",
                extern "C" fn(u64, *mut *mut Mapping, *mut *mut c_void, *mut usize) -> i32
            ),
            transfer: entry!(
                c"qemu_plugin_crucible_startup_workspace_mapping_transfer_v1",
                extern "C" fn(
                    u64,
                    *mut RuntimePurpose,
                    *mut *mut Mapping,
                    *mut *mut Mapping,
                ) -> i32
            ),
            current: entry!(
                c"qemu_plugin_crucible_startup_workspace_mapping_current_v1",
                extern "C" fn(u64, *mut Mapping) -> i32
            ),
            identity_return: entry!(
                c"qemu_plugin_crucible_startup_workspace_mapping_identity_return_v1",
                extern "C" fn(u64, *mut *mut Mapping) -> i32
            ),
        })
    }
}
