//! Explicit private Source tables for callback-order fixtures, never native exports.
//!
//! The model is attached to one retained received-plan owner before acquisition.
//! It models only signed API results; it grants no native account or operation.
// SPDX-License-Identifier: GPL-2.0-only

use super::NativeStartupApi;

pub(crate) struct InstallerStartupSourceModel {
    pub(super) api: NativeStartupApi,
}

impl InstallerStartupSourceModel {
    pub(crate) const fn ready() -> Self {
        Self {
            api: NativeStartupApi {
                acquire: accept,
                check,
                query_slice: slice,
                registration_complete: complete,
            },
        }
    }

    pub(crate) const fn refused_acquisition() -> Self {
        Self {
            api: NativeStartupApi {
                acquire: refuse,
                ..Self::ready().api
            },
        }
    }
}

extern "C" fn accept(_plugin_id: u64, _plan_fd: i32) -> i32 {
    0
}

extern "C" fn refuse(_plugin_id: u64, _plan_fd: i32) -> i32 {
    -229
}

extern "C" fn check(_plugin_id: u64) -> i32 {
    0
}

extern "C" fn slice(_plugin_id: u64, bounded_ns: *mut u64) -> i32 {
    // SAFETY: the shared adapter lends an initialized u64 for this synchronous call.
    unsafe { *bounded_ns = 1_000_000 };
    0
}

extern "C" fn complete(_plugin_id: u64, status: i32) -> i32 {
    assert_eq!(status, 0);
    0
}
