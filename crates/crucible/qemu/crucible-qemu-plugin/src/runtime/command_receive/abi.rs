//! Binds the frozen physical member and receive ABI without action authority.
// SPDX-License-Identifier: GPL-2.0-only

use super::super::control_component::NativeComponent;
use super::super::live_callbacks::{ControlIntentFacts, ParkReturnWriteProgress, ReceiveProgress};
use crate::StartupSourceError;
use std::ffi::c_void;

/// Names the genuine opaque Source command-consumer member.
#[repr(C)]
pub(super) struct Member {
    _private: [u8; 0],
}

/// Names the genuine opaque Source receive transaction owner.
#[repr(C)]
pub(super) struct Receive {
    _private: [u8; 0],
}

/// Matches the distinct first-bound bounded-reader callback signature.
pub(super) type Reader =
    extern "C" fn(*mut ControlIntentFacts, *mut ReceiveProgress, *mut c_void) -> i32;

/// Matches the first-bound Source-produced Park journal writer callback.
pub(super) type Writer =
    extern "C" fn(*const u8, usize, *mut ParkReturnWriteProgress, *mut c_void) -> i32;

/// Copies Source's actual callback and validation dispositions.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct Status {
    pub(super) serial: u64,
    pub(super) publisher_sequence: u64,
    pub(super) first_status: i32,
    pub(super) reader_status: i32,
    pub(super) validation_status: i32,
    pub(super) post_status: i32,
    pub(super) invocation_attempted: u32,
    pub(super) invocation_returned: u32,
    pub(super) progress_valid: u32,
    pub(super) terminal_uncertain: u32,
}

/// Holds only the nine genuine physical member/receive entry points.
#[derive(Clone, Copy)]
pub(super) struct Api {
    pub(super) member_create:
        extern "C" fn(u64, *mut NativeComponent, Reader, Writer, *mut *mut Member) -> i32,
    pub(super) member_transfer: extern "C" fn(u64, *mut *mut Member, *mut *mut Member) -> i32,
    pub(super) member_current: extern "C" fn(u64, *mut Member) -> i32,
    pub(super) member_return: extern "C" fn(u64, *mut *mut Member) -> i32,
    pub(super) receive_create: extern "C" fn(u64, *mut Member, *mut *mut Receive, *mut u64) -> i32,
    pub(super) receive_transfer:
        extern "C" fn(u64, *mut *mut Receive, u64, *mut *mut Receive) -> i32,
    pub(super) receive_observe: extern "C" fn(
        u64,
        *mut Receive,
        u64,
        *mut ControlIntentFacts,
        *mut ReceiveProgress,
        *mut Status,
    ) -> i32,
    pub(super) receive_current: extern "C" fn(u64, *mut Receive, u64) -> i32,
    pub(super) receive_return: extern "C" fn(u64, *mut *mut Receive, u64) -> i32,
}

impl Api {
    /// Resolves the complete actual physical ABI before any birth.
    ///
    /// # Errors
    /// Refuses absent symbols or invalid literal names without a legacy fallback.
    pub(super) fn resolve() -> Result<Self, StartupSourceError> {
        macro_rules! entry {
            ($name:literal, $ty:ty) => {{
                // SAFETY: the selected frozen SDK owns this exact GPL-private ABI.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(StartupSourceError::Unavailable {
                        symbol: $name.to_str().map_err(|_| StartupSourceError::Ownership {
                            reason: "physical receive symbol is not ASCII",
                        })?,
                    });
                }
                // SAFETY: the matched annotated declaration has this signature.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(address) }
            }};
        }
        Ok(Self {
            member_create: entry!(
                c"qemu_plugin_crucible_startup_source_command_member_create_v2",
                extern "C" fn(u64, *mut NativeComponent, Reader, Writer, *mut *mut Member) -> i32
            ),
            member_transfer: entry!(
                c"qemu_plugin_crucible_startup_source_command_member_transfer_v1",
                extern "C" fn(u64, *mut *mut Member, *mut *mut Member) -> i32
            ),
            member_current: entry!(
                c"qemu_plugin_crucible_startup_source_command_member_current_v1",
                extern "C" fn(u64, *mut Member) -> i32
            ),
            member_return: entry!(
                c"qemu_plugin_crucible_startup_source_command_member_identity_return_v1",
                extern "C" fn(u64, *mut *mut Member) -> i32
            ),
            receive_create: entry!(
                c"qemu_plugin_crucible_startup_source_command_receive_create_v1",
                extern "C" fn(u64, *mut Member, *mut *mut Receive, *mut u64) -> i32
            ),
            receive_transfer: entry!(
                c"qemu_plugin_crucible_startup_source_command_receive_transfer_v1",
                extern "C" fn(u64, *mut *mut Receive, u64, *mut *mut Receive) -> i32
            ),
            receive_observe: entry!(
                c"qemu_plugin_crucible_startup_source_command_receive_observe_v1",
                extern "C" fn(
                    u64,
                    *mut Receive,
                    u64,
                    *mut ControlIntentFacts,
                    *mut ReceiveProgress,
                    *mut Status,
                ) -> i32
            ),
            receive_current: entry!(
                c"qemu_plugin_crucible_startup_source_command_receive_current_v1",
                extern "C" fn(u64, *mut Receive, u64) -> i32
            ),
            receive_return: entry!(
                c"qemu_plugin_crucible_startup_source_command_receive_identity_return_v1",
                extern "C" fn(u64, *mut *mut Receive, u64) -> i32
            ),
        })
    }
}
