//! Resolves the exact installed Source reader custody functions.
//!
//! The table has no clock, operation factory or authority derived from symbols.
//! Every call still requires the genuine retained registration or child phase.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::abi;
use crate::ram_error::RamError;
use std::ffi::c_void;

#[derive(Clone, Copy)]
pub(super) struct Api {
    pub(super) register: abi::Register,
    pub(super) close: abi::Close,
    pub(super) return_owner: abi::Return,
    pub(super) observe_return: abi::ObserveReturn,
    pub(super) child_identity: abi::ChildIdentity,
    pub(super) child_current: abi::ChildIdentity,
    pub(super) child_return_identity: abi::ChildIdentity,
    pub(super) completion_identity: abi::CompletionIdentity,
    pub(super) acknowledge_completion: abi::CompletionIdentity,
    pub(super) observe_completion: abi::ObserveCompletion,
}

impl Api {
    /// Resolves the matching LP64 Source custody contract.
    ///
    /// # Errors
    /// Refuses unsupported pointer geometry or any missing required export.
    pub(super) fn resolve() -> Result<Self, RamError> {
        use super::super::super::symbol;

        if std::mem::size_of::<usize>() != 8 || std::mem::size_of::<std::ffi::c_int>() != 4 {
            return Err(RamError::Invariant("RAM reader SDK requires LP64 geometry"));
        }

        // SAFETY: each literal export and signature matches frozen reader SDK
        // block da09e03a. Resolution supplies no registration or operation loan.
        unsafe {
            Ok(Self {
                register: std::mem::transmute::<*mut c_void, abi::Register>(symbol(
                    b"qemu_plugin_crucible_register_ram_readers_v4\0",
                )?),
                close: std::mem::transmute::<*mut c_void, abi::Close>(symbol(
                    b"qemu_plugin_crucible_ram_reader_close_v1\0",
                )?),
                return_owner: std::mem::transmute::<*mut c_void, abi::Return>(symbol(
                    b"qemu_plugin_crucible_ram_reader_return_v1\0",
                )?),
                observe_return: std::mem::transmute::<*mut c_void, abi::ObserveReturn>(symbol(
                    b"qemu_plugin_crucible_ram_reader_returned_current_v1\0",
                )?),
                child_identity: std::mem::transmute::<*mut c_void, abi::ChildIdentity>(symbol(
                    b"qemu_plugin_crucible_ram_read_child_identity_v1\0",
                )?),
                child_current: std::mem::transmute::<*mut c_void, abi::ChildIdentity>(symbol(
                    b"qemu_plugin_crucible_ram_read_child_current_v1\0",
                )?),
                child_return_identity: std::mem::transmute::<*mut c_void, abi::ChildIdentity>(
                    symbol(b"qemu_plugin_crucible_ram_read_child_return_identity_v1\0")?,
                ),
                completion_identity: std::mem::transmute::<*mut c_void, abi::CompletionIdentity>(
                    symbol(b"qemu_plugin_crucible_ram_read_completed_identity_v1\0")?,
                ),
                acknowledge_completion: std::mem::transmute::<*mut c_void, abi::CompletionIdentity>(
                    symbol(b"qemu_plugin_crucible_ram_read_completed_ack_v1\0")?,
                ),
                observe_completion: std::mem::transmute::<*mut c_void, abi::ObserveCompletion>(
                    symbol(b"qemu_plugin_crucible_ram_reader_completion_current_v1\0")?,
                ),
            })
        }
    }
}
