//! Matches the frozen process-private Source reader custody contract.
//!
//! The records contain factual addresses and dispositions only. They stay in
//! the paid Runtime and are never serialized into the shared-memory protocol.
//! Source keeps its final completion independently of the next read birth.
// SPDX-License-Identifier: GPL-2.0-or-later

use std::ffi::c_int;
use crate::startup_source::runtime_purpose::RuntimePurpose;

use crate::paged_ram::engine::NativeRootScratch;
use crate::paged_ram::source::NativePageHasher;

#[cfg(test)]
mod tests;

/// Names Source's retained registration, independently of a read's lifetime.
#[repr(C)]
pub(super) struct SourceOwner {
    _private: [u8; 0],
}

/// Names the actual Source child during its read, post and return phases.
#[repr(C)]
pub(super) struct SourceChild {
    _private: [u8; 0],
}

/// Retains the Module's actual constructor, callback and independent post facts.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Observation {
    pub(super) schema_version: u32,
    pub(super) struct_size: u32,
    pub(super) source_epoch: u64,
    pub(super) module_epoch: u64,
    // The C SDK's const void * is historical identity, never dereferenced.
    pub(super) module_child: usize,
    pub(super) birth_attempted: u32,
    pub(super) born: u32,
    pub(super) callback_entered: u32,
    pub(super) callback_returned: u32,
    pub(super) post_recorded: u32,
    pub(super) first_status: c_int,
    pub(super) post_status: c_int,
    pub(super) reserved: u32,
}

/// Retains physical Module subloan return without querying an expired Original.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Disposition {
    pub(super) schema_version: u32,
    pub(super) struct_size: u32,
    pub(super) source_epoch: u64,
    pub(super) module_epoch: u64,
    pub(super) module_child: usize,
    pub(super) attempted: u32,
    pub(super) returned: u32,
    pub(super) consumed: u32,
    pub(super) uncertain: u32,
    pub(super) first_status: c_int,
    pub(super) post_status: c_int,
    pub(super) post_recorded: u32,
    pub(super) reserved: u32,
}

/// Holds the exact enrolled Module records before Source reads its copies.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Journal {
    pub(super) observation: Observation,
    pub(super) disposition: Disposition,
}

/// Preserves the closed Source read cell independently of Module callback status.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct SourceRead {
    pub(super) owner_epoch: u64,
    pub(super) source_epoch: u64,
    pub(super) module_epoch: u64,
    pub(super) held: u32,
    pub(super) callback_entered: u32,
    pub(super) callback_returned: u32,
    pub(super) module_post_entered: u32,
    pub(super) module_post_returned: u32,
    pub(super) source_post_recorded: u32,
    pub(super) return_attempted: u32,
    pub(super) return_entered: u32,
    pub(super) return_returned: u32,
    pub(super) returned_post_entered: u32,
    pub(super) returned_post_returned: u32,
    pub(super) consumed: u32,
    pub(super) uncertain: u32,
    pub(super) module_born: u32,
    pub(super) module_consumed: u32,
    pub(super) first_status: c_int,
    pub(super) birth_post_status: c_int,
    pub(super) callback_status: c_int,
    pub(super) module_post_status: c_int,
    pub(super) source_post_status: c_int,
    pub(super) return_status: c_int,
    pub(super) returned_post_status: c_int,
}

/// Holds immutable copies in the canonical paid field before acknowledging them.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct CompletedReceipt {
    pub(super) module: Journal,
    pub(super) source: SourceRead,
}

/// Corroborates the previous completed callback before its receipt is replaced.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Completion {
    pub(super) read: SourceRead,
    pub(super) delivery_entered: u32,
    pub(super) delivery_returned: u32,
    pub(super) acknowledgement_attempted: u32,
    pub(super) acknowledged: u32,
    pub(super) post_recorded: u32,
    pub(super) retained: u32,
    pub(super) uncertain: u32,
    pub(super) reserved: u32,
    pub(super) callback_status: c_int,
    pub(super) post_status: c_int,
    pub(super) first_status: c_int,
    pub(super) acknowledgement_status: c_int,
}

/// Observes actual registration consumption through its original field addresses.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct RegistrationReturn {
    pub(super) owner_epoch: u64,
    pub(super) attempted: u32,
    pub(super) returned: u32,
    pub(super) consumed: u32,
    pub(super) uncertain: u32,
    pub(super) first_status: c_int,
    pub(super) post_status: c_int,
}

/// Installs only the exact factual callbacks in the frozen Source SDK.
#[repr(C)]
pub(super) struct Callbacks {
    pub(super) schema_version: u32,
    pub(super) struct_size: u32,
    pub(super) ordinary: extern "C" fn(*mut SourceChild, u64, u64, *mut u8, u32) -> c_int,
    pub(super) root_scratch: extern "C" fn(
        *mut SourceChild,
        u64,
        u64,
        *mut NativeRootScratch,
        u32,
        *const NativePageHasher,
    ) -> c_int,
    pub(super) post: extern "C" fn(*mut SourceChild, u64, *mut Observation) -> c_int,
    pub(super) return_read: extern "C" fn(*mut SourceChild, u64, *mut Disposition) -> c_int,
    pub(super) returned_current: extern "C" fn(*mut SourceChild, u64, *const Disposition) -> c_int,
    pub(super) completed: extern "C" fn(*mut SourceOwner, u64, u64, *const SourceRead) -> c_int,
}

/// Names a factual callback phase; it is never a semantic clock or factory.
pub(super) type ChildIdentity = extern "C" fn(*mut SourceChild, u64) -> c_int;
pub(super) type CompletionIdentity =
    extern "C" fn(u64, *mut SourceOwner, u64, u64, *const SourceRead) -> c_int;
pub(super) type Register = extern "C" fn(
    u64,
    *mut RuntimePurpose,
    *const Callbacks,
    *mut Journal,
    *mut CompletedReceipt,
    *mut *mut SourceOwner,
    *mut u64,
) -> c_int;
pub(super) type Close = extern "C" fn(u64, *mut SourceOwner, u64) -> c_int;
pub(super) type Return = extern "C" fn(u64, *mut *mut SourceOwner, *mut u64) -> c_int;
pub(super) type ObserveReturn =
    extern "C" fn(u64, *const *mut SourceOwner, *const u64, u64, *mut RegistrationReturn) -> c_int;
pub(super) type ObserveCompletion =
    extern "C" fn(u64, *const *mut SourceOwner, *const u64, u64, u64, *mut Completion) -> c_int;
