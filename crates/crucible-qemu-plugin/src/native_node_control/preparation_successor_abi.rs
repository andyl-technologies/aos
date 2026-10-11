//! GPL-local source query ABI for one retained preparation successor.
//!
//! These layouts and function pointers stay inside QEMU. Cross-process evidence
//! uses closed canonical bytes; native pointers and padding never leave this
//! module. Query success is historical source evidence, not an ACK or Ready.

use crucible_protocol::node_control::{NativeCommandError, NativePreparationSuccessorFacts};
use std::ffi::{c_int, c_void};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativePreparationSuccessorAbi {
    pub version: u32,
    pub size: u32,
    pub flags: u32,
    pub reserved: u32,
    pub initialization_sequence: u64,
    pub hold_generation: u64,
    pub current_ps: u64,
    pub raw_icount: u64,
    pub prepared_scope_hash: [u8; 32],
    pub initialization_commitment: [u8; 32],
    pub realize_request_digest: [u8; 32],
    pub original_cut_digest: [u8; 32],
    pub applied_receipt_digest: [u8; 32],
    pub content_length: u64,
    pub content_digest: [u8; 32],
}

impl NativePreparationSuccessorAbi {
    pub(crate) fn decode(self) -> Result<NativePreparationSuccessorFacts, NativeCommandError> {
        let mut bytes = [0; 248];
        for (offset, value) in [
            (0, self.version),
            (4, self.size),
            (8, self.flags),
            (12, self.reserved),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        for (offset, value) in [
            (16, self.initialization_sequence),
            (24, self.hold_generation),
            (32, self.current_ps),
            (40, self.raw_icount),
            (208, self.content_length),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        for (offset, value) in [
            (48, &self.prepared_scope_hash),
            (80, &self.initialization_commitment),
            (112, &self.realize_request_digest),
            (144, &self.original_cut_digest),
            (176, &self.applied_receipt_digest),
            (216, &self.content_digest),
        ] {
            bytes[offset..offset + 32].copy_from_slice(value);
        }
        NativePreparationSuccessorFacts::decode(&bytes)
    }
}

pub(crate) type QueryPreparationSuccessor =
    extern "C" fn(*const u8, u64, *const u8, *mut NativePreparationSuccessorAbi) -> c_int;

pub(crate) type ReadPreparationSuccessor =
    extern "C" fn(*const u8, u64, *const u8, u64, *mut u8, u32, *mut u32) -> c_int;

pub(crate) fn resolve_query_preparation_successor() -> Option<QueryPreparationSuccessor> {
    // SAFETY: The opt-in source declares this exact versioned scalar query ABI.
    // Absence refuses the extension; no other callback is substituted.
    let pointer = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_node_query_preparation_successor".as_ptr(),
        )
    };
    if pointer.is_null() {
        None
    } else {
        // SAFETY: The symbol's source declaration has query248's exact signature.
        Some(unsafe { std::mem::transmute::<*mut c_void, QueryPreparationSuccessor>(pointer) })
    }
}

pub(crate) fn resolve_read_preparation_successor() -> Option<ReadPreparationSuccessor> {
    // SAFETY: The opt-in source declares checked-offset, bounded byte copying.
    let pointer = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_node_read_preparation_successor".as_ptr(),
        )
    };
    if pointer.is_null() {
        None
    } else {
        // SAFETY: The symbol's source declaration has this exact byte-copy ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, ReadPreparationSuccessor>(pointer) })
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativePreparationSuccessorAbi>() == 248);
    assert!(std::mem::offset_of!(NativePreparationSuccessorAbi, prepared_scope_hash) == 48);
    assert!(std::mem::offset_of!(NativePreparationSuccessorAbi, content_length) == 208);
    assert!(std::mem::offset_of!(NativePreparationSuccessorAbi, content_digest) == 216);
};

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> NativePreparationSuccessorAbi {
        NativePreparationSuccessorAbi {
            version: 1,
            size: 248,
            flags: 3,
            reserved: 0,
            initialization_sequence: 1,
            hold_generation: 7,
            current_ps: 0,
            raw_icount: 0,
            prepared_scope_hash: [1; 32],
            initialization_commitment: [2; 32],
            realize_request_digest: [3; 32],
            original_cut_digest: [4; 32],
            applied_receipt_digest: [5; 32],
            content_length: 1590,
            content_digest: [6; 32],
        }
    }

    #[test]
    fn native_unknown_flags_reserved_progress_and_extents_cannot_be_lost_in_conversion() {
        assert!(facts().decode().is_ok());
        for field in 0..8 {
            let mut changed = facts();
            match field {
                0 => changed.version = 2,
                1 => changed.size = 240,
                2 => changed.flags = 7,
                3 => changed.reserved = 1,
                4 => changed.current_ps = 1,
                5 => changed.raw_icount = 1,
                6 => changed.content_length = 2097153,
                _ => changed.hold_generation = 0,
            }
            assert!(changed.decode().is_err());
        }
    }
}
