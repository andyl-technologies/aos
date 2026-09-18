//! Private in-process ABI matching the installed aos_fuse_transport.h version 1.
//!
//! These `repr(C)` objects cross a trusted synchronous library boundary, never
//! a process or machine boundary. The C side validates all sizes and versions.
//! Callback pointers and buffers remain valid only during the scoped runner.

use std::ffi::{c_int, c_void};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Attributes {
    pub node_id: u64,
    pub size: u64,
    pub mtime_seconds: i64,
    pub mtime_nanos: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mode: u16,
    pub kind: u8,
    pub reserved: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct DirectoryEntry {
    pub node_id: u64,
    pub next_cookie: u64,
    pub name_offset: u32,
    pub name_length: u16,
    pub kind: u8,
    pub reserved: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub struct_size: u32,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub flags: u32,
    pub reserved0: u32,
    pub maximum_name_bytes: u32,
    pub maximum_symlink_bytes: u32,
    pub maximum_readdir_bytes: u32,
    pub maximum_readdir_entries: u32,
    pub maximum_write_bytes: u32,
    pub maximum_pages: u32,
    pub time_granularity_ns: u32,
    pub request_timeout_seconds: u16,
    pub reserved1: u16,
    pub entry_valid_ns: u64,
    pub attribute_valid_ns: u64,
}

pub(crate) type ReplyOpen = unsafe extern "C" fn(*mut c_void, u64) -> c_int;

#[repr(C)]
pub(crate) struct Operations {
    pub abi_major: u16,
    pub abi_minor: u16,
    pub struct_size: u32,
    pub attributes_size: u32,
    pub directory_entry_size: u32,
    pub limits_size: u32,
    pub flags: u32,
    pub reserved: u32,
    pub lookup: unsafe extern "C" fn(*mut c_void, u64, *const u8, u64, *mut Attributes) -> c_int,
    pub forget: unsafe extern "C" fn(*mut c_void, u64, u64) -> c_int,
    pub getattr: unsafe extern "C" fn(*mut c_void, u64, *mut Attributes) -> c_int,
    pub readlink: unsafe extern "C" fn(*mut c_void, u64, *mut u8, u64, *mut u64) -> c_int,
    pub opendir: unsafe extern "C" fn(*mut c_void, u64, *mut c_void, ReplyOpen) -> c_int,
    pub readdir: unsafe extern "C" fn(
        *mut c_void,
        u64,
        u64,
        u64,
        u64,
        *mut DirectoryEntry,
        u64,
        *mut u64,
        *mut u8,
        u64,
        *mut u64,
    ) -> c_int,
    pub releasedir: unsafe extern "C" fn(*mut c_void, u64, u64) -> c_int,
    pub destroy: unsafe extern "C" fn(*mut c_void),
}

pub(crate) type Run =
    unsafe extern "C" fn(c_int, c_int, *const Operations, *mut c_void, *const Limits) -> c_int;

unsafe extern "C" {
    pub(crate) fn aos_fuse_transport_run(
        connected: c_int,
        cancellation: c_int,
        operations: *const Operations,
        context: *mut c_void,
        limits: *const Limits,
    ) -> c_int;
}

const _: () = {
    // The supported AOS Linux ABIs represent every dynamically allocated u64
    // connection inode. A whole-index scan cannot bound future connection IDs.
    assert!(libc::ino_t::MAX == u64::MAX);
    assert!(size_of::<Attributes>() == 48);
    assert!(size_of::<DirectoryEntry>() == 24);
    assert!(size_of::<Limits>() == 64);
    assert!(size_of::<Operations>() == 96);
    assert!(std::mem::offset_of!(Operations, lookup) == 32);
    assert!(std::mem::offset_of!(Attributes, kind) == 42);
    assert!(std::mem::offset_of!(DirectoryEntry, kind) == 22);
    assert!(std::mem::offset_of!(Limits, entry_valid_ns) == 48);
};
