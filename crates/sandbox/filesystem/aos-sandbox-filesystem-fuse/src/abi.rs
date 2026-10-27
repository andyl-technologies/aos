//! Private in-process metadata V1 and dormant fallback V2 transport ABIs.
//!
//! These `repr(C)` objects cross a trusted synchronous library boundary, never
//! a process or machine boundary. The C side validates all sizes and versions.
//! Callback pointers and buffers remain valid only during the scoped runner.
//! The additive prepared-session ABI retains a process-local opaque owner
//! without callbacks; its original startup roles outlive C destruction.

use std::ffi::{c_int, c_void};
use std::os::fd::AsRawFd as _;
use std::ptr::NonNull;

use aos_sandbox_linux::fuse_worker_startup::FixedFuseWorkerSessionV1;

// Inert ABI declarations only: no production table, runner or guard factory.
#[allow(dead_code)]
mod scoped;

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
#[derive(Clone, Copy)]
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

#[repr(C)]
pub(crate) struct FallbackOperationsV2 {
    pub abi_major: u16,
    pub abi_minor: u16,
    pub struct_size: u32,
    pub profile: u32,
    pub reserved: u32,
    pub metadata: Operations,
    pub open: unsafe extern "C" fn(*mut c_void, u64, i32, u64, *mut c_void, ReplyOpen) -> c_int,
    pub read:
        unsafe extern "C" fn(*mut c_void, u64, u64, i64, u32, u64, *mut u8, u64, *mut u64) -> c_int,
    pub release: unsafe extern "C" fn(*mut c_void, u64, u64, i32, u32, u64, u64) -> c_int,
}

#[repr(C)]
pub(crate) struct FallbackLimitsV2 {
    pub abi_major: u16,
    pub abi_minor: u16,
    pub struct_size: u32,
    pub profile: u32,
    pub reserved: u32,
    pub metadata: Limits,
}

#[repr(C)]
struct Preparation {
    struct_size: u32,
    abi_major: u16,
    abi_minor: u16,
    flags: u32,
    reserved: u32,
    deadline_boottime_ns: u64,
    limits: Limits,
}

// Only pointers returned by the installed synchronous preparation function
// inhabit this private opaque type; its representation never crosses a wire.
#[repr(C)]
struct PreparedSession {
    _private: [u8; 0],
}

/// Owns a preparation-only C session while its original roles stay retained.
///
/// This handle deliberately has no safe callback/continuation API. A genuine
/// held Root/Mount dispatcher must be joined before that separate operation.
pub(crate) struct PreparedTransport {
    session: NonNull<PreparedSession>,
}

impl PreparedTransport {
    pub(crate) fn prepare(
        original: &FixedFuseWorkerSessionV1,
        deadline_boottime_ns: u64,
        limits: Limits,
    ) -> Result<Self, std::io::Error> {
        let preparation = Preparation {
            struct_size: size_of::<Preparation>() as u32,
            abi_major: 1,
            abi_minor: 0,
            flags: 0,
            reserved: 0,
            deadline_boottime_ns,
            limits,
        };
        let mut session = std::ptr::null_mut();

        // SAFETY: the enclosing Rust owner retains the exclusively captured
        // original session through C destruction. Preparation installs no
        // Rust callbacks and retains only its own duplicate of this same OFD;
        // the cancellation reader remains owned by that original session.
        let error = unsafe {
            aos_fuse_transport_prepare_v1(
                original.connection().as_raw_fd(),
                original.cancellation().as_raw_fd(),
                &preparation,
                &mut session,
            )
        };
        if error != 0 {
            return Err(std::io::Error::from_raw_os_error(error));
        }
        let session = NonNull::new(session).ok_or_else(|| {
            std::io::Error::other("FUSE preparation returned no retained session")
        })?;
        Ok(Self { session })
    }
}

impl Drop for PreparedTransport {
    fn drop(&mut self) {
        // SAFETY: this non-cloneable owner stores exactly the pointer returned
        // by successful preparation. No other API can take or destroy it, and
        // its enclosing owner still retains both original transport roles.
        unsafe { aos_fuse_transport_destroy_prepared_v1(self.session.as_ptr()) };
    }
}

unsafe extern "C" {
    pub(crate) fn aos_fuse_transport_run(
        connected: c_int,
        cancellation: c_int,
        operations: *const Operations,
        context: *mut c_void,
        limits: *const Limits,
    ) -> c_int;
    pub(crate) fn aos_fuse_transport_run_fallback_v2(
        connected: c_int,
        cancellation: c_int,
        operations: *const FallbackOperationsV2,
        context: *mut c_void,
        limits: *const FallbackLimitsV2,
    ) -> c_int;

    fn aos_fuse_transport_prepare_v1(
        connected: c_int,
        cancellation: c_int,
        preparation: *const Preparation,
        session: *mut *mut PreparedSession,
    ) -> c_int;

    fn aos_fuse_transport_destroy_prepared_v1(session: *mut PreparedSession);
}

const _: () = {
    // The supported AOS Linux ABIs represent every dynamically allocated u64
    // connection inode. A whole-index scan cannot bound future connection IDs.
    assert!(libc::ino_t::MAX == u64::MAX);
    assert!(size_of::<Attributes>() == 48);
    assert!(size_of::<DirectoryEntry>() == 24);
    assert!(size_of::<Limits>() == 64);
    assert!(size_of::<Operations>() == 96);
    assert!(size_of::<FallbackOperationsV2>() == 136);
    assert!(size_of::<FallbackLimitsV2>() == 80);
    assert!(std::mem::offset_of!(FallbackOperationsV2, open) == 112);
    assert!(size_of::<Preparation>() == 88);
    assert!(std::mem::offset_of!(Preparation, limits) == 24);
    assert!(std::mem::offset_of!(Operations, lookup) == 32);
    assert!(std::mem::offset_of!(Attributes, kind) == 42);
    assert!(std::mem::offset_of!(DirectoryEntry, kind) == 22);
    assert!(std::mem::offset_of!(Limits, entry_valid_ns) == 48);
};
