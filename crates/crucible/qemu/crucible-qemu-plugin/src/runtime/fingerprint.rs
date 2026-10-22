//! Enrolls Main fingerprint custody independently of checkpoint callbacks.
//!
//! The actual registered invocation issues the borrower. Module callbacks reuse
//! Source time and return physical pager/view custody; they create no local clock.
// SPDX-License-Identifier: GPL-2.0-or-later

use std::ffi::c_void;

use crate::ram_fingerprint::FingerprintPlacement;

/// Names the opaque native-issued ordinary retirement borrower.
#[repr(C)]
pub(crate) struct FingerprintLoan {
    _private: [u8; 0],
}

/// Distinguishes historical deferred obligations from the actual current capture.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct FingerprintStatus {
    pub(crate) schema_version: u32,
    pub(crate) struct_size: u32,
    pub(crate) publication_capture_generation: u64,
    pub(crate) publication_dirty_generation: u64,
    pub(crate) operation_capture_generation: u64,
    pub(crate) topology_generation: u64,
    pub(crate) dirty_generation: u64,
    pub(crate) region_count: u32,
    pub(crate) has_deferred_obligations: u32,
    pub(crate) first_status: i32,
    pub(crate) post_status: i32,
    pub(crate) deferred_first_status: i32,
    pub(crate) deferred_post_status: i32,
}

type Borrow = extern "C" fn(u64, *mut FingerprintLoan, *mut *mut c_void, *mut c_void) -> i32;
type Operation = extern "C" fn(u64, *mut FingerprintLoan, *mut c_void, *mut c_void) -> i32;
type Register = extern "C" fn(
    u64,
    Option<Borrow>,
    Option<Operation>,
    Option<Operation>,
    Option<Borrow>,
    *mut c_void,
) -> i32;
type Observe = extern "C" fn(u64, *mut FingerprintLoan, *mut FingerprintStatus) -> i32;

/// Retains the matched registrar and identity observer for one realization.
#[derive(Clone, Copy)]
pub(crate) struct FingerprintApi {
    register: Register,
    observe: Observe,
}

impl FingerprintApi {
    /// Resolves only the registrar for the selected actual realization.
    ///
    /// # Errors
    /// Refuses an absent matching native registrar or identity observer.
    pub(crate) fn resolve(placement: FingerprintPlacement) -> Result<Self, i32> {
        let registrar = match placement {
            FingerprintPlacement::Paging => {
                c"qemu_plugin_crucible_register_fingerprint_retirement_v1"
            }
            FingerprintPlacement::Resident => {
                c"qemu_plugin_crucible_register_resident_fingerprint_retirement_v1"
            }
        };
        // SAFETY: the selected frozen symbol has this same four-callback ABI.
        let register = unsafe { libc::dlsym(libc::RTLD_DEFAULT, registrar.as_ptr()) };
        // SAFETY: symbol lookup reads the retained process export table only.
        let observe = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"qemu_plugin_crucible_fingerprint_retirement_observe_v2".as_ptr(),
            )
        };
        if register.is_null() || observe.is_null() {
            return Err(-libc::ENOSYS);
        }
        // SAFETY: these exact signatures/layouts are retained in the matched SDK.
        unsafe {
            Ok(Self {
                register: std::mem::transmute::<*mut c_void, Register>(register),
                observe: std::mem::transmute::<*mut c_void, Observe>(observe),
            })
        }
    }

    /// Enrolls callbacks only after the Source observer and durable fields.
    ///
    /// # Errors
    /// Preserves the real native refusal; no alternate registrar is retried.
    pub(crate) fn register(self, id: u64, userdata: *mut c_void) -> Result<(), i32> {
        let status = (self.register)(
            id,
            Some(borrow),
            Some(rearm),
            Some(check),
            Some(end),
            userdata,
        );
        if status == 0 {
            Ok(())
        } else {
            Err(if status < 0 { status } else { -libc::EPROTO })
        }
    }
}

/// Borrows only the actual synchronous registered native retirement invocation.
pub(crate) struct FingerprintBorrowContext {
    loan: usize,
    pub(crate) status: FingerprintStatus,
}

impl FingerprintBorrowContext {
    /// Corroborates the retained nominal borrower; the number issues no loan.
    pub(crate) fn key(&self) -> usize {
        self.loan
    }
}

fn invoke(
    id: u64,
    loan: *mut FingerprintLoan,
    userdata: *mut c_void,
    callback: impl FnOnce(&FingerprintBorrowContext) -> i32,
) -> i32 {
    if loan.is_null() || userdata.is_null() {
        return -libc::EINVAL;
    }
    let api = match crate::ram_fingerprint::retirement_api(id, userdata) {
        Ok(api) => api,
        Err(status) => return status,
    };
    let mut status = FingerprintStatus::default();
    let observed = (api.observe)(id, loan, &mut status);
    if observed != 0 {
        return if observed < 0 {
            observed
        } else {
            -libc::EPROTO
        };
    }
    if status.schema_version != 2
        || status.struct_size as usize != std::mem::size_of::<FingerprintStatus>()
        || status.topology_generation == 0
        || status.dirty_generation == 0
        || status.region_count == 0
        || status.region_count > 4096
        || status.first_status > 0
        || status.post_status > 0
        || status.has_deferred_obligations > 1
        || status.deferred_first_status > 0
        || status.deferred_post_status > 0
    {
        return -libc::EPROTO;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        callback(&FingerprintBorrowContext {
            loan: loan as usize,
            status,
        })
    }))
    .unwrap_or(-libc::EIO)
}

extern "C" fn borrow(
    id: u64,
    loan: *mut FingerprintLoan,
    output: *mut *mut c_void,
    userdata: *mut c_void,
) -> i32 {
    if output.is_null() {
        return -libc::EINVAL;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        invoke(id, loan, userdata, |context| {
            crate::ram_fingerprint::borrow_retirement(context, id, userdata, output)
        })
    }))
    .unwrap_or(-libc::EIO)
}

extern "C" fn rearm(
    id: u64,
    loan: *mut FingerprintLoan,
    owner: *mut c_void,
    userdata: *mut c_void,
) -> i32 {
    invoke(id, loan, userdata, |context| {
        crate::ram_fingerprint::rearm_retirement(context, id, userdata, owner)
    })
}

extern "C" fn check(
    id: u64,
    loan: *mut FingerprintLoan,
    owner: *mut c_void,
    userdata: *mut c_void,
) -> i32 {
    invoke(id, loan, userdata, |context| {
        crate::ram_fingerprint::check_retirement(context, id, userdata, owner)
    })
}

extern "C" fn end(
    id: u64,
    loan: *mut FingerprintLoan,
    owner: *mut *mut c_void,
    userdata: *mut c_void,
) -> i32 {
    if owner.is_null() {
        return -libc::EINVAL;
    }
    invoke(id, loan, userdata, |context| {
        crate::ram_fingerprint::end_retirement(context, id, userdata, owner)
    })
}
