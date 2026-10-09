//! Dormant native callback custody for an original, incomplete root acquisition.
//!
//! The source alone selects and authenticates its opaque root and cut. This
//! bridge owns the real preparatory transport while source admission is pending;
//! it never upgrades a historical FIFO snapshot into a closed input epoch. An
//! endpoint-writer fence and native producer closure are still required before
//! a successful epoch or any scoped effect can be installed.

use std::ffi::{c_int, c_void};
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::preparation_transport::NativePreparationTransportCustody;
use super::root_epoch_abi::{
    AcquireRootEpoch, BeginRootEffect, EndRootEffect, NativeSourceEffectCut, NativeSourceRootSeal,
};

/// Owns one stable native callback userdata address and all partial transport holds.
pub(crate) struct DormantRootEpochOwner<'mapping> {
    process_id: u32,
    original_root: AtomicUsize,
    state: Mutex<PendingRootCustody<'mapping>>,
}

struct PendingRootCustody<'mapping> {
    transport: NativePreparationTransportCustody<'mapping>,
    transport_retained: bool,
    failed: bool,
}

impl<'mapping> DormantRootEpochOwner<'mapping> {
    /// Pins actual original transport custody before any native callback registration.
    pub(crate) fn pin(transport: NativePreparationTransportCustody<'mapping>) -> Pin<Box<Self>> {
        Box::pin(Self {
            process_id: std::process::id(),
            original_root: AtomicUsize::new(0),
            state: Mutex::new(PendingRootCustody {
                transport,
                transport_retained: false,
                failed: false,
            }),
        })
    }

    /// Borrows userdata without transferring or releasing its native lifetime.
    ///
    /// The installer must keep this pinned owner and its mapping alive through
    /// native containment and callback unregistration. Drop is not cancellation.
    pub(crate) fn userdata(self: Pin<&Self>) -> *mut c_void {
        std::ptr::from_ref(self.get_ref()).cast_mut().cast()
    }

    /// Supplies callbacks that retain custody but grant no executable epoch yet.
    pub(crate) fn callbacks() -> (AcquireRootEpoch, BeginRootEffect, EndRootEffect) {
        (acquire, begin, end)
    }

    fn bind_original_root(&self, root: *const NativeSourceRootSeal) -> Result<(), c_int> {
        // Refuse inherited post-fork objects before touching an inherited mutex.
        if std::process::id() != self.process_id {
            return Err(-libc::ESTALE);
        }
        let identity = root as usize;
        if identity == 0 {
            return Err(-libc::EINVAL);
        }
        match self
            .original_root
            .compare_exchange(0, identity, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(original) if original == identity => Ok(()),
            Err(_) => Err(-libc::ESTALE),
        }
    }

    fn acquire_pending(&self, root: *const NativeSourceRootSeal) -> c_int {
        if let Err(error) = self.bind_original_root(root) {
            return error;
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => return -libc::EAGAIN,
            Err(std::sync::TryLockError::Poisoned(_)) => return -libc::EOWNERDEAD,
        };
        if state.failed {
            return -libc::ENOTRECOVERABLE;
        }
        match state.transport.try_retain() {
            Ok(Some(_)) => state.transport_retained = true,
            Ok(None) => return -libc::EAGAIN,
            Err(_) => {
                state.failed = true;
                return -libc::ENOTRECOVERABLE;
            }
        }
        // A complete historical transport image is not an endpoint-writer fence.
        // Retain it unchanged; no pointer or permission may escape this boundary.
        -libc::EAGAIN
    }

    fn refuse_effect(
        &self,
        root: *const NativeSourceRootSeal,
        epoch: *mut c_void,
        cut: *const NativeSourceEffectCut,
    ) -> c_int {
        if let Err(error) = self.bind_original_root(root) {
            return error;
        }
        if epoch.is_null() || cut.is_null() {
            return -libc::EINVAL;
        }
        // Acquisition has never issued an epoch. No caller address can substitute
        // for an owned epoch, even if the source capability pointer is original.
        -libc::ESTALE
    }
}

unsafe extern "C" fn acquire(
    root: *const NativeSourceRootSeal,
    output: *mut *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if output.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: The registered source supplies writable output for this synchronous
    // callback. Clear it before any validation or partial acquisition can fail.
    unsafe { output.write(std::ptr::null_mut()) };
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Registration retains this exact pinned owner and its borrowed
    // mapping for every callback. The source never fabricates userdata.
    let owner = unsafe { &*userdata.cast::<DormantRootEpochOwner<'_>>() };
    owner.acquire_pending(root)
}

unsafe extern "C" fn begin(
    root: *const NativeSourceRootSeal,
    epoch: *mut c_void,
    cut: *const NativeSourceEffectCut,
    userdata: *mut c_void,
) -> c_int {
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: The native installer retains the same pinned userdata lifetime.
    let owner = unsafe { &*userdata.cast::<DormantRootEpochOwner<'_>>() };
    owner.refuse_effect(root, epoch, cut)
}

unsafe extern "C" fn end(
    root: *const NativeSourceRootSeal,
    epoch: *mut c_void,
    cut: *const NativeSourceEffectCut,
    userdata: *mut c_void,
) -> c_int {
    // This dormant bridge has no scoped permission to clear. A future installed
    // bridge must clear its scope before inspecting these arguments or failing.
    // SAFETY: Forwarding preserves the source callback's exact original pointers.
    unsafe { begin(root, epoch, cut, userdata) }
}

#[cfg(test)]
#[path = "root_epoch_owner_tests.rs"]
mod tests;
