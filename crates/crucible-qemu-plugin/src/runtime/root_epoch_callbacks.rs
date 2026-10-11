//! Pinned runtime userdata for explicitly selected dormant native epoch callbacks.
//!
//! Registration binds original source policy and owns the actual setup mapping
//! through process exit. Acquisition borrows that same mapping synchronously and
//! retains original initializer ACK, socket journals, FIFO bytes and all holds.
//! No RootSeal emitter, endpoint-writer fence or effect dispatcher exists in this
//! component; historical material never becomes an executable epoch.

use std::ffi::{c_int, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::{OwnedCallbackRegistrationError, OwnedCallbackRuntimeState};
use crate::PluginArgs;
use crate::native_node_control::NativePreparationTransportState;
use crate::native_node_control::root_epoch_abi::{
    NativeSourceEffectCut, NativeSourceRootSeal, resolve_register_root_epoch,
};

/// Retains dormant registration and same-original pending acquisition state.
pub(super) struct NativeRuntimeRootEpoch {
    process_id: u32,
    registered: AtomicBool,
    original_root: AtomicUsize,
    custody: Mutex<Option<NativePreparationTransportState>>,
}

impl NativeRuntimeRootEpoch {
    pub(super) fn new() -> Self {
        Self {
            process_id: std::process::id(),
            registered: AtomicBool::new(false),
            original_root: AtomicUsize::new(0),
            custody: Mutex::new(None),
        }
    }

    /// Registers only the explicit dormant edition before native resource sealing.
    ///
    /// # Errors
    /// Refuses absent original root policy, unavailable source ABI or native
    /// refusal. The outer irreversible-registration guard retains this runtime.
    pub(super) fn register(
        &self,
        args: &PluginArgs,
        userdata: *mut c_void,
    ) -> Result<(), OwnedCallbackRegistrationError> {
        if args
            .native_node_control()
            .and_then(|config| config.root_epoch_version())
            .is_none()
        {
            return Ok(());
        }
        let unavailable = || OwnedCallbackRegistrationError::AdaptersUnavailable {
            families: "original dormant native root epoch",
        };
        if userdata.is_null() || std::process::id() != self.process_id {
            return Err(unavailable());
        }
        if self.is_registered() {
            return Err(unavailable());
        }
        let original = crate::native_node_control::registered_owner()
            .and_then(|owner| owner.original_registered_root_policy())
            .ok_or_else(unavailable)?;
        let register = resolve_register_root_epoch().ok_or_else(unavailable)?;
        // SAFETY: This is the exact version1 source declaration. Userdata points
        // to the existing pinned runtime; installation retains its mapping and
        // allocation after any callback may have been stored by QEMU.
        let result = unsafe {
            register(
                1,
                &original,
                Some(acquire),
                Some(begin),
                Some(end),
                userdata,
            )
        };
        if result != 0 {
            return Err(unavailable());
        }
        self.registered.store(true, Ordering::Release);
        Ok(())
    }

    pub(super) fn is_registered(&self) -> bool {
        self.registered.load(Ordering::Acquire)
    }

    fn bind_root(&self, root: *const NativeSourceRootSeal) -> Result<(), c_int> {
        if std::process::id() != self.process_id {
            // An inherited parent mutex might have been locked at fork.
            return Err(-libc::ESTALE);
        }
        if !self.is_registered() || root.is_null() {
            return Err(-libc::EINVAL);
        }
        let identity = root as usize;
        match self
            .original_root
            .compare_exchange(0, identity, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(original) if original == identity => Ok(()),
            Err(_) => Err(-libc::ESTALE),
        }
    }

    fn acquire_pending(
        &self,
        root: *const NativeSourceRootSeal,
        runtime: &OwnedCallbackRuntimeState,
    ) -> c_int {
        if let Err(error) = self.bind_root(root) {
            return error;
        }
        let mut custody = match self.custody.try_lock() {
            Ok(custody) => custody,
            Err(std::sync::TryLockError::WouldBlock) => return -libc::EAGAIN,
            Err(std::sync::TryLockError::Poisoned(_)) => return -libc::EOWNERDEAD,
        };
        if custody.is_none() {
            let Some(owner) = crate::native_node_control::registered_owner() else {
                return -libc::ENOTRECOVERABLE;
            };
            match owner.prepare_runtime_epoch_transport(
                runtime.setup.mapped_region(),
                std::sync::Arc::clone(&runtime.quiescence),
                std::sync::Arc::clone(&runtime.workers),
            ) {
                Ok(Some(original)) => *custody = Some(original),
                Ok(None) => return -libc::EAGAIN,
                Err(_) => return -libc::ENOTRECOVERABLE,
            }
        }
        let Some(original) = custody.as_mut() else {
            return -libc::ENOTRECOVERABLE;
        };
        match original.try_retain(runtime.setup.mapped_region()) {
            Ok(_) => -libc::EAGAIN,
            Err(_) => -libc::ENOTRECOVERABLE,
        }
        // Even complete historical bytes cannot close unread peer/kernel input.
        // No epoch pointer is issued and no callback or ring permission opens.
    }

    fn refuse_unissued_effect(
        &self,
        root: *const NativeSourceRootSeal,
        epoch: *mut c_void,
        cut: *const NativeSourceEffectCut,
    ) -> c_int {
        if let Err(error) = self.bind_root(root) {
            return error;
        }
        if epoch.is_null() || cut.is_null() {
            return -libc::EINVAL;
        }
        -libc::ESTALE
    }
}

/// Retains pending original custody without issuing an executable epoch.
///
/// # Safety
/// Non-NULL userdata must identify the registration's original pinned callback
/// runtime and its owned mapping.
/// A non-NULL output must be writable, aligned pointer storage for this call,
/// disjoint from retained custody; it is cleared before validation. The native
/// source preserves its original root lifetime throughout this synchronous call.
unsafe extern "C" fn acquire(
    root: *const NativeSourceRootSeal,
    output: *mut *mut c_void,
    userdata: *mut c_void,
) -> c_int {
    if output.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: The source supplies writable output to this synchronous callback.
    // Clear it before partial acquisition, busy ownership or other failures.
    unsafe { output.write(std::ptr::null_mut()) };
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Actual native registration retains this exact pinned runtime and
    // mapping until child exit, including irreversible installation failures.
    let runtime = unsafe { &*userdata.cast::<OwnedCallbackRuntimeState>() };
    runtime.root_epoch.acquire_pending(root, runtime)
}

/// Refuses effect admission because acquisition has issued no owned epoch.
///
/// # Safety
/// Non-NULL userdata must identify the registration's original pinned callback
/// runtime and its owned mapping.
/// The native source preserves its original root and cut lifetimes for this
/// synchronous call. Opaque epoch/root/cut addresses are compared, never adopted
/// as Rust objects or dereferenced by this dormant bridge.
unsafe extern "C" fn begin(
    root: *const NativeSourceRootSeal,
    epoch: *mut c_void,
    cut: *const NativeSourceEffectCut,
    userdata: *mut c_void,
) -> c_int {
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: The original native registration retains this pinned allocation.
    let runtime = unsafe { &*userdata.cast::<OwnedCallbackRuntimeState>() };
    runtime.root_epoch.refuse_unissued_effect(root, epoch, cut)
}

/// Preserves dormant effect refusal without opening or releasing admission.
///
/// # Safety
/// The caller upholds the same retained userdata and source-object lifetimes as
/// `begin`; forwarding preserves the exact arguments. This bridge has installed
/// no effect scope. A future active bridge must revoke scope before error paths.
unsafe extern "C" fn end(
    root: *const NativeSourceRootSeal,
    epoch: *mut c_void,
    cut: *const NativeSourceEffectCut,
    userdata: *mut c_void,
) -> c_int {
    // No scope can have been installed by this dormant bridge. Future native
    // effect admission must revoke it before every validation/error path here.
    // SAFETY: Forwarding preserves the exact synchronous source arguments.
    unsafe { begin(root, epoch, cut, userdata) }
}
