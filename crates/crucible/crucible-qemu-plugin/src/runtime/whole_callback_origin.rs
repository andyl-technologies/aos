//! Source-authenticated callback origin for the original shared custody.
//!
//! This 80-byte ABI remains entirely inside the GPL process. Its native pointers
//! are comparison-only identities, never serialized or dereferenced here. The
//! native getter must authenticate its literal dispatcher before writing the
//! destination. Origin establishes callback custody, never SourceHOLD,
//! operation permission, physical retirement or source Ready.

use std::ffi::{c_int, c_void};

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct NativeCallbackOrigin {
    pub(super) version: u32,
    pub(super) size: u32,
    pub(super) family: u32,
    pub(super) cpu_index: u32,
    pub(super) plugin_id: u64,
    pub(super) process: u64,
    pub(super) actual_tid: u64,
    pub(super) loader_tid: u64,
    pub(super) userdata: *mut c_void,
    pub(super) original_constructor: *const c_void,
    pub(super) cpu: *const c_void,
    pub(super) callback: usize,
}

impl Default for NativeCallbackOrigin {
    fn default() -> Self {
        Self {
            version: 1,
            size: 80,
            family: 0,
            cpu_index: 0,
            plugin_id: 0,
            process: 0,
            actual_tid: 0,
            loader_tid: 0,
            userdata: std::ptr::null_mut(),
            original_constructor: std::ptr::null(),
            cpu: std::ptr::null(),
            callback: 0,
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativeCallbackOrigin>() == 80);
    assert!(std::mem::offset_of!(NativeCallbackOrigin, plugin_id) == 16);
    assert!(std::mem::offset_of!(NativeCallbackOrigin, userdata) == 48);
    assert!(std::mem::offset_of!(NativeCallbackOrigin, callback) == 72);
};

type ReadOrigin = extern "C" fn(*mut NativeCallbackOrigin) -> c_int;

/// Resolves the source getter without permitting a caller to replace it.
#[derive(Clone, Copy)]
pub(super) struct NativeCallbackOriginApi {
    getter: ReadOrigin,
}

/// Names the same immutable registration retained by the original callback owner.
pub(super) struct CallbackRegistration {
    pub(super) cpu_index: u32,
    pub(super) plugin_id: u64,
    pub(super) process: u32,
    pub(super) loader_tid: u64,
    pub(super) userdata: *mut c_void,
    pub(super) callback: usize,
}

/// Retains a proof for only the actual native callback's process and thread.
///
/// Native pointers intentionally prevent Send/Sync: a captured dispatcher proof
/// cannot be passed to another thread as callback participation authority.
pub(super) struct NativeCallbackOriginProof {
    original: NativeCallbackOrigin,
}

impl NativeCallbackOriginApi {
    #[cfg(test)]
    pub(super) fn modeled(getter: ReadOrigin) -> Self {
        Self { getter }
    }

    pub(super) fn resolve() -> Option<Self> {
        // SAFETY: This process-private optional GPL symbol has the exact native
        // C getter signature. Absence never selects ordinary installation.
        let symbol = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"qemu_plugin_crucible_whole_read_callback_origin_v1".as_ptr(),
            )
        };
        if symbol.is_null() {
            None
        } else {
            Some(Self {
                getter: unsafe {
                    // SAFETY: this nonnull process-local QEMU symbol names the
                    // pinned C getter with the exact ReadOrigin calling convention
                    // and 80-byte destination ABI; QEMU stays loaded while used.
                    std::mem::transmute::<*mut c_void, ReadOrigin>(symbol)
                },
            })
        }
    }

    /// Queries native origin before any Rust source/mapping/device guard.
    pub(super) fn capture(&self) -> Result<NativeCallbackOriginProof, c_int> {
        let mut original = NativeCallbackOrigin::default();
        let status = (self.getter)(&mut original);
        if status != 0 {
            return Err(status);
        }
        if original.version != 1
            || original.size != 80
            || original.family != 1
            || original.cpu_index >= 4
            || original.plugin_id == 0
            || original.process != u64::from(std::process::id())
            || original.actual_tid != current_tid()?
            || original.loader_tid == 0
            || original.userdata.is_null()
            || original.original_constructor.is_null()
            || original.cpu.is_null()
            || original.callback == 0
        {
            return Err(-libc::ESTALE);
        }
        Ok(NativeCallbackOriginProof { original })
    }
}

impl NativeCallbackOriginProof {
    /// Compares the retained family1 registration without dereferencing pointers.
    pub(super) fn validate(&self, registration: CallbackRegistration) -> Result<(), c_int> {
        if registration.process != std::process::id()
            || self.original.process != u64::from(registration.process)
            || self.original.actual_tid != current_tid()?
            || self.original.family != 1
            || self.original.cpu_index != registration.cpu_index
            || self.original.plugin_id != registration.plugin_id
            || self.original.loader_tid != registration.loader_tid
            || self.original.userdata != registration.userdata
            || self.original.callback != registration.callback
        {
            return Err(-libc::ESTALE);
        }
        Ok(())
    }

    /// Returns the original CPU's comparison-only source identity.
    pub(super) fn cpu_identity(&self) -> usize {
        self.original.cpu as usize
    }

    /// Returns comparison-only identity issued by the original native source.
    pub(super) fn original_constructor_identity(&self) -> usize {
        self.original.original_constructor as usize
    }
}

pub(super) fn current_tid() -> Result<u64, c_int> {
    // SAFETY: gettid has no pointer arguments and observes the current kernel
    // thread. It cannot enter native QEMU, mapping guards or source callbacks.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    u64::try_from(tid)
        .ok()
        .filter(|tid| *tid != 0)
        .ok_or(-libc::ESTALE)
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static FAMILY: std::cell::Cell<u32> = const { std::cell::Cell::new(1) };
    }

    extern "C" fn original_source_peer(destination: *mut NativeCallbackOrigin) -> c_int {
        let value = NativeCallbackOrigin {
            family: FAMILY.with(|family| family.get()),
            plugin_id: 7,
            process: u64::from(std::process::id()),
            actual_tid: current_tid().unwrap_or_default(),
            loader_tid: 19,
            userdata: std::ptr::dangling_mut::<c_void>(),
            original_constructor: std::ptr::dangling::<c_void>(),
            cpu: std::ptr::dangling::<c_void>(),
            callback: original_source_peer as *const () as usize,
            ..NativeCallbackOrigin::default()
        };
        // SAFETY: capture supplies one complete initialized destination. These
        // process-private fixture addresses are only compared, never read.
        unsafe {
            destination.write(value);
        }
        0
    }

    fn registration() -> CallbackRegistration {
        CallbackRegistration {
            cpu_index: 0,
            plugin_id: 7,
            process: std::process::id(),
            loader_tid: 19,
            userdata: std::ptr::dangling_mut::<c_void>(),
            callback: original_source_peer as *const () as usize,
        }
    }

    #[test]
    fn only_frozen_family1_can_authenticate_callback_custody() {
        let api = NativeCallbackOriginApi::modeled(original_source_peer);
        for family in [0, 2, 3, u32::MAX] {
            FAMILY.with(|slot| slot.set(family));
            assert!(api.capture().is_err());
        }
        FAMILY.with(|slot| slot.set(1));
        let Ok(proof) = api.capture() else {
            panic!("family1 source peer refused");
        };
        assert!(proof.validate(registration()).is_ok());
    }

    #[test]
    fn changed_registered_owner_callback_or_loader_correlation_is_refused() {
        FAMILY.with(|slot| slot.set(1));
        let api = NativeCallbackOriginApi::modeled(original_source_peer);
        let Ok(proof) = api.capture() else {
            panic!("source peer refused");
        };
        for field in 0..5 {
            let mut identity = registration();
            match field {
                0 => identity.plugin_id += 1,
                1 => identity.loader_tid += 1,
                2 => identity.cpu_index += 1,
                3 => identity.userdata = std::ptr::null_mut(),
                _ => identity.callback += 1,
            }
            assert!(proof.validate(identity).is_err());
        }
        assert!(proof.validate(registration()).is_ok());
    }
}
