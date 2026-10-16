//! Performs typed child writes and cleanup only in the genuine entered callbacks.
// SPDX-License-Identifier: GPL-2.0-only

use super::super::command_storage::NativeStorage as BridgeStorage;
use super::super::live_callbacks::initialization::CallbackAllocation;
use super::super::live_callbacks::{LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState};
use super::abi::{Api, Storage};
use std::alloc::Layout;
use std::cell::Cell;
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Carries actual entered identity-only journals for this synchronous initializer.
/// Copying these callback-local inputs cannot create entry or a completion grant.
#[derive(Clone, Copy)]
pub(in crate::runtime) struct Progress<'a> {
    id: u64,
    child: *mut Storage,
    api: Api,
    rollback_status: &'a Cell<i32>,
}

impl Progress<'_> {
    /// Marks the actual prewrite boundary; refusal must precede every field write.
    ///
    /// # Errors
    /// Preserves the Source's entered-thread/owner or placement refusal.
    pub(in crate::runtime) fn begin(self) -> Result<(), LiveVcpuTimeCallbackError> {
        super::native_status((self.api.placement_begin)(self.id, self.child))
    }

    /// Acknowledges the complete typed body before subsequent fallible work.
    ///
    /// # Errors
    /// Retains a complete body when the entered identity acknowledgement refuses.
    pub(in crate::runtime) fn initialized(self) -> Result<(), LiveVcpuTimeCallbackError> {
        super::native_status((self.api.initialized)(self.id, self.child))
    }

    fn prefix_returned(self) {
        // This call is made only at the successful end of the real guard Drop.
        // A negative acknowledgement remains debt; catching an unwind is not it.
        self.rollback_status
            .set((self.api.prefix_rollback)(self.id, self.child));
    }
}

/// Retains the unique span and its actual entered prefix completion marker.
pub(in crate::runtime) struct EnteredAllocation<'a, 'p> {
    span: &'a mut MaybeUninit<LiveVcpuTimeCallbackState>,
    progress: Progress<'p>,
}

impl<'a, 'p> EnteredAllocation<'a, 'p> {
    /// Acquires the supplied span only after the real placement marker succeeds.
    ///
    /// # Errors
    /// Refuses before any typed child field write if the marker is not admitted.
    pub(in crate::runtime) fn new(
        span: &'a mut MaybeUninit<LiveVcpuTimeCallbackState>,
        progress: Progress<'p>,
    ) -> Result<Self, LiveVcpuTimeCallbackError> {
        progress.begin()?;
        Ok(Self { span, progress })
    }
}

// SAFETY: the entered Source callback lends the unique exact live child span.
// Prefix cleanup never frees it; completion preserves the callback-local borrow.
unsafe impl<'a> CallbackAllocation for EnteredAllocation<'a, '_> {
    type Initialized = &'a mut LiveVcpuTimeCallbackState;

    fn pointer(&mut self) -> *mut LiveVcpuTimeCallbackState {
        self.span.as_mut_ptr()
    }

    /// Converts the complete entered span without changing its backing owner.
    ///
    /// # Safety
    /// The common initializer has written every field, no prefix cleanup remains,
    /// and this unique entered borrow remains live through conversion.
    unsafe fn initialized(self) -> Self::Initialized {
        // SAFETY: the common initializer recorded all forty valid unique fields.
        unsafe { self.span.assume_init_mut() }
    }

    fn prefix_rollback_completed(&mut self) {
        self.progress.prefix_returned();
    }
}

struct Input<F> {
    constructor: Option<F>,
    first_error: Option<LiveVcpuTimeCallbackError>,
    id: u64,
    child: *mut Storage,
    bridge: *mut BridgeStorage,
    api: Api,
}

pub(super) fn initialize<F>(
    id: u64,
    child: *mut Storage,
    bridge: *mut BridgeStorage,
    api: Api,
    constructor: F,
) -> Result<(), LiveVcpuTimeCallbackError>
where
    F: FnOnce(
        &mut MaybeUninit<LiveVcpuTimeCallbackState>,
        Progress<'_>,
    ) -> Result<(), LiveVcpuTimeCallbackError>,
{
    let mut input = Input {
        constructor: Some(constructor),
        first_error: None,
        id,
        child,
        bridge,
        api,
    };
    let status = (api.initialize)(
        id,
        child,
        place::<F>,
        destroy,
        std::ptr::from_mut(&mut input).cast(),
    );
    if let Some(first) = input.first_error {
        return Err(first);
    }
    super::native_status(status)
}

fn geometry(address: *mut c_void, bytes: usize, alignment: usize) -> bool {
    let layout = Layout::new::<LiveVcpuTimeCallbackState>();
    !address.is_null()
        && bytes == layout.size()
        && alignment >= layout.align()
        && alignment.is_power_of_two()
        && (address as usize).is_multiple_of(layout.align())
}

extern "C" fn place<F>(
    id: u64,
    child: *mut Storage,
    address: *mut c_void,
    bytes: usize,
    alignment: usize,
    bridge: *mut BridgeStorage,
    input: *mut c_void,
) -> i32
where
    F: FnOnce(
        &mut MaybeUninit<LiveVcpuTimeCallbackState>,
        Progress<'_>,
    ) -> Result<(), LiveVcpuTimeCallbackError>,
{
    if input.is_null() || !geometry(address, bytes, alignment) {
        return -libc::EINVAL;
    }
    // SAFETY: Source lends this exact synchronous stack context and retains
    // neither its pointer nor any Rust reference obtained during the callback.
    let input = unsafe { &mut *input.cast::<Input<F>>() };
    if id != input.id || child != input.child || bridge != input.bridge {
        return -libc::EPROTO;
    }
    let rollback_status = Cell::new(0);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(constructor) = input.constructor.take() else {
            return -libc::EALREADY;
        };
        let progress = Progress {
            id,
            child,
            api: input.api,
            rollback_status: &rollback_status,
        };
        // SAFETY: exact Source-created geometry and entered ownership lend this
        // sole uninitialized span. The reference cannot escape the FnOnce call.
        let span = unsafe { &mut *address.cast::<MaybeUninit<LiveVcpuTimeCallbackState>>() };
        match constructor(span, progress) {
            Ok(()) => rollback_status.get(),
            Err(first) => {
                input.first_error = Some(first);
                -libc::EINVAL
            }
        }
    }));
    // A caught panic never acknowledges completed rollback or typed placement.
    // Only the actual guard hook and full-init call change Source's journals.
    result.unwrap_or(-libc::EFAULT)
}

extern "C" fn destroy(
    id: u64,
    child: *mut Storage,
    address: *mut c_void,
    bytes: usize,
    alignment: usize,
) -> i32 {
    if !geometry(address, bytes, alignment) {
        return -libc::EINVAL;
    }
    let api = match Api::resolve() {
        Ok(api) => api,
        Err(_) => return -libc::ENOSYS,
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: Source excluded all real child/Bridge uses and marked once
        // destruction before this entered callback. It owns sole backing free.
        unsafe {
            let state = &*address.cast::<LiveVcpuTimeCallbackState>();
            if let Err(status) = state.capture_material_disposition() {
                return status;
            }
            drop_and_acknowledge(address.cast::<LiveVcpuTimeCallbackState>(), || {
                (api.destroyed)(id, child)
            })
        }
    }));
    result.unwrap_or(-libc::EFAULT)
}

/// Drops one exact initialized T before its genuine completion acknowledgement.
///
/// # Safety
/// The caller retains unique live initialized storage with all physical uses
/// excluded; its owning Source already recorded the once destruction attempt.
unsafe fn drop_and_acknowledge<T>(body: *mut T, acknowledge: impl FnOnce() -> i32) -> i32 {
    // SAFETY: the entered owner excluded all users of this exact initialized T.
    unsafe { std::ptr::drop_in_place(body) };
    acknowledge()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tracked<'a>(&'a Cell<usize>);

    impl Drop for Tracked<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn destruction_acknowledgement_observes_completed_drop_without_freeing_backing() {
        let drops = Cell::new(0);
        let mut backing = MaybeUninit::new(Tracked(&drops));
        let address = backing.as_mut_ptr();
        // SAFETY: one complete component object, with no users or escaped refs.
        let status = unsafe {
            drop_and_acknowledge(address, || {
                assert_eq!(drops.get(), 1);
                -libc::EKEYEXPIRED
            })
        };

        assert_eq!(status, -libc::EKEYEXPIRED);
        assert_eq!(drops.get(), 1);
        assert_eq!(backing.as_mut_ptr(), address);
        // The acknowledgement refused after real drop; raw backing remains
        // independently owned and MaybeUninit cannot repeat destruction.
    }

    #[test]
    fn uncertain_destructor_never_emits_completed_acknowledgement() {
        struct Panics;

        impl Drop for Panics {
            fn drop(&mut self) {
                panic!("actual component destructor refusal");
            }
        }

        let mut backing = MaybeUninit::new(Panics);
        let acknowledged = Cell::new(false);
        let result = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: this component object has no users; the unwind leaves
            // uncertain typed destruction, so no second drop follows.
            unsafe {
                drop_and_acknowledge(backing.as_mut_ptr(), || {
                    acknowledged.set(true);
                    0
                })
            }
        }));

        assert!(result.is_err());
        assert!(!acknowledged.get());
    }
}
