//! Executes typed placement and destruction without owning Native allocator memory.
// SPDX-License-Identifier: GPL-2.0-only

use super::abi::{Api, Storage};
use crate::fault_command::FaultCommandBridgeError;
use std::alloc::Layout;
use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Adds local retained-content refusal to Source's independent physical gates.
pub(super) trait DestructionDisposition {
    fn destruction_refused(&self) -> bool;
}

impl DestructionDisposition for crate::fault_command::FaultCommandBridge {
    fn destruction_refused(&self) -> bool {
        !self.local_custody_is_empty()
    }
}

struct Placement<F> {
    constructor: Option<F>,
    error: Option<FaultCommandBridgeError>,
    id: u64,
    storage: *mut Storage,
    api: Api,
}

pub(super) fn initialize<T, F>(
    id: u64,
    storage: *mut Storage,
    api: Api,
    constructor: F,
) -> Result<(), FaultCommandBridgeError>
where
    T: DestructionDisposition,
    F: FnOnce() -> Result<T, FaultCommandBridgeError>,
{
    let mut input = Placement {
        constructor: Some(constructor),
        error: None,
        id,
        storage,
        api,
    };
    let status = (api.initialize)(
        id,
        storage,
        place::<T, F>,
        destroy::<T>,
        std::ptr::from_mut(&mut input).cast(),
    );
    // Source copied the initialized acknowledgement before any independent post.
    // A local typed constructor failure remains primary over that later refusal.
    if let Some(error) = input.error {
        return Err(error);
    }
    super::native_status(status)
}

fn geometry<T>(address: *mut c_void, bytes: usize, alignment: usize) -> bool {
    let layout = Layout::new::<T>();
    !address.is_null()
        && bytes == layout.size()
        && alignment >= layout.align()
        && alignment.is_power_of_two()
        && (address as usize).is_multiple_of(layout.align())
}

extern "C" fn place<T, F>(
    address: *mut c_void,
    bytes: usize,
    alignment: usize,
    input: *mut c_void,
    initialized: *mut u32,
) -> i32
where
    F: FnOnce() -> Result<T, FaultCommandBridgeError>,
{
    if input.is_null() || initialized.is_null() || !geometry::<T>(address, bytes, alignment) {
        return -libc::EINVAL;
    }
    // SAFETY: Source synchronously lends this exact live input and unique output;
    // it retains neither. The typed caller does not access them during callback.
    let input = unsafe { &mut *input.cast::<Placement<F>>() };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(constructor) = input.constructor.take() else {
            return -libc::EALREADY;
        };
        let body = match constructor() {
            Ok(body) => body,
            Err(error) => {
                input.error = Some(error);
                return -libc::EINVAL;
            }
        };
        // SAFETY: actual Source allocation and checked exact T geometry permit
        // this sole placement. The Source marker immediately precedes its write.
        unsafe {
            write_body(address, initialized, body, || {
                (input.api.placement_begin)(input.id, input.storage)
            })
        }
    }));
    result.unwrap_or(-libc::EFAULT)
}

/// Commits one already-checked typed body after the real placement journal.
///
/// # Safety
/// The caller retains unique aligned writable storage of the exact T geometry
/// and a valid nonoverlapping u32 output through the synchronous marker/write.
unsafe fn write_body<T>(
    address: *mut c_void,
    initialized: *mut u32,
    body: T,
    marker: impl FnOnce() -> i32,
) -> i32 {
    let status = marker();
    if status != 0 {
        return status;
    }
    // SAFETY: caller checked the unique live T/output spans. Acknowledgement is
    // the first operation after complete placement; no post/refusal intervenes.
    unsafe {
        address.cast::<T>().write(body);
        initialized.write(1);
    }
    0
}

pub(super) extern "C" fn destroy<T: DestructionDisposition>(
    address: *mut c_void,
    bytes: usize,
    alignment: usize,
    destroyed: *mut u32,
) -> i32 {
    if destroyed.is_null() || !geometry::<T>(address, bytes, alignment) {
        return -libc::EINVAL;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the recorded typed destructor is entered only for the exact
        // initialized body after Source excluded all concurrent physical uses.
        if unsafe { &*address.cast::<T>() }.destruction_refused() {
            return -libc::EBUSY;
        }
        // SAFETY: Source invokes the recorded destructor only for this exact
        // initialized T, after excluding physical uses and marking attempted.
        // Source retains negative/unknown drop and never repeats it or frees.
        unsafe {
            std::ptr::drop_in_place(address.cast::<T>());
            destroyed.write(1);
        }
        0
    }));
    result.unwrap_or(-libc::EFAULT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Tracked<'a>(&'a AtomicUsize);

    impl DestructionDisposition for Tracked<'_> {
        fn destruction_refused(&self) -> bool {
            false
        }
    }

    impl Drop for Tracked<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn typed_destruction_returns_contents_without_freeing_the_backing() {
        let drops = AtomicUsize::new(0);
        let mut backing = std::mem::MaybeUninit::new(Tracked(&drops));
        let mut destroyed = 0;
        let layout = Layout::new::<Tracked<'_>>();
        let status = destroy::<Tracked<'_>>(
            backing.as_mut_ptr().cast(),
            layout.size(),
            layout.align(),
            &mut destroyed,
        );

        assert_eq!(status, 0);
        assert_eq!(destroyed, 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        // MaybeUninit owns the backing but does not repeat typed destruction.
    }

    #[test]
    fn rejected_geometry_never_enters_the_typed_destructor() {
        let drops = AtomicUsize::new(0);
        let mut backing = std::mem::MaybeUninit::new(Tracked(&drops));
        let mut destroyed = 0;
        let layout = Layout::new::<Tracked<'_>>();
        let status = destroy::<Tracked<'_>>(
            backing.as_mut_ptr().cast(),
            layout.size() + 1,
            layout.align(),
            &mut destroyed,
        );

        assert_eq!(status, -libc::EINVAL);
        assert_eq!(destroyed, 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        // SAFETY: rejection did not touch the one initialized fixture value.
        unsafe {
            backing.assume_init_drop();
        }
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn placement_refusal_precedes_the_write_and_drops_only_the_local_value() {
        let drops = AtomicUsize::new(0);
        let mut backing = std::mem::MaybeUninit::<Tracked<'_>>::uninit();
        let mut initialized = 0;
        // SAFETY: real fixture backing/output are unique and live. The negative
        // marker leaves the backing uninitialized; no typed read follows.
        let status = unsafe {
            write_body(
                backing.as_mut_ptr().cast(),
                &mut initialized,
                Tracked(&drops),
                || -libc::ECANCELED,
            )
        };

        assert_eq!(status, -libc::ECANCELED);
        assert_eq!(initialized, 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn placement_acknowledges_complete_body_before_any_later_postcut() {
        let drops = AtomicUsize::new(0);
        let mut backing = std::mem::MaybeUninit::<Tracked<'_>>::uninit();
        let mut initialized = 0;
        // SAFETY: the fixture supplies exact unique backing/output; a positive
        // local marker models ordering only and issues no Native allocation.
        let status = unsafe {
            write_body(
                backing.as_mut_ptr().cast(),
                &mut initialized,
                Tracked(&drops),
                || 0,
            )
        };

        assert_eq!(status, 0);
        assert_eq!(initialized, 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        // SAFETY: completed placement is acknowledged; fixture alone owns T.
        unsafe {
            backing.assume_init_drop();
        }
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
