//! Publishes and destroys the ordinary Arc belonging to a native worker control.
//!
//! The module alone allocates and frees its Arc. Source corroborates the full
//! geometry and owns one raw alias; no helper constructs a private Arc header.
//! Physical join and role-specific debt checks remain independent prerequisites.
// SPDX-License-Identifier: GPL-2.0-only

use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem::{ManuallyDrop, align_of, size_of};
use std::sync::Arc;

/// Describes the pinned-toolchain shared allocation, without issuing credit.
pub(in crate::runtime) struct ControlGeometry<T>(PhantomData<T>);

impl<T> ControlGeometry<T> {
    /// Locates the control body after the ordinary shared allocation header.
    pub(in crate::runtime) const OFFSET: usize =
        crate::runtime::prebirth::shared_data_offset::<T>();
    /// Preserves the greater alignment required by the body or shared header.
    pub(in crate::runtime) const ALIGNMENT: usize = if align_of::<T>() > align_of::<usize>() {
        align_of::<T>()
    } else {
        align_of::<usize>()
    };
    /// Includes the whole shared header, body and final alignment padding.
    pub(in crate::runtime) const BYTES: usize =
        (Self::OFFSET + size_of::<T>() + Self::ALIGNMENT - 1) & !(Self::ALIGNMENT - 1);
}

/// Supplies corroboration coordinates after the actual owner was saved.
pub(in crate::runtime) struct PublishedControl {
    /// Identifies the full ordinary allocation; foreign code must not free it.
    pub(in crate::runtime) allocation: *mut c_void,
    /// Identifies the single raw Arc alias now owned by the native lifetime.
    pub(in crate::runtime) owner: *mut c_void,
}

/// Saves the ordinary owning alias before any allocation-result or post callback.
///
/// # Safety
/// `output` must name the actual retained control-address slot for this birth.
/// Allocation entry must already be admitted by its genuine native frame.
pub(in crate::runtime) unsafe fn publish<T>(body: T, output: *mut usize) -> PublishedControl {
    let control = Arc::new(body);
    let owner = Arc::into_raw(control);
    // SAFETY: the caller supplies the retained output before any fallible post.
    unsafe { *output = owner as usize };
    // SAFETY: the pinned Rust toolchain's exact shared geometry describes this
    // allocation base for corroboration only. No foreign code frees the header.
    let allocation = unsafe { owner.cast::<u8>().sub(ControlGeometry::<T>::OFFSET) }
        .cast_mut()
        .cast();
    PublishedControl {
        allocation,
        owner: owner.cast_mut().cast(),
    }
}

/// Consumes the unique Arc only after actual role-specific checks and entry.
///
/// # Safety
/// Source must lend its exact live owning field after physical join while
/// excluding new users. The pointer must come from `publish` for the same T.
/// `begin` and `complete` must use the same genuine destruction frame.
///
/// # Panics
/// Propagates a panic from validation or the native frame callbacks. A body Drop
/// panic returns EFAULT after clearing the owner, so destruction cannot replay.
pub(in crate::runtime) unsafe fn destroy<T, A: Copy>(
    owner: *mut *mut c_void,
    validate: impl FnOnce(&mut T) -> Result<A, i32>,
    begin: impl FnOnce(A) -> i32,
    complete: impl FnOnce(A) -> i32,
) -> i32 {
    // SAFETY: the caller supplies Source's exact owning field.
    let raw = unsafe { *owner }.cast::<T>();
    if raw.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: this is the one native owning alias created by ordinary Arc.
    // Every pre-drop refusal leaves it intact without decrementing its count.
    let mut control = ManuallyDrop::new(unsafe { Arc::from_raw(raw) });
    let Some(unique) = Arc::get_mut(&mut control) else {
        return -libc::EBUSY;
    };
    let frame_api = match validate(unique) {
        Ok(frame_api) => frame_api,
        Err(status) => return status,
    };
    let status = begin(frame_api);
    if status != 0 {
        return status;
    }
    // SAFETY: destruction consumes this same owning alias once. Clear the field
    // before Drop so an unwinding destructor cannot be entered a second time.
    unsafe { *owner = std::ptr::null_mut() };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(ManuallyDrop::into_inner(control))
    }));
    if let Err(payload) = result {
        std::mem::forget(payload);
        return -libc::EFAULT;
    }
    complete(frame_api)
}
