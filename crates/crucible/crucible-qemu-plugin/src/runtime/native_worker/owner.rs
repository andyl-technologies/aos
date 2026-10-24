//! Retains distinct native creation, canonical and observation fields.
//!
//! Native writes the canonical field through its raw address. A copied
//! projection supplies identity only; it never grants readiness or operation
//! authority. The containing Runtime must remain pinned through final return.
// SPDX-License-Identifier: GPL-2.0-only

use std::cell::UnsafeCell;

/// Retains the physical fields for one native creation and canonical transfer.
pub(in crate::runtime) struct OwnerField<T> {
    canonical: UnsafeCell<*mut T>,
    creation: *mut T,
    projection: *mut T,
    transfer_attempted: bool,
}

impl<T> OwnerField<T> {
    /// Creates empty inline fields before the containing Runtime is pinned.
    pub(in crate::runtime) const fn new() -> Self {
        Self {
            canonical: UnsafeCell::new(std::ptr::null_mut()),
            creation: std::ptr::null_mut(),
            projection: std::ptr::null_mut(),
            transfer_attempted: false,
        }
    }

    /// Lends the actual creation output address to its synchronous producer.
    pub(in crate::runtime) fn creation_address(&mut self) -> *mut *mut T {
        &mut self.creation
    }

    /// Identifies the born output read by the same synchronous constructor.
    pub(in crate::runtime) fn creation_projection_address(&self) -> *const *mut T {
        &self.creation
    }

    /// Saves the born identity before any signed creation result is interpreted.
    pub(in crate::runtime) fn record_birth(&mut self) -> *mut T {
        self.projection = self.creation;
        self.projection
    }

    /// Returns only the saved identity, without reading Native canonical storage.
    pub(in crate::runtime) fn projection(&self) -> *mut T {
        self.projection
    }

    /// Records transfer entry before Native can move either physical field.
    ///
    /// # Panics
    /// Propagates a panic from the supplied transfer call after recording entry.
    pub(in crate::runtime) fn transfer(
        &mut self,
        transfer: impl FnOnce(*mut *mut T, *mut *mut T) -> i32,
    ) -> i32 {
        self.transfer_attempted = true;
        transfer(&mut self.creation, self.canonical.get())
    }

    /// Reports the local creation-field disposition after a transfer call.
    pub(in crate::runtime) fn creation_consumed(&self) -> bool {
        self.creation.is_null()
    }

    /// Selects the same physical field that an entered transfer actually left.
    pub(in crate::runtime) fn return_address(&mut self) -> *mut *mut T {
        if self.transfer_attempted && self.creation.is_null() {
            self.canonical.get()
        } else {
            &mut self.creation
        }
    }

    /// Clears the saved identity after the caller proved by-reference return.
    pub(in crate::runtime) fn returned(&mut self) {
        self.projection = std::ptr::null_mut();
    }
}
