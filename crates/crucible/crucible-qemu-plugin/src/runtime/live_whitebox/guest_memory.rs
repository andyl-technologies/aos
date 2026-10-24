//! Retains a native read buffer while the live callback borrows its payload.
//!
//! The initial trap inspection uses the GLib allocation directly. Explicit
//! owned readers copy only when their existing interface requires a `Vec`.

use std::ptr::NonNull;

use crate::{GuestMemoryAddressSpace, GuestMemoryRange, GuestMemoryReadError, GuestMemoryReader};

use super::api::{GByteArray, GByteArrayFreeFn, GByteArrayNewFn, QemuReadMemoryVaddrFn};
use super::LiveWhiteboxApis;

/// Adapts live QEMU memory reads to borrowed and explicit owned consumers.
pub(super) struct LiveGuestMemoryReader {
    /// Installed process-local QEMU and GLib entry points.
    pub(super) apis: LiveWhiteboxApis,
}

impl LiveGuestMemoryReader {
    /// Retains one native read result until all borrowed routing finishes.
    ///
    /// # Errors
    /// Returns an unsupported range, allocation, native read or buffer-shape failure.
    pub(super) fn borrow_guest_memory(
        &mut self,
        range: GuestMemoryRange,
    ) -> Result<LiveGuestMemoryBuffer, GuestMemoryReadError> {
        read_guest_buffer(
            range,
            self.apis.g_byte_array_new,
            self.apis.read_memory_vaddr,
            self.apis.g_byte_array_free,
        )
    }
}

impl GuestMemoryReader for LiveGuestMemoryReader {
    fn read_guest_memory(
        &mut self,
        _vcpu_index: u32,
        _current_icount: u64,
        range: GuestMemoryRange,
    ) -> Result<Vec<u8>, GuestMemoryReadError> {
        let buffer = self.borrow_guest_memory(range)?;
        Ok(buffer.bytes().to_vec())
    }
}

/// Owns one initialized GLib array without copying its guest bytes into Rust.
pub(super) struct LiveGuestMemoryBuffer {
    array: NonNull<GByteArray>,
    free: GByteArrayFreeFn,
}

impl LiveGuestMemoryBuffer {
    /// Borrows the complete validated native read for this owner's lifetime.
    pub(super) fn bytes(&self) -> &[u8] {
        // SAFETY: construction retains this initialized native array until Drop.
        let array = unsafe { self.array.as_ref() };
        if array.len == 0 {
            return &[];
        }
        // Avoiding the initial callback Vec copy requires borrowing the native
        // allocation. No array mutation API is exposed while this owner lives.
        // SAFETY: successful QEMU reads initialize `len` bytes; construction
        // checks a nonnull data pointer and a slice-representable exact length.
        // The array remains owned and unmodified until this borrow ends.
        unsafe { std::slice::from_raw_parts(array.data, array.len as usize) }
    }
}

impl Drop for LiveGuestMemoryBuffer {
    fn drop(&mut self) {
        (self.free)(self.array.as_ptr(), true);
    }
}

fn read_guest_buffer(
    range: GuestMemoryRange,
    new: GByteArrayNewFn,
    read: QemuReadMemoryVaddrFn,
    free: GByteArrayFreeFn,
) -> Result<LiveGuestMemoryBuffer, GuestMemoryReadError> {
    if !matches!(range.address_space(), GuestMemoryAddressSpace::Virtual) {
        return Err(GuestMemoryReadError::from_static(
            "live white-box adapter requires a virtual payload range",
        ));
    }
    let array = NonNull::new(new())
        .ok_or_else(|| GuestMemoryReadError::from_static("GLib byte-array allocation failed"))?;
    let buffer = LiveGuestMemoryBuffer { array, free };
    if !read(range.guest_address(), buffer.array.as_ptr(), range.len()) {
        return Err(GuestMemoryReadError::from_static(
            "qemu_plugin_read_memory_vaddr failed",
        ));
    }

    // SAFETY: the successful native call initializes the retained array header.
    let array = unsafe { buffer.array.as_ref() };
    let length = array.len as usize;
    if length != range.len()
        || length > isize::MAX as usize
        || (length != 0 && array.data.is_null())
    {
        return Err(GuestMemoryReadError::from_static(
            "qemu_plugin_read_memory_vaddr returned an invalid byte array",
        ));
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests;
