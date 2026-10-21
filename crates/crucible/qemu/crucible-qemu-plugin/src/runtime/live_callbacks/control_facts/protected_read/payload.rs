//! Transfers the actual inline request payload through one canonical Source field.
//!
//! The opaque pointer identifies the non-Copy payload inside the pinned complete
//! callback child. Its local serial and copied facts carry no publisher loan,
//! entered operation, ACK, action return or permission to access guest resources.
// SPDX-License-Identifier: GPL-2.0-only

use super::{ProtectedReader, TryLockError};

/// Names a module-private payload without exposing its Rust representation.
#[repr(C)]
pub(in crate::runtime) struct Payload {
    _private: [u8; 0],
}

mod borrow;

/// Names one actual local module payload borrow without exposing its record.
#[repr(C)]
pub(in crate::runtime) struct PayloadBorrow {
    _private: [u8; 0],
}

/// Keeps the original Source output fields inside the prepaid pending journal.
pub(super) struct PayloadBorrowState {
    holder: *mut *mut PayloadBorrow,
    serial_holder: *mut u64,
    serial: u64,
    thread: libc::pid_t,
}

impl ProtectedReader {
    /// Claims the retained payload into the exact stable Source output field.
    ///
    /// # Safety
    /// The reader belongs to the genuinely retained pinned complete child. Source
    /// supplies distinct aligned writable fields, both initially zero, and keeps
    /// the exact holder field alive through return. Its actual member retains the
    /// child and prevents concurrent replacement across every callback/use.
    ///
    /// # Errors
    /// Refuses occupied outputs, absent or already claimed payloads, stale local
    /// identity, active reads, contention and poisoned ownership without transfer.
    pub(in crate::runtime) unsafe fn claim_payload(
        &self,
        holder: *mut *mut Payload,
        serial: *mut u64,
    ) -> Result<(), i32> {
        if holder.is_null() || serial.is_null() {
            return Err(-libc::EINVAL);
        }
        // SAFETY: the actual first-bound Source invocation supplies the checked
        // aligned, disjoint writable outputs and retains their stable storage.
        if unsafe { !holder.read().is_null() || serial.read() != 0 } {
            return Err(-libc::EINVAL);
        }
        let mut journal = match self.journal.try_lock() {
            Ok(journal) => journal,
            Err(TryLockError::WouldBlock) => return Err(-libc::EBUSY),
            Err(TryLockError::Poisoned(_)) => return Err(-libc::EOWNERDEAD),
        };
        if journal.active || !journal.local_reader_released {
            return Err(-libc::EBUSY);
        }
        let sequence = journal.sequence;
        let pending = journal.pending.as_mut().ok_or(-libc::ENOENT)?;
        if pending.process != std::process::id() || pending.serial != sequence {
            return Err(-libc::ESTALE);
        }
        if !pending.canonical_holder.is_null() {
            return Err(-libc::EALREADY);
        }

        pending.canonical_holder = holder;
        let payload = std::ptr::from_mut(pending).cast::<Payload>();
        // SAFETY: Source owns these exact outputs. The actual payload remains
        // inside the pinned child; its recorded field, rather than a copied
        // pointer or scalar, is the sole local return destination.
        unsafe {
            holder.write(payload);
            serial.write(sequence);
        }
        Ok(())
    }

    /// Destroys the real inline payload before nulling its exact Source holder.
    ///
    /// # Safety
    /// Source retains the same pinned child and canonical holder established by
    /// `claim_payload`. The nominated holder is aligned and writable. Actual
    /// payload borrowers retain the journal lock, and no payload reference may
    /// escape that lock or outlive successful return.
    ///
    /// # Errors
    /// Refuses foreign/copied fields, stale identity, absent payloads, active
    /// reads, contention or poisoned ownership. Every negative retains custody.
    pub(in crate::runtime) unsafe fn return_payload(
        &self,
        holder: *mut *mut Payload,
        serial: u64,
    ) -> Result<(), i32> {
        if holder.is_null() || serial == 0 {
            return Err(-libc::EINVAL);
        }
        let mut journal = match self.journal.try_lock() {
            Ok(journal) => journal,
            Err(TryLockError::WouldBlock) => return Err(-libc::EBUSY),
            Err(TryLockError::Poisoned(_)) => return Err(-libc::EOWNERDEAD),
        };
        if journal.active || !journal.local_reader_released {
            return Err(-libc::EBUSY);
        }
        let sequence = journal.sequence;
        let pending = journal.pending.as_mut().ok_or(-libc::ENOENT)?;
        if pending.process != std::process::id()
            || pending.serial != sequence
            || pending.serial != serial
            || pending.canonical_holder != holder
        {
            return Err(-libc::ESTALE);
        }
        if pending.borrow.is_some() {
            return Err(-libc::EBUSY);
        }
        let payload = std::ptr::from_mut(pending).cast::<Payload>();
        // SAFETY: only the exact recorded stable field is read after the actual
        // pinned payload and its local generation have been authenticated.
        if unsafe { holder.read() } != payload {
            return Err(-libc::ESTALE);
        }

        journal.pending = None;
        // SAFETY: every payload use is closed and the real payload has been
        // destroyed. No callback or fallible post follows local consumption.
        unsafe { holder.write(std::ptr::null_mut()) };
        Ok(())
    }
}

#[cfg(test)]
mod tests;
