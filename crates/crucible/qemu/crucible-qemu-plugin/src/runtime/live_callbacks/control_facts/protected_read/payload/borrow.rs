//! Pins the actual module payload in one prepaid, canonical local borrow.
//!
//! Native supplies stable fields under its real Main/Ready custody. This record
//! pins only the local pending payload; it exports no reference, action, clock,
//! publisher membership or guest-access permission. Physical outputs precede
//! Native's independent post and cannot be replaced by its signed disposition.
// SPDX-License-Identifier: GPL-2.0-only

use super::{Payload, PayloadBorrow, PayloadBorrowState, ProtectedReader, TryLockError};

fn current_thread() -> Result<libc::pid_t, i32> {
    // SAFETY: gettid accepts no pointers and observes the calling Linux actor
    // without allocating a Rust thread handle or consulting modeled guest time.
    let thread = unsafe { libc::gettid() };
    if thread <= 0 {
        return Err(-libc::EIO);
    }
    Ok(thread)
}

impl ProtectedReader {
    /// Pins the exact payload before reporting its actual borrow output.
    ///
    /// # Safety
    /// Source retains the genuine pinned child and its canonical payload field.
    /// All outputs are aligned, writable, disjoint and stable until consumed;
    /// Source prevents concurrent access to those fields and retains Main/Ready
    /// custody throughout invocation, independent post and physical return.
    ///
    /// # Errors
    /// Refuses malformed or occupied outputs, changed canonical payload, active
    /// reads, existing borrows, exhausted serials, contention or poisoned state.
    /// Known absence is reported only for this invocation's unmodified outputs;
    /// it grants no permission and says nothing about another borrow's lifetime.
    pub(in crate::runtime) unsafe fn acquire_payload_borrow(
        &self,
        payload_holder: *mut *mut Payload,
        payload_serial: u64,
        holder: *mut *mut PayloadBorrow,
        serial_holder: *mut u64,
        known_absent: *mut u32,
    ) -> Result<(), i32> {
        if payload_holder.is_null()
            || holder.is_null()
            || serial_holder.is_null()
            || known_absent.is_null()
        {
            return Err(-libc::EINVAL);
        }

        // SAFETY: the actual first-bound Source invocation owns the disjoint
        // fields. Occupied outputs may already carry debt, so remain unknown.
        unsafe {
            known_absent.write(0);
            if !holder.read().is_null() || serial_holder.read() != 0 {
                return Err(-libc::EINVAL);
            }
            known_absent.write(1);
        }

        let thread = current_thread()?;

        let mut journal = match self.journal.try_lock() {
            Ok(journal) => journal,
            Err(TryLockError::WouldBlock) => return Err(-libc::EBUSY),
            Err(TryLockError::Poisoned(_)) => return Err(-libc::EOWNERDEAD),
        };

        if journal.active || !journal.local_reader_released {
            return Err(-libc::EBUSY);
        }

        let sequence = journal.sequence;
        let next = journal
            .borrow_sequence
            .checked_add(1)
            .ok_or(-libc::EOVERFLOW)?;
        let pending = journal.pending.as_mut().ok_or(-libc::ENOENT)?;
        if pending.process != std::process::id()
            || pending.serial != sequence
            || pending.serial != payload_serial
            || payload_serial == 0
            || pending.canonical_holder != payload_holder
        {
            return Err(-libc::ESTALE);
        }

        let payload = std::ptr::from_mut(pending).cast::<Payload>();
        // SAFETY: the exact canonical field is authenticated before reading it.
        if unsafe { payload_holder.read() } != payload {
            return Err(-libc::ESTALE);
        }
        if pending.borrow.is_some() {
            return Err(-libc::EBUSY);
        }

        // All fallible validation precedes mutation. No raw payload reference
        // escapes; the token identifies this actual pinned inline record only.
        // SAFETY: Source retains this original writable output. Clear absence
        // before a real borrower exists; every remaining output is infallible.
        unsafe { known_absent.write(0) };
        let borrowed = pending.borrow.insert(PayloadBorrowState {
            holder,
            serial_holder,
            serial: next,
            thread,
        });
        let projection = std::ptr::from_mut(borrowed).cast::<PayloadBorrow>();
        journal.borrow_sequence = next;
        // SAFETY: Source retains these exact original outputs through return.
        unsafe {
            holder.write(projection);
            serial_holder.write(next);
        }
        Ok(())
    }

    /// Consumes a real local borrow before reporting physical field closure.
    ///
    /// # Safety
    /// Source retains the same child, canonical payload and original borrow
    /// output fields used at acquisition. The outputs remain aligned, writable
    /// and disjoint; the calling actor has closed all actual users of this loan.
    ///
    /// # Errors
    /// Refuses absent, copied, stale, foreign-thread or contradictory custody,
    /// active reads, contention or poisoned state without clearing any holder.
    /// A missing record never certifies an unknown acquire attempt as absent.
    pub(in crate::runtime) unsafe fn release_payload_borrow(
        &self,
        payload_holder: *mut *mut Payload,
        payload_serial: u64,
        holder: *mut *mut PayloadBorrow,
        serial: u64,
        locally_returned: *mut u32,
    ) -> Result<(), i32> {
        if payload_holder.is_null() || holder.is_null() || locally_returned.is_null() {
            return Err(-libc::EINVAL);
        }

        // SAFETY: the genuine Source invocation owns this independent output.
        unsafe { locally_returned.write(0) };

        let thread = current_thread()?;

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
            || pending.serial != payload_serial
            || pending.canonical_holder != payload_holder
        {
            return Err(-libc::ESTALE);
        }

        let payload = std::ptr::from_mut(pending).cast::<Payload>();
        // SAFETY: this is the same authenticated stable canonical payload field.
        if unsafe { payload_holder.read() } != payload {
            return Err(-libc::ESTALE);
        }

        let borrowed = pending.borrow.as_mut().ok_or(-libc::ENOENT)?;
        if borrowed.holder != holder
            || borrowed.serial != serial
            || serial == 0
            || borrowed.thread != thread
        {
            return Err(-libc::ESTALE);
        }

        let serial_holder = borrowed.serial_holder;
        let projection = std::ptr::from_mut(borrowed).cast::<PayloadBorrow>();
        // SAFETY: the actual record retains both original output addresses.
        if unsafe { holder.read() != projection || serial_holder.read() != serial } {
            return Err(-libc::ESTALE);
        }

        pending.borrow = None;
        // SAFETY: real record consumption precedes clearing its exact fields.
        // Source saves all three physical outputs before any independent post.
        unsafe {
            holder.write(std::ptr::null_mut());
            serial_holder.write(0);
            locally_returned.write(1);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
