//! Retains the module's actual sample branch separately from payload custody.
//!
//! Native binds these process-private canonical fields at the real entered Main
//! action. The journal authenticates its own request, local borrower and typed
//! branch; a copied class, request tuple or payload token cannot issue this owner.
//! Completion and physical worker/material return remain separate observations.
// SPDX-License-Identifier: GPL-2.0-only

use super::{PendingRequest, ProtectedReader, ReadJournal, TryLockError};
use super::payload::{Payload, PayloadBorrow};

/// Names the actual inline semantic branch without exposing its Rust layout.
#[repr(C)]
pub(in crate::runtime) struct FingerprintAction {
    _private: [u8; 0],
}

/// Corroborates the matched module's independent complete-sample unit contract.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::runtime) struct FingerprintActionEvidence {
    pub(in crate::runtime) schema_version: u32,
    pub(in crate::runtime) struct_size: u32,
    pub(in crate::runtime) primary_class: u32,
    pub(in crate::runtime) preparation_present: u32,
    pub(in crate::runtime) required_units: u64,
    pub(in crate::runtime) completed_required_units: u64,
    pub(in crate::runtime) preparation_required_units: u64,
    pub(in crate::runtime) preparation_completed_required_units: u64,
}

impl FingerprintActionEvidence {
    fn sample(primary_class: u32) -> Result<Self, i32> {
        if primary_class != 4 && primary_class != 5 {
            return Err(-libc::EOPNOTSUPP);
        }
        Ok(Self {
            schema_version: 1,
            struct_size: std::mem::size_of::<Self>() as u32,
            primary_class,
            preparation_present: 0,
            required_units: 1,
            completed_required_units: 0,
            preparation_required_units: 0,
            preparation_completed_required_units: 0,
        })
    }
}

/// Keeps only the actual original fields supplied by the genuine member.
#[derive(Clone, Copy)]
pub(in crate::runtime) struct SemanticPayloadBorrow {
    pub(in crate::runtime) payload_holder: *mut *mut Payload,
    pub(in crate::runtime) payload_serial: u64,
    pub(in crate::runtime) borrow_holder: *mut *mut PayloadBorrow,
    pub(in crate::runtime) borrow_serial: u64,
}

impl SemanticPayloadBorrow {
    // The caller retains the original member fields through every access. Only
    // authenticated exact fields are read; foreign input addresses stay opaque.
    unsafe fn pending<'a>(
        self,
        journal: &'a mut ReadJournal,
    ) -> Result<&'a mut PendingRequest, i32> {
        if self.payload_holder.is_null() || self.borrow_holder.is_null() {
            return Err(-libc::EINVAL);
        }
        if journal.active || !journal.local_reader_released {
            return Err(-libc::EBUSY);
        }
        let sequence = journal.sequence;
        let pending = journal.pending.as_mut().ok_or(-libc::ENOENT)?;
        if pending.process != std::process::id()
            || pending.serial != sequence
            || pending.serial != self.payload_serial
            || pending.canonical_holder != self.payload_holder
        {
            return Err(-libc::ESTALE);
        }
        let projection = std::ptr::from_mut(pending).cast::<Payload>();
        // SAFETY: the original live canonical field has been authenticated.
        if unsafe { self.payload_holder.read() } != projection {
            return Err(-libc::ESTALE);
        }
        let borrowed = pending.borrow.as_mut().ok_or(-libc::ENOENT)?;
        if borrowed.holder != self.borrow_holder
            || borrowed.serial != self.borrow_serial
            || self.borrow_serial == 0
            || borrowed.thread != current_thread()?
        {
            return Err(-libc::ESTALE);
        }
        let borrow_projection = std::ptr::from_mut(borrowed).cast::<PayloadBorrow>();
        // SAFETY: the real borrow retains both original Source output fields.
        if unsafe {
            self.borrow_holder.read() != borrow_projection
                || borrowed.serial_holder.read() != self.borrow_serial
        } {
            return Err(-libc::ESTALE);
        }
        Ok(pending)
    }
}

fn current_thread() -> Result<libc::pid_t, i32> {
    // SAFETY: gettid observes the actual Linux caller without pointer inputs.
    let thread = unsafe { libc::gettid() };
    if thread <= 0 {
        Err(-libc::EIO)
    } else {
        Ok(thread)
    }
}

/// Saves the branch and its independent execution and cleanup histories inline.
pub(super) struct ActionState {
    holder: *mut *mut FingerprintAction,
    serial_holder: *mut u64,
    serial: u64,
    thread: libc::pid_t,
    capture: u32,
    evidence: FingerprintActionEvidence,
    worker_floor: u64,
    dispatch_entered: bool,
    dispatch_returned: bool,
    first: i32,
    post: i32,
    post_observed: bool,
    worker_first: i32,
}

impl ActionState {
    unsafe fn authenticate(
        &mut self,
        holder: *mut *mut FingerprintAction,
        serial: u64,
    ) -> Result<(), i32> {
        if self.holder != holder
            || self.serial != serial
            || serial == 0
            || self.thread != current_thread()?
        {
            return Err(-libc::ESTALE);
        }
        let projection = std::ptr::from_mut(self).cast::<FingerprintAction>();
        // SAFETY: only the saved original live fields are read after identity.
        if unsafe { holder.read() != projection || self.serial_holder.read() != serial } {
            return Err(-libc::ESTALE);
        }
        Ok(())
    }
}

impl ProtectedReader {
    /// Issues the actual retained sample branch before its independent post.
    ///
    /// # Safety
    /// The genuine first-bound member retains the pinned child and every exact
    /// common/output field. Outputs are aligned, writable, distinct and stable
    /// through physical return. `primary_class` and `worker_floor` are supplied
    /// only by the module's own retained baseline and actual worker observation.
    ///
    /// # Errors
    /// Refuses copied custody, unsupported/non-sample branches, existing owners,
    /// exhausted local serials, contention and poisoned state before birth.
    pub(in crate::runtime) unsafe fn enter_fingerprint_action(
        &self,
        input: SemanticPayloadBorrow,
        holder: *mut *mut FingerprintAction,
        serial_holder: *mut u64,
        known_absent: *mut u32,
        branch: (u32, u64),
    ) -> Result<FingerprintActionEvidence, i32> {
        if holder.is_null() || serial_holder.is_null() || known_absent.is_null() {
            return Err(-libc::EINVAL);
        }
        // SAFETY: actual Source supplies the stable disjoint output fields.
        unsafe {
            known_absent.write(0);
            if !holder.read().is_null() || serial_holder.read() != 0 {
                return Err(-libc::EINVAL);
            }
            known_absent.write(1);
        }
        let evidence = FingerprintActionEvidence::sample(branch.0)?;
        let thread = current_thread()?;
        let mut journal = self.semantic_journal()?;
        let next = journal
            .action_sequence
            .checked_add(1)
            .ok_or(-libc::EOVERFLOW)?;
        // SAFETY: genuine Source retains the exact common input fields.
        let pending = unsafe { input.pending(&mut journal) }?;
        let facts = pending.facts;
        if facts.sampler_configured != 1
            || facts.sample_present != 1
            || facts.sample_generation == 0
            || facts.sample_generation & 1 == 0
            || facts.sample_generation != facts.installed_sample_generation
        {
            return Err(-libc::EOPNOTSUPP);
        }
        if pending.action.is_some() {
            return Err(-libc::EBUSY);
        }
        if pending.semantic_attempted {
            return Err(-libc::EALREADY);
        }
        let capture = u32::try_from(facts.sample_generation).map_err(|_| -libc::EPROTO)?;
        // SAFETY: no fallible action follows birth before the exact outputs.
        unsafe { known_absent.write(0) };
        pending.semantic_attempted = true;
        let action = pending.action.insert(ActionState {
            holder,
            serial_holder,
            serial: next,
            thread,
            capture,
            evidence,
            worker_floor: branch.1,
            dispatch_entered: false,
            dispatch_returned: false,
            first: 0,
            post: 0,
            post_observed: false,
            worker_first: 0,
        });
        let projection = std::ptr::from_mut(action).cast::<FingerprintAction>();
        journal.action_sequence = next;
        // SAFETY: the real owner is retained before publishing its projection.
        unsafe {
            holder.write(projection);
            serial_holder.write(next);
        }
        Ok(evidence)
    }

    fn semantic_journal(&self) -> Result<std::sync::MutexGuard<'_, ReadJournal>, i32> {
        self.journal.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => -libc::EBUSY,
            TryLockError::Poisoned(_) => -libc::EOWNERDEAD,
        })
    }
}

impl ProtectedReader {
    /// Observes the same nominal branch and only actual returned work receipts.
    ///
    /// # Safety
    /// The genuine member retains the original common fields and action holder.
    /// `worker` comes from the same child's actual retained worker control.
    ///
    /// # Errors
    /// Refuses changed custody, duplicate/mismatched receipts or poisoned state.
    pub(in crate::runtime) unsafe fn current_fingerprint_action(
        &self,
        input: SemanticPayloadBorrow,
        holder: *mut *mut FingerprintAction,
        serial: u64,
        worker: crate::runtime::live_callbacks::fingerprint_worker::CaptureReceiptSnapshot,
    ) -> Result<FingerprintActionEvidence, i32> {
        let mut journal = self.semantic_journal()?;
        // SAFETY: the same genuine member retains the exact original fields.
        let pending = unsafe { input.pending(&mut journal) }?;
        let action = pending.action.as_mut().ok_or(-libc::ENOENT)?;
        // SAFETY: the Source holder remains stable through physical return.
        unsafe { action.authenticate(holder, serial) }?;
        action.observe_worker(worker)?;
        if action.worker_first != 0 {
            return Err(action.worker_first);
        }
        Ok(action.evidence)
    }

    /// Saves independent semantic callback/post observations without completion.
    ///
    /// # Safety
    /// The genuine member retains the same common and canonical action fields.
    ///
    /// # Errors
    /// Refuses absent or incomplete real dispatch and contradictory custody.
    pub(in crate::runtime) unsafe fn post_fingerprint_action(
        &self,
        input: SemanticPayloadBorrow,
        holder: *mut *mut FingerprintAction,
        serial: u64,
    ) -> Result<(FingerprintActionEvidence, i32, i32), i32> {
        let mut journal = self.semantic_journal()?;
        // SAFETY: the same genuine member retains the exact original fields.
        let pending = unsafe { input.pending(&mut journal) }?;
        let action = pending.action.as_mut().ok_or(-libc::ENOENT)?;
        // SAFETY: Source keeps the original holder live until consumption.
        unsafe { action.authenticate(holder, serial) }?;
        if !action.dispatch_entered || !action.dispatch_returned {
            return Err(-libc::EBUSY);
        }
        action.post_observed = true;
        Ok((action.evidence, action.first, action.post))
    }

    /// Consumes the actual semantic owner after genuine work closure.
    ///
    /// # Safety
    /// Source retains the original common/action/serial fields and a disjoint
    /// writable physical-output cell. The actual worker observation belongs to
    /// the same child and does not replace Native's independent child checks.
    ///
    /// # Errors
    /// Retains every owner for incomplete dispatch, unclosed work, stale fields,
    /// copied serial cells, contention or poison. A saved worker failure may be
    /// reported after consumption; the physical output independently records it.
    pub(in crate::runtime) unsafe fn return_fingerprint_action(
        &self,
        input: SemanticPayloadBorrow,
        holder: *mut *mut FingerprintAction,
        serial_holder: *mut u64,
        evidence: *mut FingerprintActionEvidence,
        locally_returned: *mut u32,
        worker: crate::runtime::live_callbacks::fingerprint_worker::CaptureReceiptSnapshot,
    ) -> Result<(), i32> {
        if serial_holder.is_null() || evidence.is_null() || locally_returned.is_null() {
            return Err(-libc::EINVAL);
        }
        // SAFETY: the genuine Source invocation supplies the independent output.
        unsafe { locally_returned.write(0) };
        let mut journal = self.semantic_journal()?;
        // SAFETY: Source retains the same genuine common fields.
        let pending = unsafe { input.pending(&mut journal) }?;
        let action = pending.action.as_mut().ok_or(-libc::ENOENT)?;
        if action.serial_holder != serial_holder {
            return Err(-libc::ESTALE);
        }
        // SAFETY: the actual retained serial cell is authenticated before access.
        unsafe { action.authenticate(holder, serial_holder.read()) }?;
        let returned = action.observe_worker(worker)?;
        // A refused submit may reserve a receipt epoch and then return its
        // actual capture to the prequeue owner without leaving a work cell.
        // Only failed dispatch may settle without a work receipt, and the
        // independent actual worker/material quiet proof is still mandatory.
        let failed_dispatch = action.first < 0;
        if !action.dispatch_returned
            || !action.post_observed
            || !worker.quiet
            || (!returned && !failed_dispatch)
        {
            return Err(-libc::EBUSY);
        }
        if action.first == 0
            && action.worker_first == 0
            && action.evidence.completed_required_units != action.evidence.required_units
        {
            return Err(-libc::EPROTO);
        }
        let first = action.worker_first;
        // SAFETY: the same genuine caller retains this disjoint evidence field.
        // Final asynchronous progress is saved before its owner is consumed,
        // including failed physical closure with an incomplete operation unit.
        unsafe { evidence.write(action.evidence) };
        pending.action = None;
        // SAFETY: real semantic custody is consumed before its exact fields.
        // No callback, post or other fallible operation follows consumption.
        unsafe {
            holder.write(std::ptr::null_mut());
            serial_holder.write(0);
            locally_returned.write(1);
        }
        if first != 0 { Err(first) } else { Ok(()) }
    }

    /// Records entry from the actual typed module control handler.
    ///
    /// No-action fixture/legacy dispatch remains outside this semantic journal;
    /// it cannot obtain an action through these observations.
    ///
    /// # Errors
    /// Refuses a mismatched real request, changed actor or repeated dispatch.
    pub(in crate::runtime) fn begin_semantic_dispatch(
        &self,
        control: u32,
        capture: Option<u32>,
    ) -> Result<bool, i32> {
        let mut journal = self.semantic_journal()?;
        let Some(pending) = journal.pending.as_mut() else {
            return Ok(false);
        };
        let Some(action) = pending.action.as_mut() else {
            return Ok(false);
        };
        if pending.process != std::process::id()
            || action.thread != current_thread()?
            || pending.facts.control_sequence != u64::from(control)
            || capture != Some(action.capture)
            || action.dispatch_entered
        {
            return Err(-libc::ESTALE);
        }
        action.dispatch_entered = true;
        Ok(true)
    }

    /// Records actual callback return while preserving its first signed failure.
    ///
    /// # Errors
    /// Refuses missing/repeated dispatch or changed creator custody.
    pub(in crate::runtime) fn finish_semantic_dispatch(&self, first: i32) -> Result<(), i32> {
        let mut journal = self.semantic_journal()?;
        let pending = journal.pending.as_mut().ok_or(-libc::ENOENT)?;
        let action = pending.action.as_mut().ok_or(-libc::ENOENT)?;
        if pending.process != std::process::id()
            || action.thread != current_thread()?
            || !action.dispatch_entered
            || action.dispatch_returned
            || first > 0
        {
            return Err(-libc::ESTALE);
        }
        action.first = first;
        action.dispatch_returned = true;
        Ok(())
    }
}

impl ActionState {
    fn observe_worker(
        &mut self,
        worker: crate::runtime::live_callbacks::fingerprint_worker::CaptureReceiptSnapshot,
    ) -> Result<bool, i32> {
        if worker.sequence < self.worker_floor {
            return Err(-libc::ESTALE);
        }
        let mut returned = false;
        let mut completed = false;
        let mut first = 0;
        for receipt in worker.returned.into_iter().flatten() {
            if receipt.epoch <= self.worker_floor {
                continue;
            }
            if receipt.capture != self.capture
                || returned
                || receipt.epoch > worker.sequence
                || receipt.first > 0
                || (receipt.first == 0 && !receipt.sample_completed)
            {
                return Err(-libc::EPROTO);
            }
            returned = true;
            first = receipt.first;
            if receipt.sample_completed {
                completed = true;
            }
        }
        if completed {
            self.evidence.completed_required_units = 1;
        }
        if self.worker_first == 0 && first != 0 {
            self.worker_first = first;
        }
        Ok(returned)
    }
}

#[cfg(test)]
mod tests;
