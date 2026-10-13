//! Thread-scoped ring custody across one synchronous native operation.
//!
//! Begin and end surround separate native callbacks. Their finite credits
//! never clear either HELD barrier. Local completion records actual admission
//! balance; native stopped cuts and full journals remain separate authority.

use std::cell::RefCell;
use std::thread::ThreadId;

use super::*;

/// Bounds actual selected producer and consumer admission attempts.
#[derive(Clone, Copy, Debug)]
pub struct SelectedRingAdmissionBudget {
    /// Bounds producer attempts before any ring publication.
    pub producer_attempts: u64,
    /// Bounds consumer attempts before any ring advancement.
    pub consumer_attempts: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Correlates one original local command allocation without native authority.
pub(super) struct ScopeIdentity {
    epoch: u64,
    sequence: u64,
    allocation: usize,
    process: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// Binds a live callback loan to its original process, thread and owner.
pub(super) struct ActiveScope {
    identity: ScopeIdentity,
    thread: ThreadId,
    mapping_owner: usize,
}

struct ThreadPermit {
    cell: Arc<ScopeCell>,
    headers: Arc<[usize]>,
    active: ActiveScope,
    budget: SelectedRingAdmissionBudget,
    producers: u64,
    consumers: u64,
    refused: bool,
}

impl ThreadPermit {
    fn current(&self) -> bool {
        !self.refused
            && self.active.identity.process == std::process::id()
            && self.active.thread == std::thread::current().id()
            && self.cell.selected.load(Ordering::Acquire)
            && self.cell.epoch.load(Ordering::Acquire) == self.active.identity.epoch
            && self.cell.lease_alive.load(Ordering::Acquire)
            && self.cell.lease_sequence.load(Ordering::Acquire) == self.active.identity.sequence
            && self.cell.lease_owner.load(Ordering::Acquire) == self.active.mapping_owner
    }

    fn revoke(&self) {
        // An abandoned older TLS instance cannot revoke a newer command.
        if self.cell.lease_sequence.load(Ordering::Acquire) == self.active.identity.sequence
            && self.cell.lease_owner.load(Ordering::Acquire) == self.active.mapping_owner
        {
            self.cell.lease_alive.store(false, Ordering::Release);
        }
    }
}

impl Drop for ThreadPermit {
    fn drop(&mut self) {
        // Thread exit and unwind retain uncertainty in the original cell.
        self.revoke();
    }
}

thread_local! {
    static PERMIT: RefCell<Option<ThreadPermit>> = const { RefCell::new(None) };
}

struct PermitFence;

struct CallbackFence {
    cell: Arc<ScopeCell>,
    sequence: u64,
    mapping_owner: usize,
    succeeded: bool,
}

impl Drop for CallbackFence {
    fn drop(&mut self) {
        if !self.succeeded
            && self.cell.lease_sequence.load(Ordering::Acquire) == self.sequence
            && self.cell.lease_owner.load(Ordering::Acquire) == self.mapping_owner
        {
            self.cell.lease_alive.store(false, Ordering::Release);
            refuse_selected_admission();
        }
    }
}

impl Drop for PermitFence {
    fn drop(&mut self) {
        PERMIT.with(|slot| slot.borrow_mut().take());
    }
}

/// Retains actual paired ring balance for one original command allocation.
///
/// The token cannot be cloned or caller-constructed. It binds the original
/// cell, process, epoch, sequence and allocation. Native stopped, request,
/// result and consumed-ACK journal validation must precede local retirement.
pub struct SelectedRingCompletion {
    cell: Arc<ScopeCell>,
    identity: ScopeIdentity,
    producers: u64,
    consumers: u64,
}

impl SelectedRingCompletion {
    /// Returns actual producer admission attempts within this loan.
    #[must_use]
    pub const fn producer_attempts(&self) -> u64 {
        self.producers
    }

    /// Returns actual consumer admission attempts within this loan.
    #[must_use]
    pub const fn consumer_attempts(&self) -> u64 {
        self.consumers
    }
}

/// Debits one exact live selected header before its first admission CAS.
pub(crate) fn admit_selected_header(address: usize, producer: bool, held: bool) -> Option<bool> {
    PERMIT.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return Some(false);
        };
        let permit = slot.as_mut()?;
        if !permit.current() || permit.headers.binary_search(&address).is_err() || !held {
            permit.refused = true;
            return Some(false);
        }

        let (attempts, limit) = if producer {
            (&mut permit.producers, permit.budget.producer_attempts)
        } else {
            (&mut permit.consumers, permit.budget.consumer_attempts)
        };
        if *attempts >= limit {
            permit.refused = true;
            return Some(false);
        }
        *attempts += 1;
        Some(true)
    })
}

/// Refuses further admissions in the current thread's selected permit.
pub(crate) fn refuse_selected_admission() {
    PERMIT.with(|slot| {
        if let Ok(mut slot) = slot.try_borrow_mut()
            && let Some(permit) = slot.as_mut()
        {
            permit.refused = true;
        }
    });
}

/// Authorizes the original mapped cell under the current live permit.
pub(super) fn authorize_selected_mapping(cell: &Arc<ScopeCell>, backing_selected: bool) -> bool {
    PERMIT.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return false;
        };
        let Some(permit) = slot.as_mut() else {
            return !backing_selected;
        };
        let valid = permit.current() && Arc::ptr_eq(cell, &permit.cell);
        if !valid {
            permit.refused = true;
        }
        valid
    })
}

/// Checks an exact role before exposing a selected mutable entry view.
pub(super) fn authorize_selected_view(
    cell: &Arc<ScopeCell>,
    backing_selected: bool,
    address: usize,
) -> bool {
    PERMIT.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return false;
        };
        let Some(permit) = slot.as_mut() else {
            return !backing_selected;
        };
        let valid = permit.current()
            && Arc::ptr_eq(cell, &permit.cell)
            && permit.headers.binary_search(&address).is_ok();
        if !valid {
            permit.refused = true;
        }
        valid
    })
}

/// Revokes the current thread's exact mapped allocation loan.
pub(super) fn revoke_owner(mapping_owner: usize) {
    PERMIT.with(|slot| {
        if let Ok(mut slot) = slot.try_borrow_mut()
            && slot
                .as_ref()
                .is_some_and(|permit| permit.active.mapping_owner == mapping_owner)
        {
            slot.take();
        }
    });
}

/// Revokes a failed shared callback's current original thread permit.
pub(super) fn revoke_cell(cell: &Arc<ScopeCell>) {
    PERMIT.with(|slot| {
        if let Ok(mut slot) = slot.try_borrow_mut()
            && slot
                .as_ref()
                .is_some_and(|permit| Arc::ptr_eq(cell, &permit.cell))
        {
            slot.take();
        }
    });
}

impl RetainedWholeMapping {
    pub(super) fn refuse_active_loan(&self) {
        if let Some(cell) = &self.cell
            && cell.lease_owner.load(Ordering::Acquire) == Arc::as_ptr(&self.mapping) as usize
        {
            cell.lease_alive.store(false, Ordering::Release);
        }
        refuse_selected_admission();
    }

    /// Cancels local paired custody without reading mapped state or retiring it.
    ///
    /// The provider invokes this before returning a native getter, body or
    /// currentness failure. Its exact original mapping permit is revoked before
    /// any later ring admission. The actual owner, HELD barriers and pending
    /// completion history remain retained; cancellation grants no authority.
    pub fn refuse_paired_control(&mut self) {
        self.status = Err(WholeMappingCustodyError::Selected);
        self.refuse_active_loan();
        revoke_owner(Arc::as_ptr(&self.mapping) as usize);
    }

    /// Begins finite paired custody before the native operation's callbacks.
    ///
    /// The native provider first authenticates the original current scope.
    /// This method lends its enumerated headers to this process and thread
    /// until [`Self::end_paired_scope`]. No mutex guard crosses the callback
    /// boundary. Any refusal leaves the original world selected and uncertain.
    ///
    /// # Errors
    ///
    /// Refuses an uncertain, foreign, stale, nested, exhausted, nonunique or
    /// nonquiescent original scope. It supplies no native execution authority.
    pub fn begin_paired_scope(
        &mut self,
        epoch: u64,
        sequence: u64,
        allocation: usize,
        budget: SelectedRingAdmissionBudget,
    ) -> Result<(), WholeMappingCustodyError> {
        if let Err(error) = self.selection_status() {
            self.refuse_active_loan();
            return Err(error);
        }
        let cell = self
            .cell
            .as_ref()
            .ok_or(WholeMappingCustodyError::Unregistered)?;
        let mut selection = try_lock(&cell.selection)?;
        *selection = Selection::Selected {
            epoch: self.epoch,
            uncertain: true,
        };
        if epoch != self.epoch
            || allocation == 0
            || sequence == 0
            || sequence > self.operation_capacity
            || sequence != cell.next_sequence.load(Ordering::Acquire)
            || Arc::strong_count(&self.mapping) != 1
        {
            refuse_selected_admission();
            return Err(WholeMappingCustodyError::Selected);
        }
        let rings = self
            .mapping
            .hot_fork_ring_io_snapshot()
            .map_err(|_| WholeMappingCustodyError::NotQuiescent)?;
        if !rings.quiescent() {
            return Err(WholeMappingCustodyError::NotQuiescent);
        }

        let active = ActiveScope {
            identity: ScopeIdentity {
                epoch,
                sequence,
                allocation,
                process: std::process::id(),
            },
            thread: std::thread::current().id(),
            mapping_owner: Arc::as_ptr(&self.mapping) as usize,
        };
        let mut current = try_lock(&cell.active_scope)?;
        if current.is_some() || try_lock(&cell.pending_completion)?.is_some() {
            refuse_selected_admission();
            return Err(WholeMappingCustodyError::Selected);
        }
        PERMIT.with(|slot| {
            let mut slot = slot
                .try_borrow_mut()
                .map_err(|_| WholeMappingCustodyError::Busy)?;
            if let Some(permit) = slot.as_mut() {
                permit.refused = true;
                return Err(WholeMappingCustodyError::Busy);
            }
            // All storage was allocated at mapping/selection admission.
            // The command loan only clones retained Arcs and fills TLS state.
            *current = Some(active);
            cell.lease_owner
                .store(active.mapping_owner, Ordering::Release);
            cell.lease_sequence.store(sequence, Ordering::Release);
            cell.lease_alive.store(true, Ordering::Release);
            *slot = Some(ThreadPermit {
                cell: Arc::clone(cell),
                headers: Arc::clone(&self.ring_headers),
                active,
                budget,
                producers: 0,
                consumers: 0,
                refused: false,
            });
            Ok(())
        })
    }

    /// Borrows the exact original mapping during a current native callback.
    ///
    /// Begin and end may surround several callbacks; each callback borrows
    /// the original mapping only while its same-thread permit remains current.
    /// A callback error refuses subsequent admissions in the same loan.
    ///
    /// # Errors
    ///
    /// Returns a current-loan refusal or the callback's original error. This
    /// loan supplies no stopped cut, request, result or ACK authentication.
    pub fn with_paired_mapping<T, E>(
        &mut self,
        service: impl FnOnce(&mut MappedSetupRegion) -> Result<T, E>,
    ) -> Result<Result<T, E>, WholeMappingCustodyError> {
        self.status?;
        let cell = self
            .cell
            .as_ref()
            .ok_or(WholeMappingCustodyError::Unregistered)?;
        if !authorize_selected_mapping(cell, true) {
            self.refuse_active_loan();
            return Err(WholeMappingCustodyError::Selected);
        }
        let mut fence = CallbackFence {
            cell: Arc::clone(cell),
            sequence: cell.lease_sequence.load(Ordering::Acquire),
            mapping_owner: Arc::as_ptr(&self.mapping) as usize,
            succeeded: false,
        };
        let mapping = Arc::get_mut(&mut self.mapping).ok_or(WholeMappingCustodyError::Busy)?;
        let result = service(mapping);
        fence.succeeded = result.is_ok();
        Ok(result)
    }

    /// Ends callback custody and returns actual local admission balance.
    ///
    /// The thread permit is revoked before any correlation or ring check.
    /// Refusal cannot reopen a loan. A successful token remains pending until
    /// authentic native full-journal retirement; both HELD barriers stay set.
    ///
    /// # Errors
    ///
    /// Refuses missing, foreign, moved, stale, exhausted or unbalanced loans.
    /// No result from this method establishes native retirement authority.
    pub fn end_paired_scope(
        &mut self,
        epoch: u64,
        sequence: u64,
        allocation: usize,
    ) -> Result<SelectedRingCompletion, WholeMappingCustodyError> {
        let permit = PERMIT.with(|slot| {
            let mut slot = slot
                .try_borrow_mut()
                .map_err(|_| WholeMappingCustodyError::Busy)?;
            Ok(slot.take())
        })?;
        let Some(permit) = permit else {
            self.refuse_active_loan();
            return Err(WholeMappingCustodyError::Selected);
        };
        let was_current = permit.current();
        permit.revoke();
        self.status?;
        let cell = self
            .cell
            .as_ref()
            .ok_or(WholeMappingCustodyError::Unregistered)?;
        let registered = registered_cell(self.mapping.mapping_owner_key())?;
        if !Arc::ptr_eq(cell, &registered) {
            return Err(WholeMappingCustodyError::Unregistered);
        }
        let mut selection = try_lock(&cell.selection)?;
        *selection = Selection::Selected {
            epoch: self.epoch,
            uncertain: true,
        };
        let active = try_lock(&cell.active_scope)?.take();
        let expected = ScopeIdentity {
            epoch,
            sequence,
            allocation,
            process: std::process::id(),
        };
        let rings = self
            .mapping
            .hot_fork_ring_io_snapshot()
            .map_err(|_| WholeMappingCustodyError::NotQuiescent)?;
        if !was_current
            || epoch != self.epoch
            || !Arc::ptr_eq(cell, &permit.cell)
            || permit.active.identity != expected
            || active != Some(permit.active)
            || permit.active.mapping_owner != Arc::as_ptr(&self.mapping) as usize
            || cell.next_sequence.load(Ordering::Acquire) != sequence
            || !rings.quiescent()
        {
            return Err(WholeMappingCustodyError::NotQuiescent);
        }
        *try_lock(&cell.pending_completion)? = Some(expected);
        Ok(SelectedRingCompletion {
            cell: Arc::clone(cell),
            identity: expected,
            producers: permit.producers,
            consumers: permit.consumers,
        })
    }

    /// Services one paired loan entirely within a Rust callback.
    ///
    /// Providers with several separate native callbacks use explicit begin,
    /// mapping borrow and end instead. An error or unwind revokes this loan
    /// while retaining uncertainty in the original selected mapping.
    ///
    /// # Errors
    ///
    /// Returns custody refusal or the original callback error. A completion
    /// certifies local balance only; native retirement remains separate.
    pub fn with_paired_selected_scope<T, E>(
        &mut self,
        epoch: u64,
        sequence: u64,
        allocation: usize,
        budget: SelectedRingAdmissionBudget,
        service: impl FnOnce(&mut MappedSetupRegion) -> Result<T, E>,
    ) -> Result<Result<(T, SelectedRingCompletion), E>, WholeMappingCustodyError> {
        self.begin_paired_scope(epoch, sequence, allocation, budget)?;
        let _fence = PermitFence;
        let value = match self.with_paired_mapping(service)? {
            Ok(value) => value,
            Err(error) => return Ok(Err(error)),
        };
        let completion = self.end_paired_scope(epoch, sequence, allocation)?;
        Ok(Ok((value, completion)))
    }

    /// Consumes local balance after authentic native stopped retirement.
    ///
    /// The provider first validates the exact immutable request, result,
    /// consumed ACK, native stopped cut and complete retained journals. This
    /// operation advances only the original command slot; HELD stays set.
    ///
    /// # Errors
    ///
    /// Refuses foreign, stale or unmatched completion tokens. This method
    /// supplies no native stopped, body acceptance, result or ACK authority.
    pub fn retire_paired_scope(
        &mut self,
        epoch: u64,
        sequence: u64,
        allocation: usize,
        completion: SelectedRingCompletion,
    ) -> Result<(), WholeMappingCustodyError> {
        self.status?;
        let cell = self
            .cell
            .as_ref()
            .ok_or(WholeMappingCustodyError::Unregistered)?;
        let registered = registered_cell(self.mapping.mapping_owner_key())?;
        if !Arc::ptr_eq(cell, &registered) {
            return Err(WholeMappingCustodyError::Unregistered);
        }
        let mut selection = try_lock(&cell.selection)?;
        *selection = Selection::Selected {
            epoch: self.epoch,
            uncertain: true,
        };
        let mut pending = try_lock(&cell.pending_completion)?;
        let expected = ScopeIdentity {
            epoch,
            sequence,
            allocation,
            process: std::process::id(),
        };
        let rings = self
            .mapping
            .hot_fork_ring_io_snapshot()
            .map_err(|_| WholeMappingCustodyError::NotQuiescent)?;
        if epoch != self.epoch
            || cell.epoch.load(Ordering::Acquire) != epoch
            || !Arc::ptr_eq(cell, &completion.cell)
            || completion.identity != expected
            || *pending != Some(expected)
            || try_lock(&cell.active_scope)?.is_some()
            || cell.next_sequence.load(Ordering::Acquire) != sequence
            || !rings.quiescent()
        {
            return Err(WholeMappingCustodyError::Selected);
        }
        *pending = None;
        cell.next_sequence.store(sequence + 1, Ordering::Release);
        *selection = Selection::Selected {
            epoch,
            uncertain: false,
        };
        Ok(())
    }
}
