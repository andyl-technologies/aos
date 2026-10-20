//! Retains real operations and their live publishers through physical return.
//!
//! Operation and outer subscriptions are charged intrusive lists. They retain
//! the actual publisher, cancellation and supervisor after the producing guard
//! drops. A matched physical return or the actual producer's sealed unpublished
//! action removes them; ACKs have no role here.
//! Lock order is operation state, then outer, then callback publication. A
//! publisher receives values only and must never query a supervisor.

use super::*;
use crate::host_services::process_birth::{AuthenticatedSourceHostPurpose, SourceHostControlLease};
use crucible_qemu_protocol::boundary_action::{ActionBinding, ActionParent, ActionReturn};
use crucible_qemu_protocol::parent_park_return::ParentParkReturn;

/// Publishes a real lender without recursively consulting its supervisor.
pub trait HostActionPublisher: std::fmt::Debug + Send + Sync {
    /// Records actual membership after durable output, before any projection.
    ///
    /// # Errors
    /// Refuses changed Source/request membership or uncertain publication.
    fn retain_parent(&self, binding: ActionBinding, row: u32) -> Result<(), HostSupervisionError>;

    /// Publishes one actual operation row under its lender's state lock.
    ///
    /// # Errors
    /// Refuses changed membership, immutable identity or uncertain publication.
    fn publish_parent(
        &self,
        binding: ActionBinding,
        row: u32,
        parent: ActionParent,
    ) -> Result<(), HostSupervisionError>;

    /// Publishes an actual outer mutation to every related retained row.
    ///
    /// # Errors
    /// Refuses stale revisions, changed identity or uncertain publication.
    fn publish_outer(
        &self,
        binding: ActionBinding,
        cap: [u8; 32],
        outer: HostOuterCapBinding,
    ) -> Result<(), HostSupervisionError>;

    /// Publishes a complete current cohort while all actual lender locks remain held.
    ///
    /// # Errors
    /// Refuses changed subscriptions, dirty return ownership or publication failure.
    fn publish_cohort(
        &self,
        binding: ActionBinding,
        parents: [ActionParent; 4],
        count: u32,
    ) -> Result<(), HostSupervisionError>;

    /// Observes the physical journal retained by this exact Source transport.
    ///
    /// # Errors
    /// Refuses absent, mismatched or uncertain physical-return observations.
    fn action_return(&self, binding: ActionBinding) -> Result<ActionReturn, HostSupervisionError>;

    /// Checks the actual producer's irreversible local unpublished closure.
    ///
    /// The publisher must retain that producer's nominal privilege and seal it
    /// before any request or capture publication is attempted. Observing an odd
    /// ACK, absent peer, failed wake or equal binding cannot establish this cut.
    ///
    /// # Errors
    /// Refuses any attempted publication, foreign action or uncertain custody.
    fn unpublished_return(&self, binding: ActionBinding) -> Result<(), HostSupervisionError>;

    /// Observes this actual row after its publisher corroborates Park closure.
    ///
    /// The publisher must authenticate the same request's checked transport
    /// closure and mapped terminal record independently of received-view bits.
    /// This returns no standing Source owner and completes no operation.
    ///
    /// # Errors
    /// Refuses absent closure, another row/request or unsupported publishers.
    fn parent_park_return(
        &self,
        _binding: ActionBinding,
        _row: u32,
    ) -> Result<ParentParkReturn, HostSupervisionError> {
        Err(HostSupervisionError::Unavailable)
    }

    /// Revokes semantic continuation while retaining physical owner debt.
    fn invalidate_action(&self, binding: ActionBinding);
}

#[derive(Debug)]
pub(super) struct OperationSubscriber {
    binding: ActionBinding,
    row: u32,
    preparation: u32,
    role: u32,
    publisher: Arc<dyn HostActionPublisher>,
    next: Option<Box<OperationSubscriber>>,
    // The physical node and strong publisher precede their actual credit.
    _credit: Option<SourceHostControlLease>,
}

#[derive(Debug)]
pub(super) struct OuterSubscriber {
    binding: ActionBinding,
    row: u32,
    publisher: Arc<dyn HostActionPublisher>,
    next: Option<Box<OuterSubscriber>>,
}

/// Retains one actual producing operation until its physical borrower returns.
///
/// Drop never invents return. The charged subscription remains in the original
/// operation and outer owner, retaining the publisher and cancellation. The
/// containing Source keeps this selector through all uncertain paths.
#[derive(Debug)]
pub struct HostActionLoan {
    supervisor: HostOperationSupervisor,
    operation: u64,
    binding: ActionBinding,
    row: u32,
    returned: bool,
}

/// Retains return observed through the loan's actual registered Source transport.
///
/// Private fields prevent a plain decoded journal from becoming this selector.
#[derive(Debug)]
pub struct HostActionReturnReceipt {
    shared: Arc<Shared>,
    journal: ActionReturn,
    operation: u64,
    row: u32,
    publisher: Arc<dyn HostActionPublisher>,
}

/// Binds actual membership to its producer's sealed unpublished return.
///
/// Only a retained loan can construct this selector through its registered
/// publisher. It is distinct from a native physical journal or an ACK.
#[derive(Debug)]
pub struct HostActionUnpublishedReturnReceipt {
    shared: Arc<Shared>,
    binding: ActionBinding,
    operation: u64,
    row: u32,
    publisher: Arc<dyn HostActionPublisher>,
}

/// Authenticates one Host membership after the same request physically closed.
///
/// Only the actual loan can construct this private selector by consulting its
/// registered publisher. Pair-view masks cannot construct it or select a row.
#[derive(Debug)]
pub struct HostParentParkReturnReceipt {
    shared: Arc<Shared>,
    journal: ParentParkReturn,
    operation: u64,
    row: u32,
    publisher: Arc<dyn HostActionPublisher>,
}

impl HostActionLoan {
    /// Reports the complete two-node allocation before actual borrower birth.
    pub const fn metadata_bytes() -> u64 {
        (std::mem::size_of::<OperationSubscriber>() + std::mem::size_of::<OuterSubscriber>()) as u64
    }

    /// Prices the fixed collector and receipt temporaries before Source birth.
    pub const fn cohort_scratch_bytes() -> u64 {
        (std::mem::size_of::<[Option<&Shared>; 4]>()
            + std::mem::size_of::<[Option<&Mutex<OuterAuthority>>; 4]>()
            + std::mem::size_of::<[Option<MutexGuard<'static, SupervisionState>>; 4]>()
            + std::mem::size_of::<[Option<MutexGuard<'static, OuterAuthority>>; 4]>()
            + std::mem::size_of::<[Option<MutexGuard<'static, Option<HostActionLoan>>>; 4]>()
            + 2 * std::mem::size_of::<[ActionParent; 4]>()
            + std::mem::size_of::<HostActionReturnReceipt>()
            + std::mem::size_of::<HostActionUnpublishedReturnReceipt>()
            + std::mem::size_of::<Option<SourceHostControlLease>>()
            + std::mem::size_of::<HostParentParkReturnReceipt>()
            + std::mem::size_of::<ActionReturn>()
            + std::mem::size_of::<ParentParkReturn>()
            + std::mem::size_of::<ActionParent>()
            + std::mem::size_of::<HostOuterCapBinding>()) as u64
    }

    /// Observes return through the same transport that retained this loan.
    ///
    /// # Errors
    /// Refuses missing membership, a pending journal or changed publisher/binding.
    pub fn observe_physical_return(&self) -> Result<HostActionReturnReceipt, HostSupervisionError> {
        let publisher = {
            let state = self.supervisor.lock()?;
            let mut cursor = state
                .operations
                .get(&self.operation)
                .and_then(|operation| operation.action_subscribers.as_deref());
            loop {
                let subscriber = cursor.ok_or(HostSupervisionError::Unavailable)?;
                if subscriber.binding == self.binding && subscriber.row == self.row {
                    break Arc::clone(&subscriber.publisher);
                }
                cursor = subscriber.next.as_deref();
            }
        };
        let journal = publisher.action_return(self.binding)?;
        journal
            .encode()
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        if journal.binding != self.binding
            || journal.physical_state != 1
            || journal.returned_mask & (1 << self.row) == 0
        {
            return Err(HostSupervisionError::Unavailable);
        }
        Ok(HostActionReturnReceipt {
            shared: Arc::clone(&self.supervisor.shared),
            journal,
            operation: self.operation,
            row: self.row,
            publisher,
        })
    }

    /// Observes local closure through this loan's actual registered producer.
    ///
    /// This identity-only path also handles born but unprojected subscribers.
    /// It never emits a native journal, completes work or renews an Original.
    ///
    /// # Errors
    /// Refuses missing/returned membership or an unsealed publication privilege.
    pub fn observe_unpublished_return(
        &self,
    ) -> Result<HostActionUnpublishedReturnReceipt, HostSupervisionError> {
        if self.returned || self.binding.park_request.is_some() {
            return Err(HostSupervisionError::Unavailable);
        }
        let publisher = {
            let state = self.supervisor.lock()?;
            let mut cursor = state
                .operations
                .get(&self.operation)
                .and_then(|operation| operation.action_subscribers.as_deref());
            loop {
                let subscriber = cursor.ok_or(HostSupervisionError::Unavailable)?;
                if subscriber.binding == self.binding && subscriber.row == self.row {
                    break Arc::clone(&subscriber.publisher);
                }
                cursor = subscriber.next.as_deref();
            }
        };
        publisher.unpublished_return(self.binding)?;
        Ok(HostActionUnpublishedReturnReceipt {
            shared: Arc::clone(&self.supervisor.shared),
            binding: self.binding,
            operation: self.operation,
            row: self.row,
            publisher,
        })
    }

    /// Observes Park closure through this loan's actual registered publisher.
    ///
    /// # Errors
    /// Refuses absent membership, changed identity or missing corroborated
    /// closure. A decoded terminal record alone supplies no such observation.
    pub fn observe_parent_park_return(
        &self,
    ) -> Result<HostParentParkReturnReceipt, HostSupervisionError> {
        if self.binding.park_request.is_none() || self.returned {
            return Err(HostSupervisionError::Unavailable);
        }
        let publisher = {
            let state = self.supervisor.lock()?;
            let mut cursor = state
                .operations
                .get(&self.operation)
                .and_then(|operation| operation.action_subscribers.as_deref());
            loop {
                let subscriber = cursor.ok_or(HostSupervisionError::Unavailable)?;
                if subscriber.binding == self.binding && subscriber.row == self.row {
                    break Arc::clone(&subscriber.publisher);
                }
                cursor = subscriber.next.as_deref();
            }
        };
        let journal = publisher.parent_park_return(self.binding, self.row)?;
        journal
            .encode()
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        if journal.binding != self.binding {
            return Err(HostSupervisionError::Unavailable);
        }
        Ok(HostParentParkReturnReceipt {
            shared: Arc::clone(&self.supervisor.shared),
            journal,
            operation: self.operation,
            row: self.row,
            publisher,
        })
    }

    /// Refreshes all actual primary and Preparation lenders at one locked cut.
    ///
    /// This enters no operation. Callers must release Source/publisher guards
    /// before entry. Unique operation-state locks precede unique outer locks;
    /// each set uses process-local address order only for synchronization. No
    /// address enters a public record or acts as authority. Individual owner
    /// callbacks can dirty a cohort, but cannot promote it themselves.
    ///
    /// # Errors
    /// Refuses absent/returned rows, mismatched sources, subscription changes,
    /// noncanonical dependency order or uncertain locking/publication.
    pub fn refresh_cohort(
        loans: [Option<&Self>; 4],
        count: u32,
    ) -> Result<(), HostSupervisionError> {
        if !(1..=4).contains(&count) {
            return Err(HostSupervisionError::InvalidBudget);
        }
        let first = loans[0].ok_or(HostSupervisionError::Unavailable)?;
        let binding = first.binding;
        let mut owners: [Option<&Shared>; 4] = [None; 4];
        let mut outers: [Option<&Mutex<OuterAuthority>>; 4] = [None; 4];
        let mut owner_count = 0;
        let mut outer_count = 0;
        for (index, loan) in loans.iter().enumerate() {
            if index >= count as usize {
                if loan.is_some() {
                    return Err(HostSupervisionError::Unavailable);
                }
                continue;
            }
            let loan = loan.ok_or(HostSupervisionError::Unavailable)?;
            if loan.returned || loan.binding != binding || loan.row != index as u32 {
                return Err(HostSupervisionError::Unavailable);
            }
            let owner = loan.supervisor.shared.as_ref();
            if !owners[..owner_count]
                .iter()
                .flatten()
                .any(|candidate| std::ptr::eq(*candidate, owner))
            {
                owners[owner_count] = Some(owner);
                owner_count += 1;
            }
            let outer = owner.outer.as_ref();
            if !outers[..outer_count]
                .iter()
                .flatten()
                .any(|candidate| std::ptr::eq(*candidate, outer))
            {
                outers[outer_count] = Some(outer);
                outer_count += 1;
            }
        }
        owners.sort_unstable_by_key(|owner| {
            owner.map_or(usize::MAX, |owner| std::ptr::from_ref(owner) as usize)
        });
        outers.sort_unstable_by_key(|outer| {
            outer.map_or(usize::MAX, |outer| std::ptr::from_ref(outer) as usize)
        });
        let mut states: [Option<MutexGuard<'_, SupervisionState>>; 4] =
            std::array::from_fn(|_| None);
        let mut outer_states: [Option<MutexGuard<'_, OuterAuthority>>; 4] =
            std::array::from_fn(|_| None);
        for index in 0..owner_count {
            states[index] = Some(
                owners[index]
                    .ok_or(HostSupervisionError::Unavailable)?
                    .state
                    .lock()
                    .map_err(|_| HostSupervisionError::Unavailable)?,
            );
        }
        for index in 0..outer_count {
            outer_states[index] = Some(
                outers[index]
                    .ok_or(HostSupervisionError::Unavailable)?
                    .lock()
                    .map_err(|_| HostSupervisionError::Unavailable)?,
            );
        }
        let mut parents = [ActionParent::default(); 4];
        for index in 0..count as usize {
            let loan = loans[index].ok_or(HostSupervisionError::Unavailable)?;
            let owner = loan.supervisor.shared.as_ref();
            let owner_index = owners[..owner_count]
                .iter()
                .position(|candidate| {
                    candidate.is_some_and(|candidate| std::ptr::eq(candidate, owner))
                })
                .ok_or(HostSupervisionError::Unavailable)?;
            let outer_index = outers[..outer_count]
                .iter()
                .position(|candidate| {
                    candidate.is_some_and(|candidate| std::ptr::eq(candidate, owner.outer.as_ref()))
                })
                .ok_or(HostSupervisionError::Unavailable)?;
            let state = states[owner_index]
                .as_mut()
                .ok_or(HostSupervisionError::Unavailable)?;
            let outer = outer_states[outer_index]
                .as_mut()
                .ok_or(HostSupervisionError::Unavailable)?;
            #[cfg(feature = "private-measurement-domain")]
            loan.supervisor.require_measurement_interval(state, outer)?;
            state.cap_revision = outer.revision;
            state.cap_allowance = outer.allowance;
            state.cap_state = outer.state;
            refresh_cap(state, loan.supervisor.elapsed());
            outer.state = state.cap_state;
            let operation = state
                .operations
                .get(&loan.operation)
                .ok_or(HostSupervisionError::Unavailable)?;
            let mut cursor = operation.action_subscribers.as_deref();
            let subscriber = loop {
                let current = cursor.ok_or(HostSupervisionError::Unavailable)?;
                if current.binding == binding && current.row == index as u32 {
                    break current;
                }
                cursor = current.next.as_deref();
            };
            if !has_outer(&outer.action_subscribers, binding, index as u32) {
                return Err(HostSupervisionError::Unavailable);
            }
            parents[index] = parent_snapshot(
                &loan.supervisor.shared,
                state,
                loan.operation,
                subscriber.preparation,
                subscriber.role,
            )?;
        }
        let first_owner = owners[..owner_count]
            .iter()
            .position(|owner| {
                owner.is_some_and(|owner| std::ptr::eq(owner, first.supervisor.shared.as_ref()))
            })
            .ok_or(HostSupervisionError::Unavailable)?;
        let first_state = states[first_owner]
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)?;
        let mut cursor = first_state
            .operations
            .get(&first.operation)
            .and_then(|operation| operation.action_subscribers.as_deref());
        let publisher = loop {
            let current = cursor.ok_or(HostSupervisionError::Unavailable)?;
            if current.binding == binding && current.row == 0 {
                break &current.publisher;
            }
            cursor = current.next.as_deref();
        };
        for loan in loans.iter().take(count as usize).flatten() {
            let owner_index = owners[..owner_count]
                .iter()
                .position(|owner| {
                    owner.is_some_and(|owner| std::ptr::eq(owner, loan.supervisor.shared.as_ref()))
                })
                .ok_or(HostSupervisionError::Unavailable)?;
            let state = states[owner_index]
                .as_ref()
                .ok_or(HostSupervisionError::Unavailable)?;
            let mut cursor = state
                .operations
                .get(&loan.operation)
                .and_then(|operation| operation.action_subscribers.as_deref());
            let actual = loop {
                let subscriber = cursor.ok_or(HostSupervisionError::Unavailable)?;
                if subscriber.binding == binding && subscriber.row == loan.row {
                    break &subscriber.publisher;
                }
                cursor = subscriber.next.as_deref();
            };
            if !Arc::ptr_eq(actual, publisher) {
                return Err(HostSupervisionError::Unavailable);
            }
        }
        publisher.publish_cohort(binding, parents, count)
    }

    /// Removes only this actual borrower after a validated physical journal.
    ///
    /// The containing Source transport verifies the exact journal binding and
    /// complete physical disposition before this identity-only call. Semantic
    /// expiry cannot prevent physical cleanup, and this issues no read/ACK.
    ///
    /// # Errors
    /// Refuses changed membership, duplicate return or uncertain owner locks.
    pub fn return_physical(
        &mut self,
        receipt: &HostActionReturnReceipt,
    ) -> Result<(), HostSupervisionError> {
        let journal = &receipt.journal;
        journal
            .encode()
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        if journal.binding != self.binding
            || journal.physical_state != 1
            || journal.returned_mask & (1 << self.row) == 0
        {
            return Err(HostSupervisionError::Unavailable);
        }
        self.return_registered_membership(
            &receipt.shared,
            receipt.operation,
            receipt.row,
            &receipt.publisher,
        )
    }

    /// Unlinks only this actual membership after sealed unpublished closure.
    ///
    /// Semantic cancellation cannot prevent this identity-only cleanup. The
    /// publisher's local closure must be irreversible before the receipt exists.
    ///
    /// # Errors
    /// Refuses foreign, duplicate, absent or uncertain subscription custody.
    pub fn return_unpublished(
        &mut self,
        receipt: &HostActionUnpublishedReturnReceipt,
    ) -> Result<(), HostSupervisionError> {
        if receipt.binding != self.binding || self.binding.park_request.is_some() {
            return Err(HostSupervisionError::Unavailable);
        }
        self.return_registered_membership(
            &receipt.shared,
            receipt.operation,
            receipt.row,
            &receipt.publisher,
        )
    }

    /// Returns this Host subscriber after its actual publisher verifies closure.
    ///
    /// This identity-only cleanup neither retires the standing Source nor
    /// completes a producing operation. Negative semantics do not erase debt.
    ///
    /// # Errors
    /// Refuses foreign, duplicate, missing or uncertain membership selectors.
    pub fn return_parent_park_physical(
        &mut self,
        receipt: &HostParentParkReturnReceipt,
    ) -> Result<(), HostSupervisionError> {
        receipt
            .journal
            .encode()
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        if self.binding.park_request.is_none() || receipt.journal.binding != self.binding {
            return Err(HostSupervisionError::Unavailable);
        }
        self.return_registered_membership(
            &receipt.shared,
            receipt.operation,
            receipt.row,
            &receipt.publisher,
        )
    }

    fn return_registered_membership(
        &mut self,
        shared: &Arc<Shared>,
        operation_id: u64,
        row: u32,
        publisher: &Arc<dyn HostActionPublisher>,
    ) -> Result<(), HostSupervisionError> {
        if !Arc::ptr_eq(shared, &self.supervisor.shared)
            || operation_id != self.operation
            || row != self.row
            || self.returned
        {
            return Err(HostSupervisionError::Unavailable);
        }
        let mut state = self.supervisor.lock()?;
        let mut outer = self.supervisor.lock_outer()?;
        let operation = state
            .operations
            .get_mut(&self.operation)
            .ok_or(HostSupervisionError::Unavailable)?;
        if !has_operation(&operation.action_subscribers, self.binding, self.row)
            || !has_outer(&outer.action_subscribers, self.binding, self.row)
        {
            return Err(HostSupervisionError::Unavailable);
        }

        let mut cursor = operation.action_subscribers.as_deref();
        let actual_publisher = loop {
            let subscriber = cursor.ok_or(HostSupervisionError::Unavailable)?;
            if subscriber.binding == self.binding && subscriber.row == self.row {
                break &subscriber.publisher;
            }
            cursor = subscriber.next.as_deref();
        };
        if !Arc::ptr_eq(actual_publisher, publisher) {
            return Err(HostSupervisionError::Unavailable);
        }

        let mut removed_operation =
            remove_operation(&mut operation.action_subscribers, self.binding, self.row)?;
        let removed_outer = remove_outer(&mut outer.action_subscribers, self.binding, self.row)?;
        let remove_entry = !operation.guard_live && operation.action_subscribers.is_none();
        let retired = if remove_entry {
            state.operations.remove(&self.operation)
        } else {
            None
        };
        // Detach the same paid credit before any owner destructor can unwind.
        // The Box remains owned until its complete physical destruction below.
        let credit = std::mem::ManuallyDrop::new(removed_operation._credit.take());
        self.returned = true;
        drop(outer);
        drop(state);
        // Cancellation, publisher and credit destructors never run under lender locks.
        drop_body_before_credit((retired, removed_outer, removed_operation), credit);
        Ok(())
    }
}

fn drop_body_before_credit<T, C>(body: T, credit: std::mem::ManuallyDrop<C>) {
    // If any body destructor unwinds, its actual credit remains retained. This
    // is sticky custody, not resumable cleanup or whole-pool completion.
    drop(body);
    drop(std::mem::ManuallyDrop::into_inner(credit));
}

impl HostOperationGuard {
    /// Lends this real operation without cloning a guard or starting a clock.
    ///
    /// The Source payer charges both actual list nodes before allocation. Output
    /// is stored before the fallible post/publication cut; a born-negative loan
    /// must remain in the containing Source's durable holder.
    ///
    /// # Errors
    /// Refuses occupied output, invalid row/dependency shape, expired authority,
    /// insufficient actual Source credit or uncertain synchronization.
    pub fn lend_action(
        &self,
        purpose: &AuthenticatedSourceHostPurpose,
        publisher: Arc<dyn HostActionPublisher>,
        binding: ActionBinding,
        row: u32,
        preparation: u32,
        role: u32,
        output: &mut Option<HostActionLoan>,
    ) -> Result<(), HostSupervisionError> {
        if output.is_some() || row >= 4 || preparation > 4 || role > 1 {
            return Err(HostSupervisionError::InvalidBudget);
        }
        self.wait_slice()?;
        let credit = purpose
            .reserve_controls(0, HostActionLoan::metadata_bytes())
            .map_err(|_| HostSupervisionError::CapacityExhausted)?;
        let mut operation_node = Box::new(OperationSubscriber {
            binding,
            row,
            preparation,
            role,
            publisher: Arc::clone(&publisher),
            next: None,
            _credit: Some(credit),
        });
        let mut outer_node = Box::new(OuterSubscriber {
            binding,
            row,
            publisher: Arc::clone(&publisher),
            next: None,
        });
        let mut state = self.supervisor.lock()?;
        let mut outer = self.supervisor.lock_outer()?;
        state.cap_revision = outer.revision;
        state.cap_allowance = outer.allowance;
        state.cap_state = outer.state;
        evaluate_operation_decision(&mut state, self.id, self.supervisor.elapsed())?
            .require_running(self.id)?;
        let operation = state
            .operations
            .get_mut(&self.id)
            .ok_or(HostSupervisionError::Unavailable)?;
        if !operation.guard_live || has_operation(&operation.action_subscribers, binding, row) {
            return Err(HostSupervisionError::Unavailable);
        }
        operation_node.next = operation.action_subscribers.take();
        operation.action_subscribers = Some(operation_node);
        outer_node.next = outer.action_subscribers.take();
        outer.action_subscribers = Some(outer_node);
        *output = Some(HostActionLoan {
            supervisor: self.supervisor.clone(),
            operation: self.id,
            binding,
            row,
            returned: false,
        });
        let result = publisher
            .retain_parent(binding, row)
            .and_then(|()| publish_operation(&self.supervisor.shared, &state, self.id));
        if result.is_err() {
            publisher.invalidate_action(binding);
        }
        drop(outer);
        drop(state);
        result?;
        self.wait_slice().map(|_| ())
    }

    /// Borrows the genuine retained Preparation dependency, when present.
    pub fn action_preparation(&self) -> Option<&HostOperationGuard> {
        #[cfg(feature = "private-measurement-domain")]
        {
            self.original_preparation.as_deref()
        }
        #[cfg(not(feature = "private-measurement-domain"))]
        {
            None
        }
    }
}

pub(super) fn publish_operation(
    shared: &Arc<Shared>,
    state: &SupervisionState,
    id: u64,
) -> Result<(), HostSupervisionError> {
    let operation = state
        .operations
        .get(&id)
        .ok_or(HostSupervisionError::Unavailable)?;
    let mut cursor = operation.action_subscribers.as_deref();
    let mut failure = None;
    while let Some(subscriber) = cursor {
        let result = parent_snapshot(shared, state, id, subscriber.preparation, subscriber.role)
            .and_then(|snapshot| {
                subscriber
                    .publisher
                    .publish_parent(subscriber.binding, subscriber.row, snapshot)
            });
        if let Err(error) = result {
            subscriber.publisher.invalidate_action(subscriber.binding);
            if failure.is_none() {
                failure = Some(error);
            }
        }
        cursor = subscriber.next.as_deref();
    }
    failure.map_or(Ok(()), Err)
}

pub(super) fn invalidate_operation(state: &SupervisionState, id: u64) {
    let mut cursor = state
        .operations
        .get(&id)
        .and_then(|operation| operation.action_subscribers.as_deref());
    while let Some(subscriber) = cursor {
        subscriber.publisher.invalidate_action(subscriber.binding);
        cursor = subscriber.next.as_deref();
    }
}

pub(super) fn publish_all(
    shared: &Arc<Shared>,
    state: &SupervisionState,
) -> Result<(), HostSupervisionError> {
    let mut failure = None;
    for &id in state.operations.keys() {
        if let Err(error) = publish_operation(shared, state, id) {
            if failure.is_none() {
                failure = Some(error);
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

pub(super) fn publish_outer(
    shared: &Arc<Shared>,
    outer: &OuterAuthority,
) -> Result<(), HostSupervisionError> {
    let snapshot = HostOuterCapBinding {
        cap_id: shared.cap_id,
        original_monotonic_ns: shared.original_monotonic_ns,
        revision: outer.revision,
        allowance: outer.allowance,
        state: outer.state,
    };
    let mut cursor = outer.action_subscribers.as_deref();
    let mut failure = None;
    while let Some(subscriber) = cursor {
        if let Err(error) =
            subscriber
                .publisher
                .publish_outer(subscriber.binding, shared.cap_id, snapshot)
        {
            subscriber.publisher.invalidate_action(subscriber.binding);
            if failure.is_none() {
                failure = Some(error);
            }
        }
        cursor = subscriber.next.as_deref();
    }
    failure.map_or(Ok(()), Err)
}

pub(super) fn publish_owner(shared: &Arc<Shared>) -> Result<(), HostSupervisionError> {
    let supervisor = HostOperationSupervisor {
        shared: Arc::clone(shared),
    };
    let mut state = supervisor.lock()?;
    let mut outer = supervisor.lock_outer()?;
    state.cap_revision = outer.revision;
    state.cap_allowance = outer.allowance;
    state.cap_state = outer.state;
    refresh_cap(&mut state, supervisor.elapsed());
    outer.state = state.cap_state;
    publish_outer(shared, &outer)?;
    publish_all(shared, &state)
}

fn parent_snapshot(
    shared: &Arc<Shared>,
    state: &SupervisionState,
    id: u64,
    preparation: u32,
    role: u32,
) -> Result<ActionParent, HostSupervisionError> {
    let operation = state
        .operations
        .get(&id)
        .ok_or(HostSupervisionError::Unavailable)?;
    let budget = state.budgets.get(operation.class);
    let origin = shared.original_monotonic_ns;
    #[cfg(feature = "private-measurement-domain")]
    let origin = shared
        .measurement_clock
        .map_or(origin, |clock| origin.min(clock.start_ns));
    let coordinate = |elapsed: Duration| -> Result<u64, HostSupervisionError> {
        u64::try_from(elapsed.as_nanos())
            .ok()
            .and_then(|ns| origin.checked_add(ns))
            .ok_or(HostSupervisionError::InvalidBudget)
    };
    let end = |start: Duration, span: Option<Duration>| -> Result<u64, HostSupervisionError> {
        span.map(|span| {
            start
                .checked_add(span)
                .ok_or(HostSupervisionError::InvalidBudget)
                .and_then(coordinate)
        })
        .transpose()
        .map(|value| value.unwrap_or(0))
    };
    let mut disposition = decide_operation(
        state,
        operation,
        HostOperationSupervisor {
            shared: Arc::clone(shared),
        }
        .elapsed(),
    )
    .state;
    if operation
        .startup_cancellation
        .as_ref()
        .is_some_and(|cancellation| cancellation.check().is_err())
    {
        disposition = HostOperationState::Canceled;
    }
    let private_end_ns = {
        #[cfg(feature = "private-measurement-domain")]
        {
            shared.measurement_clock.map_or(0, |clock| clock.end_ns)
        }
        #[cfg(not(feature = "private-measurement-domain"))]
        {
            0
        }
    };
    Ok(ActionParent {
        cap: shared.cap_id,
        budget_owner: shared.budget_owner,
        operation: id,
        class: operation.class as u32,
        state: match disposition {
            HostOperationState::Running => 0,
            HostOperationState::Completed => 1,
            HostOperationState::Expired => 2,
            HostOperationState::Canceled => 3,
        },
        started_revision: operation.started_revision,
        policy_revision: state.policy_revision,
        outer_revision: state.cap_revision,
        origin_ns: origin,
        started_ns: coordinate(operation.started)?,
        progress_ns: coordinate(operation.last_progress)?,
        total_end_ns: end(operation.started, budget.total_timeout)?,
        progress_end_ns: end(operation.last_progress, budget.progress_timeout)?,
        outer_end_ns: if operation.class == HostOperationClass::Cleanup {
            0
        } else {
            end(Duration::ZERO, state.cap_allowance)?
        },
        private_end_ns,
        poll_ns: u64::try_from(budget.poll_interval.as_nanos())
            .map_err(|_| HostSupervisionError::InvalidBudget)?,
        completed: operation.completed,
        required: operation.required,
        preparation,
        role,
    })
}

fn has_operation(
    head: &Option<Box<OperationSubscriber>>,
    binding: ActionBinding,
    row: u32,
) -> bool {
    let mut cursor = head.as_deref();
    while let Some(node) = cursor {
        if node.binding == binding && node.row == row {
            return true;
        }
        cursor = node.next.as_deref();
    }
    false
}

fn has_outer(head: &Option<Box<OuterSubscriber>>, binding: ActionBinding, row: u32) -> bool {
    let mut cursor = head.as_deref();
    while let Some(node) = cursor {
        if node.binding == binding && node.row == row {
            return true;
        }
        cursor = node.next.as_deref();
    }
    false
}

fn remove_operation(
    head: &mut Option<Box<OperationSubscriber>>,
    binding: ActionBinding,
    row: u32,
) -> Result<Box<OperationSubscriber>, HostSupervisionError> {
    let mut link = head;
    loop {
        if link
            .as_ref()
            .is_some_and(|node| node.binding == binding && node.row == row)
        {
            let mut removed = link.take().ok_or(HostSupervisionError::Unavailable)?;
            *link = removed.next.take();
            return Ok(removed);
        }
        link = &mut link.as_mut().ok_or(HostSupervisionError::Unavailable)?.next;
    }
}

fn remove_outer(
    head: &mut Option<Box<OuterSubscriber>>,
    binding: ActionBinding,
    row: u32,
) -> Result<Box<OuterSubscriber>, HostSupervisionError> {
    let mut link = head;
    loop {
        if link
            .as_ref()
            .is_some_and(|node| node.binding == binding && node.row == row)
        {
            let mut removed = link.take().ok_or(HostSupervisionError::Unavailable)?;
            *link = removed.next.take();
            return Ok(removed);
        }
        link = &mut link.as_mut().ok_or(HostSupervisionError::Unavailable)?.next;
    }
}

#[cfg(test)]
mod tests;
