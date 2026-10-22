//! Collects current lender facts while retaining every actual owner lock.
//!
//! Operation-state locks precede outer locks. Process-local address order
//! prevents lock-order inversions; addresses never enter public records.

use super::*;

impl HostActionLoan {
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
            if !actual.same_owner(publisher) {
                return Err(HostSupervisionError::Unavailable);
            }
        }
        publisher.publish_cohort(binding, parents, count)
    }
}
