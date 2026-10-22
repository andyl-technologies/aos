//! Collects current lender facts while retaining every actual owner lock.
//!
//! Operation-state locks precede outer locks. Process-local address order
//! prevents lock-order inversions; addresses never enter public records.

use super::*;

/// Selects one independently retained role of a Quantum action.
///
/// Work and Cleanup retain separate primary operations and their registered
/// Preparation dependencies. Selecting a role enters no operation and grants
/// no permission; the actual registered publisher decides from locked facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostQuantumActionRole {
    /// Selects the original Quantum work operation and its dependency.
    Work,
    /// Selects the independently entered finite Cleanup and its dependency.
    Cleanup,
}

impl HostQuantumActionRole {
    fn primary(self) -> usize {
        match self {
            Self::Work => 0,
            Self::Cleanup => 1,
        }
    }

    fn validate(self, parents: &[ActionParent; 4], mask: u32) -> Result<(), HostSupervisionError> {
        let index = self.primary();
        let primary = &parents[index];
        let class = match self {
            Self::Work => HostOperationClass::Quantum,
            Self::Cleanup => HostOperationClass::Cleanup,
        };
        if primary.class != class as u32 || primary.role != 0 {
            return Err(HostSupervisionError::Unavailable);
        }

        let mut expected = 1 << index;
        if primary.preparation != 0 {
            if !(3..=4).contains(&primary.preparation) {
                return Err(HostSupervisionError::Unavailable);
            }
            let dependency = primary.preparation as usize - 1;
            let preparation = &parents[dependency];
            if preparation.class != HostOperationClass::Preparation as u32
                || preparation.role != 1
                || preparation.preparation != 0
            {
                return Err(HostSupervisionError::Unavailable);
            }
            expected |= 1 << dependency;
        }

        if mask != expected {
            return Err(HostSupervisionError::Unavailable);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Projection {
    Cohort(u32),
    QuantumRole(HostQuantumActionRole),
}

impl Projection {
    fn mask(self, loans: &[Option<&HostActionLoan>; 4]) -> Result<u32, HostSupervisionError> {
        match self {
            Self::Cohort(count) => {
                if !(1..=4).contains(&count) {
                    return Err(HostSupervisionError::InvalidBudget);
                }
                Ok((1 << count) - 1)
            }
            Self::QuantumRole(role) => {
                let primary = role.primary();
                if loans[primary].is_none() || loans[1 - primary].is_some() {
                    return Err(HostSupervisionError::Unavailable);
                }
                Ok(loans.iter().enumerate().fold(0, |mask, (index, loan)| {
                    mask | if loan.is_some() { 1 << index } else { 0 }
                }))
            }
        }
    }

    fn first(self) -> usize {
        match self {
            Self::Cohort(_) => 0,
            Self::QuantumRole(role) => role.primary(),
        }
    }
}

/// Prices the forwarding selector and both caller-owned reference rosters.
pub(super) const fn selection_scratch_bytes() -> usize {
    2 * std::mem::size_of::<[Option<&HostActionLoan>; 4]>() + std::mem::size_of::<Projection>()
}

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
        Self::refresh_selected(loans, Projection::Cohort(count))
    }

    /// Refreshes only one Quantum role through its actual retained memberships.
    ///
    /// The roster uses original global row positions: Work is row zero,
    /// Cleanup is row one, and the selected primary's registered Preparation
    /// dependency, if present, occupies row two or three. All other slots must
    /// be absent. Cleanup selects no Work loan and never queries or republishes
    /// its operation. A shared supervisor still contributes its one state lock.
    ///
    /// The selected publisher receives current observations while all selected
    /// lender locks remain held. This enters no Cleanup, renews no clock and
    /// returns no semantic or physical ownership. Unsupported publishers refuse.
    /// Callers must release Source/publisher guards before entry, as for
    /// [`Self::refresh_cohort`].
    ///
    /// # Errors
    /// Refuses missing, returned or foreign memberships, changed publishers,
    /// wrong classes or dependency rosters, and uncertain locks/publication.
    pub fn refresh_quantum_role(
        loans: [Option<&Self>; 4],
        role: HostQuantumActionRole,
    ) -> Result<(), HostSupervisionError> {
        Self::refresh_selected(loans, Projection::QuantumRole(role))
    }

    fn refresh_selected(
        loans: [Option<&Self>; 4],
        projection: Projection,
    ) -> Result<(), HostSupervisionError> {
        let mask = projection.mask(&loans)?;
        let first = loans[projection.first()].ok_or(HostSupervisionError::Unavailable)?;
        let binding = first.binding;
        let mut owners: [Option<&Shared>; 4] = [None; 4];
        let mut outers: [Option<&Mutex<OuterAuthority>>; 4] = [None; 4];
        let mut owner_count = 0;
        let mut outer_count = 0;
        for (index, loan) in loans.iter().enumerate() {
            if mask & (1 << index) == 0 {
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
        for index in 0..4 {
            if mask & (1 << index) == 0 {
                continue;
            }
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
            let mut cursor = outer.action_subscribers.as_deref();
            let outer_subscriber = loop {
                let current = cursor.ok_or(HostSupervisionError::Unavailable)?;
                if current.binding == binding && current.row == index as u32 {
                    break current;
                }
                cursor = current.next.as_deref();
            };
            if !outer_subscriber.publisher.same_owner(&subscriber.publisher) {
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
            if current.binding == binding && current.row == first.row {
                break &current.publisher;
            }
            cursor = current.next.as_deref();
        };
        for loan in loans.iter().flatten() {
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
        match projection {
            Projection::Cohort(count) => publisher.publish_cohort(binding, parents, count),
            Projection::QuantumRole(role) => {
                role.validate(&parents, mask)?;
                publisher.publish_quantum_role(binding, role, parents, mask)
            }
        }
    }
}

#[cfg(test)]
mod tests;
