//! Borrows exact shared-role rows for Source birth/finalizer historical DATA.

use super::*;
use std::rc::Weak;

/// Counts one actual weak row and its retained allocation identity occurrence.
pub(crate) fn weak_demand<T>(owner: &Weak<T>) -> (usize, usize) {
    (1, usize::from(!owner.ptr_eq(&Weak::new())))
}

/// Sums defining row and alias demands without allocating or reserving credit.
///
/// # Errors
/// Refuses either checked population sum overflowing usize.
pub(crate) fn add_demands(values: &[(usize, usize)]) -> Result<(usize, usize), RuntimeError> {
    values.iter().try_fold((0usize, 0usize), |sum, value| {
        Ok((
            sum.0
                .checked_add(value.0)
                .ok_or(RuntimeError::ResourceLimit)?,
            sum.1
                .checked_add(value.1)
                .ok_or(RuntimeError::ResourceLimit)?,
        ))
    })
}

/// Names the actual weak edge through the enclosing precharged alias pass.
///
/// # Errors
/// Refuses a busy, unreserved or exhausted alias bank.
pub(crate) fn weak_edge<T>(
    owner: &Weak<T>,
    aliases: &RefCell<OriginalRestoredOwnerCapacityAliases>,
) -> Result<OriginalRestoredOwnerCapacityRow, RuntimeError> {
    aliases
        .try_borrow_mut()
        .map_err(|_| RuntimeError::OwnerBusy)?
        .weak_owner_data(owner)
}

/// Names the actual shared edge through the enclosing precharged alias pass.
///
/// # Errors
/// Refuses a busy, unreserved or exhausted alias bank.
pub(crate) fn shared_edge<T>(
    owner: &Rc<T>,
    aliases: &RefCell<OriginalRestoredOwnerCapacityAliases>,
) -> Result<OriginalRestoredOwnerCapacityRow, RuntimeError> {
    aliases
        .try_borrow_mut()
        .map_err(|_| RuntimeError::OwnerBusy)?
        .shared_owner_data(owner)
}

/// Counts the concrete borrowed, scalar, result and alias-counter views.
pub(crate) fn counter_scratch_data() -> usize {
    size_of::<OriginalRestoredOwnerCapacityRow>()
        + size_of::<Result<OriginalRestoredOwnerCapacityRow, RuntimeError>>()
        + size_of::<std::cell::RefMut<'static, OriginalRestoredOwnerCapacityAliases>>()
        + size_of::<
            Result<
                std::cell::RefMut<'static, OriginalRestoredOwnerCapacityAliases>,
                std::cell::BorrowMutError,
            >,
        >()
        + size_of::<&[(usize, usize)]>()
        + size_of::<(usize, usize)>() * 4
        + size_of::<std::slice::Iter<'static, (usize, usize)>>()
        + size_of::<Result<(usize, usize), RuntimeError>>()
        + size_of::<Option<(usize, usize)>>()
        + size_of::<Option<Result<(usize, usize), RuntimeError>>>()
        + size_of::<Result<Option<(usize, usize)>, RuntimeError>>()
        + super::original_restored_owner_capacity_counter_scratch_data()
}
