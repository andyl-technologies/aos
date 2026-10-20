//! Narrows selected windows to the actual original native journal allowance.
//!
//! The reference server reserves min(resource maximum operations, journal
//! entries). This prebirth data check repeats that installed allocation bound;
//! it creates no source qualification, operation, or model execution authority.

use crucible_node_format::U64;

use crate::node_observed_executor::{NodeObservedError, factory::refused};

#[cfg(test)]
#[path = "budget_tests.rs"]
mod tests;

pub(super) fn authenticate_window_credit(
    maximum_windows: usize,
    native_operations: U64,
    journal_entries: U64,
) -> Result<(), NodeObservedError> {
    let selected = u64::try_from(maximum_windows)
        .map_err(|_| refused("selected vendor window credit is unrepresentable"))?;
    let native = native_operations.get().min(journal_entries.get());
    if !(1..=256).contains(&maximum_windows) || selected > native {
        return Err(refused(
            "selected vendor windows exceed original native credit",
        ));
    }
    Ok(())
}
