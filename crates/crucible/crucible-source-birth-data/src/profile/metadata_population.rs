//! Shares the original pure metadata population bodies without observer authority.
//!
//! Host record/seal/origin handling remains above these source expansions. The
//! scalar operations expand in the original host method, preserving its existing
//! input/return windows rather than adding a new observer call layer.

use crate::ProviderError;
use crate::profile::serialization_storage::RetainedProtocolMetadataFacts;

/// Bounds the unchanged ordinary, unprofiled metadata traversal population.
///
/// This is a work ceiling, never requested bytes, Source credit or admission.
pub const MAXIMUM_ORDINARY_METADATA_ROWS: usize = 131_072;

/// Expands the original Vec population tail at its actual observation site.
///
/// Internal consumers provide an actual facts place, scalar capacity identifier
/// and compiled element type, with `size_of` in scope. The expansion contains
/// only the unchanged checked population arithmetic, never an observer or grant.
#[macro_export]
macro_rules! source_birth_metadata_vector_population {
    ($facts:expr, $capacity:ident, $element:ty) => {{
        let bytes = $capacity
            .checked_mul(size_of::<$element>())
            .ok_or($crate::profile::metadata_population::overflow())?;
        $crate::profile::metadata_population::add(&mut $facts.vector_capacity_bytes, bytes)?;
        $crate::profile::metadata_population::add(&mut $facts.vector_banks, 1)
    }};
}

/// Expands the original tree population tail at its actual observation site.
///
/// Internal consumers provide an actual facts place, entry-count identifier and
/// compiled key/value types, with `size_of`/`align_of` in scope. Recording and
/// source authentication remain the caller's independent prerequisites.
#[macro_export]
macro_rules! source_birth_metadata_tree_population {
    ($facts:expr, $entries:ident, $key:ty, $value:ty) => {{
        $crate::source_birth_metadata_tree_population!(@layout $facts, $entries,
            size_of::<$key>(), size_of::<$value>(), align_of::<$key>(), align_of::<$value>())
    }};
    (@layout $facts:expr, $entries:ident, $key_bytes:expr, $value_bytes:expr, $key_alignment:expr, $value_alignment:expr) => {{
        $facts.maximum_tree_entry_alignment = $facts
            .maximum_tree_entry_alignment
            .max($key_alignment.max($value_alignment));
        $crate::profile::metadata_population::add(&mut $facts.tree_containers, 1)?;
        $crate::profile::metadata_population::add(&mut $facts.tree_entries, $entries)?;
        $facts.maximum_tree_key_value_bytes = $facts.maximum_tree_key_value_bytes.max(
            ($key_bytes)
                .checked_add($value_bytes)
                .ok_or($crate::profile::metadata_population::overflow())?,
        );
        Ok::<(), $crate::ProviderError>(())
    }};
}

/// Checks the original metadata extent addition without admitting an owner.
///
/// # Errors
/// Returns the unchanged retained-metadata extent overflow.
pub fn add(total: &mut usize, value: usize) -> Result<(), ProviderError> {
    *total = total.checked_add(value).ok_or(overflow())?;
    Ok(())
}

/// Constructs the unchanged metadata extent overflow diagnostic.
pub fn overflow() -> ProviderError {
    ProviderError::ResourceExhausted("retained metadata extent overflow")
}

/// Applies the original fresh, unprofiled capacity-record prefix.
///
/// This is only the default charged=0, no-active-scope arithmetic. It neither
/// records an owner nor gathers capacities, validates origin or enters a native
/// capsule/alias/profile. Live observer guards remain independently upper.
///
/// # Errors
/// Preserves checked record overflow and the ordinary metadata record ceiling.
pub fn record_unprofiled_data(
    population: &mut RetainedProtocolMetadataFacts,
) -> Result<(), ProviderError> {
    use crate::profile::metadata_population::{MAXIMUM_ORDINARY_METADATA_ROWS, add, overflow};
    add(&mut population.capacity_records, 1)?;
    if population
        .capacity_records
        .checked_sub(0)
        .ok_or_else(overflow)?
        > MAXIMUM_ORDINARY_METADATA_ROWS
    {
        return Err(overflow());
    }
    Ok(())
}

#[cfg(test)]
#[path = "metadata_population/tests.rs"]
mod tests;
