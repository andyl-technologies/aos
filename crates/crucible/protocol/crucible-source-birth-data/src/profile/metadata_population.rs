//! Shares the original pure metadata population bodies without observer authority.
//!
//! Host record/seal/origin handling remains above these source expansions. The
//! scalar operations expand in the original host method, preserving its existing
//! input/return windows rather than adding a new observer call layer.

use crate::ProviderError;

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
        $facts.maximum_tree_entry_alignment = $facts
            .maximum_tree_entry_alignment
            .max(align_of::<$key>().max(align_of::<$value>()));
        $crate::profile::metadata_population::add(&mut $facts.tree_containers, 1)?;
        $crate::profile::metadata_population::add(&mut $facts.tree_entries, $entries)?;
        $facts.maximum_tree_key_value_bytes = $facts.maximum_tree_key_value_bytes.max(
            size_of::<$key>()
                .checked_add(size_of::<$value>())
                .ok_or($crate::profile::metadata_population::overflow())?,
        );
        Ok(())
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

#[cfg(test)]
#[path = "metadata_population/tests.rs"]
mod tests;
