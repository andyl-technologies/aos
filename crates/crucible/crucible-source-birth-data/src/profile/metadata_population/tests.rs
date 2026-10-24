//! Compares shared source expansions with the full independent old population tails.

use super::*;
use crate::profile::serialization_storage::RetainedProtocolMetadataFacts as Facts;
use std::mem::{align_of, size_of};

fn add(total: &mut usize, value: usize) -> Result<(), ProviderError> {
    *total = total.checked_add(value).ok_or(overflow())?;
    Ok(())
}

fn overflow() -> ProviderError {
    ProviderError::ResourceExhausted("retained metadata extent overflow")
}

fn old_vector<T>(facts: &mut Facts, capacity: usize) -> Result<(), ProviderError> {
    let bytes = capacity.checked_mul(size_of::<T>()).ok_or(overflow())?;
    add(&mut facts.vector_capacity_bytes, bytes)?;
    add(&mut facts.vector_banks, 1)
}

fn old_tree<K, V>(facts: &mut Facts, entries: usize) -> Result<(), ProviderError> {
    facts.maximum_tree_entry_alignment = facts
        .maximum_tree_entry_alignment
        .max(align_of::<K>().max(align_of::<V>()));
    add(&mut facts.tree_containers, 1)?;
    add(&mut facts.tree_entries, entries)?;
    facts.maximum_tree_key_value_bytes = facts.maximum_tree_key_value_bytes.max(
        size_of::<K>()
            .checked_add(size_of::<V>())
            .ok_or(overflow())?,
    );
    Ok(())
}

fn actual_vector<T>(facts: &mut Facts, capacity: usize) -> Result<(), ProviderError> {
    crate::source_birth_metadata_vector_population!(facts, capacity, T)
}

fn actual_tree<K, V>(facts: &mut Facts, entries: usize) -> Result<(), ProviderError> {
    crate::source_birth_metadata_tree_population!(facts, entries, K, V)
}

fn result(value: Result<(), ProviderError>) -> Result<(), String> {
    value.map_err(|error| error.to_string())
}

#[test]
fn actual_population_expansions_preserve_overflow_and_partial_mutation() {
    #[repr(align(64))]
    struct Aligned;
    for entries in [0, 1, usize::MAX] {
        for initial in [
            Facts::default(),
            Facts {
                tree_containers: usize::MAX,
                tree_entries: usize::MAX,
                vector_capacity_bytes: usize::MAX,
                vector_banks: usize::MAX,
                ..Facts::default()
            },
        ] {
            let mut actual = initial;
            let mut old = initial;
            assert_eq!(
                result(actual_tree::<Aligned, String>(&mut actual, entries)),
                result(old_tree::<Aligned, String>(&mut old, entries))
            );
            assert_eq!(actual, old);
            let mut actual = initial;
            let mut old = initial;
            assert_eq!(
                result(actual_vector::<u16>(&mut actual, entries)),
                result(old_vector::<u16>(&mut old, entries))
            );
            assert_eq!(actual, old);
            let mut actual = initial;
            let mut old = initial;
            assert_eq!(
                result(actual_vector::<()>(&mut actual, entries)),
                result(old_vector::<()>(&mut old, entries))
            );
            assert_eq!(actual, old);
        }
    }
}
