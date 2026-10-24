//! Retains the original native schema-generation paths for shared literal DATA.

pub(super) use crucible_source_birth_data::profile::reference_packet::service::native_startup::schema_shapes::literal_generation::{
    fresh_requested_data, requested_data,
};

#[cfg(test)]
use super::*;

#[cfg(test)]
#[path = "schema_generation/original.rs"]
mod original;

#[cfg(test)]
#[test]
fn actual_fresh_literal_algorithm_matches_full_old_observer_formula() -> Result<(), ProviderError> {
    assert_eq!(crucible_source_birth_data::profile::reference_packet::service::native_startup::schema_shapes::literal_generation::requested_data()?, original::requested_data()?);
    assert_eq!(crucible_source_birth_data::profile::reference_packet::service::native_startup::schema_shapes::literal_generation::fresh_requested_data()?, original::fresh_requested_data()?);
    Ok(())
}
