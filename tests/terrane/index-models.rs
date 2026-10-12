//! Checks published index witnesses against complete public owning models.
//!
//! These tests consume ordinary immutable data, explicit recorded semantics,
//! and finite source graphs. They establish no authority or runtime cost claim.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "fixture discrepancies intentionally panic"
)]

#[path = "index_models/fields.rs"]
mod fields;
#[path = "index_models/graphs.rs"]
mod graphs;
#[path = "index_models/models.rs"]
mod models;
#[path = "index_models/support.rs"]
mod support;

#[test]
fn reference_index_owner_bindings_and_recipes_preserve_exact_formats() {
    fields::bindings_and_recipes();
}

#[test]
fn reference_index_opaque_keys_preserve_complete_canonical_values() {
    fields::keys();
}

#[test]
fn reference_index_historical_nodes_preserve_data_without_activation() {
    fields::historical();
}

#[test]
fn reference_index_carrier_nodes_preserve_complete_models_and_descriptors() {
    fields::carriers();
}

#[test]
fn reference_index_source_models_match_complete_independent_occurrences() {
    graphs::sources();
}

#[test]
fn reference_index_contextual_relationships_refuse_invalid_routes_and_gaps() {
    graphs::controls();
}

#[test]
fn reference_index_format_negatives_refuse_independently_supplied_wires() {
    fields::negatives();
}
