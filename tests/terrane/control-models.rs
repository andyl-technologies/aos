//! Compares independent publication/control fields with owning pure codecs.
//!
//! All claims are inert data. No decoder result is treated as a verified holder,
//! original authority, backend registration permission or retirement capability.
//!
//! ```text
//! primitive fields -> independently encoded wire == published witness
//! complete typed fields -> owning encode == wire; owning decode == typed fields
//! ```

#[path = "control_models/bindings.rs"]
mod bindings;
#[path = "control_models/guard.rs"]
mod guard;
#[path = "control_models/negatives.rs"]
mod negatives;
#[path = "control_models/original.rs"]
mod original;
#[path = "control_models/publication.rs"]
mod publication;
#[path = "control_models/retirement.rs"]
mod retirement;
#[path = "control_models/wire.rs"]
mod wire;

#[test]
fn reference_backend_binding_models_preserve_all_alternatives() {
    bindings::check_models();
}

#[test]
fn reference_original_control_models_preserve_all_registered_versions() {
    original::check_models();
}

#[test]
fn reference_guard_snapshot_models_preserve_complete_nested_fields() {
    guard::check_models();
}

#[test]
fn reference_registry_attribute_revisions_preserve_registered_data_and_refuse_unknown() {
    guard::check_attribute_revisions();
}

#[test]
fn reference_portable_snapshot_and_genesis_models_preserve_mandatory_inventory() {
    publication::check_models();
}

#[test]
fn reference_publication_proof_models_preserve_all_alternatives() {
    retirement::check_models();
}

#[test]
fn reference_publication_control_negatives_require_structural_rejection() {
    negatives::check_models();
}
