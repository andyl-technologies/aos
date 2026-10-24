//! Executes existing normative wires against independently constructed models.
//!
//! This suite closes owning-codec gaps in the legacy, D-80 and D-88 corpora.
//! Published signatures and physical claims are ordinary format data. Tests
//! neither establish authority nor perform signing, verification or I/O.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "published bytes must match independent test models"
)]

extern crate alloc;

use terrane_format as core_model;

#[path = "legacy_vectors/bucket.rs"]
mod bucket;
#[path = "legacy_vectors/content.rs"]
mod content;
#[path = "legacy_vectors/journal.rs"]
mod journal;
#[path = "legacy_vectors/support.rs"]
mod support;
#[path = "legacy_vectors/token_model.rs"]
mod token_model;

#[test]
fn published_manifest_matches_separately_constructed_model_and_identity() {
    content::manifest();
}

#[test]
fn published_commit_matches_separately_constructed_model_and_identity() {
    content::commit();
}

#[test]
fn published_token_matches_separately_constructed_model_and_identity() {
    content::token();
}

#[test]
fn published_ref_matches_separately_constructed_model() {
    content::reference();
}

#[test]
fn published_reflog_matches_separately_constructed_model() {
    content::reflog();
}

#[test]
fn published_attribute_matches_separately_constructed_model_and_identity() {
    content::attribute();
}

#[test]
fn published_bundle_matches_separately_constructed_model_and_identity() {
    content::bundle();
}

#[test]
fn published_capabilities_match_separately_constructed_model() {
    bucket::capabilities();
}

#[test]
fn published_generation_manifests_match_separately_constructed_models() {
    bucket::generations();
}

#[test]
fn published_gc_tombstone_matches_separately_constructed_model() {
    bucket::collector_tombstone();
}

#[test]
fn published_creation_journals_match_separately_constructed_phase_models() {
    journal::creations();
}

#[test]
fn published_local_retirement_records_match_separately_constructed_models() {
    journal::operations();
}
