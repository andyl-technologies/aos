//! Preserves exact owning selectors while grouping real native metadata witnesses.

use super::*;
use crate::bucket::FileBucket;
use crate::bucket::held::SingleHeld;
use crate::domain::DomainNamespace;
use crate::gc::runner::{Collection, fixture::Fixture};
use crate::guard::StagedUpload;
use crate::ref_advance::{CommitRequest, CommitTiming, Coordinator};
use crate::repository::{MetadataValidator, Repository};
use crate::store::LocalFs;
use crate::store::NativeEffectClock;
use crate::store::native_publication_effects::collection::test_fs::TestFs;
use crate::store::{ContentUpload, InvalidReason, MetaUpload, StoreErrorKind};
use terrane_format::derived::{AttrRecord, AttributeValue};
use terrane_format::gc::Windows;
use terrane_format::indexing::{IndexEvaluationRecipe, completion, evaluation, maintenance};
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{Attribute, Entry, EntryKind, LeafItem, Property, TreeUse};

mod attributes;
mod checkpoints;
mod cutoffs;
mod disclosure;
mod indexes;
mod memos;
mod overlays;
mod preservation;
mod root_inventory;
mod rooted;
mod support;

use support::*;

#[tokio::test]
async fn gc_roots_native_current_inventory_keeps_all_commit_classes_and_live_jobs() {
    root_inventory::current_inventory_keeps_all_commit_classes_and_live_jobs().await;
}

#[tokio::test]
async fn gc_roots_native_retained_selection_keeps_absent_history_and_excludes_proposals() {
    root_inventory::retained_selection_keeps_absent_history_and_excludes_proposals().await;
}

#[tokio::test]
async fn gc_roots_native_snapshot_resume_preserves_roots_after_current_ref_moves() {
    root_inventory::snapshot_resume_preserves_roots_after_current_ref_moves().await;
}

#[tokio::test]
async fn gc_roots_native_incomplete_inventory_cannot_replace_selected_authority() {
    root_inventory::incomplete_inventory_cannot_replace_selected_authority().await;
}

#[tokio::test]
async fn gc_common_walk_native_indexes_preserve_exact_auxiliary_roles() {
    indexes::gc_common_walk_native_indexes_preserve_exact_auxiliary_roles().await;
}

#[tokio::test]
async fn gc_common_walk_native_manifest_dictionary_and_legacy_records_keep_declared_edges() {
    attributes::gc_common_walk_native_manifest_dictionary_and_legacy_records_keep_declared_edges()
        .await;
}

#[tokio::test]
async fn gc_common_walk_native_repeated_occurrences_cut_erased_audit_sources_only() {
    disclosure::gc_common_walk_native_repeated_occurrences_cut_erased_audit_sources_only().await;
}

#[tokio::test]
async fn gc_common_walk_native_attributes_retain_versions_without_discovery_roots() {
    attributes::gc_common_walk_native_attributes_retain_versions_without_discovery_roots().await;
}

#[tokio::test]
async fn gc_common_walk_native_witness_then_full_keeps_declared_chunks_without_body_reads() {
    attributes::gc_common_walk_native_witness_then_full_keeps_declared_chunks_without_body_reads()
        .await;
}

#[tokio::test]
async fn gc_common_walk_native_invalid_matching_attribution_keeps_frontier_unchanged() {
    attributes::gc_common_walk_native_invalid_matching_attribution_keeps_frontier_unchanged().await;
}

#[tokio::test]
async fn gc_common_walk_native_complete_checkpoint_reopens_and_preserves_contextual_marks() {
    checkpoints::complete_checkpoint_reopens_and_preserves_contextual_marks().await;
}

#[tokio::test]
async fn gc_common_walk_native_independently_rooted_source_keeps_own_producer_context() {
    rooted::independently_rooted_source_keeps_own_producer_context().await;
}

#[tokio::test]
async fn gc_common_walk_native_broader_cutoff_reuses_full_occurrence_expansion() {
    cutoffs::broader_cutoff_reuses_full_occurrence_expansion().await;
}

#[tokio::test]
async fn gc_common_walk_native_recorded_preservation_keeps_inert_index_bindings() {
    preservation::recorded_preservation_keeps_inert_index_bindings().await;
}
