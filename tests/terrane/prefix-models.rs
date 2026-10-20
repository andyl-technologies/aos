//! Compares the original published prefix with independent pure field models.
//!
//! The sandbox installs this template as `terrane/sdk/terrane-format/tests/prefix_vectors.rs`.
//! Chunking and unsigned token projections use separate private test templates.
//! No fixture authenticates a principal, a token, or an operation.

extern crate alloc;

#[path = "../../../../../tests/terrane/prefix_models/boundaries.rs"]
mod boundaries;
#[path = "../../../../../tests/terrane/prefix_models/content.rs"]
mod content;
#[path = "../../../../../tests/terrane/prefix_models/support.rs"]
mod support;

#[test]
fn published_chunk_identities_match_independent_plaintext_models() {
    content::check_chunks();
}

#[test]
fn published_inline_entry_and_leaf_preserve_complete_models() {
    content::check_entry_and_leaf();
}

#[test]
fn published_node_boundary_rows_and_item_hash_match_owning_functions() {
    boundaries::check_boundaries();
}
