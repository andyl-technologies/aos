//! Composes, compares, and merges immutable Terrane namespaces without I/O.
//!
//! Grafts preserve independent roots and use reusable [`RootGraph`] admission
//! certificates. [`Overlay`] records virtual layer order; materialized results
//! retain recipes for commit profiles. Diff and merge compare Merkle frontiers
//! and skip shared nodes. Trust contexts contain verified repository receipts;
//! fork and fold produce commit bindings before conditional ref publication.

mod branch;
mod compare;
mod compose;
mod domain;
mod graph;
mod merge;
mod metadata;
mod recipe;
mod trust;

pub use branch::{FoldResult, Fork, Retirement, fold, fold_with_domains, fork};
pub use compare::{
    Change, DescendedDiffResult, DiffResult, PathPropertiesChange, RootPropertiesChange, diff,
    diff_descend, diff_descend_with_work, diff_with_work,
};
pub use compose::{
    Error, GraftResult, MaterializedRoot, Overlay, PreparedFlatten, PreparedGraft, PreparedSplit,
    Roots, flatten, graft, graft_certified, graft_certified_with_domains, graft_with_domains,
    lookup, prepare_graft, prepare_graft_with_domains, prepare_split, prepare_split_with_domains,
    split, split_with_domains, validate_acyclic,
};
pub use domain::{DomainError, OperationDomains};
pub use graph::{GraphWork, RootGraph};
pub use merge::{
    MergeResult, merge, merge_certified, merge_certified_with_domains, merge_with_domains,
};
pub use metadata::RootPropertiesConflict;
pub use recipe::{MergePolicy, OwnedRecipe, Recipe, RecipeError};
pub use trust::{TrustContext, TrustError};

#[cfg(test)]
mod signed_fixture;

#[cfg(test)]
mod tests;
