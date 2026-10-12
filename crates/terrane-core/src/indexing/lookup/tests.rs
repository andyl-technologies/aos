//! Models complete immutable rows independently of lookup preparation and query.
//!
//! Literal carrier bytes deliberately permit malformed witnesses that the safe
//! carrier encoder rejects. Larger populations use the reviewed physical Tree
//! builder only for canonical layout, with independently assembled row models.

#![allow(clippy::unwrap_used, reason = "test model failures must panic")]

use super::*;
use crate::cbor;
use crate::identity::{IdentityKind, TERRANE_V1};
use crate::tree_format::{Attribute, ContentRef, Entry, EntryKind, Property, TreeUse};

mod internal;
mod model;

use model::*;

mod occurrences;
mod preparation;
mod ranges;

#[test]
fn candidate_ranges_match_independent_typed_rows_with_logarithmic_work() {
    ranges::check();
}

#[test]
fn occurrence_walk_preserves_local_hops_gaps_and_sharing() {
    occurrences::check();
}

#[test]
fn lookup_preparation_refuses_divergent_data_and_separates_validation_work() {
    preparation::check();
}
