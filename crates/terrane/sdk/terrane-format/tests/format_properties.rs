//! Exercises pure Terrane byte formats through public APIs with reproducible models.
//!
//! Models never establish authority: publication and retirement records are
//! untrusted representations, and no workflow, clock, store, or I/O is used.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "format_properties/closed_index.rs"]
mod closed_index;
#[path = "format_properties/common_memo.rs"]
mod common_memo;
#[path = "format_properties/containers.rs"]
mod containers;
#[path = "format_properties/content.rs"]
mod content;
#[path = "format_properties/contexts.rs"]
mod contexts;
#[path = "format_properties/foreign.rs"]
mod foreign;
#[path = "format_properties/index_carriers.rs"]
mod index_carriers;
#[path = "format_properties/policy.rs"]
mod policy;
#[path = "format_properties/publication.rs"]
mod publication;
#[path = "format_properties/records.rs"]
mod records;
#[path = "format_properties/retirement.rs"]
mod retirement;
#[path = "format_properties/support.rs"]
mod support;
