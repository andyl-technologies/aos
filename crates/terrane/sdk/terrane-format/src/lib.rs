//! Owns Terrane's pure formats and identity-producing algorithms.
//!
//! This crate uses only `core` and `alloc` and performs no I/O, clock reads,
//! environment access, or task spawning (CRATE-1, CRATE-21). Its format and
//! algorithm responsibilities follow specifications 04-10, 12-13, 17, 22-24,
//! 26 and 37; each module documents its covered requirements and input context.
//!
//! [`identity`], [`cbor`], [`codec`], [`chunking`], [`manifest`], [`tree_format`],
//! [`refs`], [`pack_format`] and [`bucket`] own content encodings and registered
//! records. [`boundary`] and [`tree_builder`] construct canonical Merkle trees;
//! [`algebra`] evaluates namespace operations over immutable inputs.
//!
//! [`properties`], [`derived`] and [`indexing`] own property interpretation,
//! per-object attributes and detached index relationships. [`derivation`] owns
//! the common advisory Memo record. [`auth`] and [`provenance`] check tokens,
//! signed histories and their supplied trust context; [`gc`] owns collector
//! records and pure reachability policy. [`model`] exposes glossary SDK names,
//! while [`surface`] defines view selectors, exposures and tree schemas.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod algebra;
pub mod auth;
pub mod boundary;
pub mod bucket;
pub mod cbor;
pub mod chunking;
pub mod codec;
pub mod derivation;
pub mod derived;
pub mod gc;
pub mod identity;
pub mod indexing;
pub mod manifest;
pub mod model;
pub mod pack_format;
pub mod properties;
pub mod provenance;
pub mod refs;
pub mod surface;
pub mod tree_builder;
pub mod tree_format;
