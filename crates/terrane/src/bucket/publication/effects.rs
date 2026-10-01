//! Derives fixed physical publication effects from genuine retained inputs.
//!
//! This module is a logical descendant of the private native executor. Public
//! record bytes alone do not provide authority to construct a submitted effect.

// The collector descendant consumes only its separately checked lease carrier;
// it reuses the retained executor without granting arbitrary effect construction.
/// Executes fixed collector lease publication under genuinely retained inputs.
#[path = "../../gc/effects.rs"]
pub(crate) mod collection;

/// Publishes fixed mark checkpoints under genuine lease and control receipts.
#[path = "../../gc/checkpoint_effects.rs"]
pub(crate) mod collection_checkpoints;
