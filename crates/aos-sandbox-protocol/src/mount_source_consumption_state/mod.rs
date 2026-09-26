//! Canonical durable companions for atomic Mount source consumption.
//!
//! This module owns the persisted `AOSMSP01` SourcePin and Mount-resource
//! JSON schemas plus the structural `AOSMAJ`/`AOSMAE` effect framing used by
//! the four-record consumption transaction. It contains no journal, broker
//! key, runtime, descriptor, or effect authority. Authentication of an
//! `AOSMAJ` value remains the broker key owner's responsibility.

mod codec;
mod correlation;
mod effect;
mod model;

pub use codec::*;
pub use correlation::*;
pub use effect::*;
pub use model::*;
