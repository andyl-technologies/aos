//! Package-specific retained-generation admission and deployment integration.
//!
//! Portable envelopes live in `aos-deployment-format`; scope-neutral evaluation,
//! handler transport, store retention, and transactions live in `aos-deployment`.
//! This module adapts retained package generations to those shared libraries.

pub(crate) mod retained;

#[cfg(test)]
mod tests;
