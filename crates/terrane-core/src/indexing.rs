//! Owns canonical owner-bound index format data and executable recipe inputs.

pub mod carrier;
pub mod evaluation;

/// Maintains ordinary immutable index data through explicit measured operations.
pub mod maintenance;

#[cfg(test)]
mod carrier_tests;

#[cfg(test)]
mod evaluation_tests;
