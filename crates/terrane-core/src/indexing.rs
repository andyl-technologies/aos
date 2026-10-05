//! Owns canonical owner-bound index format data and executable recipe inputs.

pub mod carrier;
pub mod evaluation;

/// Constructs owner-local index bindings before forming detached recipes.
pub mod completion;

/// Queries immutable index rows and local occurrence routes with measured work.
pub mod lookup;

/// Maintains ordinary immutable index data through explicit measured operations.
pub mod maintenance;

#[cfg(test)]
mod carrier_tests;

#[cfg(test)]
mod evaluation_tests;
