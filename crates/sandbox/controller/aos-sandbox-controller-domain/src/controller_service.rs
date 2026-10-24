//! Native journal queries for public projections.
//!
//! HTTP assembly lives in sandbox-services. Protected runtime integration
//! lives in sandbox-controller-runtime; Controller Journal admission and
//! identity binding belong to [`crate::journal::controller`].

pub mod public_projection;
