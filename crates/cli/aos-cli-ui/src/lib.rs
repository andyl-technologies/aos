//! Shared presentation support for the AOS command-line applications.
//!
//! [`output`] renders diagnostics, JSON results, and progress. [`invocation`]
//! constructs command hints using the selected executable name. This crate
//! owns presentation policy; portable data libraries do not depend on it.

pub mod invocation;
pub mod output;
