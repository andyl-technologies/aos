//! Owns first administrative enrollment of a genuinely created bucket.
//!
//! Complete original inode claims and the enrollment ledger must become durable
//! before project or custody setters. Existing roots and decoded records do not
//! establish a creator event. Interrupted attempts remain incomplete; this module does
//! not implement automatic enrollment recovery.
//!
//! Existing buckets cannot supply this factory's original creator evidence.

mod administrative;
mod capture;
pub(super) mod model;
mod plan;
mod preflight;
mod provision;
mod ready;
mod storage;
mod validation;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Tests use panics as assertion failures."
)]
mod tests;

pub(super) use model::{InitialLedger, VERSION};
pub use provision::provision;
pub(super) use ready::bind as bind_ready;
