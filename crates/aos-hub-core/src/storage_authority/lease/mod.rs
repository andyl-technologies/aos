//! Pure closed signed epoch leases and bounded lease-admission revocation.
//!
//! This foundation enables no live issuance or provider dispatch. Callers own
//! live issuer serialization, actual durable CAS, issuer-only key confinement,
//! immutable execution snapshots, and qualification of an explicit clock policy.
//! Archived SQL and nonce-bound Watermark responses cannot supply those facts.
//! Executors still require ordinary application authorization, exact reviewed
//! deletion grants and permanent object intent/receipt fences. Expiry never
//! settles provider I/O, clears unknown intent or retires a terminal receipt.
//!
//! ```json
//! {"payload":{"protocol_version":1,"lease_sequence":"1"},"signature":"<128 lowercase hex characters>"}
//! ```
//!
//! This abbreviated illustration omits the required full cohort and time profile.

pub mod control;
mod state;
mod wire;

pub use state::*;
pub use wire::*;

#[cfg(test)]
mod tests;
