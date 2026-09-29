//! Signs and verifies immutable commits and evaluates closed trust selectors.
//!
//! Authentication uses caller-supplied issuer keys and trusted authorization
//! context. This module performs no I/O, clock reads, or environment access.
//! Signature preimages omit commit key 8; identities include the signature.
//!
//! ```text
//! commit signature = Ed25519(canonical commit map without key 8)
//! commit identity = BLAKE3("terrane-commit-v1" || 0x00 || canonical signed commit)
//! ```

mod attributes;
mod history;
mod selector;
mod signing;
mod trust;

pub use history::{EntryLocation, VerifiedHistory, same_content, source_commit_references};
pub use selector::{Preset, Selector, SelectorError};
pub use signing::{Diagnostic, Rejected, VerifiedCommit, sign, verify, verify_diagnostic};
pub use trust::{TrustContext, validate_canonical_context};

#[cfg(test)]
pub(crate) mod tests;
