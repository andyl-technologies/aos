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
mod disclosure;
mod history;
mod root_context;
mod selector;
mod side_attributes;
mod signing;
mod snapshot;
mod trust;

pub use disclosure::{
    DisclosureAuthority, DisclosureCandidate, DisclosureSigning, VerifiedDisclosureBatch,
    VerifiedDisclosureBoundary, disclosure_target_binding, sign_disclosure,
};
pub use history::{EntryLocation, VerifiedHistory, same_content, source_commit_references};
pub use root_context::{
    AffectedRoot, OriginalBootstrapPolicy, RootChangePlan, RootSide, VerifiedRootScope,
    derive_fresh_roots, derive_root_changes, verify_root_context,
    verify_root_context_with_bootstrap,
};
pub use selector::{Preset, Selector, SelectorError};
pub use side_attributes::SideAttributeBinding;
pub use signing::{
    Diagnostic, Rejected, VerifiedCommit, sign, sign_authored, verify, verify_diagnostic,
    verify_history,
};
pub use snapshot::{sign_snapshot, verify_snapshot};
pub use trust::{TrustContext, validate_canonical_context};

#[cfg(test)]
pub(crate) mod tests;
