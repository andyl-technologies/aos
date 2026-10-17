//! Owns the private source-qualified X86Root common preparation candidate.
//!
//! The typed X86Root model remains separate from SE launch and stdout identities.
//! Enrollment, actual native Ready qualification, complete public publication
//! and signed continuation are independent checks with retained original custody.

mod archive;
mod custody;
mod evidence;
mod factory;
mod installed;
mod profile;
pub(super) mod public_catalog;
mod publication;
mod qualification;
mod queue_diagnostics;
mod retirement;
mod staging;

#[cfg(test)]
mod tests;

pub use queue_diagnostics::{InstalledX86RootCleanupFailure, InstalledX86RootCleanupStatus};

pub use retirement::{InstalledX86RootRetirement, X86RootNamespaceReleaseFailure};
