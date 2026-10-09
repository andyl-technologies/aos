//! Owns the private source-qualified Root common preparation candidate.
//!
//! The typed Root model remains separate from SE launch and stdout identities.
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
mod staging;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod cold_tests;
