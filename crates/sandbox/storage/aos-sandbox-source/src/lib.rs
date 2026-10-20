//! Hosts the protected native Source role boundary.
//!
//! Shared historical models, codecs and replay comparisons live in
//! `aos-sandbox-ledger-replay`. The native constructor requires the genuine same-C Source construction loan;
//! historical DATA cannot substitute for that actual borrower.

/// Owns Provider's actual store and separately locked challenge writer.
pub mod provider_journal;

#[cfg(target_os = "linux")]
pub mod native;

/// Shares saved-state comparison and signing without native role admission.
#[cfg(target_os = "linux")]
pub mod signer_comparison;

/// Owns the actual fixed Source signer original and its paid native purposes.
#[cfg(target_os = "linux")]
pub mod signer;
