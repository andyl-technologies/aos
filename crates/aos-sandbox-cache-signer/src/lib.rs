//! Independent Cache-only readback signer and fixed Root/Controller exchange.
//!
//! The private credential owner retains the dedicated zeroizing seed and
//! provisioned memory ceiling. [`cache_signer_exchange`] owns the fixed
//! listener, peer checks, separate challenge histories, and one-shot replies.
//! Native Cache-view replay and packet validation remain with the existing
//! Cache domain owner in `aos-sandbox`.
//!
//! Signed readback is nonauthorizing DATA, not Controller writer custody,
//! an all-owner held cut, Q04 permission, or publication authority. This crate
//! does not expose its credential owner, signing key, or listener descriptor.
//! Executable entry points and service registration remain in
//! `aos-sandbox-services`.

#![cfg(target_os = "linux")]

mod cache_signer_credential;
pub mod cache_signer_exchange;
