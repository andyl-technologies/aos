//! Independent Source-only readback signer and fixed Root-client exchange.
//!
//! The private credential owner retains the dedicated zeroizing seed and
//! Source-purpose pin validation. [`source_signer_exchange`] owns the fixed
//! listener, Root peer checks, bounded canonical requests, and retained
//! transport results. Native Source-view replay and packet validation remain
//! with the existing domain owner in `aos-sandbox`.
//!
//! Signed readback is nonauthorizing DATA, not a Controller writer loan,
//! Root admission, currentness authority, or a paid resource grant. The
//! existing Source16 ingress remains closed before key access or native
//! observation. This crate does not expose its credential owner, signing key,
//! or listener descriptor. Executable entry points and service registration
//! remain in `aos-sandbox-services`.

#![cfg(target_os = "linux")]

mod source_signer_credential;
pub mod source_signer_exchange;
