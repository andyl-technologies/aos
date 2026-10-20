//! Owns the independently confined selected Source readback signer.
//!
//! The installed entry retains its genuine original, private seed/pin capture,
//! same financial ledger and complete native/Root posts through the serving
//! lifecycle. Signed comparison DATA grants no writer or publication authority.
//! Root-client application recipes live in Services; the service stays with
//! this selected role. Shared passive codecs live in LedgerReplay.

#![cfg(target_os = "linux")]

mod source_signer_credential;
mod source_signer_exchange;

pub use source_signer_exchange::run_selected_source_signer_service_v1;
