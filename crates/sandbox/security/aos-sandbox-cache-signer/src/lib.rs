//! Owns the selected, independently confined Cache Current signer role.
//!
//! The closed service captures one genuine PID1 Cache financial original and
//! drives two distinct finite Current-proof purposes through the same native,
//! complete historical replay, physical, clock and signing engines. Its seed,
//! listener, ledger and native owners stay private. Returned signed DATA alone
//! grants no Controller-held writer custody or publication/effect authority.
//!
//! Ordinary diagnostic/Q04 application exchanges are assembled above this
//! role in `aos-sandbox-services`; this crate has no Domain integration edge.

#![cfg(target_os = "linux")]

mod cache_signer_credential;
mod service_original;

pub use service_original::run_selected_current_service_once;
