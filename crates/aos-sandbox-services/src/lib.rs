//! Role-selected daemon entry points and concrete service assembly.
//!
//! The `controller` module owns HTTP listeners and service registration. Other
//! executable modules compose the existing protected domain and session owners.
//! The `host` module owns fixed-role scheduling and retained guest launches,
//! using session security's bounded authenticated admission ports.
//! No service role or effect dependency is selected by default; each binary
//! requires its explicit role feature. Service identities, credentials, sockets,
//! and authority constructors remain with their independently confined owners.

#![cfg(target_os = "linux")]

#[cfg(feature = "controller")]
pub mod controller;

#[cfg(feature = "host")]
pub mod host;

// The installed policy role owns these Domain-dependent Root/Cache exchanges.
// Their closed transport, crypto and held-writer schedules move together.
#[cfg(feature = "policy")]
pub mod policy_authority_client;
#[cfg(feature = "policy")]
pub mod policy_cache_readback_client;
#[cfg(feature = "policy")]
pub mod policy_root_ack_v8_client;

#[cfg(feature = "policy")]
pub mod source_genesis_flight;

#[cfg(feature = "source-provider")]
pub mod production_source_provider;

// Application-level ordinary/Q04 orchestration stays above protected roles.
#[cfg(any(feature = "policy", feature = "controller"))]
mod cache_signer_ordinary_credential;
#[cfg(any(feature = "policy", feature = "controller"))]
pub mod cache_signer_exchange;

// Root-client recipes stay above the independently confined Source signer.
// The installed Source signer feature selects only its protected role runner.
#[cfg(any(feature = "policy", feature = "controller"))]
pub mod source_signer_exchange;
