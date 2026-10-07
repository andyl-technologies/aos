//! Role-selected daemon entry points and concrete service assembly.
//!
//! The `controller` module owns HTTP listeners and service registration. Other
//! executable modules compose the existing protected domain and session owners.
//! No service role or effect dependency is selected by default; each binary
//! requires its explicit role feature. Service identities, credentials, sockets,
//! and authority constructors remain with their independently confined owners.

#![cfg(target_os = "linux")]

#[cfg(feature = "controller")]
pub mod controller;
