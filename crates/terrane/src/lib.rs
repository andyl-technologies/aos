//! Provides the portable storage and role configuration layer of Terrane.
//!
//! The [`config`] module loads the vocabulary in specification 11 and 26;
//! [`role`] selects the process roles in specification 03 and 37. This T0
//! foundation implements configuration syntax only: backend capability probes,
//! repository operations, surfaces, and running services belong to later
//! milestones. No operation here claims storage or surface conformance.

#![forbid(unsafe_code)]

pub mod config;
pub mod role;
pub mod store;
