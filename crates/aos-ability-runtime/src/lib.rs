//! Durable execution and recovery for admitted AOS ability effect plans.
//!
//! This crate is the privileged boundary between checked, portable ability
//! plans and trusted platform adapters. It owns three related mechanisms:
//!
//! - [`journal`] stores a versioned, digest-chained execution history.
//! - [`adapter`] defines the typed boundary implemented by trusted providers.
//! - [`execution`] admits and advances finite operation state machines.
//!
//! Planning and validation stay in `aos-ability-model` and
//! `aos-ability-validate`. Platform integrations remain behind traits here so
//! importing the portable contract types never imports a privileged executor.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod bundle;
pub mod execution;
pub mod journal;
