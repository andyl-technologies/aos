//! Opt-in native strict-boundary callbacks and retained original command custody.
//!
//! All C callback declarations stay GPL-side. They carry process-private scalar
//! copies of commands received through the independent portable protocol and
//! never appear in shared memory. Stop facts do not qualify queue closure, exact
//! capture, producer bounds or same-time event-phase integration.

mod abi;
mod controller;
mod install;
mod manifest;
pub(crate) use install::{install, registered_owner};
pub(crate) use manifest::RegisteredResourceManifest;

pub(crate) use abi::resolve_register_node_control;
pub(crate) use controller::NativeNodeControl;
