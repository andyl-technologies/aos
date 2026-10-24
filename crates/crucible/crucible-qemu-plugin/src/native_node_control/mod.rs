//! Opt-in native strict-boundary callbacks and retained original command custody.
//!
//! All C callback declarations stay GPL-side. They carry process-private scalar
//! copies of commands received through the independent portable protocol and
//! never appear in shared memory. Stop facts do not qualify queue closure, exact
//! capture, producer bounds or same-time event-phase integration.

mod abi;
mod administration_abi;
mod administration_custody;
pub(crate) mod administrative_inbox;
pub(crate) mod administrative_mailbox;
mod construction_reducer;
mod controller;
mod initialization_abi;
mod initialization_custody;
mod install;
mod manifest;
mod phase_abi;
mod phase_custody;
mod preparation_successor_abi;
mod preparation_successor_custody;
mod root_policy;
pub(crate) use root_policy::NativeRootPolicy;
mod source_fault_abi;
mod writer_abi;
pub(crate) use install::{install, registered_owner};
pub(crate) use manifest::RegisteredResourceManifest;

pub(crate) use abi::resolve_register_node_control;
pub(crate) use controller::NativeNodeControl;

// This private acquisition component has no installed source RootSeal caller yet.
mod preparation_fifo;

pub(crate) use preparation_transport::NativePreparationTransportState;

mod preparation_transport;

// Dormant callbacks cannot manufacture the missing native root/input epoch.
pub(crate) mod root_epoch_abi;

#[cfg(test)]
mod root_epoch_owner;
