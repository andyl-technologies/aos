#![deny(missing_docs)]

//! Guest-local execution effects for the protected sandbox agent.
//!
//! [`GuestProcessEffectsV1`] owns the root-protected operation ledger and
//! process handles. The guest executable links this crate with the portable
//! agent transport, keeping the agent-to-sandbox dependency graph acyclic.
//! Root construction, physical root measurement, sealed bootstrap, and the
//! OpenSSH gate implementation also live here; `aos-sandbox-agent` owns their
//! portable records and verification contracts without Linux dependencies.
//!
//! The Controller's passive specimen collector temporarily imports tree
//! measurement here. That observational edge supplies no mount or exec permit;
//! extracting the shared integration domain remains a separate change.

pub mod dormant_guest_agent;
pub mod dormant_package;
pub mod dormant_root_builder;
pub mod guest_root_label;
pub mod guest_root_marker;
pub mod guest_root_populate;
pub mod guest_root_tree;
pub mod openssh_gate_linux;
pub mod protected_entry;
mod runtime_argument_observation;

pub use dormant_guest_agent::{
    DormantGuestAgentMainErrorV1, DormantGuestAgentServiceV1, dormant_guest_agent_main_v1,
};

mod bridge;
mod execution_tree;
mod gate;
mod ledger;
mod monitor;
mod openssh_pty;
mod process;

pub use process::{GuestProcessEffectErrorV1, GuestProcessEffectsV1};

#[cfg(all(test, target_os = "linux"))]
mod openssh_attach_qualification;

#[cfg(test)]
mod sealed_authorize_tests;
