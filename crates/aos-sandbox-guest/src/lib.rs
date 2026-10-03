#![deny(missing_docs)]

//! Guest-local execution effects for the protected sandbox agent.
//!
//! [`GuestProcessEffectsV1`] owns the root-protected operation ledger and
//! process handles. The guest executable links this crate with the portable
//! agent transport, keeping the agent-to-sandbox dependency graph acyclic.

mod bridge;
mod execution_tree;
mod gate;
mod ledger;
mod monitor;
mod openssh_pty;
mod process;

pub use process::{GuestProcessEffectErrorV1, GuestProcessEffectsV1};
