//! Owns original gem5 behavioral collection and independently accepted enrollment.
//!
//! The owning fixture drives the public Node API and retains all original
//! evidence. The ledger keeps the whole RFC population; lawful terminal cases
//! alone cannot qualify adverse timing or complete-world preservation.

mod case;
mod enrollment;
mod fixture;
mod native_oracle;
pub(in crate::node_observed_executor::factory) mod projection;
mod scope;
mod storage_oracle;
mod unit;

pub use enrollment::{Gem5BehavioralReport, InstalledGem5BehavioralAcceptance};
pub use fixture::{Gem5BehavioralCase, Gem5BehavioralRequest, Gem5BehavioralRun};
use scope::Gem5CaseScope;
