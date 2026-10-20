//! Owns trusted Controller administration of Publisher namespaces in the C journal.
//!
//! [`policy`] validates retained Publisher policy, administrative inputs and
//! resource-account cross-links. [`capabilities`] maintains the Controller's
//! durable public capability registry. [`audit`] stores execution/challenge
//! facts, and [`registration`] joins that protected state to the actual native
//! Publisher session owner. These modules retain the genuine Controller writer,
//! currentness and semantic commit gates; portable bytes and signatures remain
//! in Protocol/Policy, while Publisher owns its live sockets and process pins.
//! No Publisher role loan receives Controller append authority.

pub mod policy;
pub mod capabilities;
pub mod audit;
#[cfg(target_os = "linux")]
pub mod registration;

mod read_data;
pub(crate) use read_data::PublisherReadDataV2;

mod receiving;
pub(crate) use receiving::{authorization_namespace_entries_v1, policy_namespace_entries_v2};
