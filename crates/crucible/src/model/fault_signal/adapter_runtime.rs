//! Atomic state shared by executable fault adapters.
//!
//! Signal evaluation prepares complete action batches here before a domain
//! adapter exposes their effects. The committed contribution groups are the
//! sole input to network, storage, and node opportunity resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;

const ADAPTER_CHECKPOINT_VERSION: u16 = 2;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterCheckpointWire {
    semantic_version: u16,
    adapter: FaultAdapter,
    resource_limits: FaultResourceLimits,
    impulse_sequence: u64,
    entries: Vec<AdapterContributionWire>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterContributionWire {
    key: ActiveContributionKey,
    request: EffectRequest,
    mapped_parameters: ContentHash,
    mapping_output: ResolvedMappingOutput,
    transition_sequence: u64,
}

/// Live capability manifests for all executable adapter families.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultAdapterManifests {
    /// Network backend capabilities.
    pub network: FaultCapabilityManifest,
    /// Storage and 9p backend capabilities.
    pub storage: FaultCapabilityManifest,
    /// Node and QEMU backend capabilities.
    pub node: FaultCapabilityManifest,
}

/// One atomic transaction spanning network, storage, and node adapters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionalFaultAdapters {
    network: TransactionalAdapterRuntime,
    storage: TransactionalAdapterRuntime,
    node: TransactionalAdapterRuntime,
    prepared: Option<PreparedAdapterSet>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedAdapterSet {
    transaction: ContentHash,
    actions: Vec<ContentHash>,
    network: Option<ContentHash>,
    storage: Option<ContentHash>,
    node: Option<ContentHash>,
}

mod adapters;
mod mirrored;
mod runtime;

pub(super) use mirrored::MirroredFaultActionSink;
pub use runtime::TransactionalAdapterRuntime;
use runtime::*;

#[cfg(test)]
#[path = "adapter_runtime_test.rs"]
mod tests;
