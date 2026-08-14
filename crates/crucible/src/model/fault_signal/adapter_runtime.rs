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

/// Implementation-derived manifests for host-owned network and storage adapters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostFaultAdapterManifests {
    /// Network backend capabilities derived from its implementation registry.
    pub network: FaultCapabilityManifest,
    /// Storage and 9p capabilities derived from their implementation registry.
    pub storage: FaultCapabilityManifest,
}

impl HostFaultAdapterManifests {
    /// Builds manifests from the two concrete host adapter registries.
    ///
    /// # Errors
    ///
    /// Returns [`HostFaultAdapterManifestError`] if a registry belongs to the
    /// wrong adapter, is incomplete, or contains a malformed capability.
    pub fn from_registries(
        network: &EffectImplementationRegistry,
        storage: &EffectImplementationRegistry,
    ) -> Result<Self, HostFaultAdapterManifestError> {
        if network.adapter() != FaultAdapter::Network {
            return Err(HostFaultAdapterManifestError::AdapterMismatch {
                expected: FaultAdapter::Network,
                actual: network.adapter(),
            });
        }
        if storage.adapter() != FaultAdapter::Storage {
            return Err(HostFaultAdapterManifestError::AdapterMismatch {
                expected: FaultAdapter::Storage,
                actual: storage.adapter(),
            });
        }
        network.require_complete()?;
        storage.require_complete()?;
        Ok(Self {
            network: network.capability_manifest("network-production")?,
            storage: storage.capability_manifest("storage-production")?,
        })
    }

    /// Builds empty host manifests for a node-only production plan.
    ///
    /// Any network or storage binding fails admission against these manifests.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError`] if a fixed backend identity is malformed.
    pub fn node_only() -> Result<Self, FaultContractError> {
        Ok(Self {
            network: FaultCapabilityManifest {
                backend: FaultObjectId::parse("network-unavailable")?,
                capabilities: BTreeSet::new(),
                bounds: BTreeMap::new(),
            },
            storage: FaultCapabilityManifest {
                backend: FaultObjectId::parse("storage-unavailable")?,
                capabilities: BTreeSet::new(),
                bounds: BTreeMap::new(),
            },
        })
    }
}

/// Failure to derive exact host capabilities from implementation registries.
#[derive(Debug)]
pub enum HostFaultAdapterManifestError {
    /// A registry was supplied for the wrong adapter slot.
    AdapterMismatch {
        /// Required adapter family.
        expected: FaultAdapter,
        /// Supplied registry's adapter family.
        actual: FaultAdapter,
    },
    /// A registry is malformed or incomplete.
    Registry(EffectImplementationRegistryError),
    /// A fixed backend or capability identifier is malformed.
    Contract(FaultContractError),
}

impl std::fmt::Display for HostFaultAdapterManifestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid host fault adapter manifests: {self:?}")
    }
}

impl std::error::Error for HostFaultAdapterManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registry(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::AdapterMismatch { .. } => None,
        }
    }
}

impl From<EffectImplementationRegistryError> for HostFaultAdapterManifestError {
    fn from(error: EffectImplementationRegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<FaultContractError> for HostFaultAdapterManifestError {
    fn from(error: FaultContractError) -> Self {
        Self::Contract(error)
    }
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
