//! Production implementation evidence for executable fault effects.
//!
//! The closed effect vocabulary describes what a scenario may request. This
//! module separately records which concrete adapter executor implements each
//! request. Capability manifests are derived from these records so vocabulary
//! membership alone can never advertise production support.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use super::*;

/// Auditable production evidence for one executable effect kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectImplementationContract {
    /// Closed effect kind implemented by the adapter.
    pub effect: EffectKind,
    /// Concrete production function or state machine that applies the effect.
    pub executor: &'static str,
    /// Backend-owned state or bytes whose change proves application.
    pub mutation_evidence: &'static [&'static str],
    /// Typed event or observation emitted after application.
    pub observation_evidence: &'static [&'static str],
    /// Canonical checkpoint component that retains continuation state.
    pub checkpoint_evidence: &'static str,
    /// Recomputed-replay comparison performed for this effect.
    pub recomputed_replay_evidence: &'static str,
    /// Locked-effect replay precondition and result comparison.
    pub locked_replay_evidence: &'static str,
    /// Search behavior or explicit non-branching rationale.
    pub search_evidence: &'static str,
    /// Production-backend conformance case exercising the mutation.
    pub conformance_test: &'static str,
}

impl EffectImplementationContract {
    fn validate(self, adapter: FaultAdapter) -> Result<(), EffectImplementationRegistryError> {
        let nonempty = !self.executor.is_empty()
            && !self.mutation_evidence.is_empty()
            && self.mutation_evidence.iter().all(|value| !value.is_empty())
            && !self.observation_evidence.is_empty()
            && self
                .observation_evidence
                .iter()
                .all(|value| !value.is_empty())
            && !self.checkpoint_evidence.is_empty()
            && !self.recomputed_replay_evidence.is_empty()
            && !self.locked_replay_evidence.is_empty()
            && !self.search_evidence.is_empty()
            && !self.conformance_test.is_empty();
        if self.effect.descriptor().adapter != adapter || !nonempty {
            return Err(EffectImplementationRegistryError::InvalidContract {
                adapter,
                effect: self.effect,
            });
        }
        Ok(())
    }
}

/// Canonical implementation registry owned by one production adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectImplementationRegistry {
    adapter: FaultAdapter,
    contracts: BTreeMap<EffectKind, EffectImplementationContract>,
}

impl EffectImplementationRegistry {
    /// Validates and canonicalizes implementation contracts for one adapter.
    ///
    /// # Errors
    ///
    /// Returns [`EffectImplementationRegistryError`] for a cross-adapter,
    /// incomplete, or duplicate contract.
    pub fn new(
        adapter: FaultAdapter,
        contracts: impl IntoIterator<Item = EffectImplementationContract>,
    ) -> Result<Self, EffectImplementationRegistryError> {
        let mut canonical = BTreeMap::new();
        for contract in contracts {
            contract.validate(adapter)?;
            let effect = contract.effect;
            if canonical.insert(effect, contract).is_some() {
                return Err(EffectImplementationRegistryError::Duplicate(effect));
            }
        }
        Ok(Self {
            adapter,
            contracts: canonical,
        })
    }

    /// Returns the adapter that owns every registry entry.
    #[must_use]
    pub const fn adapter(&self) -> FaultAdapter {
        self.adapter
    }

    /// Returns one effect's production implementation evidence.
    #[must_use]
    pub fn get(&self, effect: EffectKind) -> Option<&EffectImplementationContract> {
        self.contracts.get(&effect)
    }

    /// Requires an implementation contract for an action about to execute.
    ///
    /// Adapters call this at their mutation seam as a second fail-closed check
    /// after plan admission. This prevents a checkpoint, replay record, or
    /// future internal caller from bypassing the implementation-derived
    /// capability manifest.
    ///
    /// # Errors
    ///
    /// Returns [`EffectImplementationRegistryError::Missing`] when the effect
    /// is not implemented by this registry.
    pub fn require_implemented(
        &self,
        effect: EffectKind,
    ) -> Result<&EffectImplementationContract, EffectImplementationRegistryError> {
        self.contracts
            .get(&effect)
            .ok_or(EffectImplementationRegistryError::Missing(effect))
    }

    /// Iterates contracts in canonical effect-key order.
    pub fn contracts(&self) -> impl ExactSizeIterator<Item = &EffectImplementationContract> {
        self.contracts.values()
    }

    /// Verifies that every effect owned by the adapter has one contract.
    ///
    /// # Errors
    ///
    /// Returns [`EffectImplementationRegistryError::Missing`] for the first
    /// closed effect kind absent from this registry.
    pub fn require_complete(&self) -> Result<(), EffectImplementationRegistryError> {
        for effect in EffectKind::all() {
            if effect.descriptor().adapter == self.adapter && !self.contracts.contains_key(effect) {
                return Err(EffectImplementationRegistryError::Missing(*effect));
            }
        }
        Ok(())
    }

    /// Builds the exact backend capability manifest from implemented entries.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError`] if the backend or a registry capability
    /// identifier is malformed.
    pub fn capability_manifest(
        &self,
        backend: impl AsRef<str>,
    ) -> Result<FaultCapabilityManifest, FaultContractError> {
        let backend = FaultObjectId::parse(backend.as_ref())?;
        let capabilities = self
            .contracts
            .keys()
            .map(|effect| FaultCapabilityId::parse(effect.descriptor().capability))
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(FaultCapabilityManifest {
            backend,
            capabilities,
            bounds: BTreeMap::new(),
        })
    }
}

/// Invalid production effect implementation registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectImplementationRegistryError {
    /// A contract belongs to another adapter or omits required evidence.
    InvalidContract {
        /// Registry adapter.
        adapter: FaultAdapter,
        /// Invalid effect contract.
        effect: EffectKind,
    },
    /// The same effect appears more than once.
    Duplicate(EffectKind),
    /// A closed effect kind has no production implementation contract.
    Missing(EffectKind),
}

impl fmt::Display for EffectImplementationRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid production effect implementation registry: {self:?}"
        )
    }
}

impl Error for EffectImplementationRegistryError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract(effect: EffectKind) -> EffectImplementationContract {
        EffectImplementationContract {
            effect,
            executor: "production::apply",
            mutation_evidence: &["state_digest"],
            observation_evidence: &["effect_applied"],
            checkpoint_evidence: "adapter checkpoint",
            recomputed_replay_evidence: "recomputed result digest",
            locked_replay_evidence: "precondition and result digest",
            search_evidence: "fixed effect parameters",
            conformance_test: "production::tests::applies_effect",
        }
    }

    #[test]
    fn manifest_contains_only_implemented_contracts() {
        let registry = EffectImplementationRegistry::new(
            FaultAdapter::Network,
            [contract(EffectKind::NetworkAvailability)],
        )
        .unwrap_or_else(|error| panic!("test registry must be valid: {error}"));
        let manifest = registry
            .capability_manifest("network-production")
            .unwrap_or_else(|error| panic!("test manifest must be valid: {error}"));
        let availability =
            FaultCapabilityId::parse(EffectKind::NetworkAvailability.descriptor().capability)
                .unwrap_or_else(|error| panic!("test capability must be valid: {error}"));
        let mtu = FaultCapabilityId::parse(EffectKind::NetworkMtu.descriptor().capability)
            .unwrap_or_else(|error| panic!("test capability must be valid: {error}"));
        assert!(manifest.capabilities.contains(&availability));
        assert!(!manifest.capabilities.contains(&mtu));
        assert_eq!(
            registry.require_complete(),
            Err(EffectImplementationRegistryError::Missing(
                EffectKind::NetworkFlap
            ))
        );
    }

    #[test]
    fn rejects_cross_adapter_and_incomplete_contracts() {
        assert!(
            EffectImplementationRegistry::new(
                FaultAdapter::Storage,
                [contract(EffectKind::NetworkAvailability)]
            )
            .is_err()
        );
        let mut incomplete = contract(EffectKind::NetworkAvailability);
        incomplete.conformance_test = "";
        assert!(EffectImplementationRegistry::new(FaultAdapter::Network, [incomplete]).is_err());
    }

    #[test]
    fn host_manifest_slots_reject_swapped_adapter_registries() {
        let network = EffectImplementationRegistry::new(
            FaultAdapter::Network,
            [contract(EffectKind::NetworkAvailability)],
        )
        .unwrap_or_else(|error| panic!("test network registry must be valid: {error}"));
        let storage = EffectImplementationRegistry::new(
            FaultAdapter::Storage,
            [contract(EffectKind::StorageAvailability)],
        )
        .unwrap_or_else(|error| panic!("test storage registry must be valid: {error}"));

        assert!(matches!(
            HostFaultAdapterManifests::from_registries(&storage, &network),
            Err(HostFaultAdapterManifestError::AdapterMismatch {
                expected: FaultAdapter::Network,
                actual: FaultAdapter::Storage,
            })
        ));
    }
}
