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

mod production_effects;
use production_effects::{PRODUCTION_NETWORK_EFFECTS, PRODUCTION_STORAGE_EFFECTS};

/// Production proof binding for one advertised effect kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionConformanceEvidence {
    /// Stable per-effect case identity; this must equal the canonical effect key.
    pub case_id: &'static str,
    /// Cargo or Nix harness that executes the production mutation path.
    pub harness: &'static str,
    /// Live production gate that admits the backing runtime capability.
    pub live_gate: &'static str,
    /// Concrete post-application state inspected by the harness.
    pub observed_state: &'static [&'static str],
}

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
    pub production_conformance: ProductionConformanceEvidence,
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
            && self.production_conformance.case_id == self.effect.as_str()
            && !self.production_conformance.harness.is_empty()
            && !self.production_conformance.live_gate.is_empty()
            && !self.production_conformance.observed_state.is_empty()
            && self
                .production_conformance
                .observed_state
                .iter()
                .all(|value| !value.is_empty());
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

const NETWORK_MUTATION_EVIDENCE: &[&str] = &[
    "NetworkEffectRuntimeState",
    "NetworkBoundaryApplication",
    "BackendNetworkOutput::fault_continuation",
];
const STORAGE_MUTATION_EVIDENCE: &[&str] = &[
    "QemuLiveBlockIoServicer::storage_fault_state",
    "ResolvedBlockExecutionDirective",
    "ResolvedNinepRequestDirective",
];
/// Returns the complete implementation registry for the production network adapter.
///
/// The registry lives with the closed effect vocabulary so every production
/// consumer - including the QEMU lifecycle gate and the API runtime - derives
/// its capability manifest from one set of implementation contracts.
///
/// # Errors
///
/// Returns [`EffectImplementationRegistryError`] if a contract is malformed,
/// duplicated, or missing from the closed network vocabulary.
pub fn production_network_effect_implementation_registry()
-> Result<EffectImplementationRegistry, EffectImplementationRegistryError> {
    production_effect_registry(FaultAdapter::Network)
}

/// Returns the complete implementation registry for production storage and 9p adapters.
///
/// # Errors
///
/// Returns [`EffectImplementationRegistryError`] if a contract is malformed,
/// duplicated, or missing from the closed storage vocabulary.
pub fn production_storage_effect_implementation_registry()
-> Result<EffectImplementationRegistry, EffectImplementationRegistryError> {
    production_effect_registry(FaultAdapter::Storage)
}

/// Derives the host manifests admitted by every production runtime.
///
/// # Errors
///
/// Returns [`HostFaultAdapterManifestError`] if either implementation registry
/// is incomplete or cannot produce its exact capability manifest.
pub fn production_host_fault_adapter_manifests()
-> Result<HostFaultAdapterManifests, HostFaultAdapterManifestError> {
    let network = production_network_effect_implementation_registry()
        .map_err(HostFaultAdapterManifestError::Registry)?;
    let storage = production_storage_effect_implementation_registry()
        .map_err(HostFaultAdapterManifestError::Registry)?;
    HostFaultAdapterManifests::from_registries(&network, &storage)
}

fn production_effect_registry(
    adapter: FaultAdapter,
) -> Result<EffectImplementationRegistry, EffectImplementationRegistryError> {
    let effects = match adapter {
        FaultAdapter::Network => PRODUCTION_NETWORK_EFFECTS,
        FaultAdapter::Storage => PRODUCTION_STORAGE_EFFECTS,
        FaultAdapter::Node => &[],
    };
    let registry = EffectImplementationRegistry::new(
        adapter,
        effects.iter().copied().map(production_contract),
    )?;
    registry.require_complete()?;
    Ok(registry)
}

fn production_contract(effect: EffectKind) -> EffectImplementationContract {
    let (executor, mutation_evidence, checkpoint_evidence, production_conformance) =
        match effect.descriptor().adapter {
            FaultAdapter::Network => (
                network_executor(effect),
                NETWORK_MUTATION_EVIDENCE,
                "ProductionNetworkStateCheckpoint",
                network_conformance(effect),
            ),
            FaultAdapter::Storage => (
                storage_executor(effect),
                STORAGE_MUTATION_EVIDENCE,
                "ProductionFaultRuntimeCheckpoint and live device state checkpoints",
                storage_conformance(effect),
            ),
            FaultAdapter::Node => (
                "QemuNodeSet::apply_fault_action",
                &["QemuFaultResultV1", "QemuFaultEventV1"] as &'static [&'static str],
                "QemuNodeContinuationCheckpoint",
                ProductionConformanceEvidence {
                    case_id: effect.as_str(),
                    harness: "crucible-qemu::fault_implementation",
                    live_gate: "gate:live-node-lifecycle-fault",
                    observed_state: &["QemuFaultResultV1", "QemuFaultEventV1"],
                },
            ),
        };
    EffectImplementationContract {
        effect,
        executor,
        mutation_evidence,
        observation_evidence: effect.descriptor().replay_evidence,
        checkpoint_evidence,
        recomputed_replay_evidence: "ResolvedEffectRecord::matches_recomputed_action and backend evidence digest",
        locked_replay_evidence: "ResolvedBindingAction::expected_precondition and backend result digest",
        search_evidence: "canonical keyed choices recorded in SearchFrontierChoices",
        production_conformance,
    }
}

fn network_executor(effect: EffectKind) -> &'static str {
    match effect {
        EffectKind::NetworkFlap
        | EffectKind::NetworkNegotiatedMode
        | EffectKind::NetworkForwarderLifecycle
        | EffectKind::NetworkRouteTransition
        | EffectKind::NetworkControlPlaneService
        | EffectKind::NetworkAssociation
        | EffectKind::NetworkContact => "NetworkBoundaryState::apply_actions",
        EffectKind::NetworkAvailability => {
            "ProductionFaultNetworkInterceptor::stage_availability_transition_drops"
        }
        EffectKind::NetworkPauseBackpressure => "route::apply_network_backpressure_transitions",
        EffectKind::NetworkCustodyQueue => "route::apply_network_custody_removals",
        EffectKind::NetworkControlResultTransform => "apply_network_control_transforms",
        _ => "network_faults::route::apply_network_frame_actions",
    }
}

fn storage_executor(effect: EffectKind) -> &'static str {
    match effect {
        EffectKind::StorageVolatileCacheLoss => "resolve_volatile_cache_loss",
        EffectKind::StorageControllerLifecycle => "resolve_block_controller_transition",
        EffectKind::StorageArrayState => "resolve_storage_array_policy",
        EffectKind::StorageFlashState | EffectKind::StorageMediaRange => {
            "resolve_block_persistence_media_directive"
        }
        EffectKind::NinePResult | EffectKind::NinePVisibility => {
            "ProductionNinepFaultCoordinator::evaluate_phase"
        }
        _ => "resolve_block_fault_directive",
    }
}

fn network_conformance(effect: EffectKind) -> ProductionConformanceEvidence {
    let harness = match effect {
        EffectKind::NetworkFlap
        | EffectKind::NetworkNegotiatedMode
        | EffectKind::NetworkForwarderLifecycle
        | EffectKind::NetworkRouteTransition
        | EffectKind::NetworkControlPlaneService
        | EffectKind::NetworkAssociation
        | EffectKind::NetworkContact => {
            "crucible-api::vm_lifecycle::network_faults::boundary::tests"
        }
        EffectKind::NetworkAvailability => {
            "crucible-api::vm_lifecycle::network_faults::tests::availability_transition"
        }
        EffectKind::NetworkPauseBackpressure => {
            "crucible-api::vm_lifecycle::network_faults::route_tests::backpressure"
        }
        EffectKind::NetworkCustodyQueue => {
            "crucible-api::vm_lifecycle::network_faults::route_tests::custody"
        }
        EffectKind::NetworkControlResultTransform => {
            "crucible-api::vm_lifecycle::network_faults::tests::control_result_transform"
        }
        EffectKind::NetworkServiceCurve
        | EffectKind::NetworkTokenBucket
        | EffectKind::NetworkQueuePolicy
        | EffectKind::NetworkBurstErrorState
        | EffectKind::NetworkDetectedFrameError
        | EffectKind::NetworkMtu
        | EffectKind::NetworkForwardingMutation
        | EffectKind::NetworkFirewallDisposition
        | EffectKind::NetworkConnectionState
        | EffectKind::NetworkSharedMedium
        | EffectKind::NetworkRfChannel => "crucible-api::vm_lifecycle::network_faults::route_tests",
        _ => {
            "crucible-api::vm_lifecycle::network_faults::route_tests::frame_effects::frame_effect_variants_mutate_production_frame_outcomes"
        }
    };
    ProductionConformanceEvidence {
        case_id: effect.as_str(),
        harness,
        live_gate: "gate:live-network-io",
        observed_state: NETWORK_MUTATION_EVIDENCE,
    }
}

fn storage_conformance(effect: EffectKind) -> ProductionConformanceEvidence {
    let (harness, live_gate, observed_state) = match effect {
        EffectKind::NinePResult | EffectKind::NinePVisibility => (
            "crucible-api::vm_lifecycle::storage_faults and crucible-qemu::supervision::ninep_io_servicer_tests",
            "gate:live-9p-io",
            &["ResolvedNinepRequestDirective", "NinepFaultState"] as &'static [&'static str],
        ),
        EffectKind::StorageVolatileCacheLoss
        | EffectKind::StorageControllerLifecycle
        | EffectKind::StorageArrayState
        | EffectKind::StorageFlashState
        | EffectKind::StorageMediaRange => (
            "crucible-qemu::storage_fault_resolver and crucible-device::block fault tests",
            "gate:live-block-io",
            &["BlockFaultState", "BlockDeviceCheckpoint"] as &'static [&'static str],
        ),
        _ => (
            "crucible-qemu::storage_fault_resolver and crucible-qemu::supervision::block_io_servicer_tests",
            "gate:live-block-io",
            STORAGE_MUTATION_EVIDENCE,
        ),
    };
    ProductionConformanceEvidence {
        case_id: effect.as_str(),
        harness,
        live_gate,
        observed_state,
    }
}

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
            production_conformance: ProductionConformanceEvidence {
                case_id: effect.as_str(),
                harness: "production::tests::applies_effect",
                live_gate: "gate:production-test",
                observed_state: &["state_digest"],
            },
        }
    }

    #[test]
    fn production_registration_is_explicit_and_vocabulary_growth_fails_closed() {
        assert_eq!(PRODUCTION_NETWORK_EFFECTS.len(), 31);
        assert_eq!(PRODUCTION_STORAGE_EFFECTS.len(), 20);
        assert!(production_effect_registry(FaultAdapter::Network).is_ok());
        assert!(production_effect_registry(FaultAdapter::Storage).is_ok());
        assert_eq!(
            PRODUCTION_NETWORK_EFFECTS
                .iter()
                .chain(PRODUCTION_STORAGE_EFFECTS)
                .copied()
                .collect::<BTreeSet<_>>(),
            EffectKind::all()
                .iter()
                .copied()
                .filter(|effect| effect.descriptor().adapter != FaultAdapter::Node)
                .collect::<BTreeSet<_>>()
        );
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
        incomplete.production_conformance.harness = "";
        assert!(EffectImplementationRegistry::new(FaultAdapter::Network, [incomplete]).is_err());
        let mut mismatched = contract(EffectKind::NetworkAvailability);
        mismatched.production_conformance.case_id = EffectKind::NetworkMtu.as_str();
        assert!(EffectImplementationRegistry::new(FaultAdapter::Network, [mismatched]).is_err());
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
