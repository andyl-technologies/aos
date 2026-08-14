//! Implementation registries for host-owned production fault adapters.
//!
//! The closed model vocabulary is intentionally broader than any individual
//! executor. These explicit lists are owned beside the network and storage
//! mutation seams; production capability manifests are derived from them, and
//! each action is checked against the same registry immediately before use.

use crucible::model::{
    EffectImplementationContract, EffectImplementationRegistry, EffectImplementationRegistryError,
    EffectKind, FaultAdapter,
};

const NETWORK_EFFECTS: &[EffectKind] = &[
    EffectKind::NetworkAvailability,
    EffectKind::NetworkFlap,
    EffectKind::NetworkNegotiatedMode,
    EffectKind::NetworkProfileDelta,
    EffectKind::NetworkPropagationDelay,
    EffectKind::NetworkAccessDelay,
    EffectKind::NetworkJitter,
    EffectKind::NetworkServiceCurve,
    EffectKind::NetworkTokenBucket,
    EffectKind::NetworkQueuePolicy,
    EffectKind::NetworkFrameLoss,
    EffectKind::NetworkBurstErrorState,
    EffectKind::NetworkDuplicate,
    EffectKind::NetworkReorder,
    EffectKind::NetworkPayloadTransform,
    EffectKind::NetworkDetectedFrameError,
    EffectKind::NetworkMtu,
    EffectKind::NetworkPauseBackpressure,
    EffectKind::NetworkRecipientSubset,
    EffectKind::NetworkForwarderLifecycle,
    EffectKind::NetworkForwardingMutation,
    EffectKind::NetworkRouteTransition,
    EffectKind::NetworkControlPlaneService,
    EffectKind::NetworkFirewallDisposition,
    EffectKind::NetworkConnectionState,
    EffectKind::NetworkSharedMedium,
    EffectKind::NetworkRfChannel,
    EffectKind::NetworkAssociation,
    EffectKind::NetworkControlResultTransform,
    EffectKind::NetworkContact,
    EffectKind::NetworkCustodyQueue,
];

const STORAGE_EFFECTS: &[EffectKind] = &[
    EffectKind::StorageAvailability,
    EffectKind::StorageReportedCapacity,
    EffectKind::StorageLatency,
    EffectKind::StorageService,
    EffectKind::StorageOperationFailure,
    EffectKind::StorageStallTimeout,
    EffectKind::StorageCompletionReorder,
    EffectKind::StorageDuplicateCompletion,
    EffectKind::StorageReadTransform,
    EffectKind::StorageWriteDisposition,
    EffectKind::StoragePersistenceOrder,
    EffectKind::StorageVolatileCache,
    EffectKind::StorageVolatileCacheLoss,
    EffectKind::StorageFlushDisposition,
    EffectKind::StorageMediaRange,
    EffectKind::StorageFlashState,
    EffectKind::StorageControllerLifecycle,
    EffectKind::StorageArrayState,
    EffectKind::NinePResult,
    EffectKind::NinePVisibility,
];

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

fn contract(
    effect: EffectKind,
    executor: &'static str,
    mutation_evidence: &'static [&'static str],
    checkpoint_evidence: &'static str,
    conformance_test: &'static str,
) -> EffectImplementationContract {
    EffectImplementationContract {
        effect,
        executor,
        mutation_evidence,
        observation_evidence: effect.descriptor().replay_evidence,
        checkpoint_evidence,
        recomputed_replay_evidence: "ResolvedEffectRecord::matches_recomputed_action and backend evidence digest",
        locked_replay_evidence: "ResolvedBindingAction::expected_precondition and backend result digest",
        search_evidence: "canonical keyed choices recorded in SearchFrontierChoices",
        conformance_test,
    }
}

/// Returns the complete implementation registry for the production network adapter.
///
/// # Errors
///
/// Returns [`EffectImplementationRegistryError`] if an entry is malformed,
/// duplicated, or missing from the closed network vocabulary.
pub(super) fn network_effect_implementation_registry()
-> Result<EffectImplementationRegistry, EffectImplementationRegistryError> {
    let registry = EffectImplementationRegistry::new(
        FaultAdapter::Network,
        NETWORK_EFFECTS.iter().copied().map(|effect| {
            contract(
                effect,
                network_executor(effect),
                NETWORK_MUTATION_EVIDENCE,
                "ProductionNetworkStateCheckpoint",
                "cargo test -p crucible-api --lib vm_lifecycle::network_faults",
            )
        }),
    )?;
    registry.require_complete()?;
    Ok(registry)
}

/// Returns the complete implementation registry for block, array, flash, and 9p adapters.
///
/// # Errors
///
/// Returns [`EffectImplementationRegistryError`] if an entry is malformed,
/// duplicated, or missing from the closed storage vocabulary.
pub(super) fn storage_effect_implementation_registry()
-> Result<EffectImplementationRegistry, EffectImplementationRegistryError> {
    let registry = EffectImplementationRegistry::new(
        FaultAdapter::Storage,
        STORAGE_EFFECTS.iter().copied().map(|effect| {
            contract(
                effect,
                storage_executor(effect),
                STORAGE_MUTATION_EVIDENCE,
                "ProductionFaultRuntimeCheckpoint and live device state checkpoints",
                "cargo test -p crucible-api --lib vm_lifecycle::storage_faults; cargo test -p crucible-qemu --lib storage_fault_resolver",
            )
        }),
    )?;
    registry.require_complete()?;
    Ok(registry)
}

/// Rechecks network actions at the production mutation seam.
pub(super) fn require_network_actions_implemented<'a>(
    actions: impl IntoIterator<Item = &'a crucible::model::ResolvedBindingAction>,
) -> Result<(), EffectImplementationRegistryError> {
    let registry = network_effect_implementation_registry()?;
    for action in actions {
        registry.require_implemented(action.effect.kind())?;
    }
    Ok(())
}

/// Rechecks storage and 9p actions at the production mutation seam.
pub(super) fn require_storage_actions_implemented<'a>(
    actions: impl IntoIterator<Item = &'a crucible::model::ResolvedBindingAction>,
) -> Result<(), EffectImplementationRegistryError> {
    let registry = storage_effect_implementation_registry()?;
    for action in actions {
        registry.require_implemented(action.effect.kind())?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn test_host_manifests() -> crucible::model::HostFaultAdapterManifests {
    let network = network_effect_implementation_registry()
        .unwrap_or_else(|error| panic!("test network registry must be valid: {error}"));
    let storage = storage_effect_implementation_registry()
        .unwrap_or_else(|error| panic!("test storage registry must be valid: {error}"));
    crucible::model::HostFaultAdapterManifests::from_registries(&network, &storage)
        .unwrap_or_else(|error| panic!("test host manifests must be valid: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implementation_registries_exhaustively_partition_host_effects() {
        let network = network_effect_implementation_registry()
            .unwrap_or_else(|error| panic!("network registry must be complete: {error}"));
        let storage = storage_effect_implementation_registry()
            .unwrap_or_else(|error| panic!("storage registry must be complete: {error}"));

        assert_eq!(network.contracts().len(), 31);
        assert_eq!(storage.contracts().len(), 20);
        for effect in EffectKind::all() {
            match effect.descriptor().adapter {
                FaultAdapter::Network => assert!(network.get(*effect).is_some(), "{effect}"),
                FaultAdapter::Storage => assert!(storage.get(*effect).is_some(), "{effect}"),
                FaultAdapter::Node => {
                    assert!(network.get(*effect).is_none(), "{effect}");
                    assert!(storage.get(*effect).is_none(), "{effect}");
                }
            }
        }
    }
}
