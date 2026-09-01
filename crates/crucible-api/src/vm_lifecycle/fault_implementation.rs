//! Implementation registries for host-owned production fault adapters.
//!
//! The canonical contracts live beside the closed model vocabulary in
//! `crucible`. This API module uses those exact registries both to advertise
//! capabilities and to recheck actions at the production mutation seams.

use crucible::model::{EffectImplementationRegistry, EffectImplementationRegistryError};
#[cfg(test)]
use crucible::model::{EffectKind, FaultAdapter};

/// Returns the complete implementation registry for the production network adapter.
///
/// # Errors
///
/// Returns [`EffectImplementationRegistryError`] if a contract is malformed,
/// duplicated, or missing from the closed network vocabulary.
pub fn network_effect_implementation_registry()
-> Result<EffectImplementationRegistry, EffectImplementationRegistryError> {
    crucible::model::production_network_effect_implementation_registry()
}

/// Returns the complete implementation registry for block, array, flash, and 9p adapters.
///
/// # Errors
///
/// Returns [`EffectImplementationRegistryError`] if a contract is malformed,
/// duplicated, or missing from the closed storage vocabulary.
pub fn storage_effect_implementation_registry()
-> Result<EffectImplementationRegistry, EffectImplementationRegistryError> {
    crucible::model::production_storage_effect_implementation_registry()
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
    crucible::model::production_host_fault_adapter_manifests()
        .unwrap_or_else(|error| panic!("production host manifests must be valid: {error}"))
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
