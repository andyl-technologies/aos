//! Manager-neutral service lifecycle and feature contracts.
//!
//! The service-management interface describes the lifecycle semantics consumed
//! by package providers. Concrete service managers remain separate provider
//! implementations and may satisfy the feature guarantees directly or through
//! recursive composition.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use anyhow::Result;

use crate::{
    AccessMode, GuaranteeKey, IndeterminateSemantics, InterfaceDescriptor, InterfaceDocument,
    InterfaceKey, InterfaceName, LifecycleSemantics, LocalKey, MethodDescriptor, MethodSemantics,
    OutcomeSemantics, ValueSchema, VersionedDocument,
};

/// Names the manager-neutral service lifecycle interface.
pub const SERVICE_MANAGEMENT_INTERFACE_NAME: &str = "aos.service-management";

/// Names the guarantee for continuous service supervision.
pub const SERVICE_SUPERVISION_GUARANTEE_NAME: &str = "aos.service.feature.supervision";

/// Names the guarantee for durable inter-service relationships.
pub const SERVICE_DEPENDENCIES_GUARANTEE_NAME: &str = "aos.service.feature.dependencies";

/// Names the guarantee for attaching opaque credentials before service start.
pub const SERVICE_CREDENTIALS_GUARANTEE_NAME: &str = "aos.service.feature.credentials";

/// Names the guarantee for publishing configuration before lifecycle effects.
pub const SERVICE_CONFIGURATION_GUARANTEE_NAME: &str = "aos.service.feature.configuration";

/// Names the guarantee for service-specific reload semantics.
pub const SERVICE_RELOAD_GUARANTEE_NAME: &str = "aos.service.feature.reload";

/// Names the guarantee for revision-bound readiness observation.
pub const SERVICE_READINESS_GUARANTEE_NAME: &str = "aos.service.feature.readiness";

/// Names the guarantee for stable runtime identity assignment.
pub const SERVICE_IDENTITY_GUARANTEE_NAME: &str = "aos.service.feature.identity";

/// Names the guarantee for attaching declared service storage.
pub const SERVICE_STORAGE_GUARANTEE_NAME: &str = "aos.service.feature.storage";

/// Names the guarantee for enforcing declared service isolation.
pub const SERVICE_ISOLATION_GUARANTEE_NAME: &str = "aos.service.feature.isolation";

const SERVICE_SUPERVISION_SEMANTICS: &str =
    "the selected controller continuously supervises the exact declared service process";
const SERVICE_DEPENDENCIES_SEMANTICS: &str = "the selected controller maintains declared ordering, readiness, conflict, and propagation relationships";
const SERVICE_CREDENTIALS_SEMANTICS: &str =
    "the selected controller attaches only bound opaque credential views before service execution";
const SERVICE_CONFIGURATION_SEMANTICS: &str =
    "the selected controller publishes the bound configuration revision before service convergence";
const SERVICE_RELOAD_SEMANTICS: &str =
    "the selected controller invokes and observes the service's declared reload protocol";
const SERVICE_READINESS_SEMANTICS: &str =
    "the selected controller observes readiness for the exact desired service revision";
const SERVICE_IDENTITY_SEMANTICS: &str =
    "the selected controller runs the service under its declared stable runtime identity";
const SERVICE_STORAGE_SEMANTICS: &str =
    "the selected controller attaches only bound storage views with their declared lifetimes";
const SERVICE_ISOLATION_SEMANTICS: &str =
    "the selected controller enforces every isolation property required by the service contract";

/// Builds every service feature guarantee in canonical name order.
///
/// # Errors
///
/// Returns an error only if a built-in guarantee name or version is invalid.
pub fn service_feature_guarantees() -> Result<Vec<GuaranteeKey>> {
    [
        (
            SERVICE_CONFIGURATION_GUARANTEE_NAME,
            SERVICE_CONFIGURATION_SEMANTICS,
        ),
        (
            SERVICE_CREDENTIALS_GUARANTEE_NAME,
            SERVICE_CREDENTIALS_SEMANTICS,
        ),
        (
            SERVICE_DEPENDENCIES_GUARANTEE_NAME,
            SERVICE_DEPENDENCIES_SEMANTICS,
        ),
        (SERVICE_IDENTITY_GUARANTEE_NAME, SERVICE_IDENTITY_SEMANTICS),
        (
            SERVICE_ISOLATION_GUARANTEE_NAME,
            SERVICE_ISOLATION_SEMANTICS,
        ),
        (
            SERVICE_READINESS_GUARANTEE_NAME,
            SERVICE_READINESS_SEMANTICS,
        ),
        (SERVICE_RELOAD_GUARANTEE_NAME, SERVICE_RELOAD_SEMANTICS),
        (SERVICE_STORAGE_GUARANTEE_NAME, SERVICE_STORAGE_SEMANTICS),
        (
            SERVICE_SUPERVISION_GUARANTEE_NAME,
            SERVICE_SUPERVISION_SEMANTICS,
        ),
    ]
    .into_iter()
    .map(|(name, semantics)| service_feature_guarantee(name, semantics))
    .collect()
}

/// Builds the manager-neutral service lifecycle interface.
///
/// Packages request only the methods and feature guarantees they need. A
/// concrete provider may implement the complete contract directly or compose
/// the requested features through lower providers.
///
/// # Errors
///
/// Returns an error only if a built-in identifier violates the identity grammar.
pub fn service_management_interface() -> Result<InterfaceDocument> {
    let interface_name = InterfaceName::new(SERVICE_MANAGEMENT_INTERFACE_NAME)?;
    let methods = [
        ("observe", MethodSemantics::ordinary(AccessMode::Read)),
        (
            "reload",
            MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        ),
        (
            "restart",
            MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        ),
        (
            "start",
            MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        ),
        ("stop", MethodSemantics::provider_stop()),
    ]
    .into_iter()
    .map(|(name, semantics)| {
        let method = LocalKey::new(name)?;
        Ok((
            method.clone(),
            MethodDescriptor {
                description: "Describes this declaration.".to_string(),
                semantics,
                parameters: ValueSchema::Boolean,
                target_resource: interface_name.clone(),
                outputs: BTreeMap::new(),
                permitted_operations: vec![method],
                guarantees: Vec::new(),
                outcome: OutcomeSemantics {
                    completion_evidence: ValueSchema::Boolean,
                    observation_evidence: ValueSchema::Boolean,
                    supports_rejected_before_effect: true,
                    indeterminate: IndeterminateSemantics::Reconcile,
                },
            },
        ))
    })
    .collect::<Result<BTreeMap<_, _>>>()?;

    Ok(InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            description: "Describes this declaration.".to_string(),
            name: interface_name,
            abi: NonZeroU32::new(1).ok_or_else(|| anyhow::anyhow!("invalid built-in ABI"))?,
            request: ValueSchema::Boolean,
            configuration: None,
            outputs: BTreeMap::new(),
            methods,
            lifecycle: LifecycleSemantics {
                stable_resource_identity: true,
                releases_ephemeral_on_disable: true,
                retains_persistent_by_default: false,
                persistent_delete_method: None,
            },
            aggregation: super::aggregation("service-management")?,
            guarantees: service_feature_guarantees()?,
        },
    })
}

/// Computes the canonical identity of the service-management interface.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn service_management_interface_key() -> Result<InterfaceKey> {
    Ok(service_management_interface()?.interface_key()?)
}

fn service_feature_guarantee(name: &str, semantics: &str) -> Result<GuaranteeKey> {
    super::execution_guarantee(name, semantics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_management_contract_is_canonical_and_feature_composable() {
        let document = service_management_interface().expect("built-in contract must construct");
        let key = document
            .interface_key()
            .expect("built-in contract must hash");

        assert_eq!(
            key,
            document.interface_key().expect("stable interface identity")
        );
        assert_eq!(document.interface.methods.len(), 5);
        assert_eq!(document.interface.guarantees.len(), 9);
        assert!(
            document
                .interface
                .methods
                .values()
                .all(|method| method.outcome.indeterminate == IndeterminateSemantics::Reconcile)
        );
        assert!(!document.interface.lifecycle.retains_persistent_by_default);
        assert_eq!(
            document.interface.methods["restart"].semantics,
            MethodSemantics::ordinary(AccessMode::ExclusiveWrite)
        );
        assert!(document.interface.methods["observe"].outputs.is_empty());
        assert_eq!(
            document.interface.methods["observe"].parameters,
            ValueSchema::Boolean
        );
        assert_eq!(
            document.interface.methods["observe"]
                .outcome
                .completion_evidence,
            ValueSchema::Boolean
        );
        assert_eq!(
            document.interface.methods["observe"]
                .outcome
                .observation_evidence,
            ValueSchema::Boolean
        );
    }
}
