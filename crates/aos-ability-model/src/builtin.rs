//! Portable contracts for native abilities supplied by the AOS platform.
//!
//! These constructors are the single source of truth for interfaces whose
//! terminal adapters are compiled into AOS. Package producers and native
//! adapters compare their documents against these exact contracts.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use anyhow::Result;

use crate::{
    ArtifactReference, HandlerDescriptor, ImplementationKind, IndeterminateSemantics,
    InterfaceDescriptor, InterfaceDocument, InterfaceKey, InterfaceName, LifecycleSemantics,
    LocalKey, MethodDescriptor, OperationFamily, OutcomeSemantics, OutputDescriptor,
    ProviderImplementation, ResourceLifetime, ServiceAction, StringSyntax, ValuePhase, ValueSchema,
    ValueVisibility, VersionedDocument,
};

/// Names the native systemd manager interface.
pub const SYSTEMD_MANAGER_INTERFACE_NAME: &str = "aos.systemd-manager";

/// Names the terminal handler catalog entry for the native systemd adapter.
pub const SYSTEMD_MANAGER_HANDLER_KEY: &str = "native-systemd-manager-v1";

/// Names the terminal handler entry point retained in package metadata.
pub const SYSTEMD_MANAGER_HANDLER_ENTRY_POINT: &str = "libexec/aos-systemd-manager-handler-v1";

/// Carries the exact durable evidence schema emitted by the systemd adapter.
pub const SYSTEMD_OBSERVATION_SCHEMA: &str = "aos.ability.systemd-observation/v1";

const SYSTEMD_UNIT_MAX_BYTES: u64 = 256;
const SYSTEMD_IDENTITY_MAX_BYTES: u64 = 1_024;
const SYSTEMD_STATE_MAX_BYTES: u64 = 128;
const SYSTEMD_JOB_PATH_MAX_BYTES: u64 = 4_096;

/// Builds the exact public interface implemented by the native systemd manager.
///
/// All methods accept a closed unit record and return an observed active-state
/// port. Lifecycle methods use `observe` to reconcile an indeterminate effect;
/// active state alone does not prove that a reload or restart occurred.
///
/// # Errors
///
/// Returns an error only if a built-in identifier violates the identity grammar.
pub fn systemd_manager_interface() -> Result<InterfaceDocument> {
    let interface_name = InterfaceName::new(SYSTEMD_MANAGER_INTERFACE_NAME)?;
    let active_output = OutputDescriptor {
        schema: ValueSchema::Boolean,
        phase: ValuePhase::Observation,
        visibility: ValueVisibility::Protected,
        lifetime: ResourceLifetime::Attempt,
    };
    let methods = [
        ("observe", OperationFamily::ObserveReadiness),
        (
            "reload",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Reload,
            },
        ),
        (
            "restart",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Restart,
            },
        ),
        (
            "start",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Start,
            },
        ),
        (
            "stop",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Stop,
            },
        ),
    ]
    .into_iter()
    .map(|(name, family)| {
        let method = LocalKey::new(name)?;
        let descriptor = MethodDescriptor {
            operation_family: family,
            parameters: systemd_unit_schema()?,
            target_resource: interface_name.clone(),
            outputs: BTreeMap::from([(LocalKey::new("active")?, active_output.clone())]),
            permitted_operations: vec![method.clone()],
            guarantees: Vec::new(),
            outcome: OutcomeSemantics {
                completion_evidence: systemd_observation_schema()?,
                observation_evidence: systemd_observation_schema()?,
                supports_rejected_before_effect: true,
                indeterminate: IndeterminateSemantics::Reconcile,
            },
        };
        Ok((method, descriptor))
    })
    .collect::<Result<BTreeMap<_, _>>>()?;

    Ok(InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            name: interface_name,
            abi: NonZeroU32::new(1).ok_or_else(|| anyhow::anyhow!("invalid built-in ABI"))?,
            request: systemd_unit_schema()?,
            outputs: BTreeMap::new(),
            methods,
            lifecycle: LifecycleSemantics {
                stable_resource_identity: true,
                releases_ephemeral_on_disable: false,
                retains_persistent_by_default: true,
                persistent_delete_method: None,
            },
            guarantees: Vec::new(),
        },
    })
}

/// Computes the canonical identity of the native systemd manager interface.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn systemd_manager_interface_key() -> Result<InterfaceKey> {
    Ok(systemd_manager_interface()?.interface_key()?)
}

/// Returns the exact terminal handler key used by the native systemd adapter.
///
/// # Errors
///
/// Returns an error only if the built-in key violates the identity grammar.
pub fn systemd_manager_handler_key() -> Result<LocalKey> {
    Ok(LocalKey::new(SYSTEMD_MANAGER_HANDLER_KEY)?)
}

/// Builds the exact terminal systemd handler contract for an artifact.
///
/// # Errors
///
/// Returns an error only if a built-in schema identifier violates the identity grammar.
pub fn systemd_manager_handler(artifact: ArtifactReference) -> Result<HandlerDescriptor> {
    Ok(HandlerDescriptor {
        artifact,
        entry_point: SYSTEMD_MANAGER_HANDLER_ENTRY_POINT.to_string(),
        arguments: systemd_unit_schema()?,
        result: systemd_observation_schema()?,
    })
}

/// Builds the exact terminal provider implementation for an artifact.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn systemd_manager_provider(artifact: ArtifactReference) -> Result<ProviderImplementation> {
    let interface = systemd_manager_interface_key()?;

    Ok(ProviderImplementation {
        interface: interface.clone(),
        artifact,
        requirements: Vec::new(),
        implementation: ImplementationKind::TerminalHandler {
            handler: systemd_manager_handler_key()?,
        },
        owns_resource_kinds: vec![interface.name],
    })
}

fn systemd_unit_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([(
            LocalKey::new("unit")?,
            bounded_string(SYSTEMD_UNIT_MAX_BYTES),
        )]),
        optional_fields: Vec::new(),
    })
}

fn systemd_observation_schema() -> Result<ValueSchema> {
    let optional_string = |maximum| ValueSchema::Optional {
        value: Box::new(bounded_string(maximum)),
    };

    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("active")?,
                ValueSchema::Optional {
                    value: Box::new(ValueSchema::Boolean),
                },
            ),
            (
                LocalKey::new("job_path")?,
                optional_string(SYSTEMD_JOB_PATH_MAX_BYTES),
            ),
            (
                LocalKey::new("job_result")?,
                optional_string(SYSTEMD_STATE_MAX_BYTES),
            ),
            (
                LocalKey::new("manager_bus_id")?,
                optional_string(SYSTEMD_IDENTITY_MAX_BYTES),
            ),
            (
                LocalKey::new("manager_owner")?,
                optional_string(SYSTEMD_IDENTITY_MAX_BYTES),
            ),
            (
                LocalKey::new("schema")?,
                ValueSchema::StringEnum {
                    values: vec![SYSTEMD_OBSERVATION_SCHEMA.to_string()],
                },
            ),
            (
                LocalKey::new("state")?,
                bounded_string(SYSTEMD_STATE_MAX_BYTES),
            ),
            (
                LocalKey::new("unit")?,
                bounded_string(SYSTEMD_UNIT_MAX_BYTES),
            ),
            (
                LocalKey::new("unit_identity")?,
                optional_string(SYSTEMD_IDENTITY_MAX_BYTES),
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

const fn bounded_string(max_length: u64) -> ValueSchema {
    ValueSchema::String {
        max_length,
        syntax: None::<StringSyntax>,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use aos_contract::Sha256Digest;

    use super::*;

    #[test]
    fn systemd_manager_contract_has_stable_identity_and_valid_methods() {
        let document = systemd_manager_interface().expect("built-in contract must construct");
        let key = document
            .interface_key()
            .expect("built-in contract must have an identity");

        crate::InterfaceName::new(SYSTEMD_MANAGER_INTERFACE_NAME)
            .expect("built-in interface name must remain valid");
        assert_eq!(document.interface.methods.len(), 5);
        assert!(document.interface.methods.contains_key("observe"));
        assert_eq!(key, systemd_manager_interface_key().unwrap());
        assert_eq!(
            key.descriptor,
            Sha256Digest::parse(
                "sha256:d7dcc31e3da49efad1ff728d86b107d0d2b33f558238d60e7babf65700f32004"
            )
            .unwrap()
        );
        assert!(
            crate::decode_canonical::<InterfaceDocument>(
                &crate::encode_canonical(&document).unwrap(),
                crate::ABILITY_LIMITS_V1,
                &BTreeSet::new(),
            )
            .is_ok()
        );
    }
}
