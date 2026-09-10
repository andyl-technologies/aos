//! Native host network-policy interface, schemas, handler, and provider.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use anyhow::Result;
use aos_contract::Sha256Digest;

use crate::{
    ArtifactReference, GuaranteeKey, HandlerDescriptor, InterfaceDocument, InterfaceKey,
    InterfaceName, LifecycleSemantics, LocalKey, NetworkPolicyAction, OperationFamily,
    OutputDescriptor, ProviderImplementation, ResourceLifetime, ValuePhase, ValueSchema,
    ValueVisibility,
};

use super::common::{
    interface_document, resource_method, revisioned_observation_schema, terminal_provider,
};
use super::endpoint::network_endpoint_value_schema;

/// Names the built-in host network-policy effects interface.
pub const HOST_NETWORK_POLICY_INTERFACE_NAME: &str = "aos.host-network-policy-effects";
/// Names the policy state emitted after application and observation.
pub const HOST_NETWORK_POLICY_ACTIVE_OUTPUT: &str = "active";
/// Names the native host network-policy handler.
pub const HOST_NETWORK_POLICY_HANDLER_KEY: &str = "native-host-network-policy-v1";
/// Names the policy handler executable retained in package metadata.
pub const HOST_NETWORK_POLICY_HANDLER_ENTRY_POINT: &str =
    "libexec/aos-host-network-policy-handler-v1";
/// Carries exact network-policy state and revision evidence.
pub const HOST_NETWORK_POLICY_OBSERVATION_SCHEMA: &str =
    "aos.ability.host-network-policy-observation/v1";
/// Names loopback-only TCP ingress enforcement supplied by the native policy handler.
pub const HOST_NETWORK_POLICY_LOOPBACK_TCP_INGRESS_GUARANTEE_NAME: &str =
    "aos.guarantee.loopback-tcp-ingress-enforcement";
/// Defines the exact v1 loopback-only TCP ingress guarantee semantic.
pub const HOST_NETWORK_POLICY_LOOPBACK_TCP_INGRESS_GUARANTEE_SEMANTICS: &str = "A successful apply installs a host policy that admits TCP ingress only to the requested 127.0.0.1 address and concrete port. A successful observe proves that exact rule remains active. Neither operation admits ingress to that port through a non-loopback address.";
/// Identifies the exact bytes of the v1 loopback-only TCP ingress guarantee semantic.
pub const HOST_NETWORK_POLICY_LOOPBACK_TCP_INGRESS_GUARANTEE_DESCRIPTOR: &str =
    "sha256:6b12b1c4db768f272434c6e43ca8c484887fc0fa3a51be2ae2784982325c2092";

/// Builds the exact public host network-policy interface.
///
/// # Errors
///
/// Returns an error only if a built-in identifier violates the identity grammar.
pub fn host_network_policy_interface() -> Result<InterfaceDocument> {
    let interface_name = InterfaceName::new(HOST_NETWORK_POLICY_INTERFACE_NAME)?;
    let enforcement = host_network_policy_loopback_tcp_ingress_guarantee()?;
    let active_output = OutputDescriptor {
        schema: ValueSchema::Boolean,
        phase: ValuePhase::Runtime,
        visibility: ValueVisibility::Protected,
        lifetime: ResourceLifetime::Instance,
    };
    let methods = [
        guaranteed_policy_method(
            &interface_name,
            "apply",
            OperationFamily::HostNetworkPolicy {
                action: NetworkPolicyAction::Apply,
            },
            host_network_policy_request_schema(true)?,
            host_network_policy_observation_schema()?,
            BTreeMap::from([(
                LocalKey::new(HOST_NETWORK_POLICY_ACTIVE_OUTPUT)?,
                active_output.clone(),
            )]),
            enforcement.clone(),
        )?,
        guaranteed_policy_method(
            &interface_name,
            "observe",
            OperationFamily::HostNetworkPolicy {
                action: NetworkPolicyAction::Observe,
            },
            host_network_policy_request_schema(true)?,
            host_network_policy_observation_schema()?,
            BTreeMap::from([(
                LocalKey::new(HOST_NETWORK_POLICY_ACTIVE_OUTPUT)?,
                active_output,
            )]),
            enforcement.clone(),
        )?,
        resource_method(
            &interface_name,
            "remove",
            OperationFamily::HostNetworkPolicy {
                action: NetworkPolicyAction::Remove,
            },
            host_network_policy_request_schema(false)?,
            host_network_policy_observation_schema()?,
            BTreeMap::new(),
        )?,
    ]
    .into_iter()
    .collect();

    let mut document = interface_document(
        interface_name,
        host_network_policy_request_schema(false)?,
        methods,
        LifecycleSemantics {
            stable_resource_identity: true,
            releases_ephemeral_on_disable: true,
            retains_persistent_by_default: false,
            persistent_delete_method: None,
        },
    )?;
    document.interface.guarantees = vec![enforcement];

    Ok(document)
}

/// Returns the exact loopback-only TCP ingress enforcement guarantee key.
///
/// # Errors
///
/// Returns an error only if the built-in name or descriptor violates its grammar.
pub fn host_network_policy_loopback_tcp_ingress_guarantee() -> Result<GuaranteeKey> {
    Ok(GuaranteeKey {
        name: InterfaceName::new(HOST_NETWORK_POLICY_LOOPBACK_TCP_INGRESS_GUARANTEE_NAME)?,
        version: NonZeroU32::new(1)
            .ok_or_else(|| anyhow::anyhow!("invalid built-in guarantee version"))?,
        descriptor: Sha256Digest::parse(
            HOST_NETWORK_POLICY_LOOPBACK_TCP_INGRESS_GUARANTEE_DESCRIPTOR,
        )?,
    })
}

/// Computes the canonical identity of the host network-policy interface.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn host_network_policy_interface_key() -> Result<InterfaceKey> {
    Ok(host_network_policy_interface()?.interface_key()?)
}

/// Returns the native host network-policy handler key.
///
/// # Errors
///
/// Returns an error only if the built-in key violates the identity grammar.
pub fn host_network_policy_handler_key() -> Result<LocalKey> {
    Ok(LocalKey::new(HOST_NETWORK_POLICY_HANDLER_KEY)?)
}

/// Builds the native host network-policy handler contract for an artifact.
///
/// # Errors
///
/// Returns an error only if a built-in schema identifier violates the identity grammar.
pub fn host_network_policy_handler(artifact: ArtifactReference) -> Result<HandlerDescriptor> {
    Ok(HandlerDescriptor {
        artifact,
        entry_point: HOST_NETWORK_POLICY_HANDLER_ENTRY_POINT.to_string(),
        arguments: host_network_policy_request_schema(false)?,
        result: host_network_policy_observation_schema()?,
    })
}

/// Builds the native host network-policy provider declaration for an artifact.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn host_network_policy_provider(artifact: ArtifactReference) -> Result<ProviderImplementation> {
    terminal_provider(
        host_network_policy_interface_key()?,
        host_network_policy_handler_key()?,
        artifact,
    )
}

fn host_network_policy_request_schema(require_endpoint: bool) -> Result<ValueSchema> {
    let endpoint = LocalKey::new("endpoint")?;
    let endpoint_schema = if require_endpoint {
        network_endpoint_value_schema()?
    } else {
        ValueSchema::Optional {
            value: Box::new(network_endpoint_value_schema()?),
        }
    };

    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("direction")?,
                ValueSchema::StringEnum {
                    values: vec!["ingress".to_string()],
                },
            ),
            (endpoint.clone(), endpoint_schema),
            (
                LocalKey::new("protocol")?,
                ValueSchema::StringEnum {
                    values: vec!["tcp".to_string()],
                },
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

fn host_network_policy_observation_schema() -> Result<ValueSchema> {
    revisioned_observation_schema(
        HOST_NETWORK_POLICY_OBSERVATION_SCHEMA,
        [
            (LocalKey::new("active")?, ValueSchema::Boolean),
            (
                LocalKey::new("endpoint")?,
                ValueSchema::Optional {
                    value: Box::new(network_endpoint_value_schema()?),
                },
            ),
        ],
    )
}

fn guaranteed_policy_method(
    interface: &InterfaceName,
    name: &str,
    operation_family: OperationFamily,
    parameters: ValueSchema,
    evidence: ValueSchema,
    outputs: BTreeMap<LocalKey, OutputDescriptor>,
    guarantee: GuaranteeKey,
) -> Result<(LocalKey, crate::MethodDescriptor)> {
    let (key, mut method) = resource_method(
        interface,
        name,
        operation_family,
        parameters,
        evidence,
        outputs,
    )?;
    method.guarantees = vec![guarantee];

    Ok((key, method))
}
