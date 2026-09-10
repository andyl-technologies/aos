//! Native network-endpoint interface, schemas, handler, and provider.

use std::collections::BTreeMap;

use anyhow::Result;

use crate::{
    ArtifactReference, HandlerDescriptor, InterfaceDocument, InterfaceKey, InterfaceName,
    LifecycleSemantics, LocalKey, NetworkEndpointAction, OperationFamily, OutputDescriptor,
    ProviderImplementation, ResourceLifetime, ValuePhase, ValueSchema, ValueVisibility,
};

use super::common::{
    bounded_string, interface_document, resource_method, revisioned_observation_schema,
    terminal_provider,
};

const ENDPOINT_ADDRESS_MAX_BYTES: u64 = 15;

/// Names the built-in network-endpoint effects interface.
pub const NETWORK_ENDPOINT_INTERFACE_NAME: &str = "aos.network-endpoint-effects";
/// Names the endpoint port emitted by materialization and observation.
pub const NETWORK_ENDPOINT_OUTPUT: &str = "endpoint";
/// Names the native runtime endpoint handler.
pub const NETWORK_ENDPOINT_HANDLER_KEY: &str = "native-network-endpoint-v1";
/// Names the endpoint handler executable retained in package metadata.
pub const NETWORK_ENDPOINT_HANDLER_ENTRY_POINT: &str = "libexec/aos-network-endpoint-handler-v1";
/// Carries exact endpoint ownership and revision evidence.
pub const NETWORK_ENDPOINT_OBSERVATION_SCHEMA: &str = "aos.ability.network-endpoint-observation/v1";

/// Builds the exact public runtime endpoint interface.
///
/// `materialize` is the only operation that creates an endpoint. Its output is
/// available at runtime and must reach later consumers through a typed result
/// reference rather than pure evaluation.
///
/// # Errors
///
/// Returns an error only if a built-in identifier violates the identity grammar.
pub fn network_endpoint_interface() -> Result<InterfaceDocument> {
    let interface_name = InterfaceName::new(NETWORK_ENDPOINT_INTERFACE_NAME)?;
    let endpoint_output = OutputDescriptor {
        schema: network_endpoint_value_schema()?,
        phase: ValuePhase::Runtime,
        visibility: ValueVisibility::Protected,
        lifetime: ResourceLifetime::Instance,
    };
    let methods = [
        resource_method(
            &interface_name,
            "materialize",
            OperationFamily::NetworkEndpoint {
                action: NetworkEndpointAction::Materialize,
            },
            network_endpoint_request_schema()?,
            network_endpoint_observation_schema()?,
            BTreeMap::from([(
                LocalKey::new(NETWORK_ENDPOINT_OUTPUT)?,
                endpoint_output.clone(),
            )]),
        )?,
        resource_method(
            &interface_name,
            "observe",
            OperationFamily::NetworkEndpoint {
                action: NetworkEndpointAction::Observe,
            },
            network_endpoint_request_schema()?,
            network_endpoint_observation_schema()?,
            BTreeMap::from([(LocalKey::new(NETWORK_ENDPOINT_OUTPUT)?, endpoint_output)]),
        )?,
        resource_method(
            &interface_name,
            "release",
            OperationFamily::NetworkEndpoint {
                action: NetworkEndpointAction::Release,
            },
            network_endpoint_request_schema()?,
            network_endpoint_observation_schema()?,
            BTreeMap::new(),
        )?,
    ]
    .into_iter()
    .collect();

    interface_document(
        interface_name,
        network_endpoint_request_schema()?,
        methods,
        LifecycleSemantics {
            stable_resource_identity: true,
            releases_ephemeral_on_disable: true,
            retains_persistent_by_default: false,
            persistent_delete_method: None,
        },
    )
}

/// Computes the canonical identity of the runtime endpoint interface.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn network_endpoint_interface_key() -> Result<InterfaceKey> {
    Ok(network_endpoint_interface()?.interface_key()?)
}

/// Returns the native endpoint handler key.
///
/// # Errors
///
/// Returns an error only if the built-in key violates the identity grammar.
pub fn network_endpoint_handler_key() -> Result<LocalKey> {
    Ok(LocalKey::new(NETWORK_ENDPOINT_HANDLER_KEY)?)
}

/// Builds the native endpoint handler contract for an artifact.
///
/// # Errors
///
/// Returns an error only if a built-in schema identifier violates the identity grammar.
pub fn network_endpoint_handler(artifact: ArtifactReference) -> Result<HandlerDescriptor> {
    Ok(HandlerDescriptor {
        artifact,
        entry_point: NETWORK_ENDPOINT_HANDLER_ENTRY_POINT.to_string(),
        arguments: network_endpoint_request_schema()?,
        result: network_endpoint_observation_schema()?,
    })
}

/// Builds the native endpoint provider declaration for an artifact.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn network_endpoint_provider(artifact: ArtifactReference) -> Result<ProviderImplementation> {
    terminal_provider(
        network_endpoint_interface_key()?,
        network_endpoint_handler_key()?,
        artifact,
    )
}

/// Returns the closed runtime endpoint request schema.
///
/// # Errors
///
/// Returns an error only if a built-in field name violates the identity grammar.
pub fn network_endpoint_request_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("address")?,
                ValueSchema::StringEnum {
                    values: vec!["127.0.0.1".to_string()],
                },
            ),
            (
                LocalKey::new("port")?,
                ValueSchema::Integer {
                    minimum: 0,
                    maximum: 65_535,
                },
            ),
            (
                LocalKey::new("transport")?,
                ValueSchema::StringEnum {
                    values: vec!["tcp".to_string()],
                },
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

/// Returns the closed materialized endpoint value schema.
///
/// # Errors
///
/// Returns an error only if a built-in field name violates the identity grammar.
pub fn network_endpoint_value_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("address")?,
                bounded_string(ENDPOINT_ADDRESS_MAX_BYTES),
            ),
            (
                LocalKey::new("port")?,
                ValueSchema::Integer {
                    minimum: 1_024,
                    maximum: 65_535,
                },
            ),
            (
                LocalKey::new("transport")?,
                ValueSchema::StringEnum {
                    values: vec!["tcp".to_string()],
                },
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

fn network_endpoint_observation_schema() -> Result<ValueSchema> {
    revisioned_observation_schema(
        NETWORK_ENDPOINT_OBSERVATION_SCHEMA,
        [
            (
                LocalKey::new("endpoint")?,
                ValueSchema::Optional {
                    value: Box::new(network_endpoint_value_schema()?),
                },
            ),
            (LocalKey::new("owned")?, ValueSchema::Boolean),
        ],
    )
}
