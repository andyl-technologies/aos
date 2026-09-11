//! Native PostgreSQL materialization and lifecycle interface.

use std::collections::BTreeMap;

use anyhow::Result;

use crate::{
    ArtifactReference, HandlerDescriptor, InterfaceDocument, InterfaceKey, InterfaceName,
    LifecycleSemantics, LocalKey, OperationFamily, OutputDescriptor, ProviderImplementation,
    ResourceLifetime, ServiceAction, StringSyntax, ValuePhase, ValueSchema, ValueVisibility,
};

use super::common::{
    RESOURCE_PATH_MAX_BYTES, REVISION_MAX_BYTES, bounded_string, interface_document,
    resource_method, terminal_provider,
};
use super::credential::credential_view_schema;
use super::endpoint::network_endpoint_value_schema;

/// Names the built-in PostgreSQL effects interface.
pub const POSTGRESQL_EFFECTS_INTERFACE_NAME: &str = "aos.postgresql-effects";
/// Names the native production PostgreSQL handler.
pub const POSTGRESQL_HANDLER_KEY: &str = "native-postgresql-v1";
/// Names the PostgreSQL handler executable retained in package metadata.
pub const POSTGRESQL_HANDLER_ENTRY_POINT: &str = "libexec/aos-postgresql-handler-v1";
/// Carries exact submitted and observed PostgreSQL configuration evidence.
pub const POSTGRESQL_OBSERVATION_SCHEMA: &str = "aos.ability.postgresql-observation/v1";
/// Names the materialized configuration revision output.
pub const POSTGRESQL_CONFIGURATION_REVISION_OUTPUT: &str = "configuration-revision";
/// Names the submitted revision output from a PostgreSQL observation.
pub const POSTGRESQL_SUBMITTED_REVISION_OUTPUT: &str = "submitted-revision";
/// Names the observed consumer revision output from a PostgreSQL observation.
pub const POSTGRESQL_OBSERVED_REVISION_OUTPUT: &str = "observed-revision";
/// Names the consumer-context readiness output from a PostgreSQL observation.
pub const POSTGRESQL_READY_OUTPUT: &str = "ready";
/// Limits PostgreSQL role and database names to the server's identifier width.
pub const POSTGRESQL_IDENTIFIER_MAX_BYTES: u64 = 63;

/// Builds the production PostgreSQL materialization and lifecycle interface.
///
/// The materialization method requires a resolved runtime endpoint and a
/// secret-free credential view. Native execution does not support PostgreSQL
/// trust authentication. It renders the production configuration and then
/// invokes the package's ordinary control and service paths. Observation
/// reports both the submitted revision and the revision seen through an actual
/// SQL connection from the declared consumer.
///
/// # Errors
///
/// Returns an error only if a built-in identifier violates the identity grammar.
pub fn postgresql_effects_interface() -> Result<InterfaceDocument> {
    let interface_name = InterfaceName::new(POSTGRESQL_EFFECTS_INTERFACE_NAME)?;
    let runtime_revision = OutputDescriptor {
        schema: bounded_string(REVISION_MAX_BYTES),
        phase: ValuePhase::Runtime,
        visibility: ValueVisibility::Protected,
        lifetime: ResourceLifetime::Persistent,
    };
    let observed_revision = OutputDescriptor {
        schema: ValueSchema::Optional {
            value: Box::new(bounded_string(REVISION_MAX_BYTES)),
        },
        phase: ValuePhase::Observation,
        visibility: ValueVisibility::Protected,
        lifetime: ResourceLifetime::Attempt,
    };
    let observed_value = |schema| OutputDescriptor {
        schema,
        phase: ValuePhase::Observation,
        visibility: ValueVisibility::Protected,
        lifetime: ResourceLifetime::Attempt,
    };
    let request = postgresql_request_schema()?;
    let evidence = postgresql_observation_schema()?;
    let methods = [
        resource_method(
            &interface_name,
            "materialize",
            OperationFamily::PrepareManagedConfiguration,
            request.clone(),
            evidence.clone(),
            BTreeMap::from([(
                LocalKey::new(POSTGRESQL_CONFIGURATION_REVISION_OUTPUT)?,
                runtime_revision.clone(),
            )]),
        )?,
        resource_method(
            &interface_name,
            "observe",
            OperationFamily::ObserveReadiness,
            request.clone(),
            evidence.clone(),
            BTreeMap::from([
                (
                    LocalKey::new(POSTGRESQL_OBSERVED_REVISION_OUTPUT)?,
                    observed_revision,
                ),
                (
                    LocalKey::new(POSTGRESQL_READY_OUTPUT)?,
                    observed_value(ValueSchema::Boolean),
                ),
                (
                    LocalKey::new(POSTGRESQL_SUBMITTED_REVISION_OUTPUT)?,
                    observed_value(bounded_string(REVISION_MAX_BYTES)),
                ),
            ]),
        )?,
        resource_method(
            &interface_name,
            "start",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Start,
            },
            request.clone(),
            evidence.clone(),
            BTreeMap::new(),
        )?,
        resource_method(
            &interface_name,
            "restart",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Restart,
            },
            request.clone(),
            evidence.clone(),
            BTreeMap::new(),
        )?,
        resource_method(
            &interface_name,
            "stop",
            OperationFamily::ServiceLifecycle {
                action: ServiceAction::Stop,
            },
            request.clone(),
            evidence,
            BTreeMap::new(),
        )?,
    ]
    .into_iter()
    .collect();

    interface_document(
        interface_name,
        request,
        methods,
        LifecycleSemantics {
            stable_resource_identity: true,
            releases_ephemeral_on_disable: false,
            retains_persistent_by_default: true,
            persistent_delete_method: None,
        },
    )
}

/// Computes the canonical identity of the PostgreSQL effects interface.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn postgresql_effects_interface_key() -> Result<InterfaceKey> {
    Ok(postgresql_effects_interface()?.interface_key()?)
}

/// Returns the native PostgreSQL handler key.
///
/// # Errors
///
/// Returns an error only if the built-in key violates the identity grammar.
pub fn postgresql_handler_key() -> Result<LocalKey> {
    Ok(LocalKey::new(POSTGRESQL_HANDLER_KEY)?)
}

/// Builds the native PostgreSQL handler contract for an artifact.
///
/// # Errors
///
/// Returns an error only if a built-in schema identifier violates the identity grammar.
pub fn postgresql_handler(artifact: ArtifactReference) -> Result<HandlerDescriptor> {
    Ok(HandlerDescriptor {
        artifact,
        entry_point: POSTGRESQL_HANDLER_ENTRY_POINT.to_string(),
        arguments: postgresql_request_schema()?,
        result: postgresql_observation_schema()?,
    })
}

/// Builds the native PostgreSQL provider declaration for an artifact.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn postgresql_provider(artifact: ArtifactReference) -> Result<ProviderImplementation> {
    terminal_provider(
        postgresql_effects_interface_key()?,
        postgresql_handler_key()?,
        artifact,
    )
}

/// Returns the closed PostgreSQL materialization and lifecycle request schema.
///
/// Endpoint, storage, and credential members can carry explicit null because
/// stop and recovery may resume after an interrupted materialization. Native
/// `materialize` requires non-null endpoint, storage, and credential values
/// before any filesystem effect; a null credential never enables trust mode.
///
/// # Errors
///
/// Returns an error only if a built-in field name violates the identity grammar.
pub fn postgresql_request_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("cluster")?,
                ValueSchema::String {
                    max_length: 128,
                    syntax: Some(StringSyntax::LocalKeyV1),
                },
            ),
            (
                LocalKey::new("configuration_revision")?,
                bounded_string(REVISION_MAX_BYTES),
            ),
            (
                LocalKey::new("database")?,
                ValueSchema::String {
                    max_length: POSTGRESQL_IDENTIFIER_MAX_BYTES,
                    syntax: Some(StringSyntax::LocalKeyV1),
                },
            ),
            (
                LocalKey::new("credential_view")?,
                ValueSchema::Optional {
                    value: Box::new(credential_view_schema()?),
                },
            ),
            (
                LocalKey::new("endpoint")?,
                ValueSchema::Optional {
                    value: Box::new(network_endpoint_value_schema()?),
                },
            ),
            (
                LocalKey::new("storage_path")?,
                ValueSchema::Optional {
                    value: Box::new(bounded_string(RESOURCE_PATH_MAX_BYTES)),
                },
            ),
            (
                LocalKey::new("role")?,
                ValueSchema::String {
                    max_length: POSTGRESQL_IDENTIFIER_MAX_BYTES,
                    syntax: Some(StringSyntax::LocalKeyV1),
                },
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

/// Returns the closed PostgreSQL execution evidence schema.
///
/// # Errors
///
/// Returns an error only if a built-in field name violates the identity grammar.
pub fn postgresql_observation_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("cluster")?,
                ValueSchema::String {
                    max_length: 128,
                    syntax: Some(StringSyntax::LocalKeyV1),
                },
            ),
            (
                LocalKey::new("endpoint")?,
                ValueSchema::Optional {
                    value: Box::new(network_endpoint_value_schema()?),
                },
            ),
            (
                LocalKey::new("database")?,
                ValueSchema::String {
                    max_length: POSTGRESQL_IDENTIFIER_MAX_BYTES,
                    syntax: Some(StringSyntax::LocalKeyV1),
                },
            ),
            (
                LocalKey::new("observed_revision")?,
                ValueSchema::Optional {
                    value: Box::new(bounded_string(REVISION_MAX_BYTES)),
                },
            ),
            (
                LocalKey::new("production_control_path")?,
                ValueSchema::StringEnum {
                    values: vec!["/bin/postgresql-control".to_string()],
                },
            ),
            (LocalKey::new("ready")?, ValueSchema::Boolean),
            (
                LocalKey::new("role")?,
                ValueSchema::String {
                    max_length: POSTGRESQL_IDENTIFIER_MAX_BYTES,
                    syntax: Some(StringSyntax::LocalKeyV1),
                },
            ),
            (
                LocalKey::new("schema")?,
                ValueSchema::StringEnum {
                    values: vec![POSTGRESQL_OBSERVATION_SCHEMA.to_string()],
                },
            ),
            (
                LocalKey::new("submitted_revision")?,
                bounded_string(REVISION_MAX_BYTES),
            ),
        ]),
        optional_fields: Vec::new(),
    })
}
