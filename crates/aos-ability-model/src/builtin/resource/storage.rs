//! Native host-storage interface, schemas, handler, and provider.

use std::collections::BTreeMap;

use anyhow::Result;

use crate::{
    ArtifactReference, HandlerDescriptor, HostStorageAction, InterfaceDocument, InterfaceKey,
    InterfaceName, LifecycleSemantics, LocalKey, OperationFamily, OutputDescriptor,
    ProviderImplementation, ResourceLifetime, StringSyntax, ValuePhase, ValueSchema,
    ValueVisibility,
};

use super::common::{
    RESOURCE_PATH_MAX_BYTES, bounded_string, interface_document, resource_method,
    revisioned_observation_schema, terminal_provider,
};

/// Names the built-in host-storage effects interface.
pub const HOST_STORAGE_INTERFACE_NAME: &str = "aos.host-storage-effects";
/// Names the storage path emitted after successful acquisition.
pub const HOST_STORAGE_PATH_OUTPUT: &str = "path";
/// Names the native host-storage handler.
pub const HOST_STORAGE_HANDLER_KEY: &str = "native-host-storage-v1";
/// Names the storage handler executable retained in package metadata.
pub const HOST_STORAGE_HANDLER_ENTRY_POINT: &str = "libexec/aos-host-storage-handler-v1";
/// Carries exact storage attachment and revision evidence.
pub const HOST_STORAGE_OBSERVATION_SCHEMA: &str = "aos.ability.host-storage-observation/v1";

/// Builds the exact public host-storage interface.
///
/// Releasing a storage association never requests deletion. Persistent contents
/// remain owned until a separately authorized deletion contract exists.
///
/// # Errors
///
/// Returns an error only if a built-in identifier violates the identity grammar.
pub fn host_storage_interface() -> Result<InterfaceDocument> {
    let interface_name = InterfaceName::new(HOST_STORAGE_INTERFACE_NAME)?;
    let methods = [
        resource_method(
            &interface_name,
            "ensure",
            OperationFamily::HostStorage {
                action: HostStorageAction::Ensure,
            },
            host_storage_request_schema()?,
            host_storage_observation_schema()?,
            BTreeMap::from([(
                LocalKey::new(HOST_STORAGE_PATH_OUTPUT)?,
                OutputDescriptor {
                    schema: bounded_string(RESOURCE_PATH_MAX_BYTES),
                    phase: ValuePhase::Runtime,
                    visibility: ValueVisibility::Protected,
                    lifetime: ResourceLifetime::Persistent,
                },
            )]),
        )?,
        resource_method(
            &interface_name,
            "observe",
            OperationFamily::HostStorage {
                action: HostStorageAction::Observe,
            },
            host_storage_request_schema()?,
            host_storage_observation_schema()?,
            BTreeMap::from([(
                LocalKey::new(HOST_STORAGE_PATH_OUTPUT)?,
                OutputDescriptor {
                    schema: bounded_string(RESOURCE_PATH_MAX_BYTES),
                    phase: ValuePhase::Runtime,
                    visibility: ValueVisibility::Protected,
                    lifetime: ResourceLifetime::Persistent,
                },
            )]),
        )?,
        resource_method(
            &interface_name,
            "release",
            OperationFamily::HostStorage {
                action: HostStorageAction::Release,
            },
            host_storage_request_schema()?,
            host_storage_observation_schema()?,
            BTreeMap::new(),
        )?,
    ]
    .into_iter()
    .collect();

    interface_document(
        interface_name,
        host_storage_request_schema()?,
        methods,
        LifecycleSemantics {
            stable_resource_identity: true,
            releases_ephemeral_on_disable: false,
            retains_persistent_by_default: true,
            persistent_delete_method: None,
        },
    )
}

/// Computes the canonical identity of the host-storage interface.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn host_storage_interface_key() -> Result<InterfaceKey> {
    Ok(host_storage_interface()?.interface_key()?)
}

/// Returns the native host-storage handler key.
///
/// # Errors
///
/// Returns an error only if the built-in key violates the identity grammar.
pub fn host_storage_handler_key() -> Result<LocalKey> {
    Ok(LocalKey::new(HOST_STORAGE_HANDLER_KEY)?)
}

/// Builds the native host-storage handler contract for an artifact.
///
/// # Errors
///
/// Returns an error only if a built-in schema identifier violates the identity grammar.
pub fn host_storage_handler(artifact: ArtifactReference) -> Result<HandlerDescriptor> {
    Ok(HandlerDescriptor {
        artifact,
        entry_point: HOST_STORAGE_HANDLER_ENTRY_POINT.to_string(),
        arguments: host_storage_request_schema()?,
        result: host_storage_observation_schema()?,
    })
}

/// Builds the native host-storage provider declaration for an artifact.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn host_storage_provider(artifact: ArtifactReference) -> Result<ProviderImplementation> {
    terminal_provider(
        host_storage_interface_key()?,
        host_storage_handler_key()?,
        artifact,
    )
}

fn host_storage_request_schema() -> Result<ValueSchema> {
    let local_key = || ValueSchema::String {
        max_length: 128,
        syntax: Some(StringSyntax::LocalKeyV1),
    };

    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (LocalKey::new("cluster")?, local_key()),
            (LocalKey::new("purpose")?, local_key()),
        ]),
        optional_fields: Vec::new(),
    })
}

fn host_storage_observation_schema() -> Result<ValueSchema> {
    revisioned_observation_schema(
        HOST_STORAGE_OBSERVATION_SCHEMA,
        [
            (LocalKey::new("attached")?, ValueSchema::Boolean),
            (LocalKey::new("exists")?, ValueSchema::Boolean),
            (
                LocalKey::new("path")?,
                bounded_string(RESOURCE_PATH_MAX_BYTES),
            ),
        ],
    )
}
