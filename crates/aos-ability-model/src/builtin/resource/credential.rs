//! Native credential-delivery interface, schemas, handler, and provider.

use std::collections::BTreeMap;

use anyhow::Result;

use crate::{
    ArtifactReference, CredentialAction, HandlerDescriptor, InterfaceDocument, InterfaceKey,
    InterfaceName, LifecycleSemantics, LocalKey, OperationFamily, OutputDescriptor,
    ProviderImplementation, ResourceLifetime, StringSyntax, ValuePhase, ValueSchema,
    ValueVisibility,
};

use super::common::{
    RESOURCE_PATH_MAX_BYTES, REVISION_MAX_BYTES, bounded_string, interface_document,
    resource_method, terminal_provider,
};

/// Names the built-in credential-delivery effects interface.
pub const CREDENTIAL_DELIVERY_EFFECTS_INTERFACE_NAME: &str = "aos.credential-delivery-effects";
/// Names the secret-free workload view emitted by acquire and deliver.
pub const CREDENTIAL_VIEW_OUTPUT: &str = "credential-view";
/// Names the native credential-delivery handler.
pub const CREDENTIAL_DELIVERY_HANDLER_KEY: &str = "native-credential-delivery-v1";
/// Names the credential handler executable retained in package metadata.
pub const CREDENTIAL_DELIVERY_HANDLER_ENTRY_POINT: &str =
    "libexec/aos-credential-delivery-handler-v1";
/// Carries exact credential version and workload-view evidence without secret bytes.
pub const CREDENTIAL_DELIVERY_OBSERVATION_SCHEMA: &str =
    "aos.ability.credential-delivery-observation/v1";

/// Builds the exact public credential-delivery effects interface.
///
/// Acquire reads an existing provider-scoped view, while deliver creates or
/// replaces that view. Both return the same secret-free path and opaque version
/// contract; secret bytes never enter a plan or result document.
///
/// # Errors
///
/// Returns an error only if a built-in identifier violates the identity grammar.
pub fn credential_delivery_effects_interface() -> Result<InterfaceDocument> {
    let interface_name = InterfaceName::new(CREDENTIAL_DELIVERY_EFFECTS_INTERFACE_NAME)?;
    let credential_output = OutputDescriptor {
        schema: credential_view_schema()?,
        phase: ValuePhase::Runtime,
        visibility: ValueVisibility::Protected,
        lifetime: ResourceLifetime::Instance,
    };
    let methods = [
        resource_method(
            &interface_name,
            "acquire",
            OperationFamily::Credential {
                action: CredentialAction::Acquire,
            },
            credential_delivery_request_schema()?,
            credential_delivery_observation_schema()?,
            BTreeMap::from([(
                LocalKey::new(CREDENTIAL_VIEW_OUTPUT)?,
                credential_output.clone(),
            )]),
        )?,
        resource_method(
            &interface_name,
            "deliver",
            OperationFamily::Credential {
                action: CredentialAction::Deliver,
            },
            credential_delivery_request_schema()?,
            credential_delivery_observation_schema()?,
            BTreeMap::from([(LocalKey::new(CREDENTIAL_VIEW_OUTPUT)?, credential_output)]),
        )?,
        resource_method(
            &interface_name,
            "release",
            OperationFamily::ReleaseResource,
            credential_delivery_request_schema()?,
            credential_delivery_observation_schema()?,
            BTreeMap::new(),
        )?,
    ]
    .into_iter()
    .collect();

    interface_document(
        interface_name,
        credential_delivery_request_schema()?,
        methods,
        LifecycleSemantics {
            stable_resource_identity: true,
            releases_ephemeral_on_disable: true,
            retains_persistent_by_default: false,
            persistent_delete_method: None,
        },
    )
}

/// Computes the canonical identity of the credential-delivery effects interface.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn credential_delivery_effects_interface_key() -> Result<InterfaceKey> {
    Ok(credential_delivery_effects_interface()?.interface_key()?)
}

/// Returns the native credential-delivery handler key.
///
/// # Errors
///
/// Returns an error only if the built-in key violates the identity grammar.
pub fn credential_delivery_handler_key() -> Result<LocalKey> {
    Ok(LocalKey::new(CREDENTIAL_DELIVERY_HANDLER_KEY)?)
}

/// Builds the native credential-delivery handler contract for an artifact.
///
/// # Errors
///
/// Returns an error only if a built-in schema identifier violates the identity grammar.
pub fn credential_delivery_handler(artifact: ArtifactReference) -> Result<HandlerDescriptor> {
    Ok(HandlerDescriptor {
        artifact,
        entry_point: CREDENTIAL_DELIVERY_HANDLER_ENTRY_POINT.to_string(),
        arguments: credential_delivery_request_schema()?,
        result: credential_delivery_observation_schema()?,
    })
}

/// Builds the native credential-delivery provider declaration for an artifact.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn credential_delivery_provider(artifact: ArtifactReference) -> Result<ProviderImplementation> {
    terminal_provider(
        credential_delivery_effects_interface_key()?,
        credential_delivery_handler_key()?,
        artifact,
    )
}

/// Returns the closed secret-free credential request schema.
///
/// The version is an opaque source revision. The view names the exact
/// provider-scoped destination and is checked against the operation target by
/// the native handler before it reads or writes credential state.
///
/// # Errors
///
/// Returns an error only if a built-in field name violates the identity grammar.
pub fn credential_delivery_request_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("version")?,
                bounded_string(REVISION_MAX_BYTES),
            ),
            (
                LocalKey::new("view")?,
                ValueSchema::String {
                    max_length: 128,
                    syntax: Some(StringSyntax::LocalKeyV1),
                },
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

/// Returns the closed secret-free credential observation schema.
///
/// # Errors
///
/// Returns an error only if a built-in field name violates the identity grammar.
pub fn credential_delivery_observation_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (LocalKey::new("delivered")?, ValueSchema::Boolean),
            (
                LocalKey::new("observed_version")?,
                ValueSchema::Optional {
                    value: Box::new(bounded_string(REVISION_MAX_BYTES)),
                },
            ),
            (
                LocalKey::new("requested_version")?,
                bounded_string(REVISION_MAX_BYTES),
            ),
            (
                LocalKey::new("schema")?,
                ValueSchema::StringEnum {
                    values: vec![CREDENTIAL_DELIVERY_OBSERVATION_SCHEMA.to_string()],
                },
            ),
            (
                LocalKey::new("view")?,
                ValueSchema::String {
                    max_length: 128,
                    syntax: Some(StringSyntax::LocalKeyV1),
                },
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

/// Returns the closed secret-free credential-view schema.
///
/// The path identifies a provider-controlled workload view. The revision
/// identifies the opaque source version; neither field contains secret bytes.
///
/// # Errors
///
/// Returns an error only if a built-in field name violates the identity grammar.
pub fn credential_view_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("path")?,
                bounded_string(RESOURCE_PATH_MAX_BYTES),
            ),
            (
                LocalKey::new("version")?,
                bounded_string(REVISION_MAX_BYTES),
            ),
        ]),
        optional_fields: Vec::new(),
    })
}
