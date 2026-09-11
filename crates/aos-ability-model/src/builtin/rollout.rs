//! Single-host A/B image rollout interface and terminal provider contract.
//!
//! The contract keeps immutable image identity and bounded retention explicit.
//! A provider may prepare one candidate beside one retained predecessor, while
//! boot selection admits exactly one of those images on the host.

use std::collections::BTreeMap;

use anyhow::Result;

use crate::{
    ArtifactReference, HandlerDescriptor, ImageRolloutAction, InterfaceDocument, InterfaceKey,
    InterfaceName, LifecycleSemantics, LocalKey, OperationFamily, OutputDescriptor,
    ProviderImplementation, RequiredFeature, ResourceLifetime, ValuePhase, ValueSchema,
    ValueVisibility,
};

use super::resource::common::{
    bounded_string, interface_document, resource_method, terminal_provider,
};

/// Names the built-in single-host A/B image rollout interface.
pub const AB_IMAGE_ROLLOUT_INTERFACE_NAME: &str = "aos.ab-image-rollout-effects";
/// Requires the single-host A/B rollout planning and execution semantics.
pub const AB_IMAGE_ROLLOUT_FEATURE: &str = "ab-image-rollout-v1";
/// Names the native A/B image rollout handler.
pub const AB_IMAGE_ROLLOUT_HANDLER_KEY: &str = "native-ab-image-rollout-v1";
/// Names the rollout handler executable retained by package metadata.
pub const AB_IMAGE_ROLLOUT_HANDLER_ENTRY_POINT: &str = "libexec/aos-ab-image-rollout-handler-v1";
/// Carries exact rollout lifecycle evidence.
pub const AB_IMAGE_ROLLOUT_OBSERVATION_SCHEMA: &str = "aos.ability.ab-image-rollout-observation/v1";
/// Names the output containing the exact observed rollout state.
pub const AB_IMAGE_ROLLOUT_STATE_OUTPUT: &str = "rollout-state";

const STORE_PATH_MAX_BYTES: u64 = 4_096;
const UKI_PATH_MAX_BYTES: u64 = 4_096;
const STATE_VERSION_MAX_BYTES: u64 = 128;
const JSON_MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Builds the exact single-host A/B image rollout interface.
///
/// `hold` completes after installing a durable lease. Lease expiry never keeps
/// the execution transaction open: `retire` is a later checked transition that
/// requires fresh current policy, provider, incarnation, and resource grants.
///
/// # Errors
///
/// Returns an error only if a built-in identifier violates the identity grammar.
pub fn ab_image_rollout_interface() -> Result<InterfaceDocument> {
    let interface_name = InterfaceName::new(AB_IMAGE_ROLLOUT_INTERFACE_NAME)?;
    let request = ab_image_rollout_request_schema()?;
    let observation = ab_image_rollout_observation_schema()?;
    let output = |lifetime| OutputDescriptor {
        schema: observation.clone(),
        phase: ValuePhase::Observation,
        visibility: ValueVisibility::Protected,
        lifetime,
    };
    let methods = [
        (
            "retain",
            ImageRolloutAction::Retain,
            ResourceLifetime::Transaction,
        ),
        (
            "prepare",
            ImageRolloutAction::Prepare,
            ResourceLifetime::Transaction,
        ),
        (
            "drain",
            ImageRolloutAction::Drain,
            ResourceLifetime::Attempt,
        ),
        (
            "select",
            ImageRolloutAction::Select,
            ResourceLifetime::Transaction,
        ),
        (
            "observe-boot",
            ImageRolloutAction::ObserveBoot,
            ResourceLifetime::Attempt,
        ),
        (
            "observe-health",
            ImageRolloutAction::ObserveHealth,
            ResourceLifetime::Attempt,
        ),
        (
            "withdraw",
            ImageRolloutAction::Withdraw,
            ResourceLifetime::Transaction,
        ),
        (
            "hold",
            ImageRolloutAction::Hold,
            ResourceLifetime::Persistent,
        ),
        (
            "retire",
            ImageRolloutAction::Retire,
            ResourceLifetime::Persistent,
        ),
    ]
    .into_iter()
    .map(|(name, action, lifetime)| {
        let mut outputs = BTreeMap::from([(
            LocalKey::new(AB_IMAGE_ROLLOUT_STATE_OUTPUT)?,
            output(lifetime),
        )]);
        if name == "observe-health" {
            outputs.insert(
                LocalKey::new("healthy")?,
                OutputDescriptor {
                    schema: ValueSchema::Boolean,
                    phase: ValuePhase::Observation,
                    visibility: ValueVisibility::Protected,
                    lifetime: ResourceLifetime::Attempt,
                },
            );
        }
        resource_method(
            &interface_name,
            name,
            OperationFamily::ImageRollout { action },
            request.clone(),
            observation.clone(),
            outputs,
        )
    })
    .collect::<Result<BTreeMap<_, _>>>()?;

    let mut document = interface_document(
        interface_name,
        request,
        methods,
        LifecycleSemantics {
            stable_resource_identity: true,
            releases_ephemeral_on_disable: false,
            retains_persistent_by_default: true,
            persistent_delete_method: None,
        },
    )?;
    document.required_features = vec![RequiredFeature::new(AB_IMAGE_ROLLOUT_FEATURE)?];

    Ok(document)
}

/// Computes the canonical rollout interface identity.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn ab_image_rollout_interface_key() -> Result<InterfaceKey> {
    Ok(ab_image_rollout_interface()?.interface_key()?)
}

/// Returns the native rollout handler key.
///
/// # Errors
///
/// Returns an error only if the built-in key violates the identity grammar.
pub fn ab_image_rollout_handler_key() -> Result<LocalKey> {
    Ok(LocalKey::new(AB_IMAGE_ROLLOUT_HANDLER_KEY)?)
}

/// Builds the native rollout handler contract for an artifact.
///
/// # Errors
///
/// Returns an error only if a built-in schema identifier violates the identity grammar.
pub fn ab_image_rollout_handler(artifact: ArtifactReference) -> Result<HandlerDescriptor> {
    Ok(HandlerDescriptor {
        artifact,
        entry_point: AB_IMAGE_ROLLOUT_HANDLER_ENTRY_POINT.to_string(),
        arguments: ab_image_rollout_request_schema()?,
        result: ab_image_rollout_observation_schema()?,
    })
}

/// Builds the native rollout provider declaration for an artifact.
///
/// # Errors
///
/// Returns an error if built-in construction or canonical encoding fails.
pub fn ab_image_rollout_provider(artifact: ArtifactReference) -> Result<ProviderImplementation> {
    terminal_provider(
        ab_image_rollout_interface_key()?,
        ab_image_rollout_handler_key()?,
        artifact,
    )
}

/// Returns the closed rollout request schema.
///
/// # Errors
///
/// Returns an error only if a built-in field name violates the identity grammar.
pub fn ab_image_rollout_request_schema() -> Result<ValueSchema> {
    let identity = image_identity_schema()?;
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (LocalKey::new("candidate")?, identity.clone()),
            (
                LocalKey::new("concurrency")?,
                ValueSchema::Integer {
                    minimum: 1,
                    maximum: 1,
                },
            ),
            (LocalKey::new("predecessor")?, identity),
            (
                LocalKey::new("retention-expires-at-millis")?,
                ValueSchema::Integer {
                    minimum: 1,
                    maximum: JSON_MAX_SAFE_INTEGER,
                },
            ),
            (
                LocalKey::new("strategy")?,
                ValueSchema::StringEnum {
                    values: vec!["single-host-ab-v1".to_string()],
                },
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

/// Returns the closed rollout observation schema.
///
/// # Errors
///
/// Returns an error only if a built-in field name violates the identity grammar.
pub fn ab_image_rollout_observation_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("active-image")?,
                ValueSchema::StringEnum {
                    values: vec!["candidate".into(), "predecessor".into()],
                },
            ),
            (LocalKey::new("candidate-prepared")?, ValueSchema::Boolean),
            (LocalKey::new("drained")?, ValueSchema::Boolean),
            (
                LocalKey::new("healthy")?,
                ValueSchema::Optional {
                    value: Box::new(ValueSchema::Boolean),
                },
            ),
            (
                LocalKey::new("lease-expires-at-millis")?,
                ValueSchema::Optional {
                    value: Box::new(ValueSchema::Integer {
                        minimum: 1,
                        maximum: JSON_MAX_SAFE_INTEGER,
                    }),
                },
            ),
            (
                LocalKey::new("phase")?,
                ValueSchema::StringEnum {
                    values: vec![
                        "booted".into(),
                        "drained".into(),
                        "fallback-retained".into(),
                        "healthy-retained".into(),
                        "prepared".into(),
                        "retained".into(),
                        "retired".into(),
                        "selected".into(),
                    ],
                },
            ),
            (
                LocalKey::new("schema")?,
                ValueSchema::StringEnum {
                    values: vec![AB_IMAGE_ROLLOUT_OBSERVATION_SCHEMA.to_string()],
                },
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

fn image_identity_schema() -> Result<ValueSchema> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("executor")?,
                bounded_string(STORE_PATH_MAX_BYTES),
            ),
            (
                LocalKey::new("state-format")?,
                bounded_string(STATE_VERSION_MAX_BYTES),
            ),
            (
                LocalKey::new("toplevel")?,
                bounded_string(STORE_PATH_MAX_BYTES),
            ),
            (LocalKey::new("uki")?, bounded_string(UKI_PATH_MAX_BYTES)),
        ]),
        optional_fields: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{ABILITY_LIMITS_V1, VersionedDocument, decode_canonical, encode_canonical};

    #[test]
    fn rollout_contract_is_closed_and_pins_full_image_identity() {
        let document = ab_image_rollout_interface().unwrap();
        assert_eq!(
            document.interface_key().unwrap().descriptor.to_string(),
            "sha256:5776469b1b825c017ced9db370a84d693631dad739b91961dee4ef14d8816c7c"
        );
        let bytes = encode_canonical(&document).unwrap();
        let supported = BTreeSet::from([RequiredFeature::new(AB_IMAGE_ROLLOUT_FEATURE).unwrap()]);
        decode_canonical::<InterfaceDocument>(&bytes, ABILITY_LIMITS_V1, &supported).unwrap();

        let ValueSchema::Record { fields, .. } = &document.interface.request else {
            panic!("rollout request must be a record");
        };
        let ValueSchema::Record {
            fields: identity, ..
        } = &fields["candidate"]
        else {
            panic!("candidate must carry an image identity");
        };
        assert_eq!(
            identity.keys().map(LocalKey::as_str).collect::<Vec<_>>(),
            ["executor", "state-format", "toplevel", "uki"]
        );
        assert_eq!(document.interface.methods.len(), 9);
        assert_eq!(
            document.required_features,
            supported.into_iter().collect::<Vec<_>>()
        );
        assert_eq!(document.schema(), InterfaceDocument::SCHEMA);
    }

    #[test]
    fn rollout_contract_fails_closed_for_a_pre_rollout_reader() {
        let bytes = encode_canonical(&ab_image_rollout_interface().unwrap()).unwrap();
        let error =
            decode_canonical::<InterfaceDocument>(&bytes, ABILITY_LIMITS_V1, &BTreeSet::new())
                .expect_err("a reader without rollout semantics must reject the interface");

        assert!(error.to_string().contains(AB_IMAGE_ROLLOUT_FEATURE));
    }
}
