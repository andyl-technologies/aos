//! Tests for canonical ability documents.

use super::*;
use crate::interface::{
    AggregationContract, AggregationScope, LifecycleSemantics, ValueVisibility,
};
use crate::schema::{ValueConstraint, ValueSchema};
use crate::value::ResourceLifetime;
use crate::{DocumentedValue, OptionSource, OptionType, OptionVisibility};

fn interface_document() -> InterfaceDocument {
    InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            description: "Describes this declaration.".to_string(),
            name: crate::identity::InterfaceName::new("test.echo")
                .expect("valid test interface name"),
            abi: NonZeroU32::new(1).expect("positive test ABI"),
            request: ValueSchema::Boolean,
            configuration: None,
            outputs: BTreeMap::from([(
                LocalKey::new("accepted").expect("valid test output name"),
                crate::interface::OutputDescriptor {
                    description: "Describes this declaration.".to_string(),
                    schema: ValueSchema::Boolean,
                    phase: crate::interface::ValuePhase::Evaluation,
                    visibility: ValueVisibility::Public,
                    lifetime: ResourceLifetime::Instance,
                },
            )]),
            methods: BTreeMap::new(),
            lifecycle: LifecycleSemantics {
                persistent_delete_method: None,
            },
            aggregation: AggregationContract {
                scope: AggregationScope::ProviderInstance,
                key: LocalKey::new("slot").expect("valid aggregation key"),
                controller_group: LocalKey::new("test").expect("valid controller group"),
                reject_slot_collisions: true,
                merge_contract: None,
            },
            guarantees: Vec::new(),
        },
    }
}

#[test]
fn canonical_round_trip_preserves_interface_identity() -> Result<(), DocumentError> {
    let original = interface_document();
    let bytes = encode_canonical(&original)?;
    let decoded =
        decode_canonical::<InterfaceDocument>(&bytes, ABILITY_LIMITS_V1, &BTreeSet::new())?;

    assert_eq!(decoded, original);
    assert_eq!(decoded.interface_key()?, original.interface_key()?);
    assert!(
        serde_json::to_value(&decoded)
            .expect("interface must serialize")
            .get("interface")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|interface| !interface.contains_key("configuration"))
    );
    Ok(())
}

#[test]
fn interface_prose_changes_signed_bytes_without_changing_identity() -> Result<(), DocumentError> {
    let mut original = interface_document();
    original.interface.methods.insert(
        LocalKey::new("observe").expect("valid method name"),
        crate::interface::MethodDescriptor {
            description: "Observes the test resource.".to_string(),
            semantics: crate::interface::MethodSemantics::ordinary(crate::plan::AccessMode::Read),
            parameters: ValueSchema::Boolean,
            target_resource: original.interface.name.clone(),
            outputs: BTreeMap::from([(
                LocalKey::new("observed").expect("valid output name"),
                crate::interface::OutputDescriptor {
                    description: "Reports the observed value.".to_string(),
                    schema: ValueSchema::Boolean,
                    phase: crate::interface::ValuePhase::Observation,
                    visibility: ValueVisibility::Public,
                    lifetime: ResourceLifetime::Instance,
                },
            )]),
            permitted_operations: Vec::new(),
            guarantees: Vec::new(),
            outcome: crate::interface::OutcomeSemantics {
                completion_evidence: ValueSchema::Boolean,
                observation_evidence: ValueSchema::Boolean,
                supports_rejected_before_effect: true,
                indeterminate: crate::interface::IndeterminateSemantics::Reconcile,
            },
        },
    );
    let mut edited = original.clone();
    edited.interface.description = "Reworded interface documentation.".to_string();
    edited
        .interface
        .outputs
        .get_mut(&LocalKey::new("accepted").expect("valid output name"))
        .expect("interface output")
        .description = "Reworded aggregate output documentation.".to_string();
    let method = edited
        .interface
        .methods
        .get_mut(&LocalKey::new("observe").expect("valid method name"))
        .expect("interface method");
    method.description = "Reworded method documentation.".to_string();
    method
        .outputs
        .get_mut(&LocalKey::new("observed").expect("valid output name"))
        .expect("method output")
        .description = "Reworded method output documentation.".to_string();

    assert_eq!(original.interface_key()?, edited.interface_key()?);
    assert_ne!(encode_canonical(&original)?, encode_canonical(&edited)?);
    Ok(())
}

#[test]
fn desired_instance_without_optional_configuration_round_trips_unchanged() {
    let unconfigured = serde_json::json!({
        "instance": {
            "environment": {
                "authority": "test",
                "key": "web",
                "stage": "host",
            },
            "key": "nginx",
        },
        "authority": {
            "kind": "package",
            "package": "nginx",
        },
        "package": format!("sha256:{}", "0".repeat(64)),
        "enabled": true,
    });

    let decoded: DesiredInstance =
        serde_json::from_value(unconfigured.clone()).expect("unconfigured instance decodes");

    assert_eq!(decoded.configuration, None);
    assert_eq!(
        serde_json::to_value(decoded).expect("unconfigured instance serializes"),
        unconfigured
    );
}

#[test]
fn system_instance_without_package_artifact_round_trips_unchanged() {
    let system_instance = serde_json::json!({
        "instance": {
            "environment": {
                "authority": "test",
                "key": "host",
                "stage": "host",
            },
            "key": "kernel",
        },
        "authority": {
            "kind": "system",
        },
        "enabled": true,
    });

    let decoded: DesiredInstance =
        serde_json::from_value(system_instance.clone()).expect("system instance decodes");

    assert_eq!(decoded.authority, DeclarationAuthority::System);
    assert_eq!(decoded.package, None);
    assert_eq!(
        serde_json::to_value(decoded).expect("system instance serializes"),
        system_instance
    );
}

#[test]
fn equivalent_but_noncanonical_json_is_rejected() {
    let bytes = br#"{"schema":"aos.ability.interface/v1","required_features":[],"interface":{"name":"test.echo","abi":1,"request":{"kind":"boolean"},"outputs":{},"methods":{},"lifecycle":{"persistent_delete_method":null},"guarantees":[]}}"#;

    assert!(
        decode_canonical::<InterfaceDocument>(bytes, ABILITY_LIMITS_V1, &BTreeSet::new()).is_err()
    );
}

#[test]
fn unknown_required_semantics_fail_closed() {
    let mut document = interface_document();
    document.required_features =
        vec![RequiredFeature::new("future-semantics").expect("valid test feature")];
    let bytes = encode_canonical(&document).expect("canonical test document");

    assert!(matches!(
        decode_canonical::<InterfaceDocument>(&bytes, ABILITY_LIMITS_V1, &BTreeSet::new()),
        Err(DocumentError::UnsupportedFeature { .. })
    ));
}

#[test]
fn canonical_schema_rejects_an_absent_optional_member() {
    let document = interface_document();
    let bytes = encode_canonical(&document).expect("canonical test document");
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid test JSON");
    value["interface"]["lifecycle"]
        .as_object_mut()
        .expect("test lifecycle object")
        .remove("persistent_delete_method");
    let without_null =
        aos_contract::canonical::canonical_json(&value).expect("canonical test JSON");

    assert!(
        decode_canonical::<InterfaceDocument>(&without_null, ABILITY_LIMITS_V1, &BTreeSet::new(),)
            .is_err()
    );
}

#[test]
fn decoding_applies_the_caller_document_bound_first() {
    let bytes = encode_canonical(&interface_document()).expect("canonical test document");
    let limits = LimitProfile {
        max_document_bytes: (bytes.len() - 1) as u64,
        ..ABILITY_LIMITS_V1
    };

    assert!(matches!(
        decode_canonical::<InterfaceDocument>(&bytes, limits, &BTreeSet::new()),
        Err(DocumentError::Limit { .. })
    ));
}

#[test]
fn encoding_rejects_programmatic_schema_depth_before_serialization() {
    let mut document = interface_document();
    let mut schema = ValueSchema::Boolean;
    for _ in 0..=ABILITY_LIMITS_V1.max_structural_depth {
        schema = ValueSchema::Optional {
            value: Box::new(schema),
        };
    }
    document.interface.request = schema;

    assert!(matches!(
        encode_canonical(&document),
        Err(DocumentError::Limit {
            limit: "structural depth",
            ..
        })
    ));
}

fn package_option(path: &str, option_type: OptionType) -> PackageOptionDeclaration {
    PackageOptionDeclaration {
        path: vec![path.to_string()],
        type_signature: "test option".to_string(),
        structured_type: option_type,
        description: "Test option declaration.".to_string(),
        default: None,
        example: None,
        visibility: OptionVisibility::Public,
        read_only: false,
        extensible: false,
        deprecated: None,
        replacement: None,
        source: OptionSource {
            path: RelativePath::new("module.nix").expect("valid option source path"),
        },
    }
}

#[test]
fn package_option_declarations_reject_opaque_public_types() {
    let declaration = package_option(
        "opaque",
        OptionType::Opaque {
            signature: "unstructured".to_string(),
        },
    );

    assert!(validate_package_option_declarations(&[declaration], &ABILITY_LIMITS_V1).is_err());
}

#[test]
fn package_option_declarations_reject_open_public_submodules() {
    let declaration = package_option(
        "open",
        OptionType::Submodule {
            fields: BTreeMap::new(),
            open: true,
        },
    );

    assert!(validate_package_option_declarations(&[declaration], &ABILITY_LIMITS_V1).is_err());
}

#[test]
fn package_option_declarations_check_literal_defaults_against_the_type() {
    let mut declaration = package_option("enabled", OptionType::Bool);
    declaration.default = Some(DocumentedValue::Literal {
        value: AbilityValue::new(serde_json::json!("yes")).expect("canonical test literal"),
    });

    assert!(validate_package_option_declarations(&[declaration], &ABILITY_LIMITS_V1).is_err());
}

#[test]
fn package_option_declarations_check_refined_defaults() {
    let option_type = OptionType::Refined {
        value: Box::new(OptionType::String {
            pattern: None,
            max_length: Some(16),
        }),
        constraints: vec![ValueConstraint::StringPattern {
            pattern: "[a-z]+".to_string(),
        }],
    };
    let mut declaration = package_option("name", option_type);
    declaration.default = Some(DocumentedValue::Literal {
        value: AbilityValue::new(serde_json::json!("INVALID")).expect("canonical test literal"),
    });

    assert!(validate_package_option_declarations(&[declaration], &ABILITY_LIMITS_V1).is_err());
}

#[test]
fn package_option_declarations_reject_incompatible_refinements() {
    let declaration = package_option(
        "invalid-refinement",
        OptionType::Refined {
            value: Box::new(OptionType::Bool),
            constraints: vec![ValueConstraint::MinimumSize { minimum: 1 }],
        },
    );

    assert!(validate_package_option_declarations(&[declaration], &ABILITY_LIMITS_V1).is_err());
}

#[test]
fn package_option_declarations_require_strict_path_order() {
    let first = package_option("same", OptionType::Bool);
    let second = first.clone();

    assert!(validate_package_option_declarations(&[first, second], &ABILITY_LIMITS_V1).is_err());
}

#[test]
fn package_option_declarations_accept_bounded_multiline_prose() {
    let mut declaration = package_option("multiline", OptionType::Bool);
    declaration.description = "First paragraph.\n\nSecond paragraph.".to_string();

    validate_package_option_declarations(&[declaration], &ABILITY_LIMITS_V1)
        .expect("bounded documentation prose");
}

#[test]
fn package_option_declarations_reject_non_prose_control_characters() {
    let mut declaration = package_option("control", OptionType::Bool);
    declaration.description = "Invalid\0description".to_string();

    assert!(validate_package_option_declarations(&[declaration], &ABILITY_LIMITS_V1).is_err());
}

#[test]
fn shared_nix_fixture_round_trips_canonically() -> Result<(), DocumentError> {
    let bytes = include_bytes!("../../../tests/abilities/fixtures/interface.json");
    let supported_features =
        BTreeSet::from([RequiredFeature::new("abilities-v1").expect("valid test feature")]);
    let document =
        decode_canonical::<InterfaceDocument>(bytes, ABILITY_LIMITS_V1, &supported_features)?;

    assert_eq!(encode_canonical(&document)?, bytes);
    assert_eq!(
        document.interface_key()?.descriptor.to_string(),
        "sha256:a178ff66b89a0543d28a49000b548e9f01d75170aa1d32489ebd633d03e51374"
    );
    Ok(())
}
