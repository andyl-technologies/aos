//! Verifies that the pure Rust DTOs accept exactly the canonical Nix interface projection.

use std::collections::BTreeSet;

use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, InterfaceDocument, ValueExpression, ValueSchema,
    decode_canonical,
};
use aos_ability_validate::validate_value;
use aos_package_store_model::{
    STORE_VIEW_OBSERVATION_SCHEMA, StoreViewLocator, StoreViewObservation, StoreViewRequest,
    StoreViewScope, StoreViewState,
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

const INTERFACE: &[u8] = include_bytes!("fixtures/package-store-read-view-interface.json");

fn literal(value: Value) -> ValueExpression {
    ValueExpression::Literal {
        value: AbilityValue::new(value).expect("canonical fixture value"),
    }
}

fn validate_dto<T: serde::Serialize>(schema: &ValueSchema, value: &T) {
    let value = serde_json::to_value(value).expect("serialize DTO");
    validate_value(schema, &literal(value)).expect("DTO must satisfy the Nix-authored schema");
}

fn assert_schema_values_decode<T: DeserializeOwned>(schema: &ValueSchema) {
    for value in representative_values(schema) {
        serde_json::from_value::<T>(value).unwrap_or_else(|error| {
            panic!("Nix-authored schema admits a value outside the DTO: {error}")
        });
    }
}

fn representative_values(schema: &ValueSchema) -> Vec<Value> {
    match schema {
        ValueSchema::StringEnum { values } => values.iter().cloned().map(Value::String).collect(),
        ValueSchema::String { .. } => vec![Value::String("/fixture/path".into())],
        ValueSchema::Record {
            fields,
            optional_fields,
        } => {
            assert!(
                optional_fields.is_empty(),
                "fixture DTO records must remain closed and required"
            );
            let mut products = vec![Map::new()];
            for (name, field_schema) in fields {
                let values = representative_values(field_schema);
                products = products
                    .into_iter()
                    .flat_map(|record| {
                        values.iter().cloned().map(move |value| {
                            let mut next = record.clone();
                            next.insert(name.to_string(), value);
                            next
                        })
                    })
                    .collect();
            }
            products.into_iter().map(Value::Object).collect()
        }
        other => panic!("unsupported store-view DTO schema in fixture: {other:?}"),
    }
}

fn interface() -> InterfaceDocument {
    decode_canonical(INTERFACE, ABILITY_LIMITS_V1, &BTreeSet::new())
        .expect("canonical Nix interface fixture")
}

fn locator() -> StoreViewLocator {
    StoreViewLocator::new(
        "/nix/store".into(),
        "/immutable/store".into(),
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-contract/contract.json".into(),
    )
    .expect("valid locator")
}

#[test]
fn request_locator_and_observation_match_the_nix_interface() {
    let interface = interface();
    assert_eq!(
        interface.interface.name.as_str(),
        "aos.package-store.read-view"
    );
    let observe = &interface.interface.methods["observe"];
    let locator_schema = &interface.interface.outputs["locator"].schema;
    let observation_schema = &observe.outputs["observation"].schema;

    let request = StoreViewRequest {
        scope: StoreViewScope::BootImage,
    };
    validate_dto(&interface.interface.request, &request);
    validate_dto(&observe.parameters, &request);
    validate_dto(locator_schema, &locator());

    for state in [
        StoreViewState::Available,
        StoreViewState::Unavailable,
        StoreViewState::Unknown,
    ] {
        let observation = StoreViewObservation {
            schema: STORE_VIEW_OBSERVATION_SCHEMA.into(),
            expected: request.clone(),
            locator: locator(),
            state,
        };
        observation.validate().expect("valid observation");
        validate_dto(observation_schema, &observation);
        validate_dto(&observe.outcome.completion_evidence, &observation);
        validate_dto(&observe.outcome.observation_evidence, &observation);
    }

    assert_schema_values_decode::<StoreViewRequest>(&interface.interface.request);
    assert_schema_values_decode::<StoreViewLocator>(locator_schema);
    assert_schema_values_decode::<StoreViewObservation>(observation_schema);
}

#[test]
fn fixture_remains_a_closed_single_method_interface() {
    let interface = interface();
    assert_eq!(
        interface
            .interface
            .methods
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["observe"]
    );
    assert_eq!(
        interface
            .interface
            .outputs
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["locator", "read-view-resource"]
    );
    assert_eq!(
        serde_json::to_value(StoreViewRequest {
            scope: StoreViewScope::BootImage,
        })
        .expect("request"),
        json!({"scope": "boot-image"})
    );
}
