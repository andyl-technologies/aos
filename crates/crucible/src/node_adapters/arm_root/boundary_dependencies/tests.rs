//! Checks original two-role codec geometry using data-only ledger fixtures.
//!
//! These fixtures have no native process, installed certificate or live authority.

// crucible-lint: allow panic-shortcut -- Data-only role assertions stop on their original malformed inventory invariant.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::{Id, Phase, Position, U64};
use serde_json::{Value, json};

struct Fixture {
    objects: Vec<InputPayload>,
    roots: Vec<ContentRef>,
    activation: SavedRuntimeActivation,
    owners: Vec<OwnerIdentity>,
    boundary: Gem5Boundary,
}

fn object(value: Value) -> InputPayload {
    let bytes = canonical::canonical_json(&value).unwrap();
    InputPayload {
        reference: canonical::content_ref(&bytes, "application/json").unwrap(),
        bytes,
    }
}

fn fixture() -> Fixture {
    let closure = object(json!({
        "schema":"crucible.gem5.process-closure-mechanism.v1",
        "profile":super::super::ARM_ROOT_MODEL, "guest_isa":"aarch64",
        "byte_closure_complete":true, "execution_admission_qualified":false,
        "modeled_diagnostics_complete":false, "full_system_admission_qualified":false,
        "omissions":[],
    }));
    let owner = OwnerIdentity {
        owner: Id::new("owner/root").unwrap(),
        incarnation: Id::new("original/root").unwrap(),
        generation: U64::new(1),
    };
    let owners = vec![owner];
    let position = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    let activation = SavedRuntimeActivation {
        generation: U64::new(1),
        activation_id: Id::new("original/activation").unwrap(),
        world_binding_hash: closure.reference.hash.clone(),
        owners: owners.clone(),
        boundary: position,
    };
    let boundary = Gem5Boundary {
        tick: U64::new(0),
        logical_position: position,
        ordinal: U64::new(0),
        tick_ordinal: U64::new(0),
        has_next_event: false,
        next_tick: U64::new(0),
        next_priority: 0,
        inventory: Value::Null,
    };
    let root = object(json!({
        "schema":"crucible.gem5.arm-root-observation.v1", "boundary":boundary,
        "closure":closure.reference, "owners":owners, "activation":activation,
    }));
    Fixture {
        roots: vec![root.reference.clone()],
        objects: vec![root, closure],
        activation,
        owners,
        boundary,
    }
}

impl Fixture {
    fn dependencies(
        &self,
        limits: InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        authenticate_roles(
            &self.objects,
            &self.roots,
            &self.objects[0].reference,
            &self.activation,
            &self.owners,
            &self.boundary,
            limits,
        )
    }

    fn limits(&self) -> InputProvenanceLimits {
        InputProvenanceLimits {
            maximum_objects: 2,
            maximum_bytes: self.objects.iter().map(|object| object.bytes.len()).sum(),
        }
    }
}

#[test]
fn complete_original_roles_are_selected_before_count_and_byte_credit_exhaustion() {
    let fixture = fixture();
    let limits = fixture.limits();
    assert_eq!(
        fixture.dependencies(limits).unwrap(),
        vec![fixture.objects[1].reference.clone()]
    );
    assert!(
        fixture
            .dependencies(InputProvenanceLimits {
                maximum_objects: 1,
                ..limits
            })
            .is_err()
    );
    assert!(
        fixture
            .dependencies(InputProvenanceLimits {
                maximum_bytes: limits.maximum_bytes - 1,
                ..limits
            })
            .is_err()
    );
    assert_eq!(
        fixture.dependencies(limits).unwrap(),
        vec![fixture.objects[1].reference.clone()]
    );
}

#[test]
fn missing_duplicate_corrupt_and_foreign_original_roles_refuse() {
    let mut original = fixture();
    let limits = original.limits();
    original.roots.clear();
    assert!(original.dependencies(limits).is_err());

    let mut original = fixture();
    original.objects.remove(1);
    assert!(original.dependencies(limits).is_err());

    let mut original = fixture();
    original.objects[1].bytes[0] ^= 1;
    assert!(original.dependencies(limits).is_err());

    let mut original = fixture();
    original.objects.push(original.objects[1].clone());
    assert!(original.dependencies(limits).is_err());

    let mut original = fixture();
    original.activation.activation_id = Id::new("foreign/activation").unwrap();
    assert!(original.dependencies(limits).is_err());

    let mut original = fixture();
    original.owners[0].incarnation = Id::new("foreign/incarnation").unwrap();
    assert!(original.dependencies(limits).is_err());
}

#[test]
fn rehashed_observation_and_audit_codec_changes_remain_refused() {
    for field in ["boundary", "closure", "unexpected"] {
        let mut original = fixture();
        let mut value: Value = serde_json::from_slice(&original.objects[0].bytes).unwrap();
        match field {
            "boundary" => value["boundary"]["tick"] = "1".into(),
            "closure" => {
                value["closure"] =
                    serde_json::to_value(&object(json!({"foreign":true})).reference).unwrap()
            }
            _ => value["unexpected"] = true.into(),
        }
        original.objects[0] = object(value);
        original.roots = vec![original.objects[0].reference.clone()];
        assert!(
            original
                .dependencies(InputProvenanceLimits::default())
                .is_err()
        );
    }

    let mut original = fixture();
    let mut audit: Value = serde_json::from_slice(&original.objects[1].bytes).unwrap();
    audit["profile"] = "foreign-model".into();
    original.objects[1] = object(audit);
    let mut value: Value = serde_json::from_slice(&original.objects[0].bytes).unwrap();
    value["closure"] = serde_json::to_value(&original.objects[1].reference).unwrap();
    original.objects[0] = object(value);
    original.roots = vec![original.objects[0].reference.clone()];
    assert!(
        original
            .dependencies(InputProvenanceLimits::default())
            .is_err()
    );
}
