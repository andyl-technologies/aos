//! Reviews immutable qualification scope using a measured installed package.
//!
//! These tests validate source policy and canonical data. They never spawn a
//! provider, produce a behavioral qualification report, or establish Ready.
//! The fixture path is test-only; production installation remains compile-pinned.

// crucible-lint: allow panic-shortcut -- These qualification review tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{path::Path, rc::Rc};

use crucible::node_admission::{ConnectionDelivery, ConnectionPolicy, CoordinatorPolicy};
use crucible_node_contract::{
    Bytes, CaptureScope, ContentRef, Continuation, Id, OperatingMode, Repeatability, U64, canonical,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use super::super::{
    candidate::PrivateCandidate,
    criteria::ReferenceQualificationCriteria,
    installation::SourcePublicReferenceInstallation,
    unit::{SemanticQualificationUnit, UnitSourceObjects, required_features},
};
use super::InstalledPublicReferencePackage;

fn package() -> Rc<InstalledPublicReferencePackage> {
    let path = std::env::var_os("CRUCIBLE_REFERENCE_REVIEW_MANIFEST")
        .expect("set the explicit source-built implementation fixture manifest");
    Rc::new(InstalledPublicReferencePackage::load_installed(Path::new(&path)).unwrap())
}

fn candidate(package: &Rc<InstalledPublicReferencePackage>, namespace: u8) -> PrivateCandidate {
    PrivateCandidate::with_nonce(
        Rc::clone(package),
        U64::new(1000),
        U64::new(1_000_000_000),
        Bytes::new(vec![namespace; 32]),
    )
    .unwrap()
}

fn sources() -> UnitSourceObjects {
    // Deliberately inert source-context objects. The installed issuer must
    // authenticate real source identities independently of this codec.
    let object = |role| {
        canonical::canonical_json(&json!({
            "schema": "qualification-review-context.v1",
            "role": role,
            "evidence_scope": "policy-data-only"
        }))
        .unwrap()
    };
    UnitSourceObjects {
        environment: object("environment"),
        harness: object("harness"),
        fixtures: object("fixtures"),
        specification: object("specification"),
    }
}

fn unit(
    package: &Rc<InstalledPublicReferencePackage>,
    candidate: &PrivateCandidate,
) -> SemanticQualificationUnit {
    SemanticQualificationUnit::build(
        Rc::clone(package),
        &candidate.definition,
        &candidate.installations,
        sources(),
    )
    .unwrap()
}

fn assert_rejected(package: &Rc<InstalledPublicReferencePackage>, candidate: &PrivateCandidate) {
    assert!(
        SemanticQualificationUnit::build(
            Rc::clone(package),
            &candidate.definition,
            &candidate.installations,
            sources(),
        )
        .is_err()
    );
}

fn read_object<T: DeserializeOwned>(candidate: &PrivateCandidate, reference: &ContentRef) -> T {
    let bytes = candidate.definition.content.get(reference).unwrap();
    reference.verify(bytes).unwrap();
    serde_json::from_slice(bytes).unwrap()
}

fn replace_object<T: Serialize>(
    candidate: &mut PrivateCandidate,
    original: &ContentRef,
    value: &T,
) -> ContentRef {
    let bytes = canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    assert_ne!(&reference, original);

    candidate.definition.content.remove(original).unwrap();
    candidate
        .definition
        .content
        .insert(reference.clone(), bytes);
    reference
}

#[test]
#[ignore = "requires explicitly selected source-built installed package; policy/data only"]
fn fresh_live_namespaces_preserve_the_complete_semantic_unit() {
    let package = package();
    let first = candidate(&package, 1);
    let second = candidate(&package, 2);

    for (left, right) in first.installations.iter().zip(&second.installations) {
        assert_ne!(
            left.bootstrap.authority.session_id,
            right.bootstrap.authority.session_id
        );
        assert_ne!(
            left.bootstrap.authority.incarnation_id,
            right.bootstrap.authority.incarnation_id
        );
        assert!(left.enrollment().is_err());
        assert!(right.enrollment().is_err());
    }

    let left = unit(&package, &first);
    let right = unit(&package, &second);
    assert_eq!(left.identity, right.identity);
    assert_eq!(left.objects, right.objects);
    for (reference, bytes) in &left.objects {
        reference.verify(bytes).unwrap();
        if reference.media_type == "application/json" {
            let value = canonical::parse_json(bytes, 1_048_576).unwrap();
            assert_eq!(canonical::canonical_json(&value).unwrap(), *bytes);
        }
    }
}

#[test]
#[ignore = "requires explicitly selected source-built installed package; policy/data only"]
fn resource_and_transport_limits_bind_the_realization_unit() {
    let package = package();
    let mut scope = candidate(&package, 3);
    let baseline = unit(&package, &scope).identity;
    let original = scope.installations[0].bootstrap.resource_limits.clone();

    scope.installations[0]
        .bootstrap
        .resource_limits
        .memory_bytes = U64::new(256 * 1024 * 1024);
    let changed_resource = unit(&package, &scope).identity;
    assert_ne!(baseline.realization, changed_resource.realization);
    assert_eq!(baseline.implementation, changed_resource.implementation);
    assert_eq!(baseline.contracts, changed_resource.contracts);

    scope.installations[0].bootstrap.resource_limits = original;
    scope.installations[0].bootstrap.limits.requests = U64::new(8);
    let changed_transport = unit(&package, &scope).identity;
    assert_ne!(baseline.realization, changed_transport.realization);
    assert_ne!(changed_resource.realization, changed_transport.realization);
    assert_eq!(baseline.descriptors, changed_transport.descriptors);
}

#[test]
#[ignore = "requires explicitly selected source-built installed package; policy/data only"]
fn source_context_axes_retain_exact_original_bytes() {
    let package = package();
    let scope = candidate(&package, 4);
    let baseline = unit(&package, &scope).identity;
    let mut changed = sources();
    changed.harness = canonical::canonical_json(&json!({
        "schema": "qualification-review-context.v1",
        "role": "harness",
        "revision": "different-original",
        "evidence_scope": "policy-data-only"
    }))
    .unwrap();
    let changed = SemanticQualificationUnit::build(
        Rc::clone(&package),
        &scope.definition,
        &scope.installations,
        changed,
    )
    .unwrap();

    assert_ne!(baseline.harness, changed.identity.harness);
    assert_eq!(baseline.environment, changed.identity.environment);
    assert_eq!(baseline.fixtures, changed.identity.fixtures);
    assert_eq!(baseline.specification, changed.identity.specification);
    assert_eq!(baseline.realization, changed.identity.realization);
    let bytes = changed.objects.get(&changed.identity.harness).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(bytes).unwrap()["revision"],
        "different-original"
    );
}

#[test]
#[ignore = "requires explicitly selected source-built installed package; policy/data only"]
fn internally_rehashed_route_policy_cannot_expand_the_fixed_source_scope() {
    let package = package();
    let mut changed_credit = candidate(&package, 5);
    let original = changed_credit.definition.world.connections[0]
        .policy_ref
        .clone();
    let mut policy: ConnectionPolicy = read_object(&changed_credit, &original);
    policy.maximum_pending_events = U64::new(2);
    let replacement = replace_object(&mut changed_credit, &original, &policy);
    changed_credit.definition.world.connections[0].policy_ref = replacement;
    assert_rejected(&package, &changed_credit);

    let mut changed_latency = candidate(&package, 6);
    let original = changed_latency.definition.world.connections[0]
        .policy_ref
        .clone();
    let mut policy: ConnectionPolicy = read_object(&changed_latency, &original);
    policy.delivery = ConnectionDelivery::Fixed {
        latency_ps: U64::new(1000),
    };
    let replacement = replace_object(&mut changed_latency, &original, &policy);
    let connection = &mut changed_latency.definition.world.connections[0];
    connection.policy_ref = replacement;
    connection.minimum_latency_ps = U64::new(1000);
    assert_rejected(&package, &changed_latency);

    let mut changed_endpoint = candidate(&package, 7);
    changed_endpoint.definition.world.connections[0]
        .producer
        .node_id = Id::new("consumer").unwrap();
    assert_rejected(&package, &changed_endpoint);
}

#[test]
#[ignore = "requires explicitly selected source-built installed package; policy/data only"]
fn rehashed_coordinator_and_scenario_policies_cannot_change_applicability() {
    let package = package();
    let mut coordinator = candidate(&package, 8);
    let original = coordinator
        .definition
        .world
        .coordinator_contract_ref
        .clone();
    let mut policy: CoordinatorPolicy = read_object(&coordinator, &original);
    policy.maximum_microsteps_per_instant = U64::new(2048);
    coordinator.definition.world.coordinator_contract_ref =
        replace_object(&mut coordinator, &original, &policy);
    assert_rejected(&package, &coordinator);

    let mut scenario = candidate(&package, 9);
    scenario
        .definition
        .requirements
        .accepted_visibility_conversions
        .clear();
    let original = scenario.definition.world.scenario_ref.clone();
    let bytes = canonical::canonical_json(
        &serde_json::to_value(&scenario.definition.requirements).unwrap(),
    )
    .unwrap();
    let replacement = canonical::content_ref(&bytes, "application/json").unwrap();
    scenario.definition.content.remove(&original).unwrap();
    scenario
        .definition
        .content
        .insert(replacement.clone(), bytes);
    scenario.definition.world.scenario_ref = replacement;
    assert_rejected(&package, &scenario);
}

#[test]
#[ignore = "requires explicitly selected source-built installed package; policy/data only"]
fn changed_provider_declarations_and_profile_bytes_are_not_normalized_away() {
    let package = package();
    let mut provider = candidate(&package, 10);
    provider.installations[0]
        .profile
        .provider_manifest
        .provider_id = Id::new("other-provider").unwrap();
    assert_rejected(&package, &provider);

    let mut profile = candidate(&package, 11);
    profile.installations[0].profile.descriptor.roles = vec![Id::new("different-role").unwrap()];
    assert_rejected(&package, &profile);

    let mut descriptor = candidate(&package, 12);
    descriptor.definition.descriptors[0].roles = vec![Id::new("different-role").unwrap()];
    assert_rejected(&package, &descriptor);

    let mut schema = candidate(&package, 14);
    schema.installations[0].profile.content_possession_schema.id =
        Id::new("different-possession-schema").unwrap();
    assert_rejected(&package, &schema);

    let mut body = candidate(&package, 15);
    let configuration = body.installations[0].profile.configuration_ref.clone();
    body.installations[0]
        .profile
        .contents
        .get_mut(&configuration.hash.digest)
        .unwrap()
        .1
        .push(b' ');
    assert_rejected(&package, &body);

    // A correctly hashed extra catalog object is still outside the installed
    // source catalog. Integrity alone does not authenticate selected semantics.
    let mut catalog = candidate(&package, 16);
    let bytes = canonical::canonical_json(&json!({"unqualified_catalog_entry": true})).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    catalog.installations[0]
        .profile
        .contents
        .insert(reference.hash.digest.clone(), (reference, bytes));
    assert_rejected(&package, &catalog);
}

#[test]
#[ignore = "requires explicitly selected source-built installed package; policy/data only"]
fn declaration_without_original_candidate_bytes_cannot_install_or_enroll() {
    let package = package();
    let scope = candidate(&package, 13);
    let installed = &scope.installations[0];
    let mut bootstrap = installed.bootstrap.clone();
    bootstrap
        .installed_content
        .retain(|object| !installed.qualifications.contains(&object.reference));

    assert!(
        SourcePublicReferenceInstallation::new(
            Rc::clone(&package),
            installed.profile.clone(),
            bootstrap,
            installed.qualifications.clone(),
            false,
        )
        .is_err()
    );
    assert!(installed.enrollment().is_err());

    let semantic = unit(&package, &scope);
    let realization: Value = serde_json::from_slice(
        semantic
            .objects
            .get(&semantic.identity.realization)
            .unwrap(),
    )
    .unwrap();
    let expected = serde_json::to_value(required_features().unwrap()).unwrap();
    for node in realization["nodes"].as_array().unwrap() {
        assert_eq!(node["selected_features"], expected);
        assert!(node.get("enrollment").is_none());
        assert!(node.get("authority").is_none());
        assert!(node["provider"].get("qualification_refs").is_none());
    }
}

#[test]
#[ignore = "requires explicitly selected source-built installed package; policy/data only"]
fn fixed_applicability_scope_matches_actual_regenerated_source_declarations() {
    let package = package();
    let scope = candidate(&package, 17);
    for installed in &scope.installations {
        assert_eq!(
            installed.profile.operating_contract.mode,
            OperatingMode::Quantized
        );
        let guarantees = &installed.profile.guarantees;
        assert_eq!(guarantees.repeatability, Repeatability::Nondeterministic);
        assert_eq!(guarantees.capture_scope, CaptureScope::None);
        assert_eq!(guarantees.continuation, Continuation::Unsupported);
        assert!(!guarantees.durable_restart);
        assert!(!guarantees.isolated_fork);
        assert!(!guarantees.conditional_replay);
    }
    let mut context = sources();
    context.specification = crate::node_qualification::normative_specification()
        .unwrap()
        .1;
    let semantic = SemanticQualificationUnit::build(
        Rc::clone(&package),
        &scope.definition,
        &scope.installations,
        context,
    )
    .unwrap();
    let criteria = ReferenceQualificationCriteria::build(semantic.identity.clone()).unwrap();

    assert_eq!(criteria.plan.unit, semantic.identity);
    assert_eq!(criteria.plan.requirements.len(), 382);
    assert_eq!(criteria.plan.cases.len(), 374);
    assert!(criteria.plan.requirements.values().all(|criterion| {
        match criterion {
            crate::node_qualification::WitnessCriterion::Applicable { cases, .. } => cases
                .iter()
                .any(|case| case.starts_with("reference/review/")),
            crate::node_qualification::WitnessCriterion::NotApplicable { reason, .. } => {
                !reason.is_empty()
            }
        }
    }));
}
