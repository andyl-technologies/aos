//! Exercises original revocation fences, without acceptance or native effects.

// crucible-lint: allow panic-shortcut -- Inert scope fixtures deliberately panic on invalid records or failed revocation assertions.
#![allow(clippy::unwrap_used)]

use std::cell::Cell;

use super::*;
use crucible_engine::node_contract::{
    InstalledProviderRevision, ProviderPlanningRequest, ProviderPreparationPlan,
    ProviderRegistryLimits,
};
use crucible_node_format::{Extensions, Id, LiveAuthority, ResourceLimits, U64, canonical};
use crucible_node_transport::reference_service::ReferenceProfile;

fn scope() -> ProviderAuthorizationScope {
    let artifact =
        canonical::content_ref(b"inert scope fixture", "application/octet-stream").unwrap();
    let profile = ReferenceProfile::build_closed(
        Id::new("node").unwrap(),
        Id::new("owner").unwrap(),
        artifact.clone(),
        artifact.clone(),
        U64::new(1000),
        U64::new(1_000_000),
    )
    .unwrap();
    let authority = LiveAuthority {
        schema_version: 1,
        session_id: Id::new("session").unwrap(),
        incarnation_id: Id::new("incarnation").unwrap(),
        realization_id: Id::new("realization").unwrap(),
        activation_id: None,
        world_generation: U64::new(0),
        owner_generation: U64::new(1),
        input_epoch: Id::new("epoch").unwrap(),
        host_receipt: artifact,
        extensions: Extensions::new(),
    };
    let (binding, _) = profile.bind(authority).unwrap();
    let nodes = [profile.descriptor.id.clone()];
    let resources = ResourceLimits {
        cpu_budget_ns: U64::new(1_000_000),
        memory_bytes: U64::new(64 * 1024 * 1024),
        writable_bytes: U64::new(1024),
        processes: U64::new(1),
        descriptors: U64::new(8),
        pending_events: U64::new(1),
        content_bytes: U64::new(1024 * 1024),
        maximum_operations: U64::new(8),
        extensions: Extensions::new(),
    };
    ProviderAuthorizationScope::from_plan(
        ProviderPlanningRequest {
            profile: &profile.node_manifest.profile_id,
            configuration: &profile.configuration_ref,
            nodes: &nodes,
            resources: &resources,
            limits: ProviderRegistryLimits::default(),
        },
        &ProviderPreparationPlan {
            descriptors: vec![profile.descriptor],
            bindings: vec![binding.compatibility],
        },
    )
    .unwrap()
}

#[test]
fn later_behavioral_withdrawal_refuses_before_preparation_or_birth() {
    let scope = scope();
    let source = InstalledProviderRevision::new(scope.clone(), ProviderAuthorityKind::Source);
    let behavioral =
        InstalledProviderRevision::new(scope.clone(), ProviderAuthorityKind::Behavioral);
    let class = InstalledProviderRevision::new(scope.clone(), ProviderAuthorityKind::CatalogClass);
    let preparations = Cell::new(0);
    let births = Cell::new(0);

    let authorized = original_behavioral(
        &scope,
        || Ok(source.lease()),
        || {
            source.revoke();
            Ok(behavioral.lease())
        },
        || Ok(class.lease()),
    );
    if authorized.is_ok() {
        preparations.set(preparations.get() + 1);
        births.set(births.get() + 1);
    }

    assert!(authorized.is_err());
    assert_eq!(preparations.get(), 0);
    assert_eq!(births.get(), 0);
}

#[test]
fn original_behavioral_withdrawal_and_foreign_kind_remain_refused() {
    let scope = scope();
    let source = InstalledProviderRevision::new(scope.clone(), ProviderAuthorityKind::Source);
    let behavioral =
        InstalledProviderRevision::new(scope.clone(), ProviderAuthorityKind::Behavioral);
    let class = InstalledProviderRevision::new(scope.clone(), ProviderAuthorityKind::CatalogClass);
    let lease = original_behavioral(
        &scope,
        || Ok(source.lease()),
        || Ok(behavioral.lease()),
        || Ok(class.lease()),
    )
    .unwrap();
    lease
        .authenticate(&scope, ProviderAuthorityKind::Behavioral)
        .unwrap();

    behavioral.revoke();
    assert!(
        lease
            .authenticate(&scope, ProviderAuthorityKind::Behavioral)
            .is_err()
    );
    assert!(
        original_behavioral(
            &scope,
            || Ok(source.lease()),
            || Ok(class.lease()),
            || Ok(class.lease())
        )
        .is_err()
    );
}

#[test]
fn late_preflight_withdrawal_refuses_the_actual_birth_gate() {
    let scope = scope();
    let source = InstalledProviderRevision::new(scope.clone(), ProviderAuthorityKind::Source);
    let behavioral =
        InstalledProviderRevision::new(scope.clone(), ProviderAuthorityKind::Behavioral);
    let class = InstalledProviderRevision::new(scope.clone(), ProviderAuthorityKind::CatalogClass);
    let original = OriginalBirthCurrency {
        scope: scope.clone(),
        source: source.lease(),
        behavioral: behavioral.lease(),
        class: class.lease(),
    };
    original.authenticate().unwrap();
    let spawns = Cell::new(0);

    // A repeated normal-policy preflight callback withdraws an owner after the
    // registry's earlier terminal check. Actual production uses this same gate.
    class.revoke();
    let result = original.before_birth(|| {
        spawns.set(spawns.get() + 1);
        Ok(())
    });

    assert!(result.is_err());
    assert_eq!(spawns.get(), 0);
    assert!(
        original
            .class
            .authenticate(&scope, ProviderAuthorityKind::CatalogClass)
            .is_err()
    );
}
