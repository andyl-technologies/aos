//! Durable owner selection and adoption preflight tests.

use super::*;

#[test]
fn operation_scope_cannot_select_or_spoof_a_provider_owner() {
    let plan = checked_systemd_manager_effect_plan();
    let binding = plan
        .binding_plan()
        .binding(&plan.operations()[0].binding)
        .expect("fixture binding");
    let mut operation = plan.operations()[0].clone();
    operation.key.scope = ScopePath::new(vec![
        binding.request.consumer.key.clone(),
        key("nested"),
        key("arbitrary-descriptor-spoof"),
    ])
    .expect("valid nested scope");

    assert_eq!(
        operation_provider_owner(binding, &operation),
        Some(&binding.request.consumer)
    );

    operation.key.scope = ScopePath::new(vec![key("foreign"), key("forged-descriptor")])
        .expect("valid spoofed scope");
    assert_eq!(
        operation_provider_owner(binding, &operation),
        Some(&binding.request.consumer)
    );

    operation.target.resource.provider.key = key("other-owner");
    assert_eq!(operation_provider_owner(binding, &operation), None);
}

#[test]
fn preflight_rejects_a_consumer_outside_the_desired_current_union() {
    let fixture = adoption_inventory_fixture();
    let mut orphan = fixture.candidate_consumer(RevisionId(aos_contract::Sha256Digest::of_bytes(
        "orphan revision",
    )));
    orphan.logical.key = key("orphan-consumer");
    orphan.physical.object = "/org/freedesktop/systemd1/unit/orphan_2eservice".to_string();
    orphan.owner = None;
    fixture
        .save_full_ledger(vec![fixture.source_owner()], vec![orphan])
        .expect("orphan consumer ledger");
    let before = std::fs::read(&fixture.state.ledger_path).expect("orphan ledger bytes");

    let error = fixture
        .state
        .preflight_provider_owners_for_current(|resource| resource == &fixture.resource)
        .expect_err("an unselected retained consumer must fail preflight");

    assert!(error.to_string().contains("consumer outside"), "{error}");
    assert_eq!(
        std::fs::read(&fixture.state.ledger_path).expect("unchanged orphan ledger bytes"),
        before
    );
}

#[test]
fn owner_only_endpoint_requires_the_exact_selected_owner_binding() {
    let plan = checked_systemd_manager_effect_plan();
    let operation = &plan.operations()[0];
    let mut handler_binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .expect("fixture handler binding")
        .clone();
    let package = aos_contract::Sha256Digest::of_bytes("selected owner package");
    let mut selected_owner = handler_binding.clone();
    handler_binding.provider_package = Some(package);
    selected_owner.provider_package = Some(package);
    let state_format = ProviderStateFormat {
        descriptor: aos_contract::Sha256Digest::of_bytes("selected state format"),
        artifact: selected_owner.implementation.artifact.clone(),
    };
    let candidate = ProviderAdoptionEndpoint {
        provider: selected_owner.provider.clone(),
        package,
        interface: selected_owner.interface.clone(),
        implementation: selected_owner.implementation.clone(),
        state_format: state_format.clone(),
        handler_binding: handler_binding.id.clone(),
        handler_method: operation.method.clone(),
        handler_provider: handler_binding.provider.clone(),
        handler_incarnation: IncarnationId::new("handler-incarnation")
            .expect("valid handler incarnation"),
        handler_interface: handler_binding.interface.clone(),
        handler_implementation: handler_binding.implementation.clone(),
        handler_package: package,
    };
    let mut source = candidate.clone();
    source.package = aos_contract::Sha256Digest::of_bytes("prior owner package");
    source.implementation.descriptor =
        aos_contract::Sha256Digest::of_bytes("prior owner implementation");

    assert_ne!(source.package, candidate.package);
    assert_eq!(
        source.handler_implementation,
        candidate.handler_implementation
    );
    assert_eq!(source.handler_package, candidate.handler_package);

    // The helper accepts only bindings carried by a checked plan. Its exact
    // field predicate distinguishes the selected candidate from the prior
    // owner even though both endpoints retain the same terminal handler.
    assert!(!endpoint_matches_selected_owner(
        std::slice::from_ref(&selected_owner),
        &handler_binding,
        operation,
        &source,
        &candidate.handler_binding,
        true,
    ));
    assert!(endpoint_matches_selected_owner(
        std::slice::from_ref(&selected_owner),
        &handler_binding,
        operation,
        &candidate,
        &candidate.handler_binding,
        true,
    ));
}

#[test]
fn durable_handler_identity_ignores_plan_local_binding_and_method() {
    let fixture = adoption_inventory_fixture();
    let candidate = &fixture.state.adoptions[0].candidate;
    let mut teardown = candidate.clone();
    teardown.handler_binding = BindingId(key("teardown-binding"));
    teardown.handler_method = key("stop");

    assert_eq!(
        handler_from_endpoint(candidate),
        handler_from_endpoint(&teardown)
    );

    teardown.handler_incarnation =
        IncarnationId::new("replacement-checked-incarnation").expect("valid incarnation");
    assert_eq!(
        handler_from_endpoint(candidate),
        handler_from_endpoint(&teardown)
    );

    teardown.handler_implementation.descriptor =
        aos_contract::Sha256Digest::of_bytes("replacement handler implementation");
    assert_ne!(
        handler_from_endpoint(candidate),
        handler_from_endpoint(&teardown)
    );
}

#[test]
fn owner_selection_deduplicates_one_core_and_rejects_distinct_cores() {
    let fixture = adoption_inventory_fixture();
    let selection = fixture.state.desired_owner_selections[0].clone();
    assert_eq!(
        unique_provider_owner_selections(vec![selection.clone(), selection.clone()])
            .expect("one handler core may authorize multiple methods")
            .len(),
        1
    );

    let mut distinct = selection.clone();
    distinct.handler.package = aos_contract::Sha256Digest::of_bytes("distinct handler core");
    let error = unique_provider_owner_selections(vec![selection, distinct])
        .expect_err("one resource cannot select distinct handler cores");
    assert!(error.to_string().contains("multiple durable handler"));
}

#[test]
fn one_durable_handler_core_accepts_materialize_start_restart_and_stop() {
    let mut fixture = adoption_inventory_fixture();
    let base_endpoint = fixture.state.adoptions[0].candidate.clone();
    fixture.state.adoptions.clear();
    let candidate = fixture.state.desired_owner_selections[0].identity.clone();
    let mut ledger = NativeResourceLedger {
        schema: NATIVE_RESOURCE_LEDGER_SCHEMA.to_string(),
        owners: Vec::new(),
        consumers: Vec::new(),
    };

    for (index, method) in ["materialize", "start", "restart", "stop"]
        .into_iter()
        .enumerate()
    {
        let mut endpoint = base_endpoint.clone();
        endpoint.handler_binding = BindingId(key(&format!("{method}-binding")));
        endpoint.handler_method = key(method);
        let checked_handler = handler_from_endpoint(&endpoint);
        let changed = fixture
            .state
            .authorize_provider_owner(
                &mut ledger,
                &candidate,
                &fixture.qualified_resource(),
                Some(&checked_handler),
                Some(&fixture.candidate_assignment),
                false,
                &fixture.operation_id(),
                1,
            )
            .unwrap_or_else(|error| panic!("{method} rejected the same core: {error}"));
        assert_eq!(changed, index == 0);
        fixture
            .state
            .replayed_current_effect_intents
            .lock()
            .expect("effect-intent replay set")
            .insert((fixture.operation_id(), 1));
    }
    assert_eq!(ledger.owners.len(), 1);
}

#[test]
fn failed_late_owner_validation_does_not_publish_an_adoption() {
    let mut fixture = adoption_inventory_fixture();
    let unrelated_resource = ResourceId {
        provider: fixture.resource.provider.clone(),
        key: key("unauthorized"),
    };
    let unrelated_candidate = provider_identity(
        &unrelated_resource.provider,
        &fixture.candidate.interface,
        "unrelated-candidate",
        fixture.candidate.state_format.descriptor,
    );
    let (operation_key, operation) = operation_claim(
        &fixture.plan,
        unrelated_resource.clone(),
        BindingId(key("unauthorized-binding")),
        unrelated_candidate.clone(),
        "unauthorized",
    );
    fixture.state.operations.insert(operation_key, operation);
    fixture
        .state
        .desired_owner_selections
        .push(NativeProviderSelection {
            resource: unrelated_resource.clone(),
            identity: unrelated_candidate,
            handler: handler_from_endpoint(&fixture.state.adoptions[0].candidate),
        });
    let mut unrelated_owner = fixture.source_owner();
    unrelated_owner.resource = unrelated_resource.clone();
    unrelated_owner.physical = fixture_physical_resource(&unrelated_resource);
    unrelated_owner.identity = provider_identity(
        &unrelated_resource.provider,
        &fixture.source.interface,
        "unrelated-source",
        fixture.source.state_format.descriptor,
    );
    fixture
        .save_ledger(vec![fixture.source_owner(), unrelated_owner])
        .expect("fixture ledger");
    let before = std::fs::read(&fixture.state.ledger_path).expect("fixture ledger bytes");

    let error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("an unrelated retained owner change must fail");

    assert!(
        error
            .to_string()
            .contains("not an exact successful owner write"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&fixture.state.ledger_path).expect("unchanged ledger bytes"),
        before
    );
}

#[test]
fn exact_handler_assignment_authorizes_atomic_adoption() {
    let fixture = handler_only_adoption_inventory_fixture();
    let adoption = &fixture.state.adoptions[0];
    assert_eq!(
        aos_contract::canonical::to_vec(&NativeProviderIdentity::from_endpoint(&adoption.source))
            .expect("source identity bytes"),
        aos_contract::canonical::to_vec(&NativeProviderIdentity::from_endpoint(
            &adoption.candidate
        ))
        .expect("candidate identity bytes")
    );
    assert_ne!(
        assignment_from_endpoint(&adoption.source),
        assignment_from_endpoint(&adoption.candidate)
    );
    assert_ne!(
        adoption.source.handler_package,
        adoption.candidate.handler_package
    );
    fixture
        .save_ledger(vec![fixture.source_owner()])
        .expect("fixture ledger");

    fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect("exact adoption authority");

    let ledger =
        load_native_resource_ledger(&fixture.state.ledger_path).expect("adopted fixture ledger");
    assert_eq!(ledger.owners.len(), 1);
    assert_eq!(ledger.owners[0].identity, fixture.candidate);
    assert_eq!(
        ledger.owners[0].handler.provider,
        fixture.candidate_assignment.provider
    );
    assert_eq!(
        ledger.owners[0].handler.interface,
        fixture.candidate_assignment.interface
    );
    assert_eq!(
        ledger.owners[0].handler.implementation,
        fixture.candidate_assignment.implementation
    );
    assert_eq!(ledger.owners[0].adoption, Some(fixture.receipt()));
}

#[test]
fn swapping_the_sealed_source_and_candidate_endpoints_fails_closed() {
    let mut fixture = adoption_inventory_fixture();
    let source_owner = fixture.source_owner();
    fixture
        .save_ledger(vec![source_owner])
        .expect("source owner ledger");
    let before = std::fs::read(&fixture.state.ledger_path).expect("source ledger bytes");

    let adoption = &mut fixture.state.adoptions[0];
    std::mem::swap(&mut adoption.source, &mut adoption.candidate);
    let error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("source and candidate endpoints are directional");

    assert!(
        error.to_string().contains("source owner")
            || error.to_string().contains("selected recovery endpoint")
            || error.to_string().contains("exact adoption"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&fixture.state.ledger_path).expect("unchanged source ledger bytes"),
        before
    );
}

#[test]
fn exact_handler_package_replacement_authorizes_atomic_adoption() {
    let fixture = handler_package_only_adoption_inventory_fixture();
    let adoption = &fixture.state.adoptions[0];
    assert_eq!(
        NativeProviderIdentity::from_endpoint(&adoption.source),
        NativeProviderIdentity::from_endpoint(&adoption.candidate)
    );
    assert_eq!(
        assignment_from_endpoint(&adoption.source),
        assignment_from_endpoint(&adoption.candidate)
    );
    assert_eq!(
        adoption.source.handler_binding,
        adoption.candidate.handler_binding
    );
    assert_eq!(
        adoption.source.handler_method,
        adoption.candidate.handler_method
    );
    assert_ne!(
        adoption.source.handler_package,
        adoption.candidate.handler_package
    );
    fixture
        .save_ledger(vec![fixture.source_owner()])
        .expect("fixture ledger");

    fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect("handler-package-only adoption authority");

    let ledger =
        load_native_resource_ledger(&fixture.state.ledger_path).expect("adopted fixture ledger");
    assert_eq!(ledger.owners.len(), 1);
    assert_eq!(ledger.owners[0].identity, fixture.source);
    assert_eq!(
        ledger.owners[0].handler.package,
        adoption.candidate.handler_package
    );
    assert_eq!(ledger.owners[0].adoption, Some(fixture.receipt()));
}

#[test]
fn handler_package_replacement_requires_the_exact_selected_write() {
    let mut fixture = handler_package_only_adoption_inventory_fixture();
    fixture
        .save_ledger(vec![fixture.source_owner()])
        .expect("fixture ledger");
    let before = std::fs::read(&fixture.state.ledger_path).expect("fixture ledger bytes");
    for operation in fixture.state.operations.values_mut() {
        operation.owner_handler = Some(handler_from_endpoint(&fixture.state.adoptions[0].source));
    }

    let error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("a stale handler package cannot acquire the replacement write");

    assert!(
        error
            .to_string()
            .contains("exact checked acquisition operation"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&fixture.state.ledger_path).expect("unchanged ledger bytes"),
        before
    );
}

#[test]
fn exact_owner_identity_authorizes_adoption_with_an_unchanged_handler() {
    let fixture = owner_only_adoption_inventory_fixture();
    let adoption = &fixture.state.adoptions[0];
    assert_ne!(
        NativeProviderIdentity::from_endpoint(&adoption.source),
        NativeProviderIdentity::from_endpoint(&adoption.candidate)
    );
    assert_eq!(
        assignment_from_endpoint(&adoption.source),
        assignment_from_endpoint(&adoption.candidate)
    );
    assert_eq!(
        adoption.source.handler_package,
        adoption.candidate.handler_package
    );
    fixture
        .save_ledger(vec![fixture.source_owner()])
        .expect("fixture ledger");

    fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect("owner-only adoption authority");

    let ledger =
        load_native_resource_ledger(&fixture.state.ledger_path).expect("adopted fixture ledger");
    assert_eq!(ledger.owners.len(), 1);
    assert_eq!(ledger.owners[0].identity, fixture.candidate);
    assert_eq!(
        ledger.owners[0].handler.provider,
        fixture.source_assignment.provider
    );
    assert_eq!(
        ledger.owners[0].handler.interface,
        fixture.source_assignment.interface
    );
    assert_eq!(
        ledger.owners[0].handler.implementation,
        fixture.source_assignment.implementation
    );
    assert_eq!(ledger.owners[0].adoption, Some(fixture.receipt()));
}

#[test]
fn retained_owner_with_no_effect_keeps_its_exact_desired_selection() {
    let mut fixture = adoption_inventory_fixture();
    let incumbent = fixture.source_owner();
    fixture.select_source_owner();
    fixture.state.adoptions.clear();
    fixture.state.operations.clear();
    fixture
        .save_ledger(vec![incumbent.clone()])
        .expect("fixture ledger");

    fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect("unchanged owner selection does not require an effect");

    let ledger =
        load_native_resource_ledger(&fixture.state.ledger_path).expect("retained owner ledger");
    assert_eq!(ledger.owners, vec![incumbent]);
}

#[test]
fn retained_owner_with_no_effect_rejects_a_missing_desired_selection() {
    let mut fixture = adoption_inventory_fixture();
    let incumbent = fixture.source_owner();
    fixture.select_source_owner();
    fixture.state.adoptions.clear();
    fixture.state.operations.clear();
    fixture.state.desired_owner_selections.clear();
    fixture
        .save_ledger(vec![incumbent])
        .expect("fixture ledger");
    let before = std::fs::read(&fixture.state.ledger_path).expect("fixture ledger bytes");

    let error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("missing owner selection must fail");

    assert!(error.to_string().contains("exactly one desired owner"));
    assert_eq!(
        std::fs::read(&fixture.state.ledger_path).expect("unchanged ledger bytes"),
        before
    );
}

#[test]
fn retained_owner_with_no_effect_rejects_owner_or_handler_drift() {
    let mut fixture = adoption_inventory_fixture();
    let incumbent = fixture.source_owner();
    fixture.select_source_owner();
    fixture.state.adoptions.clear();
    fixture.state.operations.clear();
    fixture.state.desired_owner_selections[0].identity.package =
        aos_contract::Sha256Digest::of_bytes("different owner package");
    fixture
        .save_ledger(vec![incumbent.clone()])
        .expect("owner-drift ledger");

    let owner_error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("owner drift must fail");
    assert!(owner_error.to_string().contains("exact selected owner"));

    fixture.state.desired_owner_selections[0].identity = incumbent.identity.clone();
    fixture.state.desired_owner_selections[0].handler.package =
        aos_contract::Sha256Digest::of_bytes("different handler package");
    let handler_error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("handler drift must fail");
    assert!(handler_error.to_string().contains("exact selected owner"));
}

#[test]
fn retained_owner_with_no_effect_rejects_ambiguous_desired_selection() {
    let mut fixture = adoption_inventory_fixture();
    let incumbent = fixture.source_owner();
    fixture.select_source_owner();
    fixture.state.adoptions.clear();
    fixture.state.operations.clear();
    let mut conflicting = fixture.state.desired_owner_selections[0].clone();
    conflicting.handler.package =
        aos_contract::Sha256Digest::of_bytes("conflicting handler package");
    fixture.state.desired_owner_selections.push(conflicting);
    fixture
        .save_ledger(vec![incumbent])
        .expect("ambiguous-selection ledger");

    let error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("ambiguous owner selection must fail");

    assert!(error.to_string().contains("exactly one desired owner"));
}
