//! Shared lifecycle package and planning fixture builders.

use super::*;

pub(super) fn pure_service_package(
    interface: &InterfaceKey,
    version: &str,
    module: ArtifactReference,
    payload: ArtifactReference,
) -> PackageDocument {
    let implementation = ProviderImplementation {
        name: key("service"),
        description: "Pure service test implementation.".to_string(),
        interface: interface.clone(),
        guarantees: Vec::new(),
        artifact: module.clone(),
        requirements: Vec::new(),
        desired_schema: None,
        composition_schema: None,
        provider_module: Some(module_locator(module.clone())),
        handler: None,
        owns_resource_kinds: Vec::new(),
        state_format: None,
    };
    let descriptor = implementation
        .descriptor_digest()
        .expect("pure service implementation must digest");
    let mut artifacts = vec![module.clone(), payload.clone()];
    artifacts.sort_by(|left, right| left.content.cmp(&right.content));
    artifacts.dedup();
    PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: effect_features(),
        package: PackageSubject {
            name: key("upgrade-service"),
            version: version.to_string(),
            payload: payload.clone(),
            source: payload,
        },
        artifacts,
        interfaces: Default::default(),
        guarantees: Default::default(),
        package_module: Some(aos_ability_model::ModuleLocator {
            artifact: module.clone(),
            path: aos_ability_model::RelativePath::new("module.nix")
                .expect("fixture package module path is valid"),
        }),
        option_declarations: Vec::new(),
        exports: vec![ExportDeclaration {
            name: key("service"),
            interface: interface.clone(),
            implementation_name: key("service"),
            implementation: descriptor,
        }],
        requirements: Vec::new(),
        implementation: PackageImplementation {
            providers: vec![implementation],
            handlers: BTreeMap::new(),
        },
        qualification: aos_ability_model::PackageQualification::default(),
    }
}

pub(super) fn terminal_package(
    interface: &InterfaceKey,
    provider: ProviderImplementation,
    artifact: ArtifactReference,
) -> PackageDocument {
    let descriptor = provider
        .descriptor_digest()
        .expect("terminal provider must digest");
    let handler_key = aos_ability_validate::test_support::test_manager_handler_key();
    let handler = aos_ability_validate::test_support::test_manager_handler(artifact.clone());
    PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: effect_features(),
        package: PackageSubject {
            name: key("systemd-terminal"),
            version: "1.0.0".to_string(),
            payload: artifact.clone(),
            source: artifact.clone(),
        },
        artifacts: vec![artifact.clone()],
        interfaces: Default::default(),
        guarantees: Default::default(),
        package_module: Some(aos_ability_model::ModuleLocator {
            artifact: artifact.clone(),
            path: aos_ability_model::RelativePath::new("module.nix")
                .expect("fixture package module path is valid"),
        }),
        option_declarations: Vec::new(),
        exports: vec![ExportDeclaration {
            name: key("manager"),
            interface: interface.clone(),
            implementation_name: key("manager"),
            implementation: descriptor,
        }],
        requirements: Vec::new(),
        implementation: PackageImplementation {
            providers: vec![provider],
            handlers: BTreeMap::from([(handler_key, handler)]),
        },
        qualification: aos_ability_model::PackageQualification::default(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn lifecycle_environment(
    template: &EnvironmentDocument,
    application: &InstanceId,
    old_manager: &InstanceId,
    new_manager: &InstanceId,
    interface: &InterfaceKey,
    implementation: &ProviderImplementationReference,
    old_resource: &ResourceId,
    new_resource: &ResourceId,
    old_controller: &AggregateId,
    new_controller: &AggregateId,
) -> EnvironmentDocument {
    let mut environment = template.clone();
    let mut inventory = template.providers[0].clone();
    inventory.provider = old_manager.clone();
    inventory.interface = interface.clone();
    inventory.implementation = implementation.clone();
    inventory.state = ProviderState::Available;
    let old_inventory = inventory.clone();
    inventory.provider = new_manager.clone();
    let new_inventory = inventory.clone();
    inventory.provider = application.clone();
    inventory.state = ProviderState::Declared;
    inventory.incarnation = None;
    environment.providers = vec![old_inventory, new_inventory, inventory];
    environment.providers.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then_with(|| left.interface.cmp(&right.interface))
    });
    environment.providers.dedup_by(|left, right| {
        left.provider == right.provider && left.interface == right.interface
    });

    environment.resources = vec![
        ResourceRevision {
            resource: old_resource.clone(),
            kind: interface.name.clone(),
            lifetime: ResourceLifetime::Instance,
            value: AbilityValue::new(serde_json::json!(true)).unwrap(),
            realization: AbilityValue::new(serde_json::Value::Null).unwrap(),
            revision: RevisionId(aos_contract::Sha256Digest::of_bytes("old unit revision")),
        },
        ResourceRevision {
            resource: new_resource.clone(),
            kind: interface.name.clone(),
            lifetime: ResourceLifetime::Instance,
            value: AbilityValue::new(serde_json::json!(true)).unwrap(),
            realization: AbilityValue::new(serde_json::Value::Null).unwrap(),
            revision: RevisionId(aos_contract::Sha256Digest::of_bytes("new unit revision")),
        },
    ];
    environment
        .resources
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    environment
        .resources
        .dedup_by(|left, right| left.resource == right.resource);
    environment.controllers = vec![
        ControllerAssignment {
            resource: old_resource.clone(),
            controller: old_controller.clone(),
        },
        ControllerAssignment {
            resource: new_resource.clone(),
            controller: new_controller.clone(),
        },
    ];
    environment
        .controllers
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    environment
        .controllers
        .dedup_by(|left, right| left.resource == right.resource);
    environment
}

#[allow(clippy::too_many_arguments)]
pub(super) fn lifecycle_planning_snapshot(
    context: &ValidationContext,
    environment: EnvironmentDocument,
    mut pure_package: PackageDocument,
    terminal_package: PackageDocument,
    application: &InstanceId,
    service: &InstanceId,
    manager: &InstanceId,
    resource: &ResourceId,
    terminal_package_digest: aos_contract::Sha256Digest,
    operator_enabled: bool,
) -> VerifiedPlanningSnapshot {
    let interface = pure_package.implementation.providers[0].interface.clone();
    let stage_guarantees = vec![aos_ability_validate::test_support::test_manager_guarantee()];
    let manager_alias = key("b-manager");
    if operator_enabled {
        let implementation = &mut pure_package.implementation.providers[0];
        implementation.requirements = vec![RequirementDeclaration {
            description: "Describes this consumed ability.".to_string(),
            alias: manager_alias.clone(),
            accepted_interfaces: vec![interface.clone().into()],
            methods: vec![key("observe"), key("start")],
            guarantees: stage_guarantees.clone(),
            strength: RequirementStrength::Required,
            fallback: None,
        }];
        let descriptor = implementation
            .descriptor_digest()
            .expect("enabled root implementation must digest");
        pure_package.exports[0].implementation = descriptor;
    }

    let pure_package_digest = pure_package
        .content_digest()
        .expect("pure package must digest");
    let pure_implementation = &pure_package.implementation.providers[0];
    let pure_reference = ProviderImplementationReference {
        descriptor: pure_implementation
            .descriptor_digest()
            .expect("pure implementation must digest"),
        artifact: pure_implementation.artifact.clone(),
        handler: None,
    };
    let terminal_implementation = &terminal_package.implementation.providers[0];
    let terminal_reference = ProviderImplementationReference {
        descriptor: terminal_implementation
            .descriptor_digest()
            .expect("terminal implementation must digest"),
        artifact: terminal_implementation.artifact.clone(),
        handler: Some(aos_ability_validate::test_support::test_manager_handler_key()),
    };
    let service_request = BindingRequest {
        package: aos_ability_model::LocalKey::new("test-package")
            .expect("valid test package provenance"),
        id: RequestId {
            consumer: application.clone(),
            scope: ScopePath::root(),
            key: key("a-service"),
        },
        accepted_interfaces: vec![interface.clone()],
        methods: vec![key("start")],
        guarantees: stage_guarantees.clone(),
        lifetime: ResourceLifetime::Instance,
        parameters: ability_value(serde_json::json!({"subject": "example.service"})),
    };
    let manager_request = BindingRequest {
        package: pure_package.package.name.clone(),
        id: if operator_enabled {
            crate::child_request_id(service, manager_alias)
                .expect("enabled root child request must be in scope")
        } else {
            RequestId {
                consumer: service.clone(),
                scope: ScopePath::root(),
                key: manager_alias,
            }
        },
        accepted_interfaces: vec![interface.clone()],
        methods: vec![key("observe"), key("start")],
        guarantees: stage_guarantees.clone(),
        lifetime: ResourceLifetime::Instance,
        parameters: ability_value(serde_json::json!({"subject": "example.service"})),
    };
    let environment_digest = environment
        .content_digest()
        .expect("lifecycle environment must digest");
    let planned_resources = environment
        .resources
        .iter()
        .filter(|candidate| candidate.resource == *resource)
        .cloned()
        .collect::<Vec<_>>();
    let planned_controllers = environment
        .controllers
        .iter()
        .filter(|assignment| assignment.resource == *resource)
        .cloned()
        .collect::<Vec<_>>();
    let child_requests = if operator_enabled {
        Vec::new()
    } else {
        vec![service_request.clone(), manager_request.clone()]
    };
    let desired = DesiredStateDocument {
        schema: DesiredStateDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        environment: environment_digest,
        instances: vec![DesiredInstance {
            instance: service.clone(),
            package: pure_package_digest,
            enabled: true,
            configuration: None,
        }],
        contributions: Vec::new(),
        child_requests,
        resources: planned_resources.clone(),
        outputs: Vec::new(),
        controllers: if operator_enabled {
            Vec::new()
        } else {
            planned_controllers.clone()
        },
    };
    let desired_digest = desired
        .content_digest()
        .expect("lifecycle desired state must digest");
    let permission = ResourcePermission {
        resource: resource.clone(),
        access: AccessMode::ExclusiveWrite,
        operations: vec![key("observe"), key("start")],
    };
    let service_candidate = BindingCandidate {
        key: key("a-service"),
        request: service_request.id.clone(),
        interface: interface.clone(),
        provider: service.clone(),
        provider_package: pure_package_digest,
        implementation: pure_reference,
        caller_grant: AuthorityGrant {
            principal: application.clone(),
            methods: vec![key("start")],
            contributions: Vec::new(),
            resources: Vec::new(),
        },
        provider_grant: AuthorityGrant {
            principal: service.clone(),
            methods: Vec::new(),
            contributions: Vec::new(),
            resources: Vec::new(),
        },
        guarantees: stage_guarantees.clone(),
        policy_revision: environment.policy_revision,
        lifetime: ResourceLifetime::Instance,
        mediation_allowed: false,
        exclusive_resources: Vec::new(),
    };
    let manager_candidate = BindingCandidate {
        key: key("b-manager"),
        request: manager_request.id.clone(),
        interface,
        provider: manager.clone(),
        provider_package: terminal_package_digest,
        implementation: terminal_reference,
        caller_grant: AuthorityGrant {
            principal: service.clone(),
            methods: vec![key("observe"), key("start")],
            contributions: Vec::new(),
            resources: vec![permission],
        },
        provider_grant: AuthorityGrant {
            principal: manager.clone(),
            methods: Vec::new(),
            contributions: Vec::new(),
            resources: Vec::new(),
        },
        guarantees: stage_guarantees,
        policy_revision: environment.policy_revision,
        lifetime: ResourceLifetime::Instance,
        mediation_allowed: false,
        exclusive_resources: Vec::new(),
    };
    let enabled_providers = if operator_enabled {
        vec![crate::EnabledProviderSelection {
            instance: service.clone(),
            interface: pure_implementation.interface.clone(),
            implementation: service_candidate.implementation.clone(),
            provider_grant: service_candidate.provider_grant.clone(),
            policy_revision: environment.policy_revision,
            lifetime: ResourceLifetime::Instance,
        }]
    } else {
        Vec::new()
    };
    let mut policies = if operator_enabled {
        let initial_policy = ResolutionPolicyDocument {
            schema: ResolutionPolicyDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            desired_state: desired_digest,
            environment: environment_digest,
            policy_revision: environment.policy_revision,
            candidates: Vec::new(),
            explicit_bindings: Vec::new(),
            existing_pins: Vec::new(),
            operator_orders: Vec::new(),
            enabled_providers: enabled_providers.clone(),
            obligations: Vec::new(),
        };
        let mut expanded = desired.clone();
        expanded.child_requests = vec![manager_request.clone()];
        let expanded_digest = expanded
            .content_digest()
            .expect("enabled root expansion must digest");
        let expanded_policy = ResolutionPolicyDocument {
            schema: ResolutionPolicyDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            desired_state: expanded_digest,
            environment: environment_digest,
            policy_revision: environment.policy_revision,
            candidates: vec![manager_candidate],
            explicit_bindings: vec![CandidateSelection {
                request: manager_request.id.clone(),
                candidate: key("b-manager"),
            }],
            existing_pins: Vec::new(),
            operator_orders: Vec::new(),
            enabled_providers,
            obligations: Vec::new(),
        };
        vec![initial_policy, expanded_policy]
    } else {
        let mut candidates = vec![service_candidate, manager_candidate];
        candidates.sort_by(|left, right| left.key.cmp(&right.key));
        let mut explicit_bindings = vec![
            CandidateSelection {
                request: service_request.id,
                candidate: key("a-service"),
            },
            CandidateSelection {
                request: manager_request.id.clone(),
                candidate: key("b-manager"),
            },
        ];
        explicit_bindings.sort_by(|left, right| left.request.cmp(&right.request));
        vec![ResolutionPolicyDocument {
            schema: ResolutionPolicyDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            desired_state: desired_digest,
            environment: environment_digest,
            policy_revision: environment.policy_revision,
            candidates,
            explicit_bindings,
            existing_pins: Vec::new(),
            operator_orders: Vec::new(),
            enabled_providers,
            obligations: Vec::new(),
        }]
    };
    policies.sort_by_key(|policy| policy.desired_state);
    let mut packages = vec![pure_package, terminal_package];
    packages.sort_by_key(|package| {
        package
            .content_digest()
            .expect("lifecycle package must digest")
    });
    if operator_enabled {
        let selection = &policies[0].enabled_providers[0];
        let package = packages
            .iter()
            .find(|package| {
                package
                    .content_digest()
                    .is_ok_and(|digest| digest == pure_package_digest)
            })
            .expect("enabled pure package");
        let implementation = &package.implementation.providers[0];
        assert_eq!(implementation.interface, selection.interface);
        assert_eq!(implementation.artifact, selection.implementation.artifact);
        assert_eq!(
            implementation
                .descriptor_digest()
                .expect("enabled implementation digest"),
            selection.implementation.descriptor
        );
        assert_eq!(
            context
                .interface(&selection.interface)
                .expect("enabled interface contract")
                .interface
                .aggregation
                .controller_group,
            key("manager")
        );
        assert!(selection.implementation.handler.is_none());
        assert_eq!(
            implementation
                .provider_module
                .as_ref()
                .map(|module| &module.artifact),
            Some(&selection.implementation.artifact)
        );
        assert!(selection.provider_grant.methods.iter().all(|method| {
            context
                .interface(&selection.interface)
                .is_some_and(|interface| interface.interface.methods.contains_key(method))
        }));
    }
    let mut composition_evaluator = LifecycleCompositionEvaluator {
        expanding_provider: operator_enabled.then(|| service.clone()),
        manager_request,
    };
    let outcome = RecursiveComposer::new(context)
        .compose(
            &policies,
            desired.clone(),
            environment.clone(),
            packages.clone(),
            &mut composition_evaluator,
        )
        .expect("lifecycle composition must reach a fixed point");
    let snapshot =
        PlanningSnapshot::from_outcome(&outcome).expect("lifecycle planning snapshot must encode");
    let snapshot_digest = snapshot
        .digest()
        .expect("lifecycle planning snapshot must digest");
    snapshot
        .verify_structure(
            &RecursiveComposer::new(context),
            PlanningReplayInputs {
                expected_digest: snapshot_digest,
                authenticated_policies: &policies,
                seed: desired,
                environment,
                packages,
            },
        )
        .expect("lifecycle planning snapshot must replay")
}
