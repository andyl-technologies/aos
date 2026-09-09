//! End-to-end source composition through the restricted Nix evaluator.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use anyhow::{Context, Result};
use aos_ability_model::document::{
    Contribution, DesiredInstance, FreshnessCondition, PackageSubject, PlatformIdentity,
    ProviderInventory, ProviderState,
};
use aos_ability_model::*;
use aos_ability_plan::{
    BindingCandidate, CandidateSelection, CompositionError, EnabledProviderSelection,
    PlanningReplayInputs, PlanningSnapshot, RecursiveComposer, ResolutionPolicyDocument,
    TransitionInputs, TransitionPlanner, VerifiedPlanningSnapshot,
};
use aos_ability_validate::{
    CheckedTransitionAuthority, TransitionAuthorityInputs, ValidationContext,
};
use aos_contract::Sha256Digest;

use super::{AbilityEvaluationLimits, RestrictedAbilityEvaluator};

const REFERENCE_ENVIRONMENT: [&str; 11] = [
    "AOS_NIX_INSTANTIATE",
    "AOS_PRLIMIT",
    "AOS_TEST_ABILITY_CACHE",
    "AOS_TEST_ABILITY_REFERENCE_NGINX",
    "AOS_TEST_ABILITY_REFERENCE_NGINX_NAR_HASH",
    "AOS_TEST_ABILITY_REFERENCE_MANAGED_CONFIGURATION",
    "AOS_TEST_ABILITY_REFERENCE_MANAGED_CONFIGURATION_NAR_HASH",
    "AOS_TEST_ABILITY_REFERENCE_CREDENTIAL",
    "AOS_TEST_ABILITY_REFERENCE_CREDENTIAL_NAR_HASH",
    "AOS_TEST_ABILITY_REFERENCE_SYSTEMD",
    "AOS_TEST_ABILITY_REFERENCE_SYSTEMD_NAR_HASH",
];

struct ReferenceFixture {
    context: ValidationContext,
    environment: EnvironmentDocument,
    packages: Vec<PackageDocument>,
    nginx_package: Sha256Digest,
    lower_packages: BTreeMap<String, Sha256Digest>,
    terminal_packages: BTreeMap<String, Sha256Digest>,
    implementations: BTreeMap<String, ProviderImplementationReference>,
    terminal_implementations: BTreeMap<String, ProviderImplementationReference>,
    interfaces: BTreeMap<String, InterfaceKey>,
    policy_revision: RevisionId,
    evaluator: RestrictedAbilityEvaluator,
}

struct Deployment<'a> {
    fixture: &'a mut ReferenceFixture,
    nginx_instances: Vec<InstanceId>,
    app_routes: Vec<(&'static str, &'static str, &'static str, bool)>,
}

struct ComposedDeployment {
    outcome: aos_ability_plan::CompositionOutcome,
    authorization_states: Vec<DesiredStateDocument>,
    policies: Vec<ResolutionPolicyDocument>,
}

impl ReferenceFixture {
    fn from_environment() -> Result<Option<Self>> {
        if std::env::var("AOS_TEST_ABILITY_EVALUATOR_DISABLED").as_deref() == Ok("1") {
            return Ok(None);
        }
        if REFERENCE_ENVIRONMENT
            .iter()
            .all(|name| std::env::var_os(name).is_none())
        {
            return Ok(None);
        }

        let required = |name: &str| {
            std::env::var(name).with_context(|| format!("reading required test variable {name}"))
        };
        let evaluator = RestrictedAbilityEvaluator::new(
            required("AOS_NIX_INSTANTIATE")?,
            required("AOS_PRLIMIT")?,
            required("AOS_TEST_ABILITY_CACHE")?,
            AbilityEvaluationLimits::default(),
        )?;

        let interface_documents = interface_documents();
        let interfaces = interface_documents
            .iter()
            .map(|document| {
                Ok((
                    document.interface.name.as_str().to_string(),
                    document.interface_key()?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let context = ValidationContext::new(BTreeSet::new(), interface_documents)
            .context("validating reference interface catalog")?;

        let artifacts = BTreeMap::from([
            (
                "aos.nginx".to_string(),
                artifact_from_environment(
                    "AOS_TEST_ABILITY_REFERENCE_NGINX",
                    "AOS_TEST_ABILITY_REFERENCE_NGINX_NAR_HASH",
                    1,
                )?,
            ),
            (
                "aos.managed-configuration".to_string(),
                artifact_from_environment(
                    "AOS_TEST_ABILITY_REFERENCE_MANAGED_CONFIGURATION",
                    "AOS_TEST_ABILITY_REFERENCE_MANAGED_CONFIGURATION_NAR_HASH",
                    2,
                )?,
            ),
            (
                "aos.credential-delivery".to_string(),
                artifact_from_environment(
                    "AOS_TEST_ABILITY_REFERENCE_CREDENTIAL",
                    "AOS_TEST_ABILITY_REFERENCE_CREDENTIAL_NAR_HASH",
                    3,
                )?,
            ),
            (
                "aos.systemd-service".to_string(),
                artifact_from_environment(
                    "AOS_TEST_ABILITY_REFERENCE_SYSTEMD",
                    "AOS_TEST_ABILITY_REFERENCE_SYSTEMD_NAR_HASH",
                    4,
                )?,
            ),
        ]);

        let nginx_requirements = vec![
            requirement(
                "configuration",
                &interfaces["aos.managed-configuration"],
                RequirementStrength::Required,
                None,
            ),
            requirement(
                "credential",
                &interfaces["aos.credential-delivery"],
                RequirementStrength::Advisory,
                Some(RequirementFallback {
                    outputs: BTreeMap::from([(
                        key("credential-views"),
                        value(serde_json::json!({})),
                    )]),
                }),
            ),
            requirement(
                "service",
                &interfaces["aos.systemd-service"],
                RequirementStrength::Required,
                None,
            ),
            method_requirement(
                "service-terminal",
                &interfaces["aos.systemd-service-effects"],
                &["observe", "reload", "start", "stop"],
            ),
            method_requirement(
                "validation-terminal",
                &interfaces["aos.nginx-validation"],
                &["record", "release", "validate"],
            ),
        ];
        let mut packages = Vec::new();
        let mut lower_packages = BTreeMap::new();
        let mut terminal_packages = BTreeMap::new();
        let mut implementations = BTreeMap::new();
        let mut terminal_implementations = BTreeMap::new();

        let nginx = provider_package(
            "reference-nginx",
            &interfaces["aos.nginx"],
            &artifacts["aos.nginx"],
            nginx_requirements,
            "nginx",
        );
        let nginx_package = nginx.content_digest()?;
        implementations.insert("aos.nginx".to_string(), provider_reference(&nginx));
        packages.push(nginx);

        for (name, terminal_name, group, terminal_methods) in [
            (
                "aos.managed-configuration",
                "aos.managed-configuration-effects",
                "configuration",
                &["prepare", "publish", "release"][..],
            ),
            ("aos.credential-delivery", "", "credentials", &[][..]),
            (
                "aos.systemd-service",
                "aos.systemd-service-effects",
                "services",
                &["observe", "reload", "start", "stop"][..],
            ),
        ] {
            let requirements = if terminal_methods.is_empty() || name == "aos.systemd-service" {
                Vec::new()
            } else {
                vec![method_requirement(
                    "effects",
                    &interfaces[terminal_name],
                    terminal_methods,
                )]
            };
            let package = provider_package(
                &format!("reference-{}", name.rsplit('.').next().unwrap()),
                &interfaces[name],
                &artifacts[name],
                requirements,
                group,
            );
            lower_packages.insert(name.to_string(), package.content_digest()?);
            implementations.insert(name.to_string(), provider_reference(&package));
            packages.push(package);

            if !terminal_methods.is_empty() {
                let terminal = terminal_package(
                    &format!("reference-{}-terminal", name.rsplit('.').next().unwrap()),
                    &interfaces[terminal_name],
                    &artifacts[name],
                );
                terminal_packages.insert(terminal_name.to_string(), terminal.content_digest()?);
                terminal_implementations
                    .insert(terminal_name.to_string(), provider_reference(&terminal));
                packages.push(terminal);
            }
        }

        let nginx_terminal = terminal_package(
            "reference-nginx-terminal",
            &interfaces["aos.nginx-validation"],
            &artifacts["aos.nginx"],
        );
        terminal_packages.insert(
            "aos.nginx-validation".to_string(),
            nginx_terminal.content_digest()?,
        );
        terminal_implementations.insert(
            "aos.nginx-validation".to_string(),
            provider_reference(&nginx_terminal),
        );
        packages.push(nginx_terminal);

        let app_artifact = artifacts["aos.nginx"].clone();
        packages.push(consumer_package(
            "reference-app-a",
            &app_artifact,
            &interfaces["aos.nginx"],
        ));
        packages.push(consumer_package(
            "reference-app-b",
            &app_artifact,
            &interfaces["aos.nginx"],
        ));
        packages.sort_by_key(|package| package.content_digest().unwrap());

        let environment_id = EnvironmentId {
            authority: key("reference"),
            key: key("host"),
            stage: ExecutionStage::Host,
        };
        let policy_revision = RevisionId(digest(20));
        let mut providers = Vec::new();
        for suffix in ["configuration", "credential", "service"] {
            let name = lower_interface_name(suffix);
            providers.push(ProviderInventory {
                provider: lower_provider(&environment_id, suffix),
                interface: interfaces[name].clone(),
                implementation: implementations[name].clone(),
                state: ProviderState::Declared,
                incarnation: None,
                guarantees: Vec::new(),
            });
            let terminal_name = terminal_interface_name(name);
            if let Some(implementation) = terminal_implementations.get(terminal_name) {
                providers.push(ProviderInventory {
                    provider: lower_provider(&environment_id, suffix),
                    interface: interfaces[terminal_name].clone(),
                    implementation: implementation.clone(),
                    state: ProviderState::Available,
                    incarnation: Some(IncarnationId::new("reference-terminal")?),
                    guarantees: Vec::new(),
                });
            }
        }
        for nginx in ["nginx-main", "nginx-one", "nginx-two"] {
            providers.push(ProviderInventory {
                provider: instance(&environment_id, nginx),
                interface: interfaces["aos.nginx-validation"].clone(),
                implementation: terminal_implementations["aos.nginx-validation"].clone(),
                state: ProviderState::Available,
                incarnation: Some(IncarnationId::new("reference-nginx-terminal")?),
                guarantees: Vec::new(),
            });
        }
        providers.sort_by(|left, right| left.provider.cmp(&right.provider));
        let environment = EnvironmentDocument {
            schema: EnvironmentDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            environment: environment_id,
            platform: PlatformIdentity {
                system: key("linux"),
                architecture: key("x86_64"),
            },
            policy_revision,
            providers,
            resources: Vec::new(),
            controllers: Vec::new(),
            guarantees: Vec::new(),
            freshness: FreshnessCondition {
                generation: RevisionId(digest(21)),
                max_age_millis: 60_000,
            },
        };

        Ok(Some(Self {
            context,
            environment,
            packages,
            nginx_package,
            lower_packages,
            terminal_packages,
            implementations,
            terminal_implementations,
            interfaces,
            policy_revision,
            evaluator,
        }))
    }

    fn package_digest(&self, name: &str) -> Sha256Digest {
        self.packages
            .iter()
            .find(|package| package.package.name.as_str() == name)
            .unwrap()
            .content_digest()
            .unwrap()
    }

    fn observe_applied_state(&mut self, state: &DesiredStateDocument) {
        // The fixture models the authenticated probe that follows successful
        // execution. Planning snapshots alone are not evidence of live state.
        self.environment.resources = state.resources.clone();
        self.environment.controllers = state.controllers.clone();
    }

    fn observe_configuration_drift(&mut self, state: &DesiredStateDocument) {
        self.observe_applied_state(state);
        let drifted = RevisionId(Sha256Digest::separated(
            "aos.test.reference-observation/v1",
            b"configuration-drifted",
        ));
        let configuration = self
            .environment
            .resources
            .iter_mut()
            .find(|revision| revision.resource.key.as_str().ends_with("-configuration"))
            .unwrap();
        configuration.revision = drifted;
    }

    fn observe_service_absent(&mut self, state: &DesiredStateDocument) {
        self.observe_applied_state(state);
        self.environment
            .resources
            .retain(|revision| !revision.resource.key.as_str().ends_with("-service"));
    }
}

impl Deployment<'_> {
    fn seed(&self, nginx_enabled: bool) -> DesiredStateDocument {
        let environment = self.fixture.environment.content_digest().unwrap();
        let mut instances = Vec::new();
        let mut requests = Vec::new();
        let mut contributions = Vec::new();

        for (app, nginx, host, tls) in &self.app_routes {
            let app_instance = instance(&self.fixture.environment.environment, app);
            let nginx_instance = instance(&self.fixture.environment.environment, nginx);
            let request = RequestId {
                consumer: app_instance.clone(),
                scope: ScopePath::root(),
                key: key("nginx"),
            };
            let candidate = binding_key(&request);
            instances.push(DesiredInstance {
                instance: app_instance.clone(),
                package: self.fixture.package_digest(&format!("reference-{app}")),
                enabled: true,
            });
            requests.push(BindingRequest {
                id: request.clone(),
                accepted_interfaces: vec![self.fixture.interfaces["aos.nginx"].clone()],
                methods: Vec::new(),
                guarantees: Vec::new(),
                lifetime: ResourceLifetime::Instance,
            });
            contributions.push(Contribution {
                request,
                aggregate: AggregateId {
                    provider: nginx_instance,
                    group: key("nginx"),
                },
                slot: app_instance.key.clone(),
                grant: BindingId(candidate),
                value: value(serde_json::json!({"host": host, "tls": tls})),
            });
        }
        for nginx in &self.nginx_instances {
            instances.push(DesiredInstance {
                instance: nginx.clone(),
                package: self.fixture.nginx_package,
                enabled: nginx_enabled,
            });
        }
        instances.sort_by(|left, right| left.instance.cmp(&right.instance));
        requests.sort_by(|left, right| left.id.cmp(&right.id));

        DesiredStateDocument {
            schema: DesiredStateDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            environment,
            instances,
            contributions,
            child_requests: requests,
            resources: Vec::new(),
            outputs: Vec::new(),
            controllers: Vec::new(),
        }
    }

    fn compose(&mut self, seed: DesiredStateDocument) -> ComposedDeployment {
        self.try_compose(seed)
            .unwrap_or_else(|error| panic!("reference composition failed: {error:#?}"))
    }

    fn try_compose(
        &mut self,
        seed: DesiredStateDocument,
    ) -> Result<ComposedDeployment, CompositionError> {
        let mut authorization_states = Vec::new();
        let mut policies = Vec::new();

        loop {
            let result = RecursiveComposer::new(&self.fixture.context).compose(
                &policies,
                seed.clone(),
                self.fixture.environment.clone(),
                self.fixture.packages.clone(),
                &mut self.fixture.evaluator,
            );
            match result {
                Ok(outcome) => {
                    return Ok(ComposedDeployment {
                        outcome,
                        authorization_states,
                        policies,
                    });
                }
                Err(CompositionError::PolicyRequired { desired_state, .. }) => {
                    policies.push(self.policy_for(&desired_state));
                    authorization_states.push(*desired_state);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn policy_for(&self, desired: &DesiredStateDocument) -> ResolutionPolicyDocument {
        let mut candidates = desired
            .child_requests
            .iter()
            .map(|request| self.candidate_for(request, desired))
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.key.cmp(&right.key));
        let mut explicit_bindings = candidates
            .iter()
            .map(|candidate| CandidateSelection {
                request: candidate.request.clone(),
                candidate: candidate.key.clone(),
            })
            .collect::<Vec<_>>();
        explicit_bindings.sort_by(|left, right| left.request.cmp(&right.request));

        let mut enabled_providers = self
            .nginx_instances
            .iter()
            .filter(|nginx| {
                desired
                    .instances
                    .iter()
                    .any(|instance| instance.enabled && instance.instance == **nginx)
            })
            .map(|nginx| EnabledProviderSelection {
                instance: nginx.clone(),
                interface: self.fixture.interfaces["aos.nginx"].clone(),
                implementation: self.fixture.implementations["aos.nginx"].clone(),
                provider_grant: AuthorityGrant {
                    principal: nginx.clone(),
                    methods: Vec::new(),
                    contributions: Vec::new(),
                    resources: vec![ResourcePermission {
                        resource: nginx_resource(nginx),
                        access: AccessMode::ExclusiveWrite,
                        operations: Vec::new(),
                    }],
                },
                policy_revision: self.fixture.policy_revision,
                lifetime: ResourceLifetime::Instance,
            })
            .collect::<Vec<_>>();
        enabled_providers.sort_by(|left, right| left.instance.cmp(&right.instance));

        ResolutionPolicyDocument {
            schema: ResolutionPolicyDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            desired_state: desired.content_digest().unwrap(),
            environment: self.fixture.environment.content_digest().unwrap(),
            policy_revision: self.fixture.policy_revision,
            candidates,
            explicit_bindings,
            existing_pins: Vec::new(),
            operator_orders: Vec::new(),
            enabled_providers,
            obligations: Vec::new(),
        }
    }

    fn candidate_for(
        &self,
        request: &BindingRequest,
        desired: &DesiredStateDocument,
    ) -> BindingCandidate {
        let interface = request.accepted_interfaces[0].clone();
        let terminal = matches!(
            request.id.key.as_str(),
            "effects" | "validation-terminal" | "service-terminal"
        );
        let (provider, provider_package, implementation, resources, contributions) = if terminal {
            let provider = if request.id.key.as_str() == "service-terminal" {
                lower_provider(&self.fixture.environment.environment, "service")
            } else {
                request.id.consumer.clone()
            };
            let resources = desired
                .resources
                .iter()
                .filter(|revision| revision.resource.provider == provider)
                .map(|revision| ResourcePermission {
                    resource: revision.resource.clone(),
                    access: AccessMode::ExclusiveWrite,
                    operations: request.methods.clone(),
                })
                .collect();
            (
                provider,
                self.fixture.terminal_packages[interface.name.as_str()],
                self.fixture.terminal_implementations[interface.name.as_str()].clone(),
                resources,
                Vec::new(),
            )
        } else if interface == self.fixture.interfaces["aos.nginx"] {
            let route = self
                .app_routes
                .iter()
                .find(|(app, _, _, _)| *app == request.id.consumer.key.as_str())
                .unwrap();
            let provider = instance(&self.fixture.environment.environment, route.1);
            let contributions = vec![ContributionPermission {
                aggregate: AggregateId {
                    provider: provider.clone(),
                    group: key("nginx"),
                },
                slot: request.id.consumer.key.clone(),
            }];

            (
                provider,
                self.fixture.nginx_package,
                self.fixture.implementations["aos.nginx"].clone(),
                Vec::new(),
                contributions,
            )
        } else {
            let suffix = request.id.key.as_str();
            let name = lower_interface_name(suffix);
            let (group, operations, resource_key) = lower_authority(suffix);
            let provider = lower_provider(&self.fixture.environment.environment, suffix);
            let resource = ResourceId {
                provider: provider.clone(),
                key: key(&format!("{}-{resource_key}", request.id.consumer.key)),
            };
            let resources = desired
                .resources
                .iter()
                .any(|revision| revision.resource == resource)
                .then(|| {
                    vec![ResourcePermission {
                        resource,
                        access: AccessMode::Read,
                        operations: operations.iter().map(|operation| key(operation)).collect(),
                    }]
                })
                .unwrap_or_default();
            let contributions = vec![ContributionPermission {
                aggregate: AggregateId {
                    provider: provider.clone(),
                    group: key(group),
                },
                slot: request.id.consumer.key.clone(),
            }];
            (
                provider,
                self.fixture.lower_packages[name],
                self.fixture.implementations[name].clone(),
                resources,
                contributions,
            )
        };
        let caller = request.id.consumer.clone();
        let caller_grant = AuthorityGrant {
            principal: caller.clone(),
            methods: request.methods.clone(),
            contributions,
            resources: resources.clone(),
        };
        let provider_grant = AuthorityGrant {
            principal: provider.clone(),
            methods: Vec::new(),
            contributions: Vec::new(),
            resources: resources
                .into_iter()
                .map(|mut permission| {
                    if permission.resource.provider == provider {
                        permission.access = AccessMode::ExclusiveWrite;
                    }
                    permission
                })
                .collect(),
        };

        BindingCandidate {
            key: binding_key(&request.id),
            request: request.id.clone(),
            interface: interface.clone(),
            provider,
            provider_package,
            implementation,
            caller_grant,
            provider_grant,
            guarantees: Vec::new(),
            policy_revision: self.fixture.policy_revision,
            lifetime: ResourceLifetime::Instance,
            mediation_allowed: true,
            exclusive_resources: Vec::new(),
        }
    }
}

#[test]
fn checked_reference_source_composes_authority_isolation_and_lifecycle() {
    let Some(mut fixture) = ReferenceFixture::from_environment().unwrap() else {
        return;
    };
    assert_fixture_interface_hashes(&fixture);

    let environment = fixture.environment.environment.clone();
    let nginx_main = instance(&environment, "nginx-main");
    let mut both = Deployment {
        fixture: &mut fixture,
        nginx_instances: vec![nginx_main.clone()],
        app_routes: vec![
            ("app-a", "nginx-main", "alpha.example", false),
            ("app-b", "nginx-main", "beta.example", false),
        ],
    };
    let seed = both.seed(true);
    let composed = both.compose(seed.clone());
    let planning = assert_snapshot_replay(both.fixture, seed, &composed);
    assert_initial_effect_pipeline(both.fixture, &planning, &nginx_main);

    assert_eq!(composed.authorization_states.len(), 5);
    assert!(composed.authorization_states[0].resources.is_empty());
    assert!(
        composed.authorization_states[1]
            .resources
            .iter()
            .any(|revision| revision.resource == nginx_resource(&nginx_main))
    );
    assert!(lower_resource_outputs(&composed.authorization_states[1]).is_empty());
    assert_eq!(
        lower_resource_outputs(&composed.authorization_states[2]).len(),
        2
    );
    assert!(
        lower_resource_outputs(&composed.authorization_states[2])
            .iter()
            .all(|output| object_field_count(output) == 0)
    );
    assert!(
        lower_resource_outputs(&composed.authorization_states[3])
            .iter()
            .all(|output| object_field_count(output) == 1)
    );
    assert!(
        nginx_output(
            &composed.authorization_states[3],
            &nginx_main,
            "configuration"
        )
        .is_none()
    );
    assert!(
        nginx_output(
            &composed.authorization_states[4],
            &nginx_main,
            "configuration"
        )
        .is_some()
    );
    assert!(policy_has_new_lower_authority(
        &composed.policies[3],
        &composed.authorization_states[3]
    ));

    let rendered = rendered_configuration(&composed.outcome.desired_state, &nginx_main);
    assert!(rendered.contains("server_name alpha.example;"));
    assert!(rendered.contains("server_name beta.example;"));
    assert_eq!(rendered.matches("listen 443 ssl;").count(), 0);
    assert!(matches!(
        &nginx_output(
            &composed.outcome.desired_state,
            &nginx_main,
            "configuration"
        )
        .unwrap()
        .value,
        ValueExpression::ResourceReference { .. }
    ));
    both.fixture
        .observe_applied_state(&planning.outcome().desired_state);

    let mut updated = Deployment {
        fixture: both.fixture,
        nginx_instances: vec![nginx_main.clone()],
        app_routes: vec![
            ("app-a", "nginx-main", "gamma.example", false),
            ("app-b", "nginx-main", "beta.example", false),
        ],
    };
    let seed = updated.seed(true);
    let updated_composed = updated.compose(seed.clone());
    let updated_planning = assert_snapshot_replay(updated.fixture, seed, &updated_composed);
    assert_update_pipeline(updated.fixture, &planning, &updated_planning);
    let updated_state = updated_composed.outcome.desired_state.clone();
    let rendered = rendered_configuration(&updated_state, &nginx_main);
    assert!(!rendered.contains("alpha.example"));
    assert!(rendered.contains("gamma.example"));
    assert!(rendered.contains("beta.example"));

    updated.fixture.observe_applied_state(&updated_state);
    let seed = updated.seed(true);
    let unchanged_composed = updated.compose(seed.clone());
    let unchanged_planning = assert_snapshot_replay(updated.fixture, seed, &unchanged_composed);
    assert_noop_pipeline(updated.fixture, &updated_planning, &unchanged_planning);

    updated.fixture.observe_configuration_drift(&updated_state);
    let seed = updated.seed(true);
    let drifted_composed = updated.compose(seed.clone());
    let drifted_planning = assert_snapshot_replay(updated.fixture, seed, &drifted_composed);
    assert_update_pipeline(updated.fixture, &unchanged_planning, &drifted_planning);

    updated.fixture.observe_service_absent(&updated_state);
    let seed = updated.seed(true);
    let stopped_composed = updated.compose(seed.clone());
    let stopped_planning = assert_snapshot_replay(updated.fixture, seed, &stopped_composed);
    assert_stopped_service_repair(updated.fixture, &drifted_planning, &stopped_planning);

    updated.fixture.observe_applied_state(&updated_state);

    let mut empty = Deployment {
        fixture: updated.fixture,
        nginx_instances: vec![nginx_main.clone()],
        app_routes: Vec::new(),
    };
    let seed = empty.seed(true);
    let empty_composed = empty.compose(seed.clone());
    let empty_planning = assert_snapshot_replay(empty.fixture, seed, &empty_composed);
    let empty_state = empty_composed.outcome.desired_state;
    assert_eq!(virtual_host_count(&empty_state, &nginx_main), 0);
    assert!(
        empty_state
            .resources
            .iter()
            .any(|revision| revision.resource == nginx_resource(&nginx_main))
    );

    empty.fixture.observe_applied_state(&empty_state);

    let seed = empty.seed(false);
    let disabled_composed = empty.compose(seed.clone());
    let disabled_planning = assert_snapshot_replay(empty.fixture, seed, &disabled_composed);
    let authority = teardown_authority(empty.fixture, &disabled_planning, &empty_planning);
    assert_disable_pipeline(
        empty.fixture,
        &empty_planning,
        &disabled_planning,
        &authority,
    );
    let disabled_state = disabled_composed.outcome.desired_state;
    assert!(disabled_state.resources.is_empty());
    assert!(disabled_state.outputs.is_empty());
    assert!(disabled_state.controllers.is_empty());

    let nginx_one = instance(&environment, "nginx-one");
    let nginx_two = instance(&environment, "nginx-two");
    let mut isolated = Deployment {
        fixture: empty.fixture,
        nginx_instances: vec![nginx_one.clone(), nginx_two.clone()],
        app_routes: vec![
            ("app-a", "nginx-one", "one.example", false),
            ("app-b", "nginx-two", "two.example", true),
        ],
    };
    let seed = isolated.seed(true);
    let isolated_outcome = isolated.compose(seed).outcome;
    assert_shared_lower_isolation(&isolated_outcome, &nginx_one, &nginx_two);

    let isolated_state = isolated_outcome.desired_state;
    let first = rendered_configuration(&isolated_state, &nginx_one);
    let second = rendered_configuration(&isolated_state, &nginx_two);
    assert!(first.contains("one.example"));
    assert!(!first.contains("two.example"));
    assert!(second.contains("two.example"));
    assert!(!second.contains("one.example"));
    assert!(nginx_output(&isolated_state, &nginx_one, "credential-view").is_none());
    assert!(nginx_output(&isolated_state, &nginx_two, "credential-view").is_some());
}

#[test]
fn checked_reference_source_rejects_directive_injection_before_effect_planning() {
    let Some(mut fixture) = ReferenceFixture::from_environment().unwrap() else {
        return;
    };
    let environment = fixture.environment.environment.clone();
    let nginx = instance(&environment, "nginx-main");

    for hostile_host in ["bad.example\n", "bad.example;", "bad.example}"] {
        let mut deployment = Deployment {
            fixture: &mut fixture,
            nginx_instances: vec![nginx.clone()],
            app_routes: vec![("app-a", "nginx-main", hostile_host, false)],
        };
        let seed = deployment.seed(true);
        let error = match deployment.try_compose(seed) {
            Ok(_) => panic!("hostile nginx server name reached a planning snapshot"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            CompositionError::Evaluation { ref source, .. }
                if source.to_string().contains("not a valid DNS server name")
        ));
    }
}

#[test]
fn checked_reference_source_rejects_duplicate_server_names_per_nginx_instance() {
    let Some(mut fixture) = ReferenceFixture::from_environment().unwrap() else {
        return;
    };
    let environment = fixture.environment.environment.clone();
    let nginx = instance(&environment, "nginx-main");
    let mut deployment = Deployment {
        fixture: &mut fixture,
        nginx_instances: vec![nginx],
        app_routes: vec![
            ("app-a", "nginx-main", "shared.example", false),
            ("app-b", "nginx-main", "shared.example", false),
        ],
    };
    let seed = deployment.seed(true);
    let error = match deployment.try_compose(seed) {
        Ok(_) => panic!("duplicate nginx server name reached a planning snapshot"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        CompositionError::Evaluation { ref source, .. }
            if source.to_string().contains("duplicate server name")
    ));
}

#[test]
fn checked_reference_source_allows_same_server_name_in_distinct_nginx_instances() {
    let Some(mut fixture) = ReferenceFixture::from_environment().unwrap() else {
        return;
    };
    let environment = fixture.environment.environment.clone();
    let nginx_one = instance(&environment, "nginx-one");
    let nginx_two = instance(&environment, "nginx-two");
    let mut deployment = Deployment {
        fixture: &mut fixture,
        nginx_instances: vec![nginx_one.clone(), nginx_two.clone()],
        app_routes: vec![
            ("app-a", "nginx-one", "shared.example", false),
            ("app-b", "nginx-two", "shared.example", false),
        ],
    };

    let seed = deployment.seed(true);
    let desired = deployment.compose(seed).outcome.desired_state;

    assert_eq!(virtual_host_count(&desired, &nginx_one), 1);
    assert_eq!(virtual_host_count(&desired, &nginx_two), 1);
    assert!(rendered_configuration(&desired, &nginx_one).contains("shared.example"));
    assert!(rendered_configuration(&desired, &nginx_two).contains("shared.example"));
}

#[test]
fn checked_reference_source_rejects_case_variant_server_name_collisions() {
    let Some(mut fixture) = ReferenceFixture::from_environment().unwrap() else {
        return;
    };
    let environment = fixture.environment.environment.clone();
    let nginx = instance(&environment, "nginx-main");
    let mut deployment = Deployment {
        fixture: &mut fixture,
        nginx_instances: vec![nginx],
        app_routes: vec![
            ("app-a", "nginx-main", "shared.example", false),
            ("app-b", "nginx-main", "Shared.Example", false),
        ],
    };
    let seed = deployment.seed(true);
    let error = match deployment.try_compose(seed) {
        Ok(_) => panic!("case-variant nginx server names reached a planning snapshot"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        CompositionError::Evaluation { ref source, .. }
            if source.to_string().contains("not a valid DNS server name")
    ));
}

fn assert_snapshot_replay(
    fixture: &mut ReferenceFixture,
    seed: DesiredStateDocument,
    composed: &ComposedDeployment,
) -> VerifiedPlanningSnapshot {
    let snapshot = PlanningSnapshot::from_outcome(&composed.outcome).unwrap();
    let canonical = snapshot.canonical_bytes().unwrap();
    let external_commitment = snapshot.digest().unwrap();
    let decoded = PlanningSnapshot::decode(&canonical).unwrap();
    let mut authenticated_policies = composed.policies.clone();
    authenticated_policies.sort_by_key(|policy| policy.desired_state);

    let structurally_verified = decoded
        .verify_structure(
            &RecursiveComposer::new(&fixture.context),
            PlanningReplayInputs {
                expected_digest: external_commitment,
                authenticated_policies: &authenticated_policies,
                seed: seed.clone(),
                environment: fixture.environment.clone(),
                packages: fixture.packages.clone(),
            },
        )
        .unwrap();
    assert_eq!(structurally_verified.snapshot_digest(), external_commitment);
    assert_eq!(
        structurally_verified.checked_binding().id(),
        composed.outcome.resolution.checked.id()
    );

    let live_verified = decoded
        .replay_with(
            &RecursiveComposer::new(&fixture.context),
            PlanningReplayInputs {
                expected_digest: external_commitment,
                authenticated_policies: &authenticated_policies,
                seed,
                environment: fixture.environment.clone(),
                packages: fixture.packages.clone(),
            },
            &mut fixture.evaluator,
        )
        .unwrap();
    assert_eq!(live_verified.snapshot_digest(), external_commitment);
    assert_eq!(
        live_verified.checked_binding().id(),
        composed.outcome.resolution.checked.id()
    );
    live_verified
}

fn assert_initial_effect_pipeline(
    fixture: &mut ReferenceFixture,
    planning: &VerifiedPlanningSnapshot,
    nginx: &InstanceId,
) {
    let transition = TransitionPlanner::new(&fixture.context)
        .plan(
            planning,
            TransitionInputs {
                current: None,
                authority: None,
            },
            &mut fixture.evaluator,
        )
        .unwrap();
    let effect = transition.checked_effect().document();
    assert_eq!(effect.operations.len(), 6);

    let operation = |method: &str| {
        effect
            .operations
            .iter()
            .find(|operation| operation.method.as_str() == method)
            .unwrap()
    };
    let prepare = operation("prepare");
    let validate = operation("validate");
    let publish = operation("publish");
    let start = operation("start");
    let observe = operation("observe");
    let record = operation("record");
    assert_eq!(
        prepare.target.resource.key.as_str(),
        "nginx-main-configuration"
    );
    assert_eq!(validate.target.resource, nginx_resource(nginx));
    assert_eq!(publish.target.resource, prepare.target.resource);
    assert_eq!(start.target.resource.key.as_str(), "nginx-main-service");
    assert_eq!(observe.target.resource, start.target.resource);
    assert_eq!(record.target.resource, nginx_resource(nginx));

    let edge_exists = |from: &ScopedOperationKey, to: &ScopedOperationKey| {
        effect.edges.iter().any(|edge| {
            edge.from == PlanNodeKey::Operation { key: from.clone() }
                && edge.to == PlanNodeKey::Operation { key: to.clone() }
                && edge.kind == DependencyKind::RequiredSuccess
        })
    };
    assert!(edge_exists(&prepare.key, &validate.key));
    assert!(edge_exists(&validate.key, &publish.key));
    assert!(edge_exists(&publish.key, &start.key));
    assert!(edge_exists(&start.key, &observe.key));
    assert!(edge_exists(&observe.key, &record.key));
}

fn assert_update_pipeline(
    fixture: &mut ReferenceFixture,
    current: &VerifiedPlanningSnapshot,
    desired: &VerifiedPlanningSnapshot,
) {
    let updated = TransitionPlanner::new(&fixture.context)
        .plan(
            desired,
            TransitionInputs {
                current: Some(current),
                authority: None,
            },
            &mut fixture.evaluator,
        )
        .unwrap();
    let methods = updated
        .checked_effect()
        .document()
        .operations
        .iter()
        .map(|operation| operation.method.as_str())
        .collect::<Vec<_>>();
    assert_eq!(methods.len(), 6);
    assert!(methods.contains(&"prepare"));
    assert!(methods.contains(&"validate"));
    assert!(methods.contains(&"publish"));
    assert!(methods.contains(&"record"));
    assert!(methods.contains(&"observe"));
    assert_eq!(
        methods.iter().filter(|method| **method == "reload").count(),
        1,
        "unexpected update methods: {methods:?}"
    );
    assert!(!methods.contains(&"start"));
}

fn assert_noop_pipeline(
    fixture: &mut ReferenceFixture,
    current: &VerifiedPlanningSnapshot,
    desired: &VerifiedPlanningSnapshot,
) {
    let unchanged = TransitionPlanner::new(&fixture.context)
        .plan(
            desired,
            TransitionInputs {
                current: Some(current),
                authority: None,
            },
            &mut fixture.evaluator,
        )
        .unwrap();
    assert!(unchanged.checked_effect().document().operations.is_empty());
}

fn assert_stopped_service_repair(
    fixture: &mut ReferenceFixture,
    current: &VerifiedPlanningSnapshot,
    desired: &VerifiedPlanningSnapshot,
) {
    let repair = TransitionPlanner::new(&fixture.context)
        .plan(
            desired,
            TransitionInputs {
                current: Some(current),
                authority: None,
            },
            &mut fixture.evaluator,
        )
        .unwrap();
    let methods = repair
        .checked_effect()
        .document()
        .operations
        .iter()
        .map(|operation| operation.method.as_str())
        .collect::<Vec<_>>();
    assert_eq!(methods.len(), 3);
    assert!(methods.contains(&"start"));
    assert!(methods.contains(&"observe"));
    assert!(methods.contains(&"record"));
    assert!(!methods.contains(&"prepare"));
    assert!(!methods.contains(&"validate"));
    assert!(!methods.contains(&"publish"));
    assert!(!methods.contains(&"reload"));
}

fn assert_disable_pipeline(
    fixture: &mut ReferenceFixture,
    current: &VerifiedPlanningSnapshot,
    desired: &VerifiedPlanningSnapshot,
    authority: &CheckedTransitionAuthority,
) {
    let transition = TransitionPlanner::new(&fixture.context)
        .plan(
            desired,
            TransitionInputs {
                current: Some(current),
                authority: Some(authority),
            },
            &mut fixture.evaluator,
        )
        .unwrap();
    let operations = &transition.checked_effect().document().operations;
    assert_eq!(operations.len(), 3);
    let stop = operations
        .iter()
        .filter(|operation| {
            matches!(
                &operation.family,
                OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Stop
                }
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(stop.len(), 1);
    assert_eq!(stop[0].target.resource.key.as_str(), "nginx-main-service");

    let releases = operations
        .iter()
        .filter(|operation| operation.family == OperationFamily::ReleaseResource)
        .collect::<Vec<_>>();
    assert_eq!(releases.len(), 2);
    let edges = &transition.checked_effect().document().edges;
    for release in releases {
        assert!(edges.iter().any(|edge| {
            edge.from
                == PlanNodeKey::Operation {
                    key: stop[0].key.clone(),
                }
                && edge.to
                    == PlanNodeKey::Operation {
                        key: release.key.clone(),
                    }
                && edge.kind == DependencyKind::RequiredSuccess
        }));
    }
}

fn teardown_authority(
    fixture: &ReferenceFixture,
    desired: &VerifiedPlanningSnapshot,
    current: &VerifiedPlanningSnapshot,
) -> CheckedTransitionAuthority {
    let mut teardown_bindings = current
        .checked_binding()
        .bindings()
        .iter()
        .map(|source| {
            let mut request = current
                .checked_binding()
                .document()
                .requests
                .iter()
                .find(|request| request.id == source.request)
                .unwrap()
                .clone();
            request.id.key = key(&format!("teardown-request-{}", source.id.0));

            let mut binding = source.clone();
            binding.id = BindingId(key(&format!("teardown-binding-{}", source.id.0)));
            binding.request = request.id.clone();
            binding.policy_revision = desired.checked_binding().document().policy_revision;
            binding.caller_grant.contributions.clear();
            binding.provider_grant.contributions.clear();

            TeardownBindingAuthorization {
                source_binding: source.id.clone(),
                request,
                binding,
            }
        })
        .collect::<Vec<_>>();
    teardown_bindings.sort_by(|left, right| {
        (&left.source_binding, &left.request.id, &left.binding.id).cmp(&(
            &right.source_binding,
            &right.request.id,
            &right.binding.id,
        ))
    });

    let mut teardown_providers = current
        .outcome()
        .resolution
        .policy
        .enabled_providers
        .iter()
        .map(|enabled| {
            let package = current
                .outcome()
                .desired_state
                .instances
                .iter()
                .find(|instance| instance.enabled && instance.instance == enabled.instance)
                .unwrap()
                .package;
            TeardownProviderAuthorization {
                provider: enabled.instance.clone(),
                implementation: enabled.implementation.clone(),
                package,
                policy_revision: desired.checked_binding().document().policy_revision,
            }
        })
        .collect::<Vec<_>>();
    teardown_providers.sort_by(|left, right| {
        (&left.provider, left.implementation.descriptor)
            .cmp(&(&right.provider, right.implementation.descriptor))
    });

    let document = TransitionAuthorizationDocument {
        schema: TransitionAuthorizationDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_planning: desired.snapshot_digest(),
        current_planning: current.snapshot_digest(),
        desired_policy_revision: desired.checked_binding().document().policy_revision,
        prior_policy_revision: current.checked_binding().document().policy_revision,
        authorization_policy_revision: desired.checked_binding().document().policy_revision,
        teardown_bindings,
        teardown_providers,
    };
    let expected_digest = document.content_digest().unwrap();
    fixture
        .context
        .validate_transition_authority(
            document,
            TransitionAuthorityInputs {
                expected_digest,
                desired_planning: desired.snapshot_digest(),
                current_planning: current.snapshot_digest(),
                authorization_policy_revision: desired.checked_binding().document().policy_revision,
                desired: desired.checked_binding(),
                current: current.checked_binding(),
            },
        )
        .unwrap()
}

fn assert_shared_lower_isolation(
    outcome: &aos_ability_plan::CompositionOutcome,
    nginx_one: &InstanceId,
    nginx_two: &InstanceId,
) {
    let bindings = &outcome.resolution.checked.document().bindings;
    for request_key in ["configuration", "service"] {
        let first = lower_binding(bindings, nginx_one, request_key);
        let second = lower_binding(bindings, nginx_two, request_key);

        assert_eq!(first.provider, second.provider);
        assert_eq!(first.provider_package, second.provider_package);
        assert_eq!(first.implementation, second.implementation);

        let first_resource = &first.caller_grant.resources[0].resource;
        let second_resource = &second.caller_grant.resources[0].resource;
        assert_eq!(first_resource.provider, first.provider);
        assert_eq!(second_resource.provider, second.provider);
        assert_ne!(first_resource, second_resource);
        assert!(
            first_resource
                .key
                .as_str()
                .starts_with(nginx_one.key.as_str())
        );
        assert!(
            second_resource
                .key
                .as_str()
                .starts_with(nginx_two.key.as_str())
        );
    }

    assert!(
        bindings
            .iter()
            .all(|binding| binding.request.consumer != *nginx_one
                || binding.request.key.as_str() != "credential")
    );
    assert_eq!(
        lower_binding(bindings, nginx_two, "credential").provider,
        lower_provider(&nginx_two.environment, "credential")
    );
}

fn lower_binding<'a>(
    bindings: &'a [Binding],
    consumer: &InstanceId,
    request_key: &str,
) -> &'a Binding {
    bindings
        .iter()
        .find(|binding| {
            binding.request.consumer == *consumer && binding.request.key.as_str() == request_key
        })
        .unwrap()
}

fn interface_documents() -> Vec<InterfaceDocument> {
    let nginx_request = ValueSchema::Record {
        fields: BTreeMap::from([
            (key("host"), string_schema()),
            (key("tls"), ValueSchema::Boolean),
        ]),
        optional_fields: Vec::new(),
    };
    let mut documents = vec![
        interface_document(
            "aos.nginx",
            nginx_request.clone(),
            vec![
                (
                    "configuration",
                    ValueSchema::ResourceReference,
                    ValueVisibility::Protected,
                ),
                (
                    "credential-view",
                    ValueSchema::Optional {
                        value: Box::new(ValueSchema::ResourceReference),
                    },
                    ValueVisibility::Protected,
                ),
                (
                    "manager",
                    ValueSchema::ResourceReference,
                    ValueVisibility::Protected,
                ),
                (
                    "rendered-configuration",
                    string_schema(),
                    ValueVisibility::Protected,
                ),
                (
                    "virtual-host-count",
                    ValueSchema::Integer {
                        minimum: 0,
                        maximum: 1024,
                    },
                    ValueVisibility::Protected,
                ),
            ],
        ),
        interface_document(
            "aos.managed-configuration",
            ValueSchema::Record {
                fields: BTreeMap::from([(
                    key("virtualHosts"),
                    ValueSchema::List {
                        element: Box::new(nginx_request),
                        max_items: 1024,
                    },
                )]),
                optional_fields: Vec::new(),
            },
            vec![
                (
                    "published-configurations",
                    resource_map_schema(),
                    ValueVisibility::Protected,
                ),
                (
                    "rendered-configurations",
                    ValueSchema::Map {
                        key: map_key_constraint(),
                        value: Box::new(string_schema()),
                        max_entries: 1024,
                    },
                    ValueVisibility::Protected,
                ),
            ],
        ),
        interface_document(
            "aos.credential-delivery",
            ValueSchema::Record {
                fields: BTreeMap::from([(
                    key("hosts"),
                    ValueSchema::List {
                        element: Box::new(string_schema()),
                        max_items: 1024,
                    },
                )]),
                optional_fields: Vec::new(),
            },
            vec![(
                "credential-views",
                resource_map_schema(),
                ValueVisibility::Protected,
            )],
        ),
        interface_document(
            "aos.systemd-service",
            ValueSchema::Record {
                fields: BTreeMap::from([
                    (key("configuration_revision"), string_schema()),
                    (key("unit"), string_schema()),
                    (
                        key("virtual_host_count"),
                        ValueSchema::Integer {
                            minimum: 0,
                            maximum: 1024,
                        },
                    ),
                ]),
                optional_fields: Vec::new(),
            },
            vec![(
                "managers",
                resource_map_schema(),
                ValueVisibility::Protected,
            )],
        ),
        interface_document("aos.nginx-validation", ValueSchema::Boolean, Vec::new()),
        interface_document(
            "aos.managed-configuration-effects",
            ValueSchema::Boolean,
            Vec::new(),
        ),
        interface_document(
            "aos.systemd-service-effects",
            ValueSchema::Boolean,
            Vec::new(),
        ),
    ];
    documents.sort_by(|left, right| left.interface.name.cmp(&right.interface.name));
    documents
}

fn interface_document(
    name: &str,
    request: ValueSchema,
    outputs: Vec<(&str, ValueSchema, ValueVisibility)>,
) -> InterfaceDocument {
    let interface_name = InterfaceName::new(name).unwrap();
    let methods = reference_method_families(name)
        .into_iter()
        .map(|(method, operation_family)| {
            (
                key(method),
                MethodDescriptor {
                    operation_family,
                    parameters: ValueSchema::Boolean,
                    target_resource: interface_name.clone(),
                    outputs: BTreeMap::new(),
                    permitted_operations: vec![key(method)],
                    guarantees: Vec::new(),
                    outcome: OutcomeSemantics {
                        completion_evidence: ValueSchema::Boolean,
                        observation_evidence: ValueSchema::Boolean,
                        supports_rejected_before_effect: true,
                        indeterminate: IndeterminateSemantics::InterventionRequired,
                    },
                },
            )
        })
        .collect();

    InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            name: interface_name,
            abi: NonZeroU32::new(1).unwrap(),
            request,
            outputs: outputs
                .into_iter()
                .map(|(name, schema, visibility)| {
                    (
                        key(name),
                        OutputDescriptor {
                            schema,
                            phase: ValuePhase::Planning,
                            visibility,
                            lifetime: ResourceLifetime::Instance,
                        },
                    )
                })
                .collect(),
            methods,
            lifecycle: LifecycleSemantics {
                stable_resource_identity: true,
                releases_ephemeral_on_disable: true,
                retains_persistent_by_default: true,
                persistent_delete_method: None,
            },
            guarantees: Vec::new(),
        },
    }
}

fn reference_method_families(name: &str) -> Vec<(&'static str, OperationFamily)> {
    match name {
        "aos.nginx-validation" => vec![
            ("record", OperationFamily::RecordGenerationAssociation),
            ("release", OperationFamily::ReleaseResource),
            ("validate", OperationFamily::ValidateCandidate),
        ],
        "aos.managed-configuration-effects" => vec![
            ("prepare", OperationFamily::PrepareManagedConfiguration),
            ("publish", OperationFamily::PublishConfiguration),
            ("release", OperationFamily::ReleaseResource),
        ],
        "aos.systemd-service-effects" => vec![
            ("observe", OperationFamily::ObserveReadiness),
            (
                "reload",
                OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Reload,
                },
            ),
            (
                "start",
                OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Start,
                },
            ),
            (
                "stop",
                OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Stop,
                },
            ),
        ],
        _ => Vec::new(),
    }
}

fn requirement(
    alias: &str,
    interface: &InterfaceKey,
    strength: RequirementStrength,
    fallback: Option<RequirementFallback>,
) -> RequirementDeclaration {
    RequirementDeclaration {
        alias: key(alias),
        accepted_interfaces: vec![interface.clone()],
        methods: Vec::new(),
        guarantees: Vec::new(),
        strength,
        fallback,
    }
}

fn method_requirement(
    alias: &str,
    interface: &InterfaceKey,
    methods: &[&str],
) -> RequirementDeclaration {
    RequirementDeclaration {
        alias: key(alias),
        accepted_interfaces: vec![interface.clone()],
        methods: methods.iter().map(|method| key(method)).collect(),
        guarantees: Vec::new(),
        strength: RequirementStrength::Required,
        fallback: None,
    }
}

fn provider_package(
    name: &str,
    interface: &InterfaceKey,
    artifact: &ArtifactReference,
    requirements: Vec<RequirementDeclaration>,
    group: &str,
) -> PackageDocument {
    let implementation = ProviderImplementation {
        interface: interface.clone(),
        artifact: artifact.clone(),
        requirements,
        implementation: ImplementationKind::PureComposition {
            compose_entry: key("compose"),
            transition_entry: key("transition"),
        },
        owns_resource_kinds: vec![interface.name.clone()],
    };
    let descriptor = implementation.descriptor_digest().unwrap();

    PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        activation_mode: AbilityActivationMode::StructuredEffects,
        package: PackageSubject {
            name: key(name),
            version: "1.0.0".to_string(),
            payload: artifact.clone(),
            source: artifact.clone(),
        },
        artifacts: vec![artifact.clone()],
        exports: vec![ExportDeclaration {
            name: key("default"),
            interface: interface.clone(),
            aggregation: Some(AggregationContract {
                scope: AggregationScope::ProviderInstance,
                key: key("slot"),
                controller_group: key(group),
                reject_slot_collisions: true,
                merge_contract: None,
            }),
            implementation: descriptor,
        }],
        requirements: Vec::new(),
        module_entry_points: BTreeMap::from([
            (key("compose"), artifact.clone()),
            (key("transition"), artifact.clone()),
        ]),
        implementation: PackageImplementation {
            providers: vec![implementation],
            handlers: BTreeMap::new(),
        },
        ownership: vec![ScopePath::root()],
    }
}

fn terminal_package(
    name: &str,
    interface: &InterfaceKey,
    artifact: &ArtifactReference,
) -> PackageDocument {
    let handler = key("terminal");
    let implementation = ProviderImplementation {
        interface: interface.clone(),
        artifact: artifact.clone(),
        requirements: Vec::new(),
        implementation: ImplementationKind::TerminalHandler {
            handler: handler.clone(),
        },
        owns_resource_kinds: vec![interface.name.clone()],
    };
    let descriptor = implementation.descriptor_digest().unwrap();

    PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        activation_mode: AbilityActivationMode::StructuredEffects,
        package: PackageSubject {
            name: key(name),
            version: "1.0.0".to_string(),
            payload: artifact.clone(),
            source: artifact.clone(),
        },
        artifacts: vec![artifact.clone()],
        exports: vec![ExportDeclaration {
            name: key("default"),
            interface: interface.clone(),
            aggregation: None,
            implementation: descriptor,
        }],
        requirements: Vec::new(),
        module_entry_points: BTreeMap::new(),
        implementation: PackageImplementation {
            providers: vec![implementation],
            handlers: BTreeMap::from([(
                handler,
                HandlerDescriptor {
                    artifact: artifact.clone(),
                    entry_point: "libexec/reference-terminal".to_string(),
                    arguments: ValueSchema::Boolean,
                    result: ValueSchema::Boolean,
                },
            )]),
        },
        ownership: vec![ScopePath::root()],
    }
}

fn consumer_package(
    name: &str,
    artifact: &ArtifactReference,
    nginx: &InterfaceKey,
) -> PackageDocument {
    PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        activation_mode: AbilityActivationMode::ContractsOnly,
        package: PackageSubject {
            name: key(name),
            version: "1.0.0".to_string(),
            payload: artifact.clone(),
            source: artifact.clone(),
        },
        artifacts: Vec::new(),
        exports: Vec::new(),
        requirements: vec![requirement(
            "nginx",
            nginx,
            RequirementStrength::Required,
            None,
        )],
        module_entry_points: BTreeMap::new(),
        implementation: PackageImplementation {
            providers: Vec::new(),
            handlers: BTreeMap::new(),
        },
        ownership: Vec::new(),
    }
}

fn provider_reference(package: &PackageDocument) -> ProviderImplementationReference {
    let implementation = &package.implementation.providers[0];
    let handler = match &implementation.implementation {
        ImplementationKind::PureComposition { .. } => None,
        ImplementationKind::TerminalHandler { handler } => Some(handler.clone()),
    };

    ProviderImplementationReference {
        descriptor: implementation.descriptor_digest().unwrap(),
        artifact: implementation.artifact.clone(),
        handler,
    }
}

fn artifact_from_environment(path: &str, nar_hash: &str, tag: u8) -> Result<ArtifactReference> {
    Ok(ArtifactReference {
        content: digest(tag),
        store_path: std::env::var(path).with_context(|| format!("reading {path}"))?,
        nar_hash: Sha256Digest::parse(
            &std::env::var(nar_hash).with_context(|| format!("reading {nar_hash}"))?,
        )?,
        closure: digest(tag.saturating_add(10)),
    })
}

fn assert_fixture_interface_hashes(fixture: &ReferenceFixture) {
    assert_eq!(
        fixture.interfaces["aos.managed-configuration"].descriptor,
        digest_from_hex("41dd1b3848c02d69542c61cdb871d588979139b321afff0edd3942c9d008fa3a")
    );
    assert_eq!(
        fixture.interfaces["aos.credential-delivery"].descriptor,
        digest_from_hex("d282faba1d3a1afd3ed7b2cde885331d8c2cf94f9b7968eb88987cffae852a3b")
    );
    assert_eq!(
        fixture.interfaces["aos.systemd-service"].descriptor,
        digest_from_hex("1be97040a30ac274816ff7d1ee53f384989165f2ed09c80956a1d90458b72f5f")
    );
    assert_eq!(
        fixture.interfaces["aos.nginx-validation"].descriptor,
        digest_from_hex("cfe3335b1ff3082ffd17e38f098e804461daaa32db19a2aba9faa2e2acaddd1d")
    );
    assert_eq!(
        fixture.interfaces["aos.managed-configuration-effects"].descriptor,
        digest_from_hex("2b5e3051194f29f19bdf178c7e51f3bc4dbee7b67eafb04cba7953580dd990bf")
    );
    assert_eq!(
        fixture.interfaces["aos.systemd-service-effects"].descriptor,
        digest_from_hex("08e463bed96f053e557f557c95342666e81358396a44f89bf4c07a2aa780d6c5")
    );
}

fn lower_resource_outputs(state: &DesiredStateDocument) -> Vec<&AggregateOutput> {
    state
        .outputs
        .iter()
        .filter(|output| {
            output.interface.name.as_str() != "aos.nginx"
                && matches!(
                    output.port.as_str(),
                    "published-configurations" | "credential-views" | "managers"
                )
                && matches!(
                    &output.value,
                    ValueExpression::Object { fields }
                        if fields.values().all(|value| matches!(value, ValueExpression::ResourceReference { .. }))
                )
        })
        .collect()
}

fn object_field_count(output: &AggregateOutput) -> usize {
    let ValueExpression::Object { fields } = &output.value else {
        panic!("lower resource output must be an object");
    };
    fields.len()
}

fn policy_has_new_lower_authority(
    policy: &ResolutionPolicyDocument,
    desired: &DesiredStateDocument,
) -> bool {
    policy
        .candidates
        .iter()
        .filter(|candidate| candidate.interface.name.as_str() != "aos.nginx")
        .all(|candidate| {
            !candidate.caller_grant.resources.is_empty()
                && candidate.caller_grant.resources.iter().all(|permission| {
                    desired
                        .resources
                        .iter()
                        .any(|revision| revision.resource == permission.resource)
                })
        })
}

fn nginx_output<'a>(
    state: &'a DesiredStateDocument,
    nginx: &InstanceId,
    port: &str,
) -> Option<&'a AggregateOutput> {
    state.outputs.iter().find(|output| {
        output.aggregate.provider == *nginx
            && output.interface.name.as_str() == "aos.nginx"
            && output.port.as_str() == port
    })
}

fn rendered_configuration(state: &DesiredStateDocument, nginx: &InstanceId) -> String {
    let ValueExpression::Literal { value } = &nginx_output(state, nginx, "rendered-configuration")
        .unwrap()
        .value
    else {
        panic!("rendered configuration must be a planning literal");
    };
    value.as_json().as_str().unwrap().to_string()
}

fn virtual_host_count(state: &DesiredStateDocument, nginx: &InstanceId) -> i64 {
    let ValueExpression::Literal { value } = &nginx_output(state, nginx, "virtual-host-count")
        .unwrap()
        .value
    else {
        panic!("virtual-host count must be a planning literal");
    };
    value.as_json().as_i64().unwrap()
}

fn nginx_resource(nginx: &InstanceId) -> ResourceId {
    ResourceId {
        provider: nginx.clone(),
        key: key("virtual-hosts"),
    }
}

fn lower_interface_name(suffix: &str) -> &'static str {
    match suffix {
        "configuration" => "aos.managed-configuration",
        "credential" => "aos.credential-delivery",
        "service" => "aos.systemd-service",
        _ => panic!("unknown lower-interface suffix"),
    }
}

fn terminal_interface_name(interface: &str) -> &'static str {
    match interface {
        "aos.managed-configuration" => "aos.managed-configuration-effects",
        "aos.systemd-service" => "aos.systemd-service-effects",
        _ => "",
    }
}

fn lower_authority(suffix: &str) -> (&'static str, Vec<&'static str>, &'static str) {
    match suffix {
        "configuration" => ("configuration", vec!["publish", "read"], "configuration"),
        "credential" => ("credentials", vec!["deliver"], "credential-view"),
        "service" => ("services", vec!["observe", "reload", "start"], "service"),
        _ => panic!("unknown lower-interface suffix"),
    }
}

fn binding_key(request: &RequestId) -> LocalKey {
    key(&format!("bind-{}-{}", request.consumer.key, request.key))
}

fn string_schema() -> ValueSchema {
    ValueSchema::String {
        max_length: 64 * 1024,
        syntax: None,
    }
}

fn resource_map_schema() -> ValueSchema {
    ValueSchema::Map {
        key: map_key_constraint(),
        value: Box::new(ValueSchema::ResourceReference),
        max_entries: 1024,
    }
}

fn map_key_constraint() -> StringConstraint {
    StringConstraint {
        max_length: 128,
        syntax: Some(StringSyntax::LocalKeyV1),
    }
}

fn lower_provider(environment: &EnvironmentId, suffix: &str) -> InstanceId {
    instance(environment, &format!("shared-{suffix}"))
}

fn instance(environment: &EnvironmentId, name: &str) -> InstanceId {
    InstanceId {
        environment: environment.clone(),
        key: key(name),
    }
}

fn key(value: &str) -> LocalKey {
    LocalKey::new(value).unwrap()
}

fn value(value: serde_json::Value) -> AbilityValue {
    AbilityValue::new(value).unwrap()
}

fn digest(tag: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([tag; 32])
}

fn digest_from_hex(hex: &str) -> Sha256Digest {
    Sha256Digest::parse(&format!("sha256:{hex}")).unwrap()
}
