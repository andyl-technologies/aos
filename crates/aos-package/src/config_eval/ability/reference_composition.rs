//! End-to-end source composition through the restricted Nix evaluator.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use anyhow::{Context, Result};
use aos_ability_model::builtin::{
    credential_delivery_effects_interface, credential_view_schema, host_network_policy_interface,
    host_network_policy_loopback_tcp_ingress_guarantee, network_endpoint_interface,
};
use aos_ability_model::document::{
    Contribution, DesiredInstance, FreshnessCondition, PlatformIdentity, ProviderInventory,
    ProviderState,
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

mod registry;

use registry::ReferencePackageCatalog;

const REFERENCE_ENVIRONMENT: [&str; 12] = [
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
    "AOS_TEST_ABILITY_REFERENCE_PACKAGES",
];
const REFERENCE_ATTEMPT_TIMEOUT_MILLIS: u64 = 300_000;
const REFERENCE_TOTAL_RECOVERY_MILLIS: u64 = 1_200_000;

struct ReferenceFixture {
    context: ValidationContext,
    environment: EnvironmentDocument,
    packages: Vec<PackageDocument>,
    consumer_package: Sha256Digest,
    nginx_package: Sha256Digest,
    lower_packages: BTreeMap<String, Sha256Digest>,
    terminal_packages: BTreeMap<String, Sha256Digest>,
    implementations: BTreeMap<String, ProviderImplementationReference>,
    terminal_implementations: BTreeMap<String, ProviderImplementationReference>,
    interfaces: BTreeMap<String, InterfaceKey>,
    policy_revision: RevisionId,
    evaluator: RestrictedAbilityEvaluator,
    registry: ReferencePackageCatalog,
}

struct Deployment<'a> {
    fixture: &'a mut ReferenceFixture,
    nginx_instances: Vec<InstanceId>,
    app_routes: Vec<AppRoute>,
}

#[derive(Clone, Copy)]
struct AppRoute {
    application: &'static str,
    nginx: &'static str,
    host: &'static str,
    tls: bool,
    response: &'static str,
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

        let registry = ReferencePackageCatalog::from_environment()?;
        let packages = registry.source_packages().to_vec();
        let interface_documents = interface_documents();
        let interface_guarantees = interface_documents
            .iter()
            .map(|document| {
                (
                    document.interface.name.as_str().to_string(),
                    document.interface.guarantees.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let interfaces = interface_documents
            .iter()
            .map(|document| {
                Ok((
                    document.interface.name.as_str().to_string(),
                    document.interface_key()?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let supported_features = BTreeSet::from([RequiredFeature::new("abilities-v1")?]);
        let context = ValidationContext::new(supported_features, interface_documents)
            .context("validating reference interface catalog")?;

        let mut nginx_package = None;
        let mut consumer_package = None;
        let mut lower_packages = BTreeMap::new();
        let mut terminal_packages = BTreeMap::new();
        let mut implementations = BTreeMap::new();
        let mut terminal_implementations = BTreeMap::new();
        for package in &packages {
            let package_digest = package.content_digest()?;
            if package.package.name.as_str() == "ability-reference-nginx-consumer" {
                consumer_package = Some(package_digest);
            }
            for provider in &package.implementation.providers {
                let name = provider.interface.name.as_str();
                ensure_interface_matches(&interfaces, &provider.interface)?;
                let reference = provider_reference(provider);
                match provider.implementation {
                    ImplementationKind::PureComposition { .. } => {
                        implementations.insert(name.to_string(), reference);
                        if name == "aos.nginx" {
                            nginx_package = Some(package_digest);
                        } else {
                            lower_packages.insert(name.to_string(), package_digest);
                        }
                    }
                    ImplementationKind::TerminalHandler { .. } => {
                        terminal_packages.insert(name.to_string(), package_digest);
                        terminal_implementations.insert(name.to_string(), reference);
                    }
                }
            }
        }
        let consumer_package =
            consumer_package.context("reference companion omits nginx consumer")?;
        let nginx_package = nginx_package.context("reference companion omits aos.nginx")?;

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
                    guarantees: interface_guarantees[terminal_name].clone(),
                });
            }
        }
        let loopback_ingress = host_network_policy_loopback_tcp_ingress_guarantee()?;
        for nginx in ["nginx-main", "nginx-one", "nginx-two"] {
            let provider = instance(&environment_id, nginx);
            for interface_name in [
                "aos.nginx-validation",
                "aos.network-endpoint-effects",
                "aos.host-network-policy-effects",
            ] {
                providers.push(ProviderInventory {
                    provider: provider.clone(),
                    interface: interfaces[interface_name].clone(),
                    implementation: terminal_implementations[interface_name].clone(),
                    state: ProviderState::Available,
                    incarnation: Some(IncarnationId::new(&format!(
                        "reference-{nginx}-{}-terminal",
                        interface_name.replace('.', "-")
                    ))?),
                    guarantees: if interface_name == "aos.host-network-policy-effects" {
                        vec![loopback_ingress.clone()]
                    } else {
                        Vec::new()
                    },
                });
            }
        }
        providers.sort_by(|left, right| {
            left.provider
                .cmp(&right.provider)
                .then_with(|| left.interface.cmp(&right.interface))
                .then_with(|| {
                    left.implementation
                        .descriptor
                        .cmp(&right.implementation.descriptor)
                })
        });
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
            consumer_package,
            nginx_package,
            lower_packages,
            terminal_packages,
            implementations,
            terminal_implementations,
            interfaces,
            policy_revision,
            evaluator,
            registry,
        }))
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

        for route in &self.app_routes {
            let app_instance = instance(&self.fixture.environment.environment, route.application);
            let nginx_instance = instance(&self.fixture.environment.environment, route.nginx);
            let request = RequestId {
                consumer: app_instance.clone(),
                scope: ScopePath::root(),
                key: key("nginx"),
            };
            let candidate = binding_key(&request);
            instances.push(DesiredInstance {
                instance: app_instance.clone(),
                package: self.fixture.consumer_package,
                enabled: true,
                configuration: None,
            });
            requests.push(BindingRequest {
                id: request.clone(),
                accepted_interfaces: vec![self.fixture.interfaces["aos.nginx"].clone()],
                methods: Vec::new(),
                guarantees: Vec::new(),
                lifetime: ResourceLifetime::Instance,
            });
            let mut contribution = serde_json::json!({
                "host": route.host,
                "response_content": route.response,
                "response_identity": route.application,
                "tls": route.tls,
            });
            if route.tls {
                contribution["credential_version"] = serde_json::json!(reference_tls_version());
            }
            contributions.push(Contribution {
                request,
                aggregate: AggregateId {
                    provider: nginx_instance,
                    group: key("nginx"),
                },
                slot: app_instance.key.clone(),
                grant: BindingId(candidate),
                value: value(contribution),
            });
        }
        for nginx in &self.nginx_instances {
            instances.push(DesiredInstance {
                instance: nginx.clone(),
                package: self.fixture.nginx_package,
                enabled: nginx_enabled,
                configuration: Some(nginx_consumer_probe(nginx)),
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
            "effects" | "validation-terminal" | "service-terminal" | "endpoint" | "network-policy"
        );
        let (provider, provider_package, implementation, resources, contributions) = if terminal {
            let provider = if request.id.key.as_str() == "service-terminal" {
                lower_provider(&self.fixture.environment.environment, "service")
            } else {
                request.id.consumer.clone()
            };
            let exact_service_key = (request.id.key.as_str() == "service-terminal")
                .then(|| format!("{}-service", request.id.consumer.key));
            let resources = desired
                .resources
                .iter()
                .filter(|revision| {
                    revision.resource.provider == provider
                        && exact_service_key
                            .as_ref()
                            .is_none_or(|expected| revision.resource.key.as_str() == expected)
                })
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
                .find(|route| route.application == request.id.consumer.key.as_str())
                .unwrap();
            let provider = instance(&self.fixture.environment.environment, route.nginx);
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
        let mut provider_resources = resources
            .into_iter()
            .map(|mut permission| {
                if permission.resource.provider == provider {
                    permission.access = AccessMode::ExclusiveWrite;
                }
                permission
            })
            .collect::<Vec<_>>();
        if interface.name.as_str() == "aos.credential-delivery" {
            provider_resources.push(ResourcePermission {
                resource: nginx_resource(&request.id.consumer),
                access: AccessMode::Read,
                operations: Vec::new(),
            });
        }
        provider_resources.sort_by(|left, right| left.resource.cmp(&right.resource));

        let provider_grant = AuthorityGrant {
            principal: provider.clone(),
            methods: Vec::new(),
            contributions: Vec::new(),
            resources: provider_resources,
        };

        let guarantees = if interface.name.as_str() == "aos.host-network-policy-effects" {
            vec![host_network_policy_loopback_tcp_ingress_guarantee().unwrap()]
        } else {
            Vec::new()
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
            guarantees,
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
            app_route("app-a", "nginx-main", "alpha.example", false, "alpha-v1"),
            app_route("app-b", "nginx-main", "beta.example", false, "beta-v1"),
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
    assert!(rendered.contains("return 200 \"app-a:alpha-v1\\n\";"));
    assert!(rendered.contains("return 200 \"app-b:beta-v1\\n\";"));
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
            app_route("app-a", "nginx-main", "alpha.example", false, "alpha-v2"),
            app_route("app-b", "nginx-main", "beta.example", false, "beta-v1"),
        ],
    };
    let seed = updated.seed(true);
    let updated_composed = updated.compose(seed.clone());
    let updated_planning = assert_snapshot_replay(updated.fixture, seed, &updated_composed);
    assert_update_pipeline(updated.fixture, &planning, &updated_planning);
    let updated_state = updated_composed.outcome.desired_state.clone();
    let rendered = rendered_configuration(&updated_state, &nginx_main);
    assert!(rendered.contains("alpha.example"));
    assert!(rendered.contains("beta.example"));
    assert!(!rendered.contains("app-a:alpha-v1"));
    assert!(rendered.contains("return 200 \"app-a:alpha-v2\\n\";"));
    assert!(rendered.contains("return 200 \"app-b:beta-v1\\n\";"));

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
    assert_eq!(
        configured_consumer_probe(&empty_state, &nginx_main),
        nginx_consumer_probe(&nginx_main)
    );
    assert_eq!(
        service_consumer_endpoint(&empty_state, &nginx_main),
        "127.0.0.1:18081"
    );
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
    assert_eq!(
        configured_consumer_probe(&disabled_state, &nginx_main),
        nginx_consumer_probe(&nginx_main)
    );
    assert!(disabled_state.resources.is_empty());
    assert!(disabled_state.outputs.is_empty());
    assert!(disabled_state.controllers.is_empty());
    empty.fixture.observe_applied_state(&disabled_state);

    let nginx_one = instance(&environment, "nginx-one");
    let nginx_two = instance(&environment, "nginx-two");
    let mut isolated = Deployment {
        fixture: empty.fixture,
        nginx_instances: vec![nginx_one.clone(), nginx_two.clone()],
        app_routes: vec![
            app_route("app-a", "nginx-one", "one.example", true, "one-v1"),
            app_route("app-b", "nginx-two", "two.example", true, "two-v1"),
        ],
    };
    let seed = isolated.seed(true);
    let isolated_composed = isolated.compose(seed.clone());
    let isolated_planning = assert_snapshot_replay(isolated.fixture, seed, &isolated_composed);
    assert_shared_lower_isolation(
        &isolated_composed.outcome,
        &nginx_one,
        &nginx_two,
        true,
        true,
    );
    let isolated_transition = TransitionPlanner::new(&isolated.fixture.context)
        .plan(
            &isolated_planning,
            TransitionInputs {
                current: None,
                authority: None,
                reconciliation: None,
            },
            &mut isolated.fixture.evaluator,
        )
        .unwrap();
    let isolated_effect = isolated_transition.checked_effect().document();
    let credential_delivery = isolated_effect
        .operations
        .iter()
        .find(|operation| {
            operation.family
                == OperationFamily::Credential {
                    action: CredentialAction::Deliver,
                }
                && operation.target.resource.key.as_str() == "nginx-two-credential-view"
        })
        .unwrap();
    assert_eq!(
        credential_delivery.target.resource.provider.key.as_str(),
        "shared-credential"
    );
    assert_eq!(
        credential_delivery.target.resource.key.as_str(),
        "nginx-two-credential-view"
    );
    let credential_effects = isolated_planning
        .checked_binding()
        .bindings()
        .iter()
        .find(|binding| {
            binding.provider == credential_delivery.target.resource.provider
                && binding.request.consumer == credential_delivery.target.resource.provider
                && binding.request.key.as_str() == "effects"
        })
        .unwrap();
    assert_eq!(credential_delivery.binding, credential_effects.id);
    assert_eq!(
        credential_effects
            .caller_grant
            .resources
            .iter()
            .map(|permission| (
                permission.resource.key.as_str(),
                permission
                    .operations
                    .iter()
                    .map(LocalKey::as_str)
                    .collect::<Vec<_>>()
            ))
            .collect::<Vec<_>>(),
        [
            (
                "nginx-one-credential-view",
                vec!["acquire", "deliver", "release"]
            ),
            (
                "nginx-two-credential-view",
                vec!["acquire", "deliver", "release"]
            ),
        ]
    );
    let nginx_two_validation = isolated_effect
        .operations
        .iter()
        .find(|operation| {
            operation.method.as_str() == "validate"
                && operation.target.resource.provider == nginx_two
        })
        .unwrap();
    assert_operation_edge(
        isolated_effect,
        credential_delivery,
        nginx_two_validation,
        DependencyKind::Data,
    );

    let isolated_state = isolated_composed.outcome.desired_state;
    let first = rendered_configuration(&isolated_state, &nginx_one);
    let second = rendered_configuration(&isolated_state, &nginx_two);
    assert!(first.contains("one.example"));
    assert!(!first.contains("two.example"));
    assert!(second.contains("two.example"));
    assert!(!second.contains("one.example"));
    assert!(nginx_output(&isolated_state, &nginx_one, "credential-view").is_some());
    assert!(nginx_output(&isolated_state, &nginx_two, "credential-view").is_some());

    isolated.fixture.observe_applied_state(&isolated_state);
    let mut tls_removed = Deployment {
        fixture: isolated.fixture,
        nginx_instances: vec![nginx_one.clone(), nginx_two.clone()],
        app_routes: vec![
            app_route("app-a", "nginx-one", "one-updated.example", true, "one-v2"),
            app_route("app-b", "nginx-two", "two.example", false, "two-v1"),
        ],
    };
    let seed = tls_removed.seed(true);
    let tls_removed_composed = tls_removed.compose(seed.clone());
    let tls_removed_planning =
        assert_snapshot_replay(tls_removed.fixture, seed, &tls_removed_composed);
    let authority = teardown_authority(
        tls_removed.fixture,
        &tls_removed_planning,
        &isolated_planning,
    );
    let tls_removed_transition = TransitionPlanner::new(&tls_removed.fixture.context)
        .plan(
            &tls_removed_planning,
            TransitionInputs {
                current: Some(&isolated_planning),
                authority: Some(&authority),
                reconciliation: None,
            },
            &mut tls_removed.fixture.evaluator,
        )
        .unwrap();
    let tls_removed_effect = tls_removed_transition.checked_effect().document();
    let credential_release = tls_removed_effect
        .operations
        .iter()
        .find(|operation| {
            operation.family == OperationFamily::ReleaseResource
                && operation.target.resource.provider.key.as_str() == "shared-credential"
                && operation.target.resource.key.as_str() == "nginx-two-credential-view"
        })
        .unwrap();
    assert_eq!(
        credential_release.target.resource.key.as_str(),
        "nginx-two-credential-view"
    );
    let credential_delivery = tls_removed_effect
        .operations
        .iter()
        .find(|operation| {
            operation.family
                == OperationFamily::Credential {
                    action: CredentialAction::Deliver,
                }
                && operation.target.resource.key.as_str() == "nginx-one-credential-view"
        })
        .unwrap();
    let credential_provider = lower_provider(&environment, "credential");
    let desired_effects = tls_removed_planning
        .checked_binding()
        .bindings()
        .iter()
        .find(|binding| {
            binding.provider == credential_provider
                && binding.request.consumer == credential_provider
                && binding.request.key.as_str() == "effects"
        })
        .unwrap();
    let teardown_effects = authority
        .document()
        .teardown_bindings
        .iter()
        .find(|entry| entry.source_binding == desired_effects.id)
        .unwrap();
    assert_eq!(
        desired_effects
            .caller_grant
            .resources
            .iter()
            .map(|permission| permission.resource.key.as_str())
            .collect::<Vec<_>>(),
        ["nginx-one-credential-view"]
    );
    assert_eq!(
        teardown_effects
            .binding
            .caller_grant
            .resources
            .iter()
            .map(|permission| permission.resource.key.as_str())
            .collect::<Vec<_>>(),
        ["nginx-two-credential-view"]
    );
    assert_eq!(credential_delivery.binding, desired_effects.id);
    assert_eq!(credential_release.binding, teardown_effects.binding.id);
    let nginx_two_observation = tls_removed_effect
        .operations
        .iter()
        .find(|operation| {
            operation.family == OperationFamily::ObserveReadiness
                && operation.target.resource.key.as_str() == "nginx-two-service"
        })
        .unwrap();
    assert_operation_edge(
        tls_removed_effect,
        nginx_two_observation,
        credential_release,
        DependencyKind::RequiredSuccess,
    );

    tls_removed.fixture.observe_applied_state(&isolated_state);
    let mut tls_disabled = Deployment {
        fixture: tls_removed.fixture,
        nginx_instances: vec![nginx_one.clone(), nginx_two.clone()],
        app_routes: Vec::new(),
    };
    let seed = tls_disabled.seed(false);
    let tls_disabled_composed = tls_disabled.compose(seed.clone());
    let tls_disabled_planning =
        assert_snapshot_replay(tls_disabled.fixture, seed, &tls_disabled_composed);
    let authority = teardown_authority(
        tls_disabled.fixture,
        &tls_disabled_planning,
        &isolated_planning,
    );
    let tls_disabled_transition = TransitionPlanner::new(&tls_disabled.fixture.context)
        .plan(
            &tls_disabled_planning,
            TransitionInputs {
                current: Some(&isolated_planning),
                authority: Some(&authority),
                reconciliation: None,
            },
            &mut tls_disabled.fixture.evaluator,
        )
        .unwrap();
    let tls_disabled_effect = tls_disabled_transition.checked_effect().document();
    let credential_release = tls_disabled_effect
        .operations
        .iter()
        .find(|operation| {
            operation.family == OperationFamily::ReleaseResource
                && operation.target.resource.provider.key.as_str() == "shared-credential"
                && operation.target.resource.key.as_str() == "nginx-two-credential-view"
        })
        .unwrap();
    let nginx_two_stop = tls_disabled_effect
        .operations
        .iter()
        .find(|operation| {
            matches!(
                &operation.family,
                OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Stop
                }
            ) && operation.target.resource.key.as_str() == "nginx-two-service"
        })
        .unwrap();
    assert_operation_edge(
        tls_disabled_effect,
        nginx_two_stop,
        credential_release,
        DependencyKind::RequiredSuccess,
    );

    tls_disabled.fixture.observe_applied_state(&disabled_state);
    let mut transitioning = Deployment {
        fixture: tls_disabled.fixture,
        nginx_instances: vec![nginx_one.clone(), nginx_two.clone()],
        app_routes: vec![
            app_route("app-a", "nginx-one", "one.example", false, "one-v1"),
            app_route("app-b", "nginx-two", "two.example", false, "two-v1"),
        ],
    };
    let seed = transitioning.seed(true);
    let transitioning_composed = transitioning.compose(seed.clone());
    let transitioning_planning =
        assert_snapshot_replay(transitioning.fixture, seed, &transitioning_composed);
    assert_shared_lower_isolation(
        &transitioning_composed.outcome,
        &nginx_one,
        &nginx_two,
        false,
        false,
    );
    let transitioning_transition = TransitionPlanner::new(&transitioning.fixture.context)
        .plan(
            &transitioning_planning,
            TransitionInputs {
                current: None,
                authority: None,
                reconciliation: None,
            },
            &mut transitioning.fixture.evaluator,
        )
        .unwrap();
    assert_eq!(
        transitioning_transition
            .checked_effect()
            .document()
            .operations
            .len(),
        12
    );

    let transitioning_state = transitioning_composed.outcome.desired_state;
    transitioning
        .fixture
        .observe_applied_state(&transitioning_state);
    let mut reduced = Deployment {
        fixture: transitioning.fixture,
        nginx_instances: vec![nginx_one],
        app_routes: vec![app_route(
            "app-a",
            "nginx-one",
            "one.example",
            false,
            "one-v2",
        )],
    };
    let seed = reduced.seed(true);
    let reduced_composed = reduced.compose(seed.clone());
    let reduced_planning = assert_snapshot_replay(reduced.fixture, seed, &reduced_composed);
    let authority = teardown_authority(reduced.fixture, &reduced_planning, &transitioning_planning);
    let configuration_provider = lower_provider(&environment, "configuration");
    let desired_effects = reduced_planning
        .checked_binding()
        .bindings()
        .iter()
        .find(|binding| {
            binding.provider == configuration_provider
                && binding.request.consumer == configuration_provider
                && binding.request.key.as_str() == "effects"
        })
        .unwrap();
    let teardown_effects = authority
        .document()
        .teardown_bindings
        .iter()
        .find(|entry| entry.source_binding == desired_effects.id)
        .unwrap();
    assert_eq!(
        desired_effects
            .caller_grant
            .resources
            .iter()
            .map(|permission| permission.resource.key.as_str())
            .collect::<Vec<_>>(),
        ["nginx-one-configuration"]
    );
    assert_eq!(
        teardown_effects
            .binding
            .caller_grant
            .resources
            .iter()
            .map(|permission| permission.resource.key.as_str())
            .collect::<Vec<_>>(),
        ["nginx-two-configuration"]
    );

    let reduced_transition = TransitionPlanner::new(&reduced.fixture.context)
        .plan(
            &reduced_planning,
            TransitionInputs {
                current: Some(&transitioning_planning),
                authority: Some(&authority),
                reconciliation: None,
            },
            &mut reduced.fixture.evaluator,
        )
        .unwrap();
    let configuration_operations = reduced_transition
        .checked_effect()
        .document()
        .operations
        .iter()
        .filter(|operation| {
            operation.target.resource.provider.key.as_str() == "shared-configuration"
        })
        .map(|operation| {
            (
                operation.method.as_str(),
                operation.target.resource.key.as_str(),
                &operation.binding,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        configuration_operations,
        [
            ("prepare", "nginx-one-configuration", &desired_effects.id),
            ("publish", "nginx-one-configuration", &desired_effects.id),
            (
                "release",
                "nginx-two-configuration",
                &teardown_effects.binding.id
            ),
        ]
    );
}

#[test]
fn authenticated_registry_and_source_paths_produce_identical_plans() {
    let Some(mut fixture) = ReferenceFixture::from_environment().unwrap() else {
        return;
    };
    assert_fixture_interface_hashes(&fixture);

    let environment = fixture.environment.environment.clone();
    let nginx = instance(&environment, "nginx-main");
    let mut deployment = Deployment {
        fixture: &mut fixture,
        nginx_instances: vec![nginx.clone()],
        app_routes: vec![
            app_route("app-a", "nginx-main", "alpha.example", false, "alpha-v1"),
            app_route("app-b", "nginx-main", "beta.example", false, "beta-v1"),
        ],
    };
    let seed = deployment.seed(true);
    let source = deployment.compose(seed.clone());

    let verified_packages = deployment.fixture.registry.verified_packages();
    let catalog = verified_packages.planning_catalog().unwrap();
    let authenticated_artifacts = verified_packages
        .iter()
        .flat_map(|package| package.artifacts().iter().cloned())
        .collect::<Vec<_>>();
    verified_packages
        .verify_plan_inputs(
            &deployment.fixture.environment.platform,
            catalog.packages(),
            &authenticated_artifacts,
        )
        .unwrap();

    let registry = catalog
        .composer()
        .compose(
            &source.policies,
            seed.clone(),
            deployment.fixture.environment.clone(),
            catalog.packages().to_vec(),
            &mut deployment.fixture.evaluator,
        )
        .unwrap();

    assert_eq!(
        source.outcome.desired_state.contributions,
        registry.desired_state.contributions
    );
    assert_eq!(
        source.outcome.resolution.decisions,
        registry.resolution.decisions
    );
    assert_eq!(
        source.outcome.desired_state.resources,
        registry.desired_state.resources
    );
    assert_eq!(
        rendered_configuration(&source.outcome.desired_state, &nginx),
        rendered_configuration(&registry.desired_state, &nginx)
    );

    let source_snapshot = PlanningSnapshot::from_outcome(&source.outcome).unwrap();
    let registry_snapshot = PlanningSnapshot::from_outcome(&registry).unwrap();
    assert_eq!(
        source_snapshot.canonical_bytes().unwrap(),
        registry_snapshot.canonical_bytes().unwrap()
    );
    let mut authenticated_policies = source.policies.clone();
    authenticated_policies.sort_by_key(|policy| policy.desired_state);

    let source_verified = source_snapshot
        .verify_structure(
            &RecursiveComposer::new(&deployment.fixture.context),
            PlanningReplayInputs {
                expected_digest: source_snapshot.digest().unwrap(),
                authenticated_policies: &authenticated_policies,
                seed: seed.clone(),
                environment: deployment.fixture.environment.clone(),
                packages: deployment.fixture.packages.clone(),
            },
        )
        .unwrap();
    let registry_verified = registry_snapshot
        .verify_structure(
            &catalog.composer(),
            PlanningReplayInputs {
                expected_digest: registry_snapshot.digest().unwrap(),
                authenticated_policies: &authenticated_policies,
                seed,
                environment: deployment.fixture.environment.clone(),
                packages: catalog.packages().to_vec(),
            },
        )
        .unwrap();

    let source_transition = TransitionPlanner::new(&deployment.fixture.context)
        .plan(
            &source_verified,
            TransitionInputs {
                current: None,
                authority: None,
                reconciliation: None,
            },
            &mut deployment.fixture.evaluator,
        )
        .unwrap();
    let registry_transition = TransitionPlanner::new(catalog.validation_context())
        .plan(
            &registry_verified,
            TransitionInputs {
                current: None,
                authority: None,
                reconciliation: None,
            },
            &mut deployment.fixture.evaluator,
        )
        .unwrap();
    assert_eq!(
        source_transition.checked_effect().document(),
        registry_transition.checked_effect().document()
    );
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
            app_routes: vec![app_route(
                "app-a",
                "nginx-main",
                hostile_host,
                false,
                "safe-response",
            )],
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
fn checked_reference_source_rejects_unsafe_response_content_before_effect_planning() {
    let Some(mut fixture) = ReferenceFixture::from_environment().unwrap() else {
        return;
    };
    let environment = fixture.environment.environment.clone();
    let nginx = instance(&environment, "nginx-main");

    for hostile_response in [
        "bad\nresponse",
        "bad\"; return 500",
        "bad${nginx_version}",
        "bad\\response",
    ] {
        let mut deployment = Deployment {
            fixture: &mut fixture,
            nginx_instances: vec![nginx.clone()],
            app_routes: vec![app_route(
                "app-a",
                "nginx-main",
                "safe.example",
                false,
                hostile_response,
            )],
        };
        let seed = deployment.seed(true);
        let error = match deployment.try_compose(seed) {
            Ok(_) => panic!("hostile nginx response reached a planning snapshot"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            CompositionError::Evaluation { ref source, .. }
                if source.to_string().contains("response content is invalid")
        ));
    }
}

#[test]
fn checked_reference_source_rejects_response_identity_outside_its_slot() {
    let Some(mut fixture) = ReferenceFixture::from_environment().unwrap() else {
        return;
    };
    let environment = fixture.environment.environment.clone();
    let nginx = instance(&environment, "nginx-main");
    let mut deployment = Deployment {
        fixture: &mut fixture,
        nginx_instances: vec![nginx],
        app_routes: vec![app_route(
            "app-a",
            "nginx-main",
            "safe.example",
            false,
            "safe-response",
        )],
    };
    let mut seed = deployment.seed(true);
    seed.contributions[0].value = value(serde_json::json!({
        "host": "safe.example",
        "response_content": "safe-response",
        "response_identity": "app-b",
        "tls": false,
    }));

    let error = match deployment.try_compose(seed) {
        Ok(_) => panic!("a response identity outside its slot reached a planning snapshot"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        CompositionError::Evaluation { ref source, .. }
            if source.to_string().contains("does not match its authorized slot")
    ));
}

#[test]
fn checked_reference_source_rejects_app_selected_consumer_probe() {
    let Some(mut fixture) = ReferenceFixture::from_environment().unwrap() else {
        return;
    };
    let environment = fixture.environment.environment.clone();
    let nginx = instance(&environment, "nginx-main");
    let mut deployment = Deployment {
        fixture: &mut fixture,
        nginx_instances: vec![nginx],
        app_routes: vec![app_route(
            "app-a",
            "nginx-main",
            "safe.example",
            false,
            "safe-response",
        )],
    };
    let mut seed = deployment.seed(true);
    let contribution = seed.contributions[0].value.as_json().as_object().unwrap();
    let mut injected = contribution.clone();
    injected.insert(
        "consumer_probe".to_string(),
        serde_json::json!({"address": "127.0.0.1", "port": 28081}),
    );
    seed.contributions[0].value = value(serde_json::Value::Object(injected));

    let error = match deployment.try_compose(seed) {
        Ok(_) => panic!("an app-selected consumer probe reached a planning snapshot"),
        Err(error) => error,
    };
    assert!(matches!(error, CompositionError::Resolution(_)));
    assert!(format!("{error:#?}").contains("consumer_probe"));
}

#[test]
fn checked_reference_source_rejects_a_strategy_incompatible_with_its_stage() {
    let Some(mut fixture) = ReferenceFixture::from_environment().unwrap() else {
        return;
    };
    let environment = fixture.environment.environment.clone();
    let nginx = instance(&environment, "nginx-main");
    let mut deployment = Deployment {
        fixture: &mut fixture,
        nginx_instances: vec![nginx],
        app_routes: vec![app_route(
            "app-a",
            "nginx-main",
            "safe.example",
            false,
            "safe-response",
        )],
    };
    let mut seed = deployment.seed(true);
    let configuration = seed.instances[0]
        .configuration
        .as_ref()
        .unwrap()
        .as_json()
        .as_object()
        .unwrap();
    let mut incompatible = configuration.clone();
    incompatible.insert(
        "execution_strategy".to_string(),
        serde_json::json!("foreground-process"),
    );
    seed.instances[0].configuration = Some(value(serde_json::Value::Object(incompatible)));

    let error = match deployment.try_compose(seed) {
        Ok(_) => panic!("an incompatible execution strategy reached a planning snapshot"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        CompositionError::Evaluation { ref source, .. }
            if source.to_string().contains("execution strategy is incompatible")
    ));
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
            app_route("app-a", "nginx-main", "shared.example", false, "a-v1"),
            app_route("app-b", "nginx-main", "shared.example", false, "b-v1"),
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
            app_route("app-a", "nginx-one", "shared.example", false, "a-v1"),
            app_route("app-b", "nginx-two", "shared.example", false, "b-v1"),
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
            app_route("app-a", "nginx-main", "shared.example", false, "a-v1"),
            app_route("app-b", "nginx-main", "Shared.Example", false, "b-v1"),
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
                reconciliation: None,
            },
            &mut fixture.evaluator,
        )
        .unwrap();
    let effect = transition.checked_effect().document();
    assert_eq!(effect.operations.len(), 8);

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
    let endpoint = operation("materialize");
    let policy = operation("apply");
    for recoverable in [
        prepare, validate, publish, observe, record, endpoint, policy,
    ] {
        assert_recovery_method(recoverable, recoverable.method.as_str());
    }
    assert!(start.recovery.reconcile.is_none());
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
    assert!(effect.edges.iter().any(|edge| {
        edge.from
            == PlanNodeKey::Operation {
                key: endpoint.key.clone(),
            }
            && edge.to
                == PlanNodeKey::Operation {
                    key: policy.key.clone(),
                }
            && edge.kind == DependencyKind::Data
    }));
    assert!(edge_exists(&policy.key, &start.key));
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
                reconciliation: None,
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
    assert_eq!(methods.len(), 8);
    assert!(methods.contains(&"prepare"));
    assert!(methods.contains(&"validate"));
    assert!(methods.contains(&"publish"));
    assert!(methods.contains(&"record"));
    assert!(methods.contains(&"observe"));
    assert_eq!(
        methods
            .iter()
            .filter(|method| **method == "observe")
            .count(),
        3
    );
    assert_eq!(
        methods.iter().filter(|method| **method == "reload").count(),
        1,
        "unexpected update methods: {methods:?}"
    );
    assert!(!methods.contains(&"start"));
    for operation in &updated.checked_effect().document().operations {
        if operation.method.as_str() == "reload" {
            assert!(operation.recovery.reconcile.is_none());
        } else {
            assert_recovery_method(operation, operation.method.as_str());
        }
    }
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
                reconciliation: None,
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
                reconciliation: None,
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
    assert_eq!(methods.len(), 5);
    assert!(methods.contains(&"start"));
    assert_eq!(
        methods
            .iter()
            .filter(|method| **method == "observe")
            .count(),
        3
    );
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
                reconciliation: None,
            },
            &mut fixture.evaluator,
        )
        .unwrap();
    let operations = &transition.checked_effect().document().operations;
    assert_eq!(operations.len(), 5);
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
    assert_recovery_method(stop[0], "observe");

    let releases = operations
        .iter()
        .filter(|operation| operation.family == OperationFamily::ReleaseResource)
        .collect::<Vec<_>>();
    assert_eq!(releases.len(), 2);
    let edges = &transition.checked_effect().document().edges;
    for release in releases {
        assert_recovery_method(release, "release");
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

    let policy_remove = operations
        .iter()
        .find(|operation| {
            matches!(
                &operation.family,
                OperationFamily::HostNetworkPolicy {
                    action: NetworkPolicyAction::Remove
                }
            )
        })
        .unwrap();
    let endpoint_release = operations
        .iter()
        .find(|operation| {
            matches!(
                &operation.family,
                OperationFamily::NetworkEndpoint {
                    action: NetworkEndpointAction::Release
                }
            )
        })
        .unwrap();
    assert_operation_edge(
        transition.checked_effect().document(),
        stop[0],
        policy_remove,
        DependencyKind::RequiredSuccess,
    );
    assert_operation_edge(
        transition.checked_effect().document(),
        policy_remove,
        endpoint_release,
        DependencyKind::RequiredSuccess,
    );
}

fn assert_recovery_method(operation: &Operation, method: &str) {
    assert_eq!(
        operation.deadline.attempt_timeout_millis.get(),
        REFERENCE_ATTEMPT_TIMEOUT_MILLIS
    );
    assert_eq!(
        operation.deadline.total_recovery_millis.get(),
        REFERENCE_TOTAL_RECOVERY_MILLIS
    );
    assert_eq!(
        operation.deadline.total_recovery_millis.get(),
        operation.deadline.attempt_timeout_millis.get() * 4,
        "reference recovery must fund interruption, reconciliation, retry, and final reconciliation"
    );

    let recovery = operation
        .recovery
        .reconcile
        .as_ref()
        .expect("operation must carry its declared reconciliation method");
    assert_eq!(recovery.interface, operation.interface);
    assert_eq!(recovery.method.as_str(), method);
}

fn assert_operation_edge(
    effect: &EffectPlanDocument,
    predecessor: &Operation,
    successor: &Operation,
    kind: DependencyKind,
) {
    assert!(effect.edges.iter().any(|edge| {
        edge.from
            == PlanNodeKey::Operation {
                key: predecessor.key.clone(),
            }
            && edge.to
                == PlanNodeKey::Operation {
                    key: successor.key.clone(),
                }
            && edge.kind == kind
    }));
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
        .filter_map(|source| {
            let retained = desired
                .checked_binding()
                .bindings()
                .iter()
                .find(|retained| {
                    retained.id == source.id
                        && retained.provider == source.provider
                        && retained.provider_package == source.provider_package
                        && retained.implementation == source.implementation
                });
            let caller_resources = withdrawn_resource_permissions(
                &source.caller_grant.resources,
                retained.map(|binding| binding.caller_grant.resources.as_slice()),
                &source.provider,
            );
            let provider_resources = withdrawn_resource_permissions(
                &source.provider_grant.resources,
                retained.map(|binding| binding.provider_grant.resources.as_slice()),
                &source.provider,
            );
            if retained.is_some() && caller_resources.is_empty() && provider_resources.is_empty() {
                return None;
            }

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
            binding.caller_grant.resources = caller_resources;
            binding.provider_grant.contributions.clear();
            binding.provider_grant.resources = provider_resources;

            Some(TeardownBindingAuthorization {
                source_binding: source.id.clone(),
                request,
                binding,
            })
        })
        .collect::<Vec<_>>();
    teardown_bindings.sort_by(|left, right| {
        (&left.source_binding, &left.request.id, &left.binding.id).cmp(&(
            &right.source_binding,
            &right.request.id,
            &right.binding.id,
        ))
    });

    let enabled_package = |snapshot: &VerifiedPlanningSnapshot, instance: &InstanceId| {
        snapshot
            .outcome()
            .desired_state
            .instances
            .iter()
            .find(|candidate| candidate.enabled && candidate.instance == *instance)
            .unwrap()
            .package
    };
    let mut teardown_providers = current
        .outcome()
        .resolution
        .policy
        .enabled_providers
        .iter()
        .filter(|source| {
            let source_package = enabled_package(current, &source.instance);
            !desired
                .outcome()
                .resolution
                .policy
                .enabled_providers
                .iter()
                .any(|retained| {
                    retained.instance == source.instance
                        && enabled_package(desired, &retained.instance) == source_package
                        && retained.implementation == source.implementation
                })
        })
        .map(|enabled| {
            let package = enabled_package(current, &enabled.instance);
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
        provider_adoptions: Vec::new(),
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

fn withdrawn_resource_permissions(
    source: &[ResourcePermission],
    retained: Option<&[ResourcePermission]>,
    provider: &InstanceId,
) -> Vec<ResourcePermission> {
    let Some(retained) = retained else {
        return source
            .iter()
            .filter(|permission| permission.resource.provider == *provider)
            .cloned()
            .collect();
    };

    source
        .iter()
        .filter(|permission| permission.resource.provider == *provider)
        .filter_map(|permission| {
            let retained = retained
                .iter()
                .find(|candidate| candidate.resource == permission.resource);
            let Some(retained) = retained else {
                return Some(permission.clone());
            };

            if !retained.access.permits(permission.access) {
                return Some(permission.clone());
            }

            let mut withdrawn = permission.clone();
            withdrawn
                .operations
                .retain(|operation| !retained.operations.contains(operation));
            (!withdrawn.operations.is_empty()).then_some(withdrawn)
        })
        .collect()
}

fn assert_shared_lower_isolation(
    outcome: &aos_ability_plan::CompositionOutcome,
    nginx_one: &InstanceId,
    nginx_two: &InstanceId,
    nginx_one_has_credential: bool,
    nginx_two_has_credential: bool,
) {
    let bindings = &outcome.resolution.checked.document().bindings;
    let configuration_provider = lower_provider(&nginx_one.environment, "configuration");
    let effects = lower_binding(bindings, &configuration_provider, "effects");
    let expected_resources = outcome
        .desired_state
        .resources
        .iter()
        .filter(|revision| revision.resource.provider == configuration_provider)
        .map(|revision| revision.resource.clone())
        .collect::<Vec<_>>();
    let granted_resources = effects
        .caller_grant
        .resources
        .iter()
        .map(|permission| permission.resource.clone())
        .collect::<Vec<_>>();
    assert_eq!(granted_resources, expected_resources);

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

    for nginx in [nginx_one, nginx_two] {
        let service = lower_binding(bindings, nginx, "service");
        let terminal = lower_binding(bindings, nginx, "service-terminal");

        assert_eq!(service.caller_grant.resources.len(), 1);
        assert_eq!(terminal.caller_grant.resources.len(), 1);
        assert_eq!(
            terminal.caller_grant.resources[0].resource,
            service.caller_grant.resources[0].resource,
        );
    }

    for (nginx, has_credential) in [
        (nginx_one, nginx_one_has_credential),
        (nginx_two, nginx_two_has_credential),
    ] {
        let credential = bindings.iter().find(|binding| {
            binding.request.consumer == *nginx && binding.request.key.as_str() == "credential"
        });
        if has_credential {
            assert_eq!(
                credential.unwrap().provider,
                lower_provider(&nginx.environment, "credential")
            );
        } else {
            assert!(credential.is_none());
        }
    }
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
    let consumer_probe = ValueSchema::Record {
        fields: BTreeMap::from([
            (
                key("address"),
                ValueSchema::String {
                    max_length: 15,
                    syntax: None,
                },
            ),
            (
                key("execution_strategy"),
                ValueSchema::StringEnum {
                    values: vec![
                        "foreground-process".to_string(),
                        "systemd-manager".to_string(),
                    ],
                },
            ),
            (
                key("port"),
                ValueSchema::Integer {
                    minimum: 1024,
                    maximum: 65535,
                },
            ),
            (
                key("tls_credential_path"),
                ValueSchema::String {
                    max_length: 4096,
                    syntax: None,
                },
            ),
            (
                key("tls_port"),
                ValueSchema::Integer {
                    minimum: 1024,
                    maximum: 65535,
                },
            ),
        ]),
        optional_fields: vec![key("tls_credential_path"), key("tls_port")],
    };
    let nginx_request = ValueSchema::Record {
        fields: BTreeMap::from([
            (key("host"), string_schema()),
            (
                key("response_content"),
                ValueSchema::String {
                    max_length: 256,
                    syntax: None,
                },
            ),
            (
                key("response_identity"),
                ValueSchema::String {
                    max_length: 128,
                    syntax: Some(StringSyntax::LocalKeyV1),
                },
            ),
            (key("tls"), ValueSchema::Boolean),
            (
                key("credential_version"),
                ValueSchema::String {
                    max_length: 71,
                    syntax: None,
                },
            ),
        ]),
        optional_fields: vec![key("credential_version")],
    };
    let storage_paths = ValueSchema::Record {
        fields: ["logs", "runtime", "state"]
            .into_iter()
            .map(|name| {
                (
                    key(name),
                    ValueSchema::String {
                        max_length: 4096,
                        syntax: None,
                    },
                )
            })
            .collect(),
        optional_fields: Vec::new(),
    };
    let nginx_validation_request = ValueSchema::Record {
        fields: BTreeMap::from([
            (key("candidate"), ValueSchema::Boolean),
            (
                key("credential_views"),
                ValueSchema::List {
                    element: Box::new(credential_view_schema().unwrap()),
                    max_items: 1024,
                },
            ),
            (
                key("storage_paths"),
                ValueSchema::Optional {
                    value: Box::new(storage_paths.clone()),
                },
            ),
        ]),
        optional_fields: Vec::new(),
    };
    let mut documents = vec![
        network_endpoint_interface().unwrap(),
        host_network_policy_interface().unwrap(),
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
                fields: BTreeMap::from([
                    (key("consumer_content_revision"), string_schema()),
                    (key("consumer_controller_revision"), string_schema()),
                    (key("consumer_instance"), string_schema()),
                    (key("consumer_probe"), consumer_probe.clone()),
                    (key("consumer_storage_paths"), storage_paths),
                    (
                        key("virtualHosts"),
                        ValueSchema::List {
                            element: Box::new(nginx_request),
                            max_items: 1024,
                        },
                    ),
                ]),
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
                fields: BTreeMap::from([
                    (
                        key("hosts"),
                        ValueSchema::List {
                            element: Box::new(string_schema()),
                            max_items: 1024,
                        },
                    ),
                    (
                        key("version"),
                        ValueSchema::String {
                            max_length: 71,
                            syntax: None,
                        },
                    ),
                ]),
                optional_fields: Vec::new(),
            },
            vec![(
                "credential-views",
                resource_map_schema(),
                ValueVisibility::Protected,
            )],
        ),
        credential_delivery_effects_interface().unwrap(),
        interface_document(
            "aos.systemd-service",
            ValueSchema::Record {
                fields: BTreeMap::from([
                    (key("configuration_revision"), string_schema()),
                    (key("consumer_endpoint"), string_schema()),
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
        aos_ability_model::builtin::foreground_process_interface().unwrap(),
    ];
    documents
        .iter_mut()
        .find(|document| document.interface.name.as_str() == "aos.systemd-service-effects")
        .unwrap()
        .interface
        .guarantees = vec![
        aos_ability_model::builtin::local_systemd_manager_guarantee().unwrap(),
        aos_ability_model::builtin::system_container_manager_delegation_guarantee().unwrap(),
    ];
    documents
        .iter_mut()
        .find(|document| document.interface.name.as_str() == "aos.nginx")
        .unwrap()
        .interface
        .configuration = Some(consumer_probe);
    let nginx_validation = documents
        .iter_mut()
        .find(|document| document.interface.name.as_str() == "aos.nginx-validation")
        .unwrap();
    for method in nginx_validation.interface.methods.values_mut() {
        method.parameters = nginx_validation_request.clone();
    }
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
                        indeterminate: if reference_method_is_recoverable(method) {
                            IndeterminateSemantics::Reconcile
                        } else {
                            IndeterminateSemantics::InterventionRequired
                        },
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
            configuration: None,
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

fn reference_method_is_recoverable(method: &str) -> bool {
    matches!(
        method,
        "acquire"
            | "deliver"
            | "observe"
            | "prepare"
            | "publish"
            | "record"
            | "release"
            | "stop"
            | "validate"
    )
}

fn reference_method_families(name: &str) -> Vec<(&'static str, OperationFamily)> {
    match name {
        "aos.credential-delivery-effects" => vec![
            (
                "acquire",
                OperationFamily::Credential {
                    action: CredentialAction::Acquire,
                },
            ),
            (
                "deliver",
                OperationFamily::Credential {
                    action: CredentialAction::Deliver,
                },
            ),
            ("release", OperationFamily::ReleaseResource),
        ],
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

fn provider_reference(implementation: &ProviderImplementation) -> ProviderImplementationReference {
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

fn ensure_interface_matches(
    expected: &BTreeMap<String, InterfaceKey>,
    actual: &InterfaceKey,
) -> Result<()> {
    let expected = expected.get(actual.name.as_str()).with_context(|| {
        format!(
            "production companion exports unknown interface {}",
            actual.name
        )
    })?;
    anyhow::ensure!(
        actual == expected,
        "production companion interface {} differs from the source contract",
        actual.name
    );
    Ok(())
}

fn assert_fixture_interface_hashes(fixture: &ReferenceFixture) {
    assert_interface_hashes(&fixture.interfaces);
}

#[test]
fn reference_source_interface_descriptors_are_stable() {
    let interfaces = interface_documents()
        .into_iter()
        .map(|document| {
            (
                document.interface.name.as_str().to_string(),
                document.interface_key().unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_interface_hashes(&interfaces);
}

fn assert_interface_hashes(interfaces: &BTreeMap<String, InterfaceKey>) {
    assert_eq!(
        interfaces["aos.nginx"].descriptor,
        digest_from_hex("9528cf4f6b14102dd6164602bd698e7e4caac000ea1620cab11f1456d39208f1")
    );
    assert_eq!(
        interfaces["aos.managed-configuration"].descriptor,
        digest_from_hex("64bc590155806e0b69dac2503f44cca63e16dc0603b72fa6602b46d49f135e67")
    );
    assert_eq!(
        interfaces["aos.credential-delivery"].descriptor,
        digest_from_hex("e8c5924bd71f8c018958430a91907c662e09af55221d2c94a758dc4a1377d44f")
    );
    assert_eq!(
        interfaces["aos.credential-delivery-effects"].descriptor,
        digest_from_hex("bc251c0837c1d453a6c5840d9146d9e27a95ad82032d9b4c60baf40d293cf1eb")
    );
    assert_eq!(
        interfaces["aos.systemd-service"].descriptor,
        digest_from_hex("b712c9e3697e87d62bb62549d8692b4d8f825bae9733ae523f76a40bd3882666")
    );
    assert_eq!(
        interfaces["aos.nginx-validation"].descriptor,
        digest_from_hex("3aaa289923966ca40279d7030374aa6d72d0cbf07e655b9c61741ca5b59507e1")
    );
    assert_eq!(
        interfaces["aos.network-endpoint-effects"].descriptor,
        digest_from_hex("6b4d345ab4350917a04b770f0ac4b82888ffe6ef7e647caa9fe94ccb9f9dac6a")
    );
    assert_eq!(
        interfaces["aos.host-network-policy-effects"].descriptor,
        digest_from_hex("13851cb0af020c2ba09663d562017a706124e00ae4a66279d09bf9ffec3dd199")
    );
    assert_eq!(
        interfaces["aos.managed-configuration-effects"].descriptor,
        digest_from_hex("682ee08aadd9d0198b409146a373bf38d901ba530b74180400c9087616a41dab")
    );
    assert_eq!(
        interfaces["aos.systemd-service-effects"].descriptor,
        digest_from_hex("383803bfd7eb105968a80a796fc4726b5663890e88220d26b20dbd2b33349b50")
    );
    assert_eq!(
        interfaces["aos.foreground-process"].descriptor,
        digest_from_hex("6f692b67b0670968fb335b4ebe93951cd40bdedf925f98f025b93024b30b17cb")
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

fn configured_consumer_probe(state: &DesiredStateDocument, nginx: &InstanceId) -> AbilityValue {
    state
        .instances
        .iter()
        .find(|desired| desired.instance == *nginx)
        .and_then(|desired| desired.configuration.clone())
        .unwrap()
}

fn service_consumer_endpoint<'a>(state: &'a DesiredStateDocument, nginx: &InstanceId) -> &'a str {
    state
        .contributions
        .iter()
        .find(|contribution| {
            contribution.request.consumer == *nginx
                && contribution.request.key.as_str() == "service"
        })
        .and_then(|contribution| contribution.value.as_json().get("consumer_endpoint"))
        .and_then(serde_json::Value::as_str)
        .unwrap()
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
        "aos.credential-delivery" => "aos.credential-delivery-effects",
        "aos.managed-configuration" => "aos.managed-configuration-effects",
        "aos.systemd-service" => "aos.systemd-service-effects",
        _ => "",
    }
}

fn lower_authority(suffix: &str) -> (&'static str, Vec<&'static str>, &'static str) {
    match suffix {
        "configuration" => (
            "configuration",
            vec!["prepare", "publish", "read", "release"],
            "configuration",
        ),
        "credential" => ("credentials", vec!["acquire", "deliver"], "credential-view"),
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

fn app_route(
    application: &'static str,
    nginx: &'static str,
    host: &'static str,
    tls: bool,
    response: &'static str,
) -> AppRoute {
    AppRoute {
        application,
        nginx,
        host,
        tls,
        response,
    }
}

fn nginx_consumer_probe(nginx: &InstanceId) -> AbilityValue {
    let port = if nginx.key.as_str() == "nginx-two" {
        18082
    } else {
        18081
    };
    let tls_port = if nginx.key.as_str() == "nginx-two" {
        18444
    } else {
        18443
    };
    value(serde_json::json!({
        "address": "127.0.0.1",
        "execution_strategy": "systemd-manager",
        "port": port,
        "tls_credential_path": reference_tls_path(nginx),
        "tls_port": tls_port,
    }))
}

fn reference_tls_version() -> String {
    digest(91).to_string()
}

fn reference_tls_path(nginx: &InstanceId) -> String {
    let resource = ResourceId {
        provider: lower_provider(&nginx.environment, "credential"),
        key: key(&format!("{}-credential-view", nginx.key)),
    };
    let resource_digest =
        Sha256Digest::of_canonical("aos.ability.native-host-resource/v1", &resource)
            .unwrap()
            .hex();
    let view_key = serde_json::json!({
        "resource": resource,
        "version": reference_tls_version(),
    });
    let version_digest =
        Sha256Digest::of_canonical("aos.ability.credential-view-key/v1", &view_key)
            .unwrap()
            .hex();
    format!("/var/lib/aos/ability-runtime/credentials/{resource_digest}-{version_digest}.view")
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
