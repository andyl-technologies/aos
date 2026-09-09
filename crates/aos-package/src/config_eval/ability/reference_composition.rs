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
};
use aos_ability_validate::ValidationContext;
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
    implementations: BTreeMap<String, ProviderImplementationReference>,
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
        ];
        let mut packages = Vec::new();
        let mut lower_packages = BTreeMap::new();
        let mut implementations = BTreeMap::new();

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

        for (name, group) in [
            ("aos.managed-configuration", "configuration"),
            ("aos.credential-delivery", "credentials"),
            ("aos.systemd-service", "services"),
        ] {
            let package = provider_package(
                &format!("reference-{}", name.rsplit('.').next().unwrap()),
                &interfaces[name],
                &artifacts[name],
                Vec::new(),
                group,
            );
            lower_packages.insert(name.to_string(), package.content_digest()?);
            implementations.insert(name.to_string(), provider_reference(&package));
            packages.push(package);
        }

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
            implementations,
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
                    return ComposedDeployment {
                        outcome,
                        authorization_states,
                        policies,
                    };
                }
                Err(CompositionError::PolicyRequired { desired_state, .. }) => {
                    policies.push(self.policy_for(&desired_state));
                    authorization_states.push(*desired_state);
                }
                Err(error) => panic!("reference composition failed: {error:#?}"),
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
        let (provider, provider_package, group, operations, resource_key) =
            if interface == self.fixture.interfaces["aos.nginx"] {
                let route = self
                    .app_routes
                    .iter()
                    .find(|(app, _, _, _)| *app == request.id.consumer.key.as_str())
                    .unwrap();
                (
                    instance(&self.fixture.environment.environment, route.1),
                    self.fixture.nginx_package,
                    "nginx",
                    Vec::new(),
                    None,
                )
            } else {
                let suffix = request.id.key.as_str();
                let name = lower_interface_name(suffix);
                let (group, operations, resource_key) = lower_authority(suffix);
                (
                    lower_provider(&self.fixture.environment.environment, suffix),
                    self.fixture.lower_packages[name],
                    group,
                    operations,
                    Some(resource_key),
                )
            };
        let resource = resource_key.map(|resource_key| ResourceId {
            provider: provider.clone(),
            key: key(&format!("{}-{resource_key}", request.id.consumer.key)),
        });
        let resources = resource
            .filter(|resource| {
                desired
                    .resources
                    .iter()
                    .any(|revision| revision.resource == *resource)
            })
            .map(|resource| {
                vec![ResourcePermission {
                    resource,
                    access: AccessMode::Read,
                    operations: operations.iter().map(|operation| key(operation)).collect(),
                }]
            })
            .unwrap_or_default();
        let caller = request.id.consumer.clone();
        let caller_grant = AuthorityGrant {
            principal: caller.clone(),
            methods: request.methods.clone(),
            contributions: vec![ContributionPermission {
                aggregate: AggregateId {
                    provider: provider.clone(),
                    group: key(group),
                },
                slot: caller.key.clone(),
            }],
            resources: resources.clone(),
        };
        let provider_grant = AuthorityGrant {
            principal: provider.clone(),
            methods: Vec::new(),
            contributions: Vec::new(),
            resources: resources
                .into_iter()
                .map(|mut permission| {
                    permission.access = AccessMode::ExclusiveWrite;
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
            implementation: self.fixture.implementations[interface.name.as_str()].clone(),
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
            ("app-b", "nginx-main", "beta.example", true),
        ],
    };
    let seed = both.seed(true);
    let composed = both.compose(seed.clone());
    assert_snapshot_replay(both.fixture, seed, &composed);

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
        3
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
    assert_eq!(rendered.matches("listen 443 ssl;").count(), 1);
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
    assert!(matches!(
        &nginx_output(
            &composed.outcome.desired_state,
            &nginx_main,
            "credential-view"
        )
        .unwrap()
        .value,
        ValueExpression::ResourceReference { .. }
    ));

    let mut one = Deployment {
        fixture: both.fixture,
        nginx_instances: vec![nginx_main.clone()],
        app_routes: vec![("app-b", "nginx-main", "beta.example", true)],
    };
    let seed = one.seed(true);
    let one_state = one.compose(seed).outcome.desired_state;
    let rendered = rendered_configuration(&one_state, &nginx_main);
    assert!(!rendered.contains("alpha.example"));
    assert!(rendered.contains("beta.example"));

    let mut empty = Deployment {
        fixture: one.fixture,
        nginx_instances: vec![nginx_main.clone()],
        app_routes: Vec::new(),
    };
    let seed = empty.seed(true);
    let empty_state = empty.compose(seed).outcome.desired_state;
    assert_eq!(virtual_host_count(&empty_state, &nginx_main), 0);
    assert!(
        empty_state
            .resources
            .iter()
            .any(|revision| revision.resource == nginx_resource(&nginx_main))
    );

    let seed = empty.seed(false);
    let disabled_state = empty.compose(seed).outcome.desired_state;
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

fn assert_snapshot_replay(
    fixture: &mut ReferenceFixture,
    seed: DesiredStateDocument,
    composed: &ComposedDeployment,
) {
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
    ];
    documents.sort_by(|left, right| left.interface.name.cmp(&right.interface.name));
    documents
}

fn interface_document(
    name: &str,
    request: ValueSchema,
    outputs: Vec<(&str, ValueSchema, ValueVisibility)>,
) -> InterfaceDocument {
    InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            name: InterfaceName::new(name).unwrap(),
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
            methods: BTreeMap::new(),
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
    ProviderImplementationReference {
        descriptor: implementation.descriptor_digest().unwrap(),
        artifact: implementation.artifact.clone(),
        handler: None,
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
        digest_from_hex("6efc2412e7facd35f64d49b0c028517aa0fadde05d5022532455a5e70f14ced4")
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
