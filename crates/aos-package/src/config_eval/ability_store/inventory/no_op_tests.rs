//! Native inventory ownership, observation, and settlement tests.

use aos_ability_model::{
    AbilityValue, BindingId, IncarnationId, InterfaceKey, LocalKey, OperationId, PlanId,
    ProviderAdoptionEndpoint, ProviderAssignment, ProviderImplementationReference,
    ProviderStateFormat, ResourceLifetime, ScopePath, TransactionId,
};
use aos_ability_plan::{
    RUNTIME_OBSERVATIONS_SCHEMA, RuntimeResourceHealth, RuntimeResourceObservation,
    RuntimeResourceState, TransitionReconciliation,
};
use aos_ability_validate::test_support::checked_systemd_manager_effect_plan;

use super::*;

fn key(value: &str) -> LocalKey {
    LocalKey::new(value).expect("valid fixture key")
}

fn provider_identity(
    provider: &InstanceId,
    interface: &InterfaceKey,
    label: &str,
    state_descriptor: aos_contract::Sha256Digest,
) -> NativeProviderIdentity {
    let artifact = ArtifactReference {
        content: aos_contract::Sha256Digest::of_bytes(format!("{label} content")),
        store_path: format!("/nix/store/00000000000000000000000000000000-{label}-provider"),
        nar_hash: aos_contract::Sha256Digest::of_bytes(format!("{label} nar")),
        closure: aos_contract::Sha256Digest::of_bytes(format!("{label} closure")),
    };

    NativeProviderIdentity {
        provider: provider.clone(),
        package: aos_contract::Sha256Digest::of_bytes(format!("{label} package")),
        interface: interface.clone(),
        implementation: ProviderImplementationReference {
            descriptor: aos_contract::Sha256Digest::of_bytes(format!("{label} descriptor")),
            artifact: artifact.clone(),
            handler: None,
        },
        state_format: ProviderStateFormat {
            descriptor: state_descriptor,
            artifact,
        },
    }
}

fn assignment(plan: &CheckedEffectPlan, label: &str) -> ProviderAssignment {
    let binding = plan
        .binding_plan()
        .binding(&plan.operations()[0].binding)
        .expect("fixture binding");

    ProviderAssignment {
        provider: binding.provider.clone(),
        interface: binding.interface.clone(),
        implementation: binding.implementation.clone(),
        incarnation: IncarnationId::new(label).expect("valid fixture incarnation"),
    }
}

fn handler_identity(
    _binding: &str,
    assignment: ProviderAssignment,
) -> NativeProviderHandlerIdentity {
    NativeProviderHandlerIdentity {
        package: aos_contract::Sha256Digest::of_bytes("handler package"),
        provider: assignment.provider,
        interface: assignment.interface,
        implementation: assignment.implementation,
    }
}

fn endpoint(
    identity: &NativeProviderIdentity,
    binding: BindingId,
    handler: &ProviderAssignment,
) -> ProviderAdoptionEndpoint {
    ProviderAdoptionEndpoint {
        provider: identity.provider.clone(),
        package: identity.package,
        interface: identity.interface.clone(),
        implementation: identity.implementation.clone(),
        state_format: identity.state_format.clone(),
        handler_binding: binding,
        handler_method: key("start"),
        handler_provider: handler.provider.clone(),
        handler_incarnation: handler.incarnation.clone(),
        handler_interface: handler.interface.clone(),
        handler_implementation: handler.implementation.clone(),
        handler_package: aos_contract::Sha256Digest::of_bytes("handler package"),
    }
}

fn fixture_physical_resource(resource: &ResourceId) -> NativePhysicalResource {
    let unit = format!("{}.service", resource.key);
    let escaped_unit = unit.bytes().fold(String::new(), |mut escaped, byte| {
        if byte.is_ascii_alphanumeric() {
            escaped.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut escaped, "_{byte:02x}").expect("writing to String cannot fail");
        }
        escaped
    });

    NativePhysicalResource {
        class: "systemd-unit".to_string(),
        authority: "system-manager".to_string(),
        object: format!("/org/freedesktop/systemd1/unit/{escaped_unit}"),
    }
}

fn owner(
    resource: ResourceId,
    identity: NativeProviderIdentity,
    handler: NativeProviderHandlerIdentity,
    plan: &CheckedEffectPlan,
) -> NativeProviderOwner {
    let physical = fixture_physical_resource(&resource);
    NativeProviderOwner {
        resource,
        physical,
        identity,
        handler,
        generation: "gen-1".to_string(),
        transaction: TransactionId(key("source")),
        plan: plan.id(),
        artifacts: plan.required_runtime_artifacts().to_vec(),
        claim_by: Vec::new(),
        established_by: plan.operations().first().map(|operation| {
            ownership::NativeProviderEstablishment {
                generation: "gen-1".to_string(),
                transaction: TransactionId(key("source")),
                plan: plan.id(),
                operation: OperationId {
                    plan: plan.id(),
                    operation: operation.key.clone(),
                },
                attempt: 1,
                artifacts: plan.required_runtime_artifacts().to_vec(),
            }
        }),
        adoption: None,
    }
}

fn operation_claim(
    plan: &CheckedEffectPlan,
    resource: ResourceId,
    binding: BindingId,
    owner: NativeProviderIdentity,
    label: &str,
) -> (ScopedOperationKey, NativeOperationClaim) {
    let mut operation = plan.operations()[0].clone();
    operation.key = ScopedOperationKey {
        scope: ScopePath::root(),
        key: key(label),
    };
    operation.binding = binding.clone();
    operation.target.resource = resource.clone();
    operation.target.interface = owner.interface.clone();
    operation.target.lifetime = ResourceLifetime::Persistent;
    operation.accesses = vec![ResourceAccess {
        resource,
        mode: AccessMode::ExclusiveWrite,
    }];
    let handler_assignment = assignment(plan, "candidate-incarnation");

    (
        operation.key.clone(),
        NativeOperationClaim {
            operation,
            binding: binding.clone(),
            consumer: owner.provider.clone(),
            provider: owner.provider.clone(),
            implementation: handler_assignment.implementation.clone(),
            owner: Some(owner),
            owner_handler: Some(NativeProviderHandlerIdentity {
                package: aos_contract::Sha256Digest::of_bytes("handler package"),
                provider: handler_assignment.provider,
                interface: handler_assignment.interface,
                implementation: handler_assignment.implementation,
            }),
            resources: BTreeSet::new(),
            desired_revisions: BTreeMap::new(),
            retains_consumer: true,
            admits_receipt_source: false,
        },
    )
}

fn inventory_state(
    root: &Path,
    plan: &CheckedEffectPlan,
    adoption: ProviderAdoptionAuthorization,
    operations: BTreeMap<ScopedOperationKey, NativeOperationClaim>,
) -> NativeInventoryState {
    let plan_bundle = aos_contract::Sha256Digest::of_bytes("fixture plan bundle");
    let desired_revisions = operations
        .values()
        .flat_map(|operation| &operation.desired_revisions)
        .map(|(resource, revision)| (resource.clone(), *revision))
        .collect();
    let desired_resources = operations
        .values()
        .map(|operation| operation.operation.target.resource.clone())
        .collect();
    let desired_owner_selections = operations
        .values()
        .filter(|operation| {
            !matches!(
                operation.operation.family,
                aos_ability_model::OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Stop
                }
            )
        })
        .filter_map(|operation| {
            Some(NativeProviderSelection {
                resource: operation.operation.target.resource.clone(),
                identity: operation.owner.clone()?,
                handler: operation.owner_handler.clone()?,
            })
        })
        .collect();
    let dispatch_positions = operations
        .keys()
        .enumerate()
        .map(|(position, operation)| (operation.clone(), position))
        .collect();

    NativeInventoryState {
        generation: "gen-2".to_string(),
        ledger_path: root.join(NATIVE_RESOURCE_LEDGER_FILE),
        transaction: TransactionId(key("candidate")),
        plan: plan.id(),
        plan_bundle: Some(plan_bundle),
        supported_features: BTreeSet::new(),
        artifacts: plan.required_runtime_artifacts().to_vec(),
        transition_authority: Some(aos_contract::Sha256Digest::of_bytes("authority")),
        adoptions: vec![adoption],
        desired_revisions,
        desired_resources,
        desired_owner_selections,
        current_owner_selections: Vec::new(),
        linked_recovery_observations: BTreeMap::new(),
        reconciliation_authority_publication: None,
        operations,
        dispatch_positions,
        required_success_edges: Vec::new(),
        replayed_current_effect_intents: Mutex::new(BTreeSet::new()),
        replayed_clean_current_claims: Mutex::new(BTreeSet::new()),
        replayed_current_successes: Mutex::new(BTreeSet::new()),
        replayed_current_terminal: Mutex::new(None),
        authenticated_current_claims: Mutex::new(BTreeSet::new()),
        reservations: Mutex::new(BTreeMap::new()),
        _switch_lock: Arc::new(
            acquire_switch_lock_pub(&root.join("switch.lock")).expect("fixture switch lock"),
        ),
    }
}

struct AdoptionInventoryFixture {
    _root: Arc<tempfile::TempDir>,
    plan: CheckedEffectPlan,
    state: NativeInventoryState,
    resource: ResourceId,
    source: NativeProviderIdentity,
    candidate: NativeProviderIdentity,
    source_assignment: ProviderAssignment,
    candidate_assignment: ProviderAssignment,
    source_owner: NativeProviderOwner,
}

impl AdoptionInventoryFixture {
    fn save_ledger(
        &self,
        owners: Vec<NativeProviderOwner>,
    ) -> Result<(), GenerationAbilityStoreError> {
        self.save_full_ledger(owners, Vec::new())
    }

    fn save_full_ledger(
        &self,
        owners: Vec<NativeProviderOwner>,
        consumers: Vec<ActiveNativeConsumer>,
    ) -> Result<(), GenerationAbilityStoreError> {
        save_native_resource_ledger(
            &self.state.ledger_path,
            &NativeResourceLedger {
                schema: NATIVE_RESOURCE_LEDGER_SCHEMA.to_string(),
                owners,
                consumers,
            },
        )
    }

    fn source_owner(&self) -> NativeProviderOwner {
        self.source_owner.clone()
    }

    fn candidate_owner(
        &self,
        resource: ResourceId,
        adoption: Option<NativeProviderAdoptionReceipt>,
    ) -> NativeProviderOwner {
        let operation = self.operation_id();
        let claim = ownership::NativeProviderClaim {
            generation: self.state.generation.clone(),
            transaction: self.state.transaction.clone(),
            plan: self.state.plan,
            operation,
            attempt: 1,
            artifacts: self.state.artifacts.clone(),
        };
        let handler = self
            .state
            .desired_owner_selections
            .iter()
            .find(|selection| selection.resource == resource)
            .expect("candidate owner selection")
            .handler
            .clone();

        NativeProviderOwner {
            physical: fixture_physical_resource(&resource),
            resource,
            identity: self.candidate.clone(),
            handler,
            generation: self.state.generation.clone(),
            transaction: self.state.transaction.clone(),
            plan: self.state.plan,
            artifacts: self.state.artifacts.clone(),
            claim_by: vec![claim],
            established_by: None,
            adoption,
        }
    }

    fn select_source_owner(&mut self) {
        self.state.desired_owner_selections = vec![NativeProviderSelection {
            resource: self.resource.clone(),
            identity: self.source.clone(),
            handler: self.source_owner.handler.clone(),
        }];
    }

    fn disable_adoption(&mut self) {
        self.state.adoptions.clear();
        self.state.operations.retain(|_, operation| {
            !matches!(
                operation.operation.family,
                aos_ability_model::OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Stop
                }
            )
        });
        self.state
            .dispatch_positions
            .retain(|operation, _| self.state.operations.contains_key(operation));
        self.state.required_success_edges.clear();
    }

    fn receipt(&self) -> NativeProviderAdoptionReceipt {
        let source_owner = self.source_owner();
        let source_establishment = source_owner
            .established_by
            .clone()
            .expect("source owner establishment");

        NativeProviderAdoptionReceipt {
            authority: self
                .state
                .transition_authority
                .expect("fixture transition authority"),
            source: self.source.clone(),
            source_handler: handler_from_endpoint(&self.state.adoptions[0].source),
            source_generation: source_owner.generation,
            source_transaction: source_owner.transaction,
            source_plan: source_owner.plan,
            source_artifacts: source_owner.artifacts,
            source_establishment,
            consumer_requirement: None,
            linked_verification: None,
        }
    }

    fn qualified_resource(&self) -> NativeQualifiedResource {
        NativeQualifiedResource {
            logical: self.resource.clone(),
            physical: fixture_physical_resource(&self.resource),
        }
    }

    fn operation_key(&self) -> ScopedOperationKey {
        self.state
            .operations
            .keys()
            .next()
            .cloned()
            .expect("fixture operation")
    }

    fn operation_id(&self) -> OperationId {
        OperationId {
            plan: self.state.plan,
            operation: self.operation_key(),
        }
    }

    fn successful_operations(&self) -> BTreeMap<ScopedOperationKey, u32> {
        self.state
            .operations
            .keys()
            .cloned()
            .map(|operation| (operation, 1))
            .collect()
    }

    fn write_terminal_marker(&self, terminal: aos_ability_model::document::TerminalResult) {
        self.write_terminal_marker_for(
            &self.state.generation,
            &self.state.transaction,
            self.state.plan,
            terminal,
        );
    }

    fn write_terminal_marker_for(
        &self,
        generation: &str,
        transaction: &TransactionId,
        plan: PlanId,
        terminal: aos_ability_model::document::TerminalResult,
    ) {
        let transaction_directory = self
            ._root
            .path()
            .join(generation)
            .join(TRANSACTION_ROOT)
            .join(transaction.0.as_str());
        std::fs::create_dir_all(&transaction_directory).expect("transaction directory");
        let marker = TerminalMarker {
            schema: super::super::TERMINAL_MARKER_SCHEMA.to_string(),
            transaction: transaction.clone(),
            plan,
            terminal,
        };
        std::fs::write(
            transaction_directory.join(TERMINAL_MARKER_FILE),
            aos_contract::canonical::to_vec(&marker).expect("terminal marker bytes"),
        )
        .expect("terminal marker");
    }

    fn candidate_consumer(&self, revision: RevisionId) -> ActiveNativeConsumer {
        let operation = self
            .state
            .operations
            .get(&self.operation_key())
            .expect("fixture operation claim");
        ActiveNativeConsumer {
            physical: self.qualified_resource().physical,
            logical: self.resource.clone(),
            generation: self.state.generation.clone(),
            transaction: self.state.transaction.clone(),
            plan: self.state.plan,
            binding: operation.binding.clone(),
            consumer: operation.consumer.clone(),
            provider: operation.provider.clone(),
            owner: Some(self.candidate.clone()),
            desired_revision: Some(revision),
            artifacts: self.plan.required_runtime_artifacts().to_vec(),
            operation: OperationId {
                plan: self.state.plan,
                operation: self.operation_key(),
            },
            attempt: 1,
        }
    }

    fn linked_evidence(
        &self,
        revision: RevisionId,
        consumer_requirement: NativeConsumerRequirement,
    ) -> (TransitionReconciliation, NativeNoOpResourceObservation) {
        let state = RuntimeResourceState::Present {
            revision,
            health: RuntimeResourceHealth::Healthy,
        };
        let authority_document = AbilityValue::new(serde_json::json!({
            "fixture": "linked-authority"
        }))
        .expect("bounded fixture authority");
        (
            TransitionReconciliation {
                schema: RUNTIME_OBSERVATIONS_SCHEMA.to_string(),
                source_plan: self.state.plan,
                transaction: self.state.transaction.clone(),
                policy_fence: RevisionId(aos_contract::Sha256Digest::of_bytes("fixture policy")),
                authority_epoch: 1,
                sequence: 1,
                observed_at_restart_millis: 1,
                max_age_millis: 1,
                authority_publication: aos_contract::Sha256Digest::of_bytes("fixture publication"),
                authority_document,
                unsettled_provider_adoptions: vec![self.resource.clone()],
                observations: vec![RuntimeResourceObservation {
                    resource: self.resource.clone(),
                    state,
                }],
            },
            NativeNoOpResourceObservation {
                qualified: self.qualified_resource(),
                state,
                consumer_requirement,
            },
        )
    }
}

fn adoption_inventory_fixture() -> AdoptionInventoryFixture {
    let root = Arc::new(tempfile::tempdir().expect("temporary profile"));
    let authenticated = recovery_tests::establish_authenticated_source_owner(Arc::clone(&root))
        .expect("authenticated source owner");
    let plan = checked_systemd_manager_effect_plan();
    let supported_features = authenticated.supported_features;
    let mut source_owner = authenticated.owner;
    let provider = source_owner.resource.provider.clone();
    let interface = source_owner.identity.interface.clone();
    let source = source_owner.identity.clone();
    let source_assignment = authenticated.assignment;
    let candidate_assignment = assignment(&plan, "candidate-incarnation");
    let mut candidate = provider_identity(
        &provider,
        &interface,
        "candidate",
        source.state_format.descriptor,
    );
    candidate.implementation = candidate_assignment.implementation.clone();
    candidate.state_format.artifact = candidate_assignment.implementation.artifact.clone();
    let resource = source_owner.resource.clone();
    source_owner.physical = fixture_physical_resource(&resource);
    let candidate_binding = BindingId(key("candidate-binding"));
    let mut source_endpoint = endpoint(
        &source,
        BindingId(key("source-binding")),
        &source_assignment,
    );
    source_endpoint.handler_provider = source_owner.handler.provider.clone();
    source_endpoint.handler_interface = source_owner.handler.interface.clone();
    source_endpoint.handler_implementation = source_owner.handler.implementation.clone();
    source_endpoint.handler_package = source_owner.handler.package;
    let adoption = ProviderAdoptionAuthorization {
        resource: resource.clone(),
        resource_interface: interface,
        source: source_endpoint,
        candidate: endpoint(&candidate, candidate_binding.clone(), &candidate_assignment),
    };
    let (candidate_key, mut candidate_operation) = operation_claim(
        &plan,
        resource.clone(),
        candidate_binding.clone(),
        candidate.clone(),
        "adopt",
    );
    candidate_operation.operation.family = aos_ability_model::OperationFamily::ServiceLifecycle {
        action: ServiceAction::Start,
    };
    let (stop_key, mut stop_operation) = operation_claim(
        &plan,
        resource.clone(),
        candidate_binding,
        source.clone(),
        "stop",
    );
    stop_operation.operation.family = aos_ability_model::OperationFamily::ServiceLifecycle {
        action: ServiceAction::Stop,
    };
    stop_operation.owner_handler = Some(source_owner.handler.clone());
    stop_operation.retains_consumer = false;
    let operations = BTreeMap::from([
        (candidate_key.clone(), candidate_operation),
        (stop_key.clone(), stop_operation),
    ]);
    let mut state = inventory_state(root.path(), &plan, adoption, operations);
    state.supported_features = supported_features;
    state.required_success_edges = vec![(
        aos_ability_model::PlanNodeKey::Operation {
            key: stop_key.clone(),
        },
        aos_ability_model::PlanNodeKey::Operation {
            key: candidate_key.clone(),
        },
    )];
    state.dispatch_positions.insert(stop_key, 0);
    state.dispatch_positions.insert(candidate_key, 1);

    AdoptionInventoryFixture {
        _root: root,
        plan,
        state,
        resource,
        source,
        candidate,
        source_assignment,
        candidate_assignment,
        source_owner,
    }
}

fn handler_only_adoption_inventory_fixture() -> AdoptionInventoryFixture {
    let mut fixture = adoption_inventory_fixture();
    fixture.candidate = fixture.source.clone();
    fixture.candidate_assignment.implementation.descriptor =
        aos_contract::Sha256Digest::of_bytes("replacement handler descriptor");

    let candidate_binding = fixture.state.adoptions[0].candidate.handler_binding.clone();
    let mut candidate = endpoint(
        &fixture.candidate,
        candidate_binding,
        &fixture.candidate_assignment,
    );
    candidate.handler_package = aos_contract::Sha256Digest::of_bytes("replacement handler package");
    fixture.state.adoptions[0].candidate = candidate;
    for operation in fixture.state.operations.values_mut().filter(|operation| {
        !matches!(
            operation.operation.family,
            aos_ability_model::OperationFamily::ServiceLifecycle {
                action: ServiceAction::Stop
            }
        )
    }) {
        operation.owner = Some(fixture.candidate.clone());
        operation.owner_handler =
            Some(handler_from_endpoint(&fixture.state.adoptions[0].candidate));
    }
    for selection in &mut fixture.state.desired_owner_selections {
        selection.identity = fixture.candidate.clone();
        selection.handler = handler_from_endpoint(&fixture.state.adoptions[0].candidate);
    }

    fixture
}

fn handler_package_only_adoption_inventory_fixture() -> AdoptionInventoryFixture {
    let mut fixture = adoption_inventory_fixture();
    fixture.candidate = fixture.source.clone();
    fixture.candidate_assignment = fixture.source_assignment.clone();

    let mut candidate = fixture.state.adoptions[0].source.clone();
    candidate.handler_package = aos_contract::Sha256Digest::of_bytes("replacement handler package");
    fixture.state.adoptions[0].candidate = candidate;
    for operation in fixture.state.operations.values_mut().filter(|operation| {
        !matches!(
            operation.operation.family,
            aos_ability_model::OperationFamily::ServiceLifecycle {
                action: ServiceAction::Stop
            }
        )
    }) {
        operation.binding = fixture.state.adoptions[0].candidate.handler_binding.clone();
        operation.operation.binding = operation.binding.clone();
        operation.owner = Some(fixture.candidate.clone());
        operation.owner_handler =
            Some(handler_from_endpoint(&fixture.state.adoptions[0].candidate));
    }
    for selection in &mut fixture.state.desired_owner_selections {
        selection.identity = fixture.candidate.clone();
        selection.handler = handler_from_endpoint(&fixture.state.adoptions[0].candidate);
    }

    fixture
}

fn owner_only_adoption_inventory_fixture() -> AdoptionInventoryFixture {
    let mut fixture = adoption_inventory_fixture();
    fixture.candidate_assignment = fixture.source_assignment.clone();

    let candidate_binding = fixture.state.adoptions[0].candidate.handler_binding.clone();
    let mut candidate = endpoint(
        &fixture.candidate,
        candidate_binding,
        &fixture.candidate_assignment,
    );
    candidate.handler_provider = fixture.source_owner.handler.provider.clone();
    candidate.handler_interface = fixture.source_owner.handler.interface.clone();
    candidate.handler_implementation = fixture.source_owner.handler.implementation.clone();
    candidate.handler_package = fixture.source_owner.handler.package;
    fixture.state.adoptions[0].candidate = candidate;
    for operation in fixture.state.operations.values_mut().filter(|operation| {
        !matches!(
            operation.operation.family,
            aos_ability_model::OperationFamily::ServiceLifecycle {
                action: ServiceAction::Stop
            }
        )
    }) {
        operation.owner_handler =
            Some(handler_from_endpoint(&fixture.state.adoptions[0].candidate));
    }
    for selection in &mut fixture.state.desired_owner_selections {
        selection.handler = handler_from_endpoint(&fixture.state.adoptions[0].candidate);
    }

    fixture
}

mod consumer_tests;
mod linked_observations;
mod preflight_tests;
mod recovery_tests;
mod selection_tests;
mod settlement_tests;
