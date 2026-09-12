//! Effect-free provider-adoption session recovery tests.

use super::*;

struct RejectedAdapter;

impl TrustedAdapter for RejectedAdapter {
    type Request = AbilityValue;
    type Completion = RecoveryRecord;
    type Observation = RecoveryRecord;
    type Handle = String;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        _implementation: &aos_ability_model::ProviderImplementationReference,
        _method: &aos_ability_model::MethodReference,
        _purpose: InvocationPurpose,
    ) -> bool {
        true
    }

    fn supports_compensation(&self) -> bool {
        false
    }

    fn prepare_durable(
        &self,
        _operation: &aos_ability_model::Operation,
        inputs: &AbilityValue,
        _resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        Ok(inputs.clone())
    }

    fn recover_request(
        &self,
        durable: &AbilityValue,
        _resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError> {
        Ok(durable.clone())
    }

    fn execute(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        EffectDisposition::RejectedBeforeEffect(recovery_record())
    }

    fn reconcile(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        ReconcileDisposition::InterventionRequired(recovery_record())
    }

    fn cancel(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        CancellationDisposition::Indeterminate(recovery_record())
    }
}

fn establish_first_write_then_settle_later_failure(
    fixture: &IntegratedRecoveryFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut transaction = fixture.open()?;
    fixture.preflight(&transaction, false)?;
    let reservation = fixture.reserve(1)?;
    let mut catalog = JournalCatalog;
    let mut policy = AllowAllPolicy;
    let mut adapter = CompletedAdapter::for_fixture(fixture);
    let admitted = transaction
        .admit(
            &fixture.operation().key,
            &adapter,
            &mut catalog,
            &mut policy,
            &RecoveryClock,
        )
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &admitted,
            &mut adapter,
            &mut policy,
            &RecoveryClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Completed
    );
    transaction
        .release_admitted::<CompletedAdapter, _, _>(admitted, &mut catalog, &RecoveryClock)
        .map_err(|failure| io::Error::other(failure.error().to_string()))?;
    drop(reservation);

    let later_failure = &fixture.plan.operations()[1];
    let mut rejected = RejectedAdapter;
    let admitted = transaction
        .admit(
            &later_failure.key,
            &rejected,
            &mut catalog,
            &mut policy,
            &RecoveryClock,
        )
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &admitted,
            &mut rejected,
            &mut policy,
            &RecoveryClock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::RejectedBeforeEffect
    );
    transaction
        .release_admitted::<RejectedAdapter, _, _>(admitted, &mut catalog, &RecoveryClock)
        .map_err(|failure| io::Error::other(failure.error().to_string()))?;
    assert_eq!(
        transaction.next_action(&later_failure.key)?,
        RecoveryAction::SettleFailureBeforeEffect
    );
    transaction.settle_failure_before_effect(&later_failure.key, bool_value(false))?;
    assert_eq!(
        transaction.summary().terminal(),
        Some(aos_ability_model::document::TerminalResult::SettledFailure)
    );
    fixture.write_terminal_marker(aos_ability_model::document::TerminalResult::SettledFailure)?;
    fixture
        .state
        .finalize_existing_terminal_marker(&transaction.summary())?;
    Ok(())
}

fn adoption_endpoint(
    real: &RealRecoveryPlan,
) -> Result<aos_ability_model::ProviderAdoptionEndpoint, Box<dyn std::error::Error>> {
    let plan = real.transition.checked_effect();
    let selections = selected_provider_owners(plan)?;
    let [selection] = selections.as_slice() else {
        return Err("recovery plan must select one durable owner".into());
    };
    let operation = &plan.operations()[0];
    let binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .ok_or("recovery operation binding is absent")?;
    let inventory = plan
        .binding_plan()
        .environment()
        .providers
        .iter()
        .find(|inventory| {
            inventory.provider == binding.provider
                && inventory.interface == binding.interface
                && inventory.implementation == binding.implementation
        })
        .ok_or("recovery handler inventory is absent")?;

    Ok(aos_ability_model::ProviderAdoptionEndpoint {
        provider: selection.identity.provider.clone(),
        package: selection.identity.package,
        interface: selection.identity.interface.clone(),
        implementation: selection.identity.implementation.clone(),
        state_format: selection.identity.state_format.clone(),
        handler_binding: operation.binding.clone(),
        handler_method: operation.method.clone(),
        handler_provider: selection.handler.provider.clone(),
        handler_incarnation: inventory
            .incarnation
            .clone()
            .ok_or("recovery handler incarnation is absent")?,
        handler_interface: selection.handler.interface.clone(),
        handler_implementation: selection.handler.implementation.clone(),
        handler_package: selection.handler.package,
    })
}

fn empty_linked_repair_bundle(
    source: &RealRecoveryPlan,
    candidate: &RealRecoveryPlan,
    transaction: &aos_ability_model::TransactionId,
) -> Result<
    (
        ReloadablePlanBundle,
        aos_ability_validate::CheckedEffectPlan,
        aos_ability_plan::TransitionReconciliation,
        aos_contract::Sha256Digest,
    ),
    Box<dyn std::error::Error>,
> {
    let resource = candidate.transition.checked_effect().operations()[0]
        .target
        .resource
        .clone();
    let adoption = aos_ability_model::ProviderAdoptionAuthorization {
        resource: resource.clone(),
        resource_interface: candidate.transition.checked_effect().operations()[0]
            .target
            .interface
            .clone(),
        source: adoption_endpoint(source)?,
        candidate: adoption_endpoint(candidate)?,
    };
    let policy_revision = candidate
        .planning
        .checked_binding()
        .document()
        .policy_revision;
    let authority_document = aos_ability_model::TransitionAuthorizationDocument {
        schema: aos_ability_model::TransitionAuthorizationDocument::SCHEMA.to_string(),
        required_features: vec![aos_ability_model::RequiredFeature::new(
            aos_ability_model::PROVIDER_STATE_ADOPTION_V1,
        )?],
        desired_planning: candidate.planning.snapshot_digest(),
        current_planning: source.planning.snapshot_digest(),
        desired_policy_revision: policy_revision,
        prior_policy_revision: source.planning.checked_binding().document().policy_revision,
        authorization_policy_revision: policy_revision,
        teardown_bindings: Vec::new(),
        teardown_providers: Vec::new(),
        provider_adoptions: vec![adoption],
    };
    let authority_digest = authority_document.content_digest()?;
    let authority = candidate.context.validate_transition_authority(
        authority_document,
        aos_ability_validate::TransitionAuthorityInputs {
            expected_digest: authority_digest,
            desired_planning: candidate.planning.snapshot_digest(),
            current_planning: source.planning.snapshot_digest(),
            authorization_policy_revision: policy_revision,
            desired: candidate.planning.checked_binding(),
            current: source.planning.checked_binding(),
        },
    )?;

    let source_plan = candidate.transition.checked_effect().id();
    let authority_json = serde_json::json!({
        "schema": "aos.ability.current-authority/v2",
        "policy_fence": policy_revision,
        "transaction": transaction,
        "authority_epoch": 1,
        "sequence": 1,
        "observed_at_restart_millis": 1,
        "max_age_millis": 1_000,
        "plan": source_plan,
        "resource_observations": candidate
            .planning
            .outcome()
            .desired_state
            .resources
            .iter()
            .map(|revision| serde_json::json!({
                "resource": revision.resource,
                "state": {
                    "state": "present",
                    "revision": revision.revision,
                    "health": "healthy",
                },
            }))
            .collect::<Vec<_>>(),
    });
    let authority_publication = aos_contract::Sha256Digest::separated(
        "aos.ability.current-authority/v2",
        aos_contract::canonical::to_vec(&authority_json)?,
    );
    let observations = candidate
        .planning
        .outcome()
        .desired_state
        .resources
        .iter()
        .map(|revision| aos_ability_plan::RuntimeResourceObservation {
            resource: revision.resource.clone(),
            state: aos_ability_plan::RuntimeResourceState::Present {
                revision: revision.revision,
                health: aos_ability_plan::RuntimeResourceHealth::Healthy,
            },
        })
        .collect();
    let reconciliation = aos_ability_plan::TransitionReconciliation {
        schema: aos_ability_plan::RUNTIME_OBSERVATIONS_SCHEMA.to_string(),
        source_plan,
        transaction: transaction.clone(),
        policy_fence: policy_revision,
        authority_epoch: 1,
        sequence: 1,
        observed_at_restart_millis: 1,
        max_age_millis: 1_000,
        authority_publication,
        authority_document: AbilityValue::new(authority_json)?,
        unsettled_provider_adoptions: vec![resource],
        observations,
    };
    let transition = TransitionPlanner::new(&candidate.context).plan(
        &candidate.planning,
        TransitionInputs {
            current: Some(&source.planning),
            authority: Some(&authority),
            reconciliation: Some(&reconciliation),
        },
        &mut EmptyRecoveryTransitionEvaluator,
    )?;
    let bundle = ReloadablePlanBundle::from_verified(
        &candidate.planning,
        Some(&source.planning),
        Some(&authority),
        &transition,
    )?;
    let plan = transition.into_checked_effect();
    assert!(plan.operations().is_empty());
    Ok((bundle, plan, reconciliation, authority_digest))
}

struct EmptyRepairFixture {
    _root: Arc<tempfile::TempDir>,
    generation: PathBuf,
    transaction: aos_ability_model::TransactionId,
    plan: aos_ability_validate::CheckedEffectPlan,
    bundle: ReloadablePlanBundle,
    reconciliation: aos_ability_plan::TransitionReconciliation,
    state: Arc<NativeInventoryState>,
}

impl EmptyRepairFixture {
    fn new(claim_only: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let root = Arc::new(tempfile::tempdir()?);
        let source_real = real_recovery_plan_with_package("source-incarnation", "1.0.0");
        let candidate_real =
            real_recovery_plan_with_later_failure("candidate-incarnation", "2.0.0");
        let candidate_transaction = aos_ability_model::TransactionId(key("candidate"));
        let (bundle, plan, reconciliation, authority) =
            empty_linked_repair_bundle(&source_real, &candidate_real, &candidate_transaction)?;

        let source = IntegratedRecoveryFixture::from_real_in_profile(
            Arc::clone(&root),
            "gen-1",
            "source",
            source_real,
        )?;
        complete_and_finalize(&source)?;
        let source_owner = source.ledger()?.owners.remove(0);
        save_native_resource_ledger(
            &source.state.ledger_path,
            &NativeResourceLedger {
                schema: NATIVE_RESOURCE_LEDGER_SCHEMA.to_string(),
                owners: Vec::new(),
                consumers: Vec::new(),
            },
        )?;
        drop(source);

        let candidate = IntegratedRecoveryFixture::from_real_in_profile(
            Arc::clone(&root),
            "gen-2",
            "candidate",
            candidate_real,
        )?;
        establish_first_write_then_settle_later_failure(&candidate)?;
        let mut candidate_owner = candidate.ledger()?.owners.remove(0);
        drop(candidate);

        let source_establishment = source_owner
            .established_by
            .clone()
            .ok_or("source establishment is absent")?;
        if claim_only {
            let establishment = candidate_owner
                .established_by
                .take()
                .ok_or("candidate establishment is absent")?;
            candidate_owner.claim_by = vec![ownership::NativeProviderClaim {
                generation: establishment.generation,
                transaction: establishment.transaction,
                plan: establishment.plan,
                operation: establishment.operation,
                attempt: establishment.attempt,
                artifacts: establishment.artifacts,
            }];
        }
        candidate_owner.adoption = Some(NativeProviderAdoptionReceipt {
            authority,
            source: source_owner.identity.clone(),
            source_handler: source_owner.handler.clone(),
            source_generation: source_establishment.generation.clone(),
            source_transaction: source_establishment.transaction.clone(),
            source_plan: source_establishment.plan,
            source_artifacts: source_owner.artifacts,
            source_establishment,
            consumer_requirement: None,
            linked_verification: None,
        });
        save_native_resource_ledger(
            &root.path().join(NATIVE_RESOURCE_LEDGER_FILE),
            &NativeResourceLedger {
                schema: NATIVE_RESOURCE_LEDGER_SCHEMA.to_string(),
                owners: vec![candidate_owner],
                consumers: Vec::new(),
            },
        )?;

        let generation = root.path().join("gen-3");
        std::fs::create_dir(&generation)?;
        let transaction = aos_ability_model::TransactionId(key("repair"));
        let mut store = GenerationAbilityStore::with_bundle_at(
            &generation,
            bundle.clone(),
            BTreeSet::from([
                aos_ability_model::RequiredFeature::new("abilities-v1")?,
                aos_ability_model::RequiredFeature::new(
                    aos_ability_model::PROVIDER_STATE_FORMAT_V1,
                )?,
                aos_ability_model::RequiredFeature::new(
                    aos_ability_model::PROVIDER_STATE_ADOPTION_V1,
                )?,
            ]),
            RecoveryArtifactVerifier,
            root.path().join("switch.lock"),
        )?;
        let state = NativeInventoryState::for_generation(
            &generation,
            &transaction,
            &plan,
            store.pending_bundle.as_ref(),
            store.supported_features.clone(),
            Arc::clone(&store.switch_lock),
        )?;
        store.retain_plan(&transaction, &plan)?;

        Ok(Self {
            _root: root,
            generation,
            transaction,
            plan,
            bundle,
            reconciliation,
            state,
        })
    }

    fn open(&self) -> Result<ExecutionTransaction<'_>, Box<dyn std::error::Error>> {
        let mut store = ReopenStore {
            bundle: self.bundle.digest()?,
        };
        Ok(ExecutionTransaction::open(
            &self.plan,
            self.transaction.clone(),
            self.generation
                .join(TRANSACTION_ROOT)
                .join(self.transaction.0.as_str())
                .join(EXECUTION_JOURNAL_FILE),
            JournalLimits::default(),
            &mut store,
        )?)
    }
}

#[test]
fn empty_linked_repair_session_settles_an_authenticated_zero_write_adoption()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = EmptyRepairFixture::new(false)?;
    let transaction = fixture.open()?;
    fixture
        .state
        .preflight_provider_owners(&fixture.bundle, &transaction)?;
    let owner = fixture.state.desired_owner_selections[0].resource.clone();
    let physical = fixture.state.ledger_path.parent().ok_or("ledger parent")?;
    let ledger = load_native_resource_ledger(&fixture.state.ledger_path)?;
    let owner_row = ledger.owners.first().ok_or("owner row")?;
    let observations = fixture
        .reconciliation
        .observations
        .iter()
        .map(|observation| NativeNoOpResourceObservation {
            qualified: NativeQualifiedResource {
                logical: observation.resource.clone(),
                physical: if observation.resource == owner {
                    owner_row.physical.clone()
                } else {
                    NativePhysicalResource {
                        class: "recovery-test".to_string(),
                        authority: "recovery-test".to_string(),
                        object: physical.display().to_string(),
                    }
                },
            },
            state: observation.state,
            consumer_requirement: NativeConsumerRequirement::Forbidden,
        })
        .collect::<Vec<_>>();
    fixture
        .state
        .verify_linked_adoption_no_op_with_consumer_status(
            &fixture.reconciliation,
            &observations,
            &BTreeSet::new(),
            true,
            |_, _| Ok(false),
        )?;
    let no_op_marker = NativeNoOpVerificationMarker {
        schema: NATIVE_NO_OP_VERIFICATION_SCHEMA.to_string(),
        transaction: fixture.transaction.clone(),
        plan: fixture.plan.id(),
        plan_bundle: fixture.bundle.digest()?,
    };
    let transaction_dir = fixture
        .generation
        .join(TRANSACTION_ROOT)
        .join(fixture.transaction.0.as_str());
    std::fs::write(
        transaction_dir.join(NATIVE_NO_OP_VERIFICATION_FILE),
        aos_contract::canonical::to_vec(&no_op_marker)?,
    )?;
    let terminal = TerminalMarker {
        schema: TERMINAL_MARKER_SCHEMA.to_string(),
        transaction: fixture.transaction.clone(),
        plan: fixture.plan.id(),
        terminal: aos_ability_model::document::TerminalResult::Succeeded,
    };
    std::fs::write(
        transaction_dir.join(TERMINAL_MARKER_FILE),
        aos_contract::canonical::to_vec(&terminal)?,
    )?;
    fixture
        .state
        .finalize_existing_terminal_marker(&transaction.summary())?;
    assert!(
        load_native_resource_ledger(&fixture.state.ledger_path)?.owners[0]
            .adoption
            .is_none()
    );
    Ok(())
}

#[test]
fn empty_linked_repair_session_rejects_claim_only_lost_result_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = EmptyRepairFixture::new(true)?;
    let transaction = fixture.open()?;
    let before = std::fs::read(&fixture.state.ledger_path)?;
    let error = fixture
        .state
        .preflight_provider_owners(&fixture.bundle, &transaction)
        .expect_err("claim-only candidate cannot settle an effect-free adoption");
    assert!(error.to_string().contains(
        "effect-free provider adoption recovery lacks exact healthy observation and authenticated candidate establishment"
    ));
    assert_eq!(std::fs::read(&fixture.state.ledger_path)?, before);
    Ok(())
}
