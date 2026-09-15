//! Executor candidate publication and exact-retention regressions.

use super::*;

#[test]
fn executor_candidate_publishes_fresh_choices_with_shared_contract_records() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, basis) =
        admitted_observation_fixture(&repository, &lineage, &policy, "fresh-candidate-choice");
    let alternative = AlternativeId::from_hash(CampaignHash::derive(
        "test-fresh-candidate-alternative",
        b"new",
    ));
    let domain = ChoiceDomain::Discrete(
        DiscreteDomain::new(
            1,
            BTreeMap::from([(
                alternative,
                DiscreteAlternative::new(alternative, "new", None).expect("fresh alternative"),
            )]),
        )
        .expect("fresh domain"),
    );
    let declaration = SelectableDeclaration::new(
        "product.test.fresh-candidate-choice",
        ChoiceSource::Workload {
            producer: "fresh-candidate-producer".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Discrete(alternative),
        ChoiceClassContext::new(BTreeSet::new()).expect("fresh choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("fresh declaration");
    let fresh = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test-fresh-candidate-scheduler", b"new"),
            producer: CampaignHash::derive("test-fresh-candidate-producer", b"new"),
        },
        "fresh-executor-discovery",
        None,
    )
    .expect("fresh opportunity");
    let fresh_id = fresh.id().expect("fresh opportunity id");
    let second = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test-fresh-candidate-scheduler", b"second"),
            producer: CampaignHash::derive("test-fresh-candidate-producer", b"new"),
        },
        "second-fresh-executor-discovery",
        None,
    )
    .expect("second fresh opportunity");
    let second_id = second.id().expect("second fresh opportunity id");
    let declaration_id = declaration.id().expect("fresh declaration id");
    let domain_id = domain.id().expect("fresh domain id");
    assert!(matches!(
        repository.load_selectable(declaration_id),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
    assert!(matches!(
        repository.load_choice_domain(domain_id),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
    assert!(matches!(
        repository.load_choice_opportunity(fresh_id),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
    assert!(matches!(
        repository.load_choice_opportunity(second_id),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));

    let observation = Observation::new(
        basis.attempt(),
        Observation::outcome(
            basis.child(),
            basis.child_content(),
            basis.path(),
            basis.stop().clone(),
            basis.measurements(),
            basis.properties(),
            basis.coverage(),
        ),
        BTreeSet::from([fresh_id, second_id]),
    )
    .expect("fresh-choice observation");
    let candidate = ObservationCandidate::new(
        repository
            .load_configuration_artifact(observation.child_content())
            .expect("candidate child"),
        repository
            .load_measurement_set(observation.measurements())
            .expect("candidate measurements"),
        repository
            .load_property_verdict_set(observation.properties())
            .expect("candidate properties"),
        repository
            .load_coverage_projection(observation.coverage())
            .expect("candidate coverage"),
        vec![
            ChoiceDiscovery::new(declaration.clone(), domain.clone(), fresh.clone())
                .expect("fresh choice discovery"),
            ChoiceDiscovery::new(declaration, domain, second.clone())
                .expect("second fresh choice discovery"),
        ],
        observation,
    )
    .expect("fresh candidate");
    assert!(Arc::ptr_eq(
        &candidate.discovered_choices()[0].declaration,
        &candidate.discovered_choices()[1].declaration,
    ));
    assert!(Arc::ptr_eq(
        &candidate.discovered_choices()[0].domain,
        &candidate.discovered_choices()[1].domain,
    ));
    let selection_observation = Observation::new(
        candidate.observation().attempt(),
        Observation::outcome(
            candidate.observation().child(),
            candidate.observation().child_content(),
            candidate.observation().path(),
            StopOutcome::Reached(StopCondition::Terminal),
            candidate.observation().measurements(),
            candidate.observation().properties(),
            candidate.observation().coverage(),
        ),
        candidate.observation().discovered_choices().clone(),
    )
    .expect("produced-selection observation");
    let selection_candidate = ObservationCandidate::new(
        candidate.child().clone(),
        candidate.measurements().clone(),
        candidate.properties().clone(),
        candidate.coverage().clone(),
        candidate.discovered_choices().to_vec(),
        selection_observation,
    )
    .expect("produced-selection candidate");
    let produced_selection = Selection::new(
        &fresh,
        candidate.discovered_choices()[0].domain(),
        ChoiceValue::Discrete(alternative),
        SelectionOrigin::Default,
    )
    .expect("produced default selection");
    let produced_candidate = selection_candidate
        .with_produced_selections(vec![produced_selection.clone()])
        .expect("candidate with produced selection");
    assert_eq!(
        produced_candidate.observation().produced_selections(),
        &BTreeSet::from([produced_selection.id().expect("produced selection id")])
    );
    assert!(matches!(
        produced_candidate.with_produced_selections(Vec::new()),
        Err(CampaignCodecError::InvalidValue {
            reason: "observation candidate already carries produced selections"
        })
    ));
    let mut mismatched_candidate = candidate.clone();
    mismatched_candidate.observation = mismatched_candidate
        .observation
        .clone()
        .with_produced_selections(BTreeSet::from([produced_selection
            .id()
            .expect("produced selection id")]))
        .expect("mismatched candidate observation");
    assert!(matches!(
        repository.validate_observation_candidate(&mismatched_candidate),
        Err(CampaignRepositoryError::Integrity {
            reason: "observation-produced-selection-bundle-mismatch"
        })
    ));

    repository
        .publish_observation_candidate(&candidate)
        .expect("publish candidate and fresh choice");
    assert_eq!(
        repository
            .load_selectable(declaration_id)
            .expect("load published declaration"),
        *candidate.discovered_choices()[0].declaration()
    );
    assert_eq!(
        repository
            .load_choice_domain(domain_id)
            .expect("load published domain"),
        *candidate.discovered_choices()[0].domain()
    );
    assert_eq!(
        repository
            .load_choice_opportunity(fresh_id)
            .expect("load published fresh choice"),
        fresh
    );
    assert_eq!(
        repository
            .load_choice_opportunity(second_id)
            .expect("load second published fresh choice"),
        second
    );
    let published = repository
        .publish_observation(
            "fresh-candidate-choice",
            admitted.new_snapshot,
            candidate.observation(),
        )
        .expect("admit candidate observation");
    let head = repository
        .head("fresh-candidate-choice")
        .expect("choice-index head");
    assert_eq!(head.snapshot_id(), published.new_snapshot);
    let (page, _, _) = repository
        .scan_choice_page(head.snapshot().roots().graph, None, 16)
        .expect("choice index page");
    for opportunity in [fresh_id, second_id] {
        assert!(page.entries().iter().any(|(key, value)| {
            *key == choice_index_order_key(opportunity) && *value == opportunity.content_id()
        }));
    }
}

#[test]
fn invalid_executor_candidate_is_rejected_before_any_bundle_write() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let (_, _, observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "invalid-observation-candidate",
    );
    let child = ConfigurationArtifact::new(
        lineage.scenario(),
        lineage.scenario_content(),
        ConfigurationId::from_hash(CampaignHash::derive(
            "test-invalid-candidate-child",
            b"child",
        )),
        1,
        b"unpublished-invalid-child".to_vec(),
    )
    .expect("candidate child");
    let candidate = ObservationCandidate::new(
        child,
        repository
            .load_measurement_set(observation.measurements())
            .expect("candidate measurements"),
        repository
            .load_property_verdict_set(observation.properties())
            .expect("candidate properties"),
        repository
            .load_coverage_projection(observation.coverage())
            .expect("candidate coverage"),
        observation
            .discovered_choices()
            .iter()
            .map(|id| choice_discovery_fixture(&repository, *id))
            .collect(),
        observation,
    )
    .expect("valid candidate");
    let objects_before = blobs.object_count().expect("objects before rejection");

    assert!(matches!(
        repository.publish_observation_candidate(&candidate),
        Err(CampaignRepositoryError::Integrity {
            reason: "observation-candidate-bundle-mismatch"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        objects_before
    );
}

#[test]
fn observation_ref_conflict_leaves_the_admitted_head_authoritative() {
    let (fixture_repository, lineage, policy, blobs) = counted_fixture();
    drop(fixture_repository);
    let refs = Arc::new(ConflictAfterCreateRefBackend::new());
    let repository = CampaignRepository::new(blobs, refs.clone());
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "observation-cas");
    let checkpoint_count = repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .len();
    refs.arm();

    assert!(matches!(
        repository.publish_observation("observation-cas", admitted.new_snapshot, &observation,),
        Err(CampaignRepositoryError::RefConflict { .. })
    ));
    assert_eq!(
        repository
            .head("observation-cas")
            .expect("authoritative admitted head")
            .snapshot_id(),
        admitted.new_snapshot
    );
    assert_eq!(
        repository
            .validated_heads
            .lock()
            .expect("validation checkpoints")
            .len(),
        checkpoint_count
    );
}

struct RecordingFindingCheckpointAuthenticator {
    calls: Arc<Mutex<Vec<(ExactCheckpointId, u64)>>>,
    metadata_bytes: u64,
    scenario_override: Option<ScenarioDefId>,
    configuration_override: Option<ConfigurationId>,
    event_counts: BTreeMap<ExactCheckpointId, u64>,
    failure: Option<FindingExactCheckpointAuthenticationError>,
    object_source: Option<Arc<MemoryBlobBackend>>,
}

impl FindingExactCheckpointAuthenticator for RecordingFindingCheckpointAuthenticator {
    fn authenticate_finding_exact_checkpoint(
        &self,
        checkpoint: ExactCheckpointId,
        scenario: ScenarioDefId,
        _scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        maximum_metadata_bytes: u64,
    ) -> Result<AuthenticatedFindingExactCheckpoint, FindingExactCheckpointAuthenticationError>
    {
        self.calls
            .lock()
            .expect("record finding checkpoint authentication")
            .push((checkpoint, maximum_metadata_bytes));
        if let Some(error) = self.failure {
            return Err(error);
        }
        Ok(AuthenticatedFindingExactCheckpoint::new(
            self.scenario_override.unwrap_or(scenario),
            self.configuration_override.unwrap_or(configuration),
            *self
                .event_counts
                .get(&checkpoint)
                .expect("recorded checkpoint event count"),
            self.metadata_bytes,
        ))
    }

    fn read_finding_exact_checkpoint_object(
        &self,
        object: ContentId,
    ) -> Result<BlobHandle, FindingExactCheckpointAuthenticationError> {
        self.object_source
            .as_ref()
            .ok_or(FindingExactCheckpointAuthenticationError::AuthenticationFailed)?
            .read(object, None)
            .map_err(|_| FindingExactCheckpointAuthenticationError::AuthenticationFailed)
    }
}

fn recording_finding_checkpoint_authenticator(
    calls: Arc<Mutex<Vec<(ExactCheckpointId, u64)>>>,
    metadata_bytes: u64,
    event_counts: BTreeMap<ExactCheckpointId, u64>,
) -> RecordingFindingCheckpointAuthenticator {
    RecordingFindingCheckpointAuthenticator {
        calls,
        metadata_bytes,
        scenario_override: None,
        configuration_override: None,
        event_counts,
        failure: None,
        object_source: None,
    }
}

fn publish_test_exact_checkpoint_closure(
    repository: &CampaignRepository,
    label: &[u8],
) -> (ExactCheckpointId, ContentId, Vec<u8>) {
    let mut manifest_bytes = b"test exact manifest ".to_vec();
    manifest_bytes.extend_from_slice(label);
    let manifest = ContentId::for_bytes(ObjectKind::DeviceState, 1, &manifest_bytes);
    repository
        .blobs
        .put_if_absent(manifest, &BlobHandle::from_bytes(manifest_bytes))
        .expect("publish test exact manifest");

    let mut leaf_bytes = b"test exact leaf ".to_vec();
    leaf_bytes.extend_from_slice(label);
    let leaf = ContentId::for_bytes(ObjectKind::Trace, 1, &leaf_bytes);
    repository
        .blobs
        .put_if_absent(leaf, &BlobHandle::from_bytes(leaf_bytes.clone()))
        .expect("publish test exact leaf");

    let index = ContentEnvelope::new(
        "crucible.test.exact-checkpoint-index",
        1,
        BTreeSet::from([ContentChild::new("object.0000", leaf).expect("index child")]),
        b"test exact index".to_vec(),
    )
    .expect("test exact index");
    let index_id = index.content_id(ObjectKind::ExactManifest);
    repository
        .blobs
        .put_if_absent(index_id, &BlobHandle::from_bytes(index.canonical_bytes()))
        .expect("publish test exact index");

    let root = ContentEnvelope::new(
        "crucible.test.exact-checkpoint-root",
        4,
        BTreeSet::from([
            ContentChild::new("index.0000", index_id).expect("root index child"),
            ContentChild::new("manifest", manifest).expect("root manifest child"),
        ]),
        b"test exact root".to_vec(),
    )
    .expect("test exact root");
    let root_id = root.content_id(ObjectKind::ExactManifest);
    repository
        .blobs
        .put_if_absent(root_id, &BlobHandle::from_bytes(root.canonical_bytes()))
        .expect("publish test exact root");

    (
        ExactCheckpointId::from_content_id(root_id).expect("test exact checkpoint ID"),
        leaf,
        leaf_bytes,
    )
}

fn delete_test_blob(blobs: &MemoryBlobBackend, id: ContentId) {
    let mut inventory = blobs
        .acquire_inventory_fence()
        .expect("acquire test deletion fence");
    inventory
        .delete_candidate(id)
        .expect("delete test blob candidate");
}

#[test]
fn complete_exact_retention_requires_executor_authentication_and_cold_loads_attestation() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let (_, admitted, observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "authenticated-exact-retention",
    );
    let observed = repository
        .publish_observation(
            "authenticated-exact-retention",
            admitted.new_snapshot,
            &observation,
        )
        .expect("publish exact-retention observation");

    let fingerprint = CampaignHash::derive("test-finding", b"authenticated retention");
    let original = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"authenticated original".to_vec(),
        )
        .expect("publish authenticated original");
    let final_state = CampaignHash::derive("test-finding", b"authenticated final state");
    let minimization = FindingMinimizationEvidence::new(
        original,
        3,
        b"authenticated minimization".to_vec(),
        vec![FindingMinimizationAttempt::new(
            0,
            CampaignHash::derive("test-finding", b"authenticated candidate"),
            CampaignHash::derive("test-finding", b"authenticated schedule"),
            final_state,
            Some(fingerprint),
            true,
        )],
        final_state,
    )
    .expect("authenticated minimization evidence");
    let minimized = repository
        .publish_minimized_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"authenticated minimized".to_vec(),
            minimization.clone(),
        )
        .expect("publish authenticated minimized reproduction");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        "qemu.authenticated-retention".to_owned(),
        Some(FindingTarget::Configuration(observation.child_content())),
        BTreeSet::new(),
    )
    .expect("authenticated signature");
    let signatures = FindingSignatureMinimizationEvidence::new(
        &signature,
        &minimization,
        vec![Some(signature.clone()), Some(signature.clone())],
        vec![Some(signature.clone()), Some(signature.clone())],
    )
    .expect("authenticated signature evidence");

    let checkpoint_blobs = Arc::new(MemoryBlobBackend::new(
        "selected-exact-checkpoint-source",
        64 * 1024 * 1024,
    ));
    let checkpoint_repository =
        CampaignRepository::new(checkpoint_blobs.clone(), Arc::new(MemoryRefBackend::new()));
    let (checkpoint, selected_leaf, selected_leaf_bytes) =
        publish_test_exact_checkpoint_closure(&checkpoint_repository, b"selected");
    let (unselected_checkpoint, _, _) =
        publish_test_exact_checkpoint_closure(&checkpoint_repository, b"unselected");
    let exact_pins = FindingExactPins::new(
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::from([checkpoint]),
        BTreeSet::new(),
    )
    .expect("selected exact pins");
    let mut candidates = vec![
        FindingExactRetentionCandidate::new(checkpoint, 5),
        FindingExactRetentionCandidate::new(unselected_checkpoint, 6),
    ];
    candidates.sort_by_key(|candidate| candidate.checkpoint());
    let evidence =
        FindingExactRetentionEvidence::new(candidates, checkpoint, 5, None, exact_pins.clone())
            .expect("authenticated inventory evidence");
    let basis = repository
        .attempt_retention_policy_basis_at(admitted.new_snapshot, admitted.attempt)
        .expect("retention policy basis");
    let retention = FindingExactRetention::new(
        basis.snapshot(),
        basis.policy(),
        basis.admission(),
        2,
        FindingExactRetentionDisposition::Complete,
    )
    .expect("complete retention outcome");
    let single_candidate_evidence = FindingExactRetentionEvidence::new(
        vec![FindingExactRetentionCandidate::new(checkpoint, 5)],
        checkpoint,
        5,
        None,
        exact_pins.clone(),
    )
    .expect("single-candidate exact evidence");
    let single_candidate_retention = FindingExactRetention::new(
        basis.snapshot(),
        basis.policy(),
        basis.admission(),
        1,
        FindingExactRetentionDisposition::Complete,
    )
    .expect("single-candidate exact retention");
    assert!(matches!(
        FindingCandidateBundle::new_with_exact_retention(
            crate::FindingCandidateCore::new(
                observed.observation,
                signature.clone(),
                original,
                minimized,
                signatures.clone(),
                exact_pins.clone(),
            ),
            None,
            single_candidate_retention,
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "complete finding exact retention requires authenticated evidence"
        })
    ));
    let single_candidate_bundle = FindingCandidateBundle::new_with_authenticated_exact_retention(
        crate::FindingCandidateCore::new(
            observed.observation,
            signature.clone(),
            original,
            minimized,
            signatures.clone(),
            exact_pins.clone(),
        ),
        None,
        single_candidate_retention,
        single_candidate_evidence,
    )
    .expect("single-candidate V5 finding bundle");
    let bundle = FindingCandidateBundle::new_with_authenticated_exact_retention(
        crate::FindingCandidateCore::new(
            observed.observation,
            signature,
            original,
            minimized,
            signatures,
            exact_pins,
        ),
        None,
        retention,
        evidence,
    )
    .expect("V5 finding bundle");
    let bundle_id = bundle.id().expect("V5 finding bundle ID");
    assert!(matches!(
        repository.publish_finding_candidate_bundle(&bundle),
        Err(CampaignRepositoryError::Integrity {
            reason: "finding-exact-checkpoint-authenticator-is-missing"
        })
    ));
    assert!(
        !repository
            .blobs
            .contains(bundle_id.content_id())
            .expect("rejected bundle presence")
    );

    let repository = Arc::new(repository);
    let candidate_events = BTreeMap::from([(checkpoint, 5), (unselected_checkpoint, 6)]);

    let mut failed_authenticator = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        17,
        candidate_events.clone(),
    );
    failed_authenticator.failure =
        Some(FindingExactCheckpointAuthenticationError::AuthenticationFailed);
    let failed_store = CampaignExecutorStore::new(Arc::clone(&repository));
    assert!(matches!(
        failed_store.publish_executor_finding_candidate(&bundle, &failed_authenticator),
        Err(CampaignRepositoryError::Integrity {
            reason: "finding-exact-retention-candidate-authentication-failed"
        })
    ));

    let mut wrong_scenario = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        17,
        candidate_events.clone(),
    );
    wrong_scenario.scenario_override = Some(ScenarioDefId::from_hash(CampaignHash::derive(
        "test.wrong-finding-scenario",
        b"wrong scenario",
    )));
    let wrong_scenario_store = CampaignExecutorStore::new(Arc::clone(&repository));
    assert!(
        wrong_scenario_store
            .publish_executor_finding_candidate(&bundle, &wrong_scenario)
            .is_err()
    );

    let mut wrong_configuration = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        17,
        candidate_events.clone(),
    );
    wrong_configuration.configuration_override = Some(ConfigurationId::from_hash(
        CampaignHash::derive("test.wrong-finding-configuration", b"wrong configuration"),
    ));
    let wrong_configuration_store = CampaignExecutorStore::new(Arc::clone(&repository));
    assert!(
        wrong_configuration_store
            .publish_executor_finding_candidate(&bundle, &wrong_configuration)
            .is_err()
    );

    let wrong_events = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        17,
        BTreeMap::from([(checkpoint, 4), (unselected_checkpoint, 6)]),
    );
    let wrong_events_store = CampaignExecutorStore::new(Arc::clone(&repository));
    assert!(
        wrong_events_store
            .publish_executor_finding_candidate(&bundle, &wrong_events)
            .is_err()
    );

    let single_over_limit = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        (64 * 1024 * 1024) + 1,
        BTreeMap::from([(checkpoint, 5)]),
    );
    let single_over_limit_store = CampaignExecutorStore::new(Arc::clone(&repository));
    assert!(matches!(
        single_over_limit_store
            .publish_executor_finding_candidate(&single_candidate_bundle, &single_over_limit,),
        Err(CampaignRepositoryError::Integrity {
            reason: "finding-exact-retention-metadata-byte-limit"
        })
    ));

    let mut single_at_limit = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        64 * 1024 * 1024,
        BTreeMap::from([(checkpoint, 5)]),
    );
    single_at_limit.object_source = Some(Arc::clone(&checkpoint_blobs));
    let single_at_limit_store = CampaignExecutorStore::new(Arc::clone(&repository));
    single_at_limit_store
        .publish_executor_finding_candidate(&single_candidate_bundle, &single_at_limit)
        .expect("accept exact 64 MiB checkpoint metadata limit");

    let aggregate_over_limit = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        (32 * 1024 * 1024) + 1,
        candidate_events.clone(),
    );
    let aggregate_over_limit_store = CampaignExecutorStore::new(Arc::clone(&repository));
    assert!(matches!(
        aggregate_over_limit_store
            .publish_executor_finding_candidate(&bundle, &aggregate_over_limit,),
        Err(CampaignRepositoryError::Integrity {
            reason: "finding-exact-retention-metadata-byte-limit"
        })
    ));

    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut authenticator = recording_finding_checkpoint_authenticator(
        Arc::clone(&calls),
        32 * 1024 * 1024,
        candidate_events.clone(),
    );
    authenticator.object_source = Some(Arc::clone(&checkpoint_blobs));
    let executor = CampaignExecutorStore::new(Arc::clone(&repository));
    let publication = executor
        .publish_executor_finding_candidate(&bundle, &authenticator)
        .expect("publish executor-attested V5 bundle");
    assert_eq!(publication, bundle_id);
    let ordered_checkpoints = candidate_events.keys().copied().collect::<Vec<_>>();
    assert_eq!(
        calls.lock().expect("authentication calls").as_slice(),
        &[
            (ordered_checkpoints[0], 64 * 1024 * 1024),
            (ordered_checkpoints[1], 32 * 1024 * 1024),
        ]
    );
    assert!(
        blobs
            .contains(selected_leaf)
            .expect("imported selected exact leaf presence")
    );
    assert!(
        !blobs
            .contains(unselected_checkpoint.content_id())
            .expect("unselected exact root presence")
    );
    assert_eq!(
        repository
            .load_finding_candidate_bundle(bundle_id)
            .expect("cold-load V5 attestation"),
        bundle
    );
    assert!(matches!(
        repository.incorporate_finding_candidate_bundle(
            "authenticated-exact-retention",
            observed.new_snapshot,
            bundle_id,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "complete-finding-exact-retention-requires-executor-attested-incorporation"
        })
    ));
    delete_test_blob(blobs.as_ref(), selected_leaf);
    let head_before_rejection = repository
        .head("authenticated-exact-retention")
        .expect("head before missing selected descendant")
        .snapshot_id();
    assert!(
        repository
            .incorporate_checked_executor_finding_candidate_bundle(
                "authenticated-exact-retention",
                observed.new_snapshot,
                bundle_id,
                observed.observation,
                CampaignHash::derive("test.checked-executor-completion", b"missing descendant"),
            )
            .is_err()
    );
    assert_eq!(
        repository
            .head("authenticated-exact-retention")
            .expect("head after missing selected descendant")
            .snapshot_id(),
        head_before_rejection
    );
    repository
        .blobs
        .put_if_absent(selected_leaf, &BlobHandle::from_bytes(selected_leaf_bytes))
        .expect("restore selected exact descendant");
    let incorporated = repository
        .incorporate_checked_executor_finding_candidate_bundle(
            "authenticated-exact-retention",
            observed.new_snapshot,
            bundle_id,
            observed.observation,
            CampaignHash::derive("test.checked-executor-completion", b"exact completion"),
        )
        .expect("incorporate executor-attested V5 bundle");
    assert!(!incorporated.replayed);
    let cold = CampaignRepository::new(Arc::clone(&repository.blobs), Arc::clone(&repository.refs));
    assert!(
        cold.incorporate_finding_candidate_bundle(
            "authenticated-exact-retention",
            observed.new_snapshot,
            bundle_id,
        )
        .expect("cold replay of incorporated V5 bundle")
        .replayed
    );
}
