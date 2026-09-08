//! Prepared finding publication and reconciliation tests.

use super::*;

#[test]
fn prepared_finding_publishes_and_authenticates_an_admitted_observation_closure() {
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 1 },
        order: Vec::new(),
    }));
    let scenario_record = encode_crucible_scenario_artifact(&scenario).expect("scenario record");
    let genesis = encode_crucible_configuration_artifact(&scenario_record, &Schedule::empty())
        .expect("genesis configuration");
    let child = encode_crucible_configuration_artifact(&scenario_record, &schedule)
        .expect("finding configuration");

    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "prepared-finding-publication",
            u64::MAX,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    repository
        .publish_scenario_artifact(
            scenario_record.scenario(),
            scenario_record.payload_schema(),
            scenario_record.payload().to_vec(),
        )
        .expect("publish scenario");
    repository
        .publish_configuration_artifact(
            genesis.scenario(),
            genesis.scenario_artifact(),
            genesis.configuration(),
            genesis.payload_schema(),
            genesis.payload().to_vec(),
        )
        .expect("publish genesis");
    let lineage = CampaignLineage::new(
        scenario_record.scenario(),
        scenario_record.id().expect("scenario ID"),
        genesis.configuration(),
        genesis.id().expect("genesis ID"),
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario_record.payload_schema(),
        1,
    )
    .expect("campaign lineage");
    let widening = ProgressiveWideningPolicy::new(
        crucible_campaign::ExactRational::new(1, 1).expect("widening numerator"),
        crucible_campaign::ExactRational::new(1, 2).expect("widening exponent"),
        1,
        100,
        1,
    )
    .expect("widening policy");
    let policy = CampaignPolicy::new(
        lineage.scenario(),
        CampaignSeed::from_bytes([7; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness policy"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("campaign policy");
    let created = repository
        .create("prepared-finding", &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    let resumed = repository
        .apply_control(
            "prepared-finding",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"resume-prepared-finding",
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume campaign");
    let funded = repository
        .apply_control(
            "prepared-finding",
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "test",
                    b"fund-prepared-finding",
                )),
                expected_snapshot: resumed.new_snapshot,
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 1).expect("attempt grant"),
                ),
            },
        )
        .expect("fund campaign");
    let attempt = repository
        .admit_initial_discovery_if_ready("prepared-finding")
        .expect("admit initial discovery")
        .expect("discovery attempt");
    assert_ne!(funded.new_snapshot, created.snapshot_id());
    let attempt_record = repository.load_attempt(attempt).expect("load attempt");

    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.test.prepared-finding-choice",
        ChoiceSource::Scheduler {
            producer: String::from("prepared-finding-test"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("selectable declaration");
    let opportunity = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test", b"prepared-finding-scheduler"),
            producer: CampaignHash::derive("test", b"prepared-finding-producer"),
        },
        "prepared-finding-choice",
        None,
    )
    .expect("choice opportunity");
    let discovery =
        ChoiceDiscovery::new(declaration, domain, opportunity.clone()).expect("discovery");
    let measurements = MeasurementSet::new(BTreeMap::new()).expect("measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let coverage =
        CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage projection");
    let observation = Observation::new(
        attempt,
        child.configuration(),
        child.id().expect("child ID"),
        attempt_record.path(),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements.id().expect("measurement ID"),
        properties.id().expect("property ID"),
        coverage.id().expect("coverage ID"),
        BTreeSet::from([opportunity.id().expect("opportunity ID")]),
    )
    .expect("observation");
    let observation_candidate = ObservationCandidate::new(
        child.clone(),
        measurements,
        properties.clone(),
        coverage,
        vec![discovery],
        observation,
    )
    .expect("observation candidate");
    let executor_store = CampaignExecutorStore::new(Arc::clone(&repository));
    let observation = observation_candidate
        .observation()
        .id()
        .expect("observation ID");

    let fingerprint = ContentHash::from_bytes(b"published-finding-fingerprint");
    let finding = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        fingerprint,
        &scenario,
        &Configuration {
            def: scenario.scenario_def(),
            schedule,
        },
    )
    .expect("capture finding reproduction");
    let property = properties.id().expect("causal property record");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        CampaignHash::from_bytes(fingerprint.bytes),
        None,
        String::from("qemu.replay-divergence"),
        Some(FindingTarget::Configuration(
            child.id().expect("finding target"),
        )),
        BTreeSet::from([property.content_id()]),
    )
    .expect("finding signature");
    let seed = crucible::Seed::from_u64(0xface);
    let mut transcript = CrucibleFindingReplayTranscript::new();
    for pass in [
        FindingReplayPass::Minimization,
        FindingReplayPass::Verification,
    ] {
        minimize_signature_preserving_finding(
            &finding,
            &signature,
            seed,
            pass,
            &mut transcript,
            |candidate| {
                let candidate_scenario =
                    encode_crucible_scenario_artifact(candidate.artifact.scenario_form())
                        .expect("candidate scenario");
                let candidate_configuration = encode_crucible_configuration_artifact(
                    &candidate_scenario,
                    candidate.artifact.schedule(),
                )
                .expect("candidate configuration");
                let observed = if candidate.artifact.schedule() == finding.artifact.schedule() {
                    signature.clone()
                } else {
                    FindingSignature::new(
                        FindingKind::Divergence,
                        CampaignHash::derive("test", b"reduced-candidate-divergence"),
                        None,
                        String::from("qemu.different-replay-divergence"),
                        Some(FindingTarget::Configuration(
                            candidate_configuration.id().expect("candidate target"),
                        )),
                        BTreeSet::from([property.content_id()]),
                    )
                    .expect("rejected candidate signature")
                };
                Ok(CrucibleFindingReplayEvidence::new(
                    Some(observed),
                    candidate_configuration,
                    MeasurementSet::new(BTreeMap::new()).expect("replay measurements"),
                    properties.clone(),
                    CoverageProjection::new(BTreeSet::new(), BTreeSet::new())
                        .expect("replay coverage"),
                    Vec::new(),
                    Vec::new(),
                )
                .expect("replay evidence"))
            },
        )
        .expect("finding replay pass");
    }
    let prepared = prepare_signature_preserving_minimized_finding_candidate(
        signature.clone(),
        observation,
        &finding,
        FindingExactPins::default(),
        seed,
        transcript,
    )
    .expect("prepare finding candidate");
    assert!(
        prepared
            .minimized()
            .minimization()
            .expect("minimization evidence")
            .attempts()
            .iter()
            .any(|attempt| !attempt.accepted()),
        "the reduced empty schedule must be rejected by the concrete target"
    );

    let observation_publication =
        empty_measurement_publication(scenario_record.scenario(), child.configuration());
    let (observation_evidence, _, observation_measurements) = observation_publication.into_parts();
    let observation_candidate_v2 =
        observation_with_measurements(&observation_candidate, observation_measurements);
    let observation_v2 = observation_candidate_v2
        .observation()
        .id()
        .expect("v2 observation ID");
    let mut measurement_evidence = BTreeMap::from([(
        observation_evidence.id().expect("observation evidence ID"),
        observation_evidence,
    )]);
    let mut v2_transcript = CrucibleFindingReplayTranscript::new();
    for pass in [
        FindingReplayPass::Minimization,
        FindingReplayPass::Verification,
    ] {
        minimize_signature_preserving_finding(
            &finding,
            &signature,
            seed,
            pass,
            &mut v2_transcript,
            |candidate| {
                let candidate_scenario =
                    encode_crucible_scenario_artifact(candidate.artifact.scenario_form())
                        .expect("v2 candidate scenario");
                let candidate_configuration = encode_crucible_configuration_artifact(
                    &candidate_scenario,
                    candidate.artifact.schedule(),
                )
                .expect("v2 candidate configuration");
                let observed = if candidate.artifact.schedule() == finding.artifact.schedule() {
                    signature.clone()
                } else {
                    FindingSignature::new(
                        FindingKind::Divergence,
                        CampaignHash::derive("test", b"v2-reduced-candidate-divergence"),
                        None,
                        String::from("qemu.different-v2-replay-divergence"),
                        Some(FindingTarget::Configuration(
                            candidate_configuration.id().expect("v2 candidate target"),
                        )),
                        BTreeSet::from([property.content_id()]),
                    )
                    .expect("v2 rejected candidate signature")
                };
                let publication = empty_measurement_publication(
                    candidate_scenario.scenario(),
                    candidate_configuration.configuration(),
                );
                let (evidence, _, measurements) = publication.into_parts();
                measurement_evidence
                    .insert(evidence.id().expect("v2 replay evidence ID"), evidence);
                Ok(CrucibleFindingReplayEvidence::new(
                    Some(observed),
                    candidate_configuration,
                    measurements,
                    properties.clone(),
                    CoverageProjection::new(BTreeSet::new(), BTreeSet::new())
                        .expect("v2 replay coverage"),
                    Vec::new(),
                    Vec::new(),
                )
                .expect("v2 replay evidence"))
            },
        )
        .expect("v2 finding replay pass");
    }
    let prepared_v2 = prepare_signature_preserving_minimized_finding_candidate(
        signature.clone(),
        observation_v2,
        &finding,
        FindingExactPins::default(),
        seed,
        v2_transcript,
    )
    .expect("prepare v2 finding candidate");
    let measurement_evidence = measurement_evidence.into_values().collect::<Vec<_>>();
    assert!(measurement_evidence.len() >= 2);
    assert!(
        measurement_evidence
            .iter()
            .any(|evidence| evidence.configuration() != child.configuration())
    );
    let v2_result = PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
        observation_candidate_v2.clone(),
        measurement_evidence.clone(),
        Some(prepared_v2.clone()),
    )
    .expect("bind v2 prepared semantic result");
    v2_result
        .verify_measurement_publications(&scenario)
        .expect("verify every authenticated v2 measurement owner");

    let measurement_records = prepared_v2
        .replay_records
        .measurements
        .iter()
        .map(|measurement| {
            (
                measurement.id().expect("replay measurement ID"),
                measurement,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let shared_evidence = measurement_evidence
        .iter()
        .map(|evidence| evidence.id().expect("shared evidence ID"))
        .find(|evidence| {
            prepared_v2.minimization_replays.iter().any(|replay| {
                measurement_records
                    .get(&replay.measurements)
                    .and_then(|measurement| measurement.evaluation())
                    .is_some_and(|evaluation| evaluation.evidence().contains(evidence))
            }) && prepared_v2.verification_replays.iter().any(|replay| {
                measurement_records
                    .get(&replay.measurements)
                    .and_then(|measurement| measurement.evaluation())
                    .is_some_and(|evaluation| evaluation.evidence().contains(evidence))
            })
        })
        .expect("one raw leaf shared by both replay passes");
    let verification_replay = prepared_v2
        .verification_replays
        .iter()
        .position(|replay| {
            measurement_records
                .get(&replay.measurements)
                .and_then(|measurement| measurement.evaluation())
                .is_some_and(|evaluation| evaluation.evidence().contains(&shared_evidence))
        })
        .expect("verification owner of shared raw leaf");
    let original_measurement = measurement_records
        .get(&prepared_v2.verification_replays[verification_replay].measurements)
        .copied()
        .expect("shared replay measurement");
    let retained = original_measurement
        .evaluation()
        .expect("shared replay evaluation");
    let mut tampered_payload = retained.payload().to_vec();
    tampered_payload.push(b' ');
    let tampered_measurement = MeasurementSet::from_evaluation(
        retained.definitions(),
        retained.payload_schema(),
        retained.evaluation(),
        tampered_payload,
        retained.evidence().clone(),
    )
    .expect("structurally valid tampered replay measurement");
    let tampered_measurement_id = tampered_measurement
        .id()
        .expect("tampered replay measurement ID");
    let mut tampered_finding = prepared_v2.clone();
    tampered_finding
        .replay_records
        .measurements
        .push(tampered_measurement);
    tampered_finding.verification_replays[verification_replay].measurements =
        tampered_measurement_id;
    let tampered_result = PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
        observation_candidate_v2.clone(),
        measurement_evidence.clone(),
        Some(tampered_finding),
    )
    .expect("retain structurally owned shared evidence");
    assert!(matches!(
        tampered_result.verify_measurement_publications(&scenario),
        Err(PreparedSemanticResultCodecError::Measurement(_))
    ));

    let v2_bytes = v2_result
        .canonical_bytes()
        .expect("encode v2 prepared result");
    assert_eq!(
        PreparedSemanticAttemptResult::from_canonical_bytes(&v2_bytes)
            .expect("decode v2 prepared result"),
        v2_result
    );

    let mut unordered_evidence = measurement_evidence.clone();
    unordered_evidence.reverse();
    assert!(matches!(
        PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
            observation_candidate_v2.clone(),
            unordered_evidence,
            Some(prepared_v2.clone()),
        ),
        Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "measurement replay evidence order"
        })
    ));

    let unused_publication = empty_measurement_publication(
        scenario_record.scenario(),
        ConfigurationId::from_hash(CampaignHash::derive(
            "test",
            b"unused-replay-measurement-configuration",
        )),
    );
    let (unused_evidence, _, unused_measurements) = unused_publication.into_parts();
    let mut evidence_with_extra = measurement_evidence
        .iter()
        .cloned()
        .map(|evidence| (evidence.id().expect("retained evidence ID"), evidence))
        .collect::<BTreeMap<_, _>>();
    evidence_with_extra.insert(
        unused_evidence.id().expect("unused evidence ID"),
        unused_evidence.clone(),
    );
    assert!(matches!(
        PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
            observation_candidate_v2.clone(),
            evidence_with_extra.values().cloned().collect(),
            Some(prepared_v2.clone()),
        ),
        Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "unowned measurement replay evidence"
        })
    ));
    let mut finding_with_unused_measurement = prepared_v2.clone();
    finding_with_unused_measurement
        .replay_records
        .measurements
        .push(unused_measurements);
    assert!(matches!(
        PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
            observation_candidate_v2.clone(),
            evidence_with_extra.into_values().collect(),
            Some(finding_with_unused_measurement),
        ),
        Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "unreferenced finding replay measurement record"
        })
    ));

    for (wrong_scenario, wrong_configuration, wrong_definitions) in [
        (
            ScenarioDefId::from_hash(CampaignHash::derive("test", b"wrong-scenario")),
            child.configuration(),
            None,
        ),
        (
            scenario_record.scenario(),
            ConfigurationId::from_hash(CampaignHash::derive("test", b"wrong-configuration")),
            None,
        ),
        (
            scenario_record.scenario(),
            child.configuration(),
            Some(CampaignHash::derive("test", b"wrong-definitions")),
        ),
    ] {
        let wrong_publication = empty_measurement_publication(wrong_scenario, wrong_configuration);
        let (wrong_evidence, _, _) = wrong_publication.into_parts();
        let definitions = wrong_definitions.unwrap_or_else(|| {
            observation_candidate_v2
                .measurements()
                .evaluation()
                .expect("v2 measurement evaluation")
                .definitions()
        });
        let wrong_measurements = measurement_with_evidence(
            observation_candidate_v2.measurements(),
            &wrong_evidence,
            definitions,
        );
        let wrong_candidate =
            observation_with_measurements(&observation_candidate_v2, wrong_measurements);
        assert!(matches!(
            PreparedSemanticAttemptResult::new_with_measurement_replay_evidence(
                wrong_candidate,
                vec![wrong_evidence],
                None,
            ),
            Err(PreparedSemanticResultCodecError::Inconsistent {
                component: "measurement replay evidence binding"
            })
        ));
    }

    let smuggled_v1 = prepared_result::encode_v1_without_measurement_evidence_for_test(
        &observation_candidate_v2,
        None,
    )
    .expect("encode invalid legacy v1 payload");
    assert!(matches!(
        PreparedSemanticAttemptResult::from_canonical_bytes(&smuggled_v1),
        Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "missing measurement replay evidence"
        })
    ));

    let expected = prepared.id().expect("prepared candidate ID");
    let expected_bundle = prepared.bundle().clone();
    let durable_result =
        PreparedSemanticAttemptResult::new(observation_candidate.clone(), Some(prepared.clone()))
            .expect("bind prepared semantic result");
    let durable_bytes = durable_result
        .canonical_bytes()
        .expect("encode prepared semantic result");
    let decoded = PreparedSemanticAttemptResult::from_canonical_bytes(&durable_bytes)
        .expect("decode prepared semantic result");
    assert_eq!(decoded, durable_result);
    let mut trailing = durable_bytes.clone();
    trailing.push(0);
    assert!(matches!(
        PreparedSemanticAttemptResult::from_canonical_bytes(&trailing),
        Err(PreparedSemanticResultCodecError::TrailingBytes)
    ));

    let unrelated_observation = Observation::new(
        attempt,
        genesis.configuration(),
        genesis.id().expect("unrelated observation child"),
        attempt_record.path(),
        StopOutcome::Reached(StopCondition::NextChoice),
        observation_candidate
            .measurements()
            .id()
            .expect("unrelated observation measurements"),
        observation_candidate
            .properties()
            .id()
            .expect("unrelated observation properties"),
        observation_candidate
            .coverage()
            .id()
            .expect("unrelated observation coverage"),
        BTreeSet::from([opportunity.id().expect("unrelated observation choice")]),
    )
    .expect("unrelated observation");
    let unrelated_candidate = ObservationCandidate::new(
        genesis.clone(),
        observation_candidate.measurements().clone(),
        observation_candidate.properties().clone(),
        observation_candidate.coverage().clone(),
        observation_candidate.discovered_choices().to_vec(),
        unrelated_observation,
    )
    .expect("unrelated observation candidate");
    let mut mismatched_finding = prepared.clone();
    mismatched_finding.bundle = FindingCandidateBundle::new(
        unrelated_candidate
            .observation()
            .id()
            .expect("unrelated observation ID"),
        signature.clone(),
        prepared.bundle().reproduction(),
        prepared.bundle().minimized(),
        prepared.bundle().signature_minimization().clone(),
        prepared.bundle().exact_pins().clone(),
    )
    .expect("finding rebound to unrelated observation ID");
    assert!(matches!(
        PreparedSemanticAttemptResult::new(unrelated_candidate, Some(mismatched_finding)),
        Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "finding observation reproduction basis"
        })
    ));

    let mut inconsistent_finding = prepared.clone();
    let unrelated_schedule = finding
        .artifact
        .schedule()
        .clone()
        .appended(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 2 },
            order: Vec::new(),
        }));
    let unrelated_configuration =
        encode_crucible_configuration_artifact(&scenario_record, &unrelated_schedule)
            .expect("unrelated replay configuration")
            .id()
            .expect("unrelated replay configuration ID");
    inconsistent_finding.minimization_replays[0].configuration = unrelated_configuration;
    let inconsistent = PreparedSemanticAttemptResult::new(
        observation_candidate.clone(),
        Some(inconsistent_finding),
    )
    .expect("observation binding remains valid");
    assert!(matches!(
        inconsistent.canonical_bytes_with_limit(1),
        Err(PreparedSemanticResultCodecError::LimitExceeded)
    ));
    assert!(matches!(
        inconsistent.canonical_bytes(),
        Err(PreparedSemanticResultCodecError::Inconsistent {
            component: "finding replay record index"
        })
    ));

    let epoch = DaemonEpoch::from_bytes([0x57; 16]).expect("daemon epoch");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x58; 16]).expect("assignment"),
        epoch,
        lineage.id().expect("lineage ID"),
        attempt,
        AttemptResourceLimits::new(1, 4096, 4096, 64).expect("attempt resources"),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("submit request");
    let mut supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(1, 1, 4096, 4096, 64).expect("executor capacity"),
    );
    let response = supervisor
        .submit_attempt(&request)
        .expect("admit finding attempt");
    let SubmitAttemptDisposition::Accepted { execution } = response.disposition() else {
        panic!("finding attempt should be accepted")
    };
    let queued = supervisor.next_queued().expect("queued finding attempt");
    let checkpoint_directory = tempfile::tempdir().expect("checkpoint directory");
    let checkpoints = ExactCheckpointStore::new(
        Arc::new(DirectoryBlobBackend::new(
            "prepared-finding-checkpoints",
            checkpoint_directory.path(),
        )),
        1024 * 1024,
    )
    .expect("checkpoint store");
    let work = AttemptWorkResult::<()>::new(
        queued,
        Ok(AttemptExecutionProduct::observation_with_finding(
            observation_candidate,
            prepared,
        )),
    );
    let prepared = prepare_attempt_result(&executor_store, &checkpoints, work)
        .expect("prepare paired worker result");
    let PreparedAttemptWorkResult::Observation(prepared) = prepared else {
        panic!("finding worker returned an exact checkpoint")
    };
    assert_eq!(prepared.observation(), observation);
    assert_eq!(prepared.finding_candidate(), Some(expected));

    let staged = stage_prepared_attempt_result(&mut supervisor, *prepared)
        .expect("stage paired publication");
    let AttemptResultStageOutcome::Publish(staged) = staged else {
        panic!("current finding result should publish")
    };
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    assert!(matches!(
        supervisor
            .ledger()
            .load_attempt(key)
            .expect("load staged finding pair"),
        Some(AttemptRuntimeState::Publishing {
            observation: retained_observation,
            finding_candidate: Some(retained_candidate),
            ..
        }) if retained_observation == observation && retained_candidate == expected
    ));
    assert_eq!(
        supervisor
            .stage_observation_and_finding_candidate_publication(
                staged.queued(),
                observation,
                expected,
            )
            .expect("retry exact staged pair"),
        crate::ObservationPublicationOutcome::AlreadyStaged
    );
    let wrong_candidate_content =
        ContentId::for_bytes(ObjectKind::Finding, 1, b"wrong staged finding candidate");
    let wrong_candidate = FindingCandidateBundleId::parse(&format!(
        "crucible.campaign.finding-candidate-bundle@{wrong_candidate_content}"
    ))
    .expect("wrong finding candidate ID");
    assert!(matches!(
        supervisor.stage_and_reconcile_completion_with_finding_candidate(
            staged.queued(),
            observation,
            Some(wrong_candidate),
        ),
        Err(LocalExecutorError::ConflictingCompletion)
    ));

    let published = publish_prepared_attempt_result(&executor_store, staged)
        .expect("publish paired finding result");
    assert_eq!(published.finding_candidate(), Some(expected));
    let reconciled = reconcile_published_attempt_result::<_, _, ()>(&mut supervisor, published)
        .expect("reconcile paired finding result");
    assert_eq!(
        reconciled,
        AttemptWorkerReconcileOutcome::Reconciled {
            observation,
            completion: CompletionOutcome::Completed,
        }
    );

    let loaded = repository
        .load_finding_candidate_bundle(expected)
        .expect("load and authenticate finding closure");
    assert_eq!(loaded, expected_bundle);
    assert_eq!(loaded.observation(), observation);
    assert_eq!(loaded.signature().target(), signature.target());
    assert_eq!(
        loaded.signature().causal_evidence(),
        signature.causal_evidence()
    );

    let campaign = CampaignName::new("prepared-finding").expect("campaign name");
    let observation_parent = repository
        .head(campaign.as_str())
        .expect("current finding campaign head")
        .snapshot_id();
    let observation_record = repository
        .load_observation(observation)
        .expect("load paired observation");
    let incorporated_observation = repository
        .publish_observation(campaign.as_str(), observation_parent, &observation_record)
        .expect("incorporate paired observation");
    let mut ledger = supervisor.into_ledger();
    let handoff = incorporate_and_acknowledge_finding_candidate(
        &repository,
        &mut ledger,
        &campaign,
        incorporated_observation.new_snapshot,
        key,
        execution,
        observation,
        expected,
    )
    .expect("incorporate and acknowledge exact finding pair");
    let crate::FindingCandidateRetentionOutcome::Released(acknowledgement) =
        handoff.acknowledgement()
    else {
        panic!("exact finding pair should release its operational root")
    };
    assert_eq!(acknowledgement.bundle(), expected);
    assert!(matches!(
        ledger
            .load_attempt(key)
            .expect("load acknowledged finding pair"),
        Some(AttemptRuntimeState::Completed {
            observation: retained_observation,
            finding_candidate: CompletedFindingCandidate::Acknowledged(retained_candidate),
            ..
        }) if retained_observation == observation && retained_candidate == expected
    ));
}

#[test]
fn finding_candidate_publication_waits_for_both_replay_passes() {
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 1 },
        order: Vec::new(),
    }));
    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule,
    };
    let fingerprint = ContentHash::from_bytes(b"two-pass-finding-fingerprint");
    let finding = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        fingerprint,
        &scenario,
        &configuration,
    )
    .expect("capture finding reproduction");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        CampaignHash::from_bytes(fingerprint.bytes),
        None,
        String::from("qemu.replay-divergence"),
        None,
        BTreeSet::new(),
    )
    .expect("stable finding signature");
    let seed = crucible::Seed::from_u64(0x7777);
    let mut probe = CrucibleFindingReplayTranscript::new();
    let first = minimize_signature_preserving_finding(
        &finding,
        &signature,
        seed,
        FindingReplayPass::Minimization,
        &mut probe,
        |candidate| Ok(replay_evidence(candidate, signature.clone())),
    )
    .expect("first replay pass");
    let (_, original_configuration, original) =
        prepare_original_reproduction(&finding).expect("prepare original reproduction");
    let observation_content =
        ContentId::for_bytes(ObjectKind::Observation, 1, b"two-pass-finding-observation");
    let observation = ObservationId::parse(&format!(
        "crucible.campaign.observation@{observation_content}"
    ))
    .expect("observation ID");
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "two-pass-finding-no-partial-write",
            u64::MAX,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let store = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
    let mut calls = 0;

    let error = store
        .publish_signature_preserving_minimized_finding_candidate(
            signature.clone(),
            observation,
            &finding,
            FindingExactPins::default(),
            seed,
            |candidate| {
                if calls == first.attempts.len() + 1 {
                    return Err(crucible::ReproductionArtifact::from_compact_binary(
                        b"invalid replay artifact",
                    )
                    .expect_err("invalid replay artifact"));
                }
                calls += 1;
                Ok(replay_evidence(candidate, signature.clone()))
            },
        )
        .expect_err("second replay pass must fail");

    assert!(matches!(
        error,
        CrucibleArtifactError::InvalidPayload {
            artifact: "signature-preserving finding minimization",
            ..
        }
    ));
    assert_eq!(calls, first.attempts.len() + 1);
    assert!(
        repository
            .load_configuration_artifact(
                original_configuration
                    .id()
                    .expect("original configuration ID"),
            )
            .is_err()
    );
    assert!(
        repository
            .load_reproduction_artifact(original.id().expect("original reproduction ID"))
            .is_err()
    );
}
