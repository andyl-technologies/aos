//! Finding replay and minimization preparation tests.

use super::*;

#[test]
fn verifier_backed_store_replays_finding_before_reproduction_publication() {
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule: Schedule::empty(),
    };
    let finding = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        ContentHash::from_bytes(b"stable-failure-fingerprint"),
        &scenario,
        &configuration,
    )
    .expect("capture finding reproduction");
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "crucible-reproduction-import",
            u64::MAX,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let store = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));

    let id = store
        .import_reproduction(&finding)
        .expect("import verified reproduction");
    let stored = repository
        .load_reproduction_artifact(id)
        .expect("load stored reproduction");
    assert_eq!(
        stored.finding_fingerprint(),
        CampaignHash::from_bytes(finding.finding_fingerprint.bytes)
    );
    assert_eq!(
        crucible::ReproductionArtifact::from_compact_binary(stored.payload())
            .expect("decode stored reproduction")
            .replay()
            .expect("replay stored reproduction"),
        finding.replay
    );

    let run = finding
        .minimize(
            MinimizationConfig::new(crucible::Seed::from_u64(0x5151)),
            |_| Ok(Some(finding.finding_fingerprint)),
        )
        .expect("verify deterministic minimization");
    let mislabeled = repository
        .publish_reproduction_artifact(
            stored.scenario(),
            stored.scenario_artifact(),
            stored.configuration(),
            stored.configuration_artifact(),
            stored.finding_fingerprint(),
            CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3 + 1,
            stored.payload().to_vec(),
        )
        .expect("publish structurally valid mislabeled reproduction");
    assert!(matches!(
        store.import_minimized_reproduction(mislabeled, &run, |_| {
            Ok(Some(finding.finding_fingerprint))
        }),
        Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "minimization original"
        })
    ));
    let minimized = store
        .import_minimized_reproduction(id, &run, |_| Ok(Some(finding.finding_fingerprint)))
        .expect("import minimized reproduction");
    let minimized = repository
        .load_reproduction_artifact(minimized)
        .expect("load minimized reproduction");
    assert_eq!(minimized.schema_version(), 2);
    let minimization = minimized
        .minimization()
        .expect("retained minimization evidence");
    assert_eq!(minimization.original(), id);
    assert_eq!(
        minimization.policy_schema(),
        CRUCIBLE_MINIMIZATION_POLICY_SCHEMA_V2
    );
    assert!(
        minimization
            .policy()
            .starts_with(CRUCIBLE_MINIMIZATION_POLICY_MAGIC_V2)
    );
}

#[test]
fn finding_candidate_preparation_deduplicates_bounded_replay_records_without_writes() {
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
    let fingerprint = ContentHash::from_bytes(b"prepared-finding-fingerprint");
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
    let seed = crucible::Seed::from_u64(0x5eed);
    let mut transcript = CrucibleFindingReplayTranscript::new();
    let first = minimize_signature_preserving_finding(
        &finding,
        &signature,
        seed,
        FindingReplayPass::Minimization,
        &mut transcript,
        |candidate| Ok(replay_evidence(candidate, signature.clone())),
    )
    .expect("first replay pass");
    let second = minimize_signature_preserving_finding(
        &finding,
        &signature,
        seed,
        FindingReplayPass::Verification,
        &mut transcript,
        |candidate| Ok(replay_evidence(candidate, signature.clone())),
    )
    .expect("second replay pass");
    assert_eq!(first, second);
    assert!(first.shrank());
    assert_eq!(transcript.minimization_pass.len(), first.attempts.len() + 1);
    assert_eq!(transcript.verification_pass.len(), first.attempts.len() + 1);

    let observation_content =
        ContentId::for_bytes(ObjectKind::Observation, 1, b"prepared-finding-observation");
    let observation = ObservationId::parse(&format!(
        "crucible.campaign.observation@{observation_content}"
    ))
    .expect("observation ID");
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "prepared-finding-no-write",
            u64::MAX,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    let mut truncated = transcript.clone();
    truncated.verification_pass.pop();
    assert!(matches!(
        prepare_signature_preserving_minimized_finding_candidate(
            signature.clone(),
            observation,
            &finding,
            FindingExactPins::default(),
            seed,
            truncated,
        ),
        Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "finding minimization replay observation count"
        })
    ));

    let prepared = prepare_signature_preserving_minimized_finding_candidate(
        signature,
        observation,
        &finding,
        FindingExactPins::default(),
        seed,
        transcript,
    )
    .expect("prepare finding candidate");
    assert_eq!(prepared.replay_record_count(), 5);
    assert!(prepared.replay_record_bytes() > 0);
    assert!(
        repository
            .load_scenario_artifact(prepared.scenario().id().expect("scenario ID"))
            .is_err()
    );
    assert!(
        repository
            .load_reproduction_artifact(prepared.original().id().expect("original ID"))
            .is_err()
    );
}

#[test]
fn finding_replay_retains_nonempty_configuration_target_and_causal_evidence() {
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
    let fingerprint = ContentHash::from_bytes(b"owned-replay-evidence-fingerprint");
    let finding = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::StateSpaceSearch,
        fingerprint,
        &scenario,
        &configuration,
    )
    .expect("capture finding reproduction");
    let scenario_record = encode_crucible_scenario_artifact(&scenario).expect("scenario record");
    let original_configuration =
        encode_crucible_configuration_artifact(&scenario_record, finding.artifact.schedule())
            .expect("original configuration");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("empty properties");
    let property_id = properties.id().expect("property ID");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        CampaignHash::from_bytes(fingerprint.bytes),
        None,
        String::from("qemu.replay-divergence"),
        Some(FindingTarget::Configuration(
            original_configuration.id().expect("configuration ID"),
        )),
        BTreeSet::from([property_id.content_id()]),
    )
    .expect("targeted finding signature");
    let seed = crucible::Seed::from_u64(0xe71d);
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
                let scenario =
                    encode_crucible_scenario_artifact(candidate.artifact.scenario_form())
                        .expect("candidate scenario");
                let candidate_configuration = encode_crucible_configuration_artifact(
                    &scenario,
                    candidate.artifact.schedule(),
                )
                .expect("candidate configuration");
                let candidate_signature = FindingSignature::new(
                    FindingKind::Divergence,
                    CampaignHash::from_bytes(fingerprint.bytes),
                    None,
                    String::from("qemu.replay-divergence"),
                    Some(FindingTarget::Configuration(
                        candidate_configuration
                            .id()
                            .expect("candidate configuration ID"),
                    )),
                    BTreeSet::from([property_id.content_id()]),
                )
                .expect("candidate signature");
                Ok(CrucibleFindingReplayEvidence::new(
                    Some(candidate_signature),
                    candidate_configuration,
                    MeasurementSet::new(BTreeMap::new()).expect("measurements"),
                    properties.clone(),
                    CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage"),
                    Vec::new(),
                    Vec::new(),
                )
                .expect("candidate replay evidence"))
            },
        )
        .expect("targeted replay pass");
    }
    let observation_content =
        ContentId::for_bytes(ObjectKind::Observation, 1, b"targeted-finding-observation");
    let observation = ObservationId::parse(&format!(
        "crucible.campaign.observation@{observation_content}"
    ))
    .expect("observation ID");
    let prepared = prepare_signature_preserving_minimized_finding_candidate(
        signature.clone(),
        observation,
        &finding,
        FindingExactPins::default(),
        seed,
        transcript,
    )
    .expect("prepare targeted finding");
    let retained = prepared
        .bundle()
        .signature_minimization()
        .minimization_pass();
    assert!(
        retained.iter().flatten().all(|observed| {
            observed.target().is_some() && !observed.causal_evidence().is_empty()
        })
    );
    assert!(prepared.replay_records.configurations.iter().any(|record| {
        record.id().ok() == Some(original_configuration.id().expect("configuration ID"))
    }));
    assert!(
        prepared
            .replay_records
            .properties
            .iter()
            .any(|record| record.id().ok() == Some(property_id))
    );
}
