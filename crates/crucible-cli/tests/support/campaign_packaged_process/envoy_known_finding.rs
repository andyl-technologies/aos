//! A measured five-guest network failure through the packaged campaign owner.
//!
//! Router A's unsafe recovery strategy returns a response without contacting
//! traffic-east. The traffic guest reports that product failure; the campaign
//! must retain the same observation, measurement evidence, and replayable finding.

use std::io::Write as _;
use std::os::unix::net::UnixStream;

use super::*;
use crucible_campaign::{
    CampaignExecutorStore, CampaignLineage, CampaignRepository, FindingId, ObjectiveEvaluation,
    ObservationId, PropertyVerdict, RankingCandidate, RankingDisposition, RankingMethod,
    StopOutcome, SurvivorRule, rank_survivors,
};
use crucible_core::NetworkFaultSelectable;
use crucible_core::model::{
    MeasurementAggregateValue, MeasurementEvaluation, MeasurementId, MeasurementWindowOutcome,
    MetricId,
};
use crucible_daemon::{
    CrucibleMeasurementReplayEvidence, evaluate_crucible_objectives,
    verify_crucible_measurement_publication,
};

const UNSAFE_SHORT_CIRCUIT: [u8; 32] = [0xff; 32];
const FAILURE_PROPERTY: &str = "forbidden-destination-delivery";

#[test]
#[ignore = "requires packaged QEMU and a dedicated five-guest cgroup and project quota"]
fn public_five_node_envoy_network_retains_known_failure() -> Result<(), Box<dyn Error>> {
    let fixture = FlightFixture::new()?;
    grant_finding_export(&fixture)?;
    let envoy_network::EnvoyCampaignFlight {
        generated,
        lineage,
        policy,
        authority: _,
        mut service,
    } = envoy_network::start_envoy_campaign(&fixture, false)?;
    let scenario =
        ScenarioDefForm::from_compact_binary(&fs::read(fixture.fixture.join("scenario.bin"))?)?;
    let fault = envoy_network::group_argument(NetworkFaultSelectable::selected_value(
        "link_down",
        "primary",
        30_000_000,
        0,
        0,
    )?);
    let safe = envoy_network::recovery_argument(&scenario, [0x22; 32])?;
    let followup_fault = envoy_network::group_argument(NetworkFaultSelectable::selected_value(
        "packet_loss",
        "backup",
        10_000_000,
        1_000,
        0,
    )?);
    let unsafe_recovery = envoy_network::recovery_argument(&scenario, UNSAFE_SHORT_CIRCUIT)?;

    let discovery = envoy_network::wait_for_public_attempt(
        &fixture,
        &mut service,
        envoy_network::initial_discovery_attempt(&lineage, &policy)?,
        Duration::from_secs(900),
    )?;
    assert_eq!(
        discovery["attempt"]["configuration"],
        generated["configuration"]
    );
    assert_eq!(discovery["observation"]["stop"], "reached:next-choice");
    envoy_network::require_semantic_marker(&discovery, "network.converged", "traffic-west")?;
    let mut progress = envoy_network::FlightProgress {
        parent: json_string(&discovery["observation"], "child_artifact")?,
        configuration: json_string(&discovery["observation"], "child")?,
    };

    let disruption = envoy_network::choose(
        &fixture,
        &mut service,
        &mut progress,
        "fault.network",
        &fault,
        "next-choice",
        0x73,
    )?;
    let recovery = envoy_network::choose(
        &fixture,
        &mut service,
        &mut progress,
        "recovery.response",
        &safe,
        "next-choice",
        0x74,
    )?;
    envoy_network::require_network_effect(
        &[&disruption, &recovery],
        "availability",
        &["segment-router-a-router-b", "segment-router-b-router-c"],
        Some("down"),
    )?;
    envoy_network::require_semantic_marker(&recovery, "network.failover.observed", "traffic-west")?;
    envoy_network::require_semantic_marker(&recovery, "recovery.measured", "traffic-west")?;
    envoy_network::require_measured_backup_route(&recovery)?;
    let measured_observation = json_string(&recovery["observation"], "id")?;

    let followup = envoy_network::choose(
        &fixture,
        &mut service,
        &mut progress,
        "fault.network",
        &followup_fault,
        "next-choice",
        0x75,
    )?;
    envoy_network::require_network_effect(
        &[&followup],
        "frame-loss",
        &["segment-router-a-router-c"],
        None,
    )?;
    let choice = guest_choice::wait_for_choice(
        &fixture,
        "recovery.response",
        &progress.parent,
        &progress.configuration,
    )?;
    let submission = guest_choice::submit_choice(
        &fixture,
        &choice,
        &unsafe_recovery,
        "boundary:campaign.complete",
        0x76,
    )?;
    let request = guest_choice::accepted_branch_request(&submission)?;
    let failed = envoy_network::wait_for_request_attempt(
        &fixture,
        &mut service,
        &request,
        &unsafe_recovery,
        Duration::from_secs(900),
    )?;
    assert_eq!(
        failed["observation"]["stop"],
        format!("assertion-failure:{FAILURE_PROPERTY}")
    );
    let failed_observation = json_string(&failed["observation"], "id")?;
    assert_ne!(failed_observation, measured_observation);

    let measured_objective = verify_measured_objective(
        &fixture,
        &scenario,
        &lineage,
        &policy,
        &measured_observation,
    )?;
    let failed_objective =
        verify_failed_observation(&fixture, &scenario, &lineage, &policy, &failed_observation)?;
    let policy_record = CampaignPolicy::from_canonical_bytes(&fs::read(&policy)?)?;
    let safe_configuration = measured_objective.configuration();
    let unsafe_configuration = failed_objective.configuration();
    let ranking = rank_survivors(
        &policy_record,
        SurvivorRule::new(RankingMethod::WeightedTopK, 1, 0, 0)?,
        vec![
            RankingCandidate::new(measured_objective, 0, 0),
            RankingCandidate::new(failed_objective, 0, 1),
        ],
    )?;
    if !ranking.selection().selected().contains(&safe_configuration)
        || !matches!(
            ranking.explanations()[&unsafe_configuration].disposition(),
            RankingDisposition::Filtered(_)
        )
    {
        return Err("objective ranking did not filter unsafe endpoint bypass".into());
    }
    let (snapshot, finding) = wait_for_finding(&fixture, &mut service, &failed_observation)?;
    verify_packaged_replay(&fixture, &snapshot, &finding)?;
    service.stop()?;

    println!("envoy_known_finding_authenticated=true");
    Ok(())
}

fn grant_finding_export(fixture: &FlightFixture) -> Result<(), Box<dyn Error>> {
    let mut policy = fs::OpenOptions::new()
        .append(true)
        .open(&fixture.peer_policy)?;
    for operation in [
        "query-campaign-findings",
        "get-campaign-finding-object",
        "query-campaign-finding-occurrences",
        "get-campaign-finding-occurrence-object",
        "get-campaign-finding-triage-replay-segment",
    ] {
        writeln!(
            policy,
            "\n[[grants]]\nprincipal = {PRINCIPAL:?}\noperation = {operation:?}\ncampaign = \"*\""
        )?;
    }
    Ok(())
}

fn repository(fixture: &FlightFixture) -> Arc<CampaignRepository> {
    Arc::new(CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "envoy-known-finding-evidence",
            &fixture.objects,
        )),
        Arc::new(crucible_cas::content_store::DirectoryRefBackend::new(
            fixture._temporary.path().join("refs"),
        )),
    ))
}

fn verified_observation(
    fixture: &FlightFixture,
    scenario: &ScenarioDefForm,
    lineage_path: &Path,
    observation: &str,
) -> Result<
    (
        crucible_campaign::Observation,
        crucible_campaign::MeasurementSet,
        MeasurementEvaluation,
    ),
    Box<dyn Error>,
> {
    let repository = repository(fixture);
    let observation = repository.load_observation(ObservationId::parse(observation)?)?;
    let measurements = repository.load_measurement_set(observation.measurements())?;
    let evidence_id = *measurements
        .evaluation()
        .evidence()
        .iter()
        .next()
        .ok_or("measured observation omitted its raw event log")?;
    let bytes = CampaignExecutorStore::new(Arc::clone(&repository))
        .read_measurement_evidence_leaf(
            observation.measurements(),
            evidence_id,
            64 * 1024 * 1024,
        )?;
    let evidence = CrucibleMeasurementReplayEvidence::from_canonical_bytes(&bytes)?;
    let lineage = CampaignLineage::from_canonical_bytes(&fs::read(lineage_path)?)?;
    let evaluation = verify_crucible_measurement_publication(
        &measurements,
        &evidence,
        lineage.scenario(),
        observation.child(),
        scenario.measurements(),
    )?;
    Ok((observation, measurements, evaluation))
}

fn verify_measured_objective(
    fixture: &FlightFixture,
    scenario: &ScenarioDefForm,
    lineage: &Path,
    policy: &Path,
    observation_id: &str,
) -> Result<ObjectiveEvaluation, Box<dyn Error>> {
    let repository = repository(fixture);
    let (observation, measurements, evaluation) =
        verified_observation(fixture, scenario, lineage, observation_id)?;
    let properties = repository.load_property_verdict_set(observation.properties())?;
    let policy = CampaignPolicy::from_canonical_bytes(&fs::read(policy)?)?;
    let objective = evaluate_crucible_objectives(
        &measurements,
        &evaluation,
        &policy,
        &observation,
        &properties,
    )?;
    objective.validate_basis(&policy, &observation, &properties)?;
    if !objective.is_admissible() || objective.components().len() != 3 {
        return Err(
            format!("measured recovery was not ranked by all objectives: {objective:?}").into(),
        );
    }

    for name in [
        "recovery_time_us",
        "traffic_loss_packets",
        "control_plane_cpu_us",
    ] {
        let outcome = evaluation
            .outcomes()
            .get(&MeasurementId::parse(name)?)
            .ok_or("declared measurement omitted from verified publication")?;
        if !matches!(outcome.window(), MeasurementWindowOutcome::Completed { .. }) {
            return Err(format!("{name} window did not complete: {outcome:?}").into());
        }
    }
    let traffic = &evaluation.outcomes()[&MeasurementId::parse("traffic_loss_packets")?];
    let drops = &traffic.metrics()[&MetricId::parse("modeled_drop_count")?];
    if drops.samples().is_empty()
        || !matches!(drops.aggregate(), MeasurementAggregateValue::Unsigned(_))
    {
        return Err("traffic objective lacks model-derived drop evidence".into());
    }
    println!("envoy_known_finding_measured_objective=true");
    Ok(objective)
}

fn verify_failed_observation(
    fixture: &FlightFixture,
    scenario: &ScenarioDefForm,
    lineage: &Path,
    policy: &Path,
    observation_id: &str,
) -> Result<ObjectiveEvaluation, Box<dyn Error>> {
    let repository = repository(fixture);
    let (observation, measurements, evaluation) =
        verified_observation(fixture, scenario, lineage, observation_id)?;
    if observation.stop() != &StopOutcome::AssertionFailure(FAILURE_PROPERTY.to_owned()) {
        return Err(format!("unsafe recovery stopped for another reason: {observation:?}").into());
    }
    let properties = repository.load_property_verdict_set(observation.properties())?;
    if properties
        .properties()
        .get(FAILURE_PROPERTY)
        .map(|evidence| evidence.verdict())
        != Some(PropertyVerdict::Failed)
    {
        return Err("unsafe recovery did not fail the guest's endpoint assertion".into());
    }
    let policy = CampaignPolicy::from_canonical_bytes(&fs::read(policy)?)?;
    let objective = evaluate_crucible_objectives(
        &measurements,
        &evaluation,
        &policy,
        &observation,
        &properties,
    )?;
    objective.validate_basis(&policy, &observation, &properties)?;
    if objective.is_admissible() {
        return Err("unsafe recovery was incorrectly admitted to objective ranking".into());
    }
    println!("envoy_known_finding_rank_filtered=true");
    Ok(objective)
}

fn wait_for_finding(
    fixture: &FlightFixture,
    service: &mut CampaignServiceChild,
    observation: &str,
) -> Result<(String, String), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(900);
    wait_for_process_observation(deadline, || {
        if let Some(status) = service.child.try_wait()? {
            return Err(format!("Envoy campaign service exited before finding: {status}").into());
        }
        let snapshot = json_string(&campaign_status(fixture)?, "snapshot")?;
        let findings = run_json(
            connected_campaign(fixture).args([
                "findings",
                CAMPAIGN,
                "--snapshot",
                &snapshot,
                "--limit",
                "16",
                "--pages",
                "16",
            ]),
            "query authenticated Envoy finding",
        )?;
        if findings["complete"] != true {
            return Err("Envoy finding query was incomplete".into());
        }
        let Some(entry) = findings["entries"]
            .as_array()
            .ok_or("Envoy finding query omitted entries")?
            .iter()
            .find(|entry| entry["observation"] == observation)
        else {
            return Ok(None);
        };
        let finding = json_string(entry, "finding")?;
        let request = crucible_campaign::GetCampaignFindingObjectRequest::new(
            CampaignPrincipal::new(PRINCIPAL)?,
            CampaignName::new(CAMPAIGN)?,
            crucible_campaign::CampaignSnapshotId::parse(&snapshot)?,
            FindingId::parse(&finding)?,
            crucible_campaign::CampaignFindingObjectKind::Reproduction,
        )?;
        use crucible_campaign::CampaignService as _;
        let response =
            crucible_daemon::LoopbackCampaignService::new(UnixStream::connect(&fixture.socket)?)?
                .get_campaign_finding_object(&request)?;
        response.validate_for(&request)?;
        if response.finding().signature().property() != Some(FAILURE_PROPERTY)
            || response.finding().signature().causal_evidence().is_empty()
        {
            return Err("retained Envoy finding lost its causal product failure".into());
        }
        Ok(Some((snapshot, finding)))
    })?
    .ok_or_else(|| "unsafe Envoy recovery produced no retained finding".into())
}

fn verify_packaged_replay(
    fixture: &FlightFixture,
    snapshot: &str,
    finding: &str,
) -> Result<(), Box<dyn Error>> {
    let bundle = fixture._temporary.path().join("envoy-known-finding-bundle");
    let exported = run_json(
        command(&[
            "--format",
            "jsonl",
            "campaign",
            "finding-bundle",
            "export",
            CAMPAIGN,
        ])
        .args(["--snapshot", snapshot, "--finding", finding])
        .arg("--source-state")
        .arg(&fixture.state)
        .arg("--source-policy")
        .arg(&fixture.peer_policy)
        .arg("--source-store")
        .arg(&fixture.store)
        .arg("--output")
        .arg(&bundle),
        "export measured Envoy failure",
    )?;
    assert_eq!(exported["native_signature_verified"], true);
    let binary = std::env::var_os("CRUCIBLE_EXACT_BUNDLE_BINARY")
        .ok_or("packaged finding verifier is unavailable")?;
    let deployment = required_path("CRUCIBLE_FLIGHT_DEPLOYMENT")?;
    let verified = run_json(
        Command::new(binary)
            .current_dir(fixture._temporary.path())
            .env_remove("CRUCIBLE_QEMU")
            .env_remove("CRUCIBLE_PLUGIN")
            .env_remove("CRUCIBLE_EXACT_BUNDLE_BINARY")
            .env_remove("CRUCIBLE_PROCESS_FLIGHT_BINARY")
            .env_remove("CRUCIBLE_FLIGHT_DEPLOYMENT")
            .env_remove("CRUCIBLE_FLIGHT_QEMU")
            .env_remove("CRUCIBLE_FLIGHT_PLUGIN")
            .env_remove("CRUCIBLE_DEBUG_GATEWAY")
            .env_remove("CRUCIBLE_KERNEL")
            .env_remove("CRUCIBLE_INITRD")
            .env_remove("CRUCIBLE_ROOT_IMAGE")
            .env_remove("CRUCIBLE_RUN_STATE_ROOT")
            .env_remove("CRUCIBLE_NATIVE_GUEST_ARCHITECTURE")
            .args(["--format", "jsonl", "--campaign-deployment"])
            .arg(deployment)
            .args(["campaign", "finding-bundle", "verify"])
            .arg(&bundle)
            .arg("--exact"),
        "fresh packaged Envoy finding replay",
    )?;
    assert_eq!(verified["native_signature_verified"], true);
    assert_eq!(verified["model_replay"]["authenticated"], true);
    assert_eq!(verified["exact_replay"]["reproduced"], true);
    if json_u64(&verified["exact_replay"], "completed_quanta")? == 0 {
        return Err("fresh Envoy finding replay executed no guest quantum".into());
    }
    println!("envoy_known_finding_fresh_packaged_replay=true");
    Ok(())
}
