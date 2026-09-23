//! Authenticated packaged-QEMU campaign timeout and retained causal marker.

use std::io::Write as _;
use std::os::unix::net::UnixStream;

use super::*;
use crucible_campaign::{ObservationId, PolicyTimeoutKind, StopOutcome};
use crucible_core::{FailureClusterReportFailure, FailureTimeoutBudgetKind};

const POLICY_DEADLINE_NS: u64 = 2_000_000;
const TIMEOUT_FAILURE_CLASS: &str = "qemu.virtual-time-timeout";

pub(super) fn grant_finding_queries(fixture: &FlightFixture) -> Result<(), Box<dyn Error>> {
    let mut policy = fs::OpenOptions::new()
        .append(true)
        .open(&fixture.peer_policy)?;
    for operation in ["query-campaign-findings", "get-campaign-finding-object"] {
        writeln!(
            policy,
            "\n[[grants]]\nprincipal = {PRINCIPAL:?}\noperation = {operation:?}\ncampaign = \"*\""
        )?;
    }
    Ok(())
}

pub(super) fn validate(fixture: &FlightFixture, explanation: &Value) -> Result<(), Box<dyn Error>> {
    let observation_id = json_string(&explanation["observation"], "id")?;
    let label = json_string(&explanation["observation"], "stop")?;
    if !label.starts_with("policy-timeout:VirtualTime:next-choice:frontier-ns=2000000:quanta=") {
        return Err(format!("packaged timeout returned a different stop: {label}").into());
    }

    let repository = crucible_campaign::CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "packaged-policy-timeout-proof",
            &fixture.objects,
        )),
        Arc::new(crucible_cas::content_store::DirectoryRefBackend::new(
            fixture._temporary.path().join("refs"),
        )),
    );
    let observation = repository.load_observation(ObservationId::parse(&observation_id)?)?;
    let StopOutcome::PolicyTimeout { stop, kind, proof } = observation.stop() else {
        return Err("packaged timeout did not publish a typed policy outcome".into());
    };
    if *kind != PolicyTimeoutKind::VirtualTime
        || proof.frontier_nanoseconds() != POLICY_DEADLINE_NS
        || proof.completed_quanta() == 0
        || !matches!(stop.primary(), crucible_campaign::StopCondition::NextChoice)
    {
        return Err(format!("packaged timeout carried the wrong proof: {observation:?}").into());
    }
    println!("packaged_policy_timeout_observation_authenticated=true");

    let finding = wait_for_timeout_finding(fixture, &observation_id)?;
    let signature = finding.finding().signature();
    if signature.failure_class() != TIMEOUT_FAILURE_CLASS
        || signature.property().is_some()
        || signature.causal_evidence().is_empty()
    {
        return Err(format!("packaged timeout finding has wrong signature: {signature:?}").into());
    }
    let bundle_id = finding
        .finding()
        .latest_candidate_bundle()
        .ok_or("packaged timeout finding has no retained candidate bundle")?;
    let bundle = repository.load_finding_candidate_bundle(bundle_id)?;
    if bundle.signature() != signature {
        return Err("packaged timeout bundle changed the finding signature".into());
    }
    let replay_id = bundle
        .triage_evidence()
        .ok_or("packaged timeout finding has no triage evidence")?
        .verification_original();
    let replay_record = repository.load_finding_triage_replay_evidence(replay_id)?;
    let reproduction = repository.load_reproduction_artifact(replay_record.reproduction())?;
    let artifact =
        crucible_core::ReproductionArtifact::from_compact_binary(reproduction.payload())?;
    let configuration = crucible_core::Configuration {
        def: artifact.scenario_def(),
        schedule: artifact.schedule().clone(),
    }
    .id();
    let native_finding = crucible_core::FindingReproductionArtifact {
        discovery_path: crucible_core::FindingDiscoveryPath::StateSpaceSearch,
        finding_fingerprint: crucible_core::ContentHash {
            bytes: reproduction.finding_fingerprint().as_bytes(),
        },
        configuration,
        replay: artifact.replay()?,
        artifact,
    };
    let native_replay = crucible_core::FailureTriageReplayEvidence::from_compact_binary(
        native_finding,
        replay_record.payload(),
    )?;
    let FailureClusterReportFailure::Timeout(timeout) = native_replay.failure() else {
        return Err("packaged policy timeout replay retained a different failure".into());
    };
    if timeout.budget_kind != FailureTimeoutBudgetKind::VirtualTime
        || timeout.configured_limit != Some(POLICY_DEADLINE_NS)
        || timeout.at_virtual_time.ticks != POLICY_DEADLINE_NS
        || timeout.event_kind != "execution_budget_exhausted"
        || !native_replay.causal_entries().iter().any(|entry| {
            entry.event_payload().kind() == "execution_budget_exhausted"
                && entry.event_payload().string("budget_kind") == Some("virtual-time")
                && entry.at().ticks == POLICY_DEADLINE_NS
        })
    {
        return Err(
            format!("packaged policy timeout replay lost its marker: {native_replay:?}").into(),
        );
    }
    println!("packaged_policy_timeout_marker_authenticated=true");
    Ok(())
}

fn wait_for_timeout_finding(
    fixture: &FlightFixture,
    observation: &str,
) -> Result<crucible_campaign::GetCampaignFindingObjectResponse, Box<dyn Error>> {
    use crucible_campaign::CampaignService as _;

    let deadline = Instant::now() + Duration::from_secs(120);
    let mut last_findings = None;
    let found = wait_for_process_observation(deadline, || {
        let snapshot = json_string(&campaign_status(fixture)?, "snapshot")?;
        let findings = run_json(
            connected_campaign(fixture).args([
                "findings",
                CAMPAIGN,
                "--snapshot",
                &snapshot,
                "--limit",
                "4",
                "--pages",
                "16",
            ]),
            "query packaged timeout finding",
        )?;
        last_findings = Some(findings.clone());
        if findings["complete"] != true {
            return Err(
                format!("packaged timeout findings query was incomplete: {findings}").into(),
            );
        }
        let entries = findings["entries"]
            .as_array()
            .ok_or("packaged timeout findings entries are not an array")?;
        let Some(entry) = entries
            .iter()
            .find(|entry| entry["observation"] == observation)
        else {
            return Ok(None);
        };
        let finding_id = json_string(entry, "finding")?;
        let request = crucible_campaign::GetCampaignFindingObjectRequest::new(
            crucible_campaign::CampaignPrincipal::new(PRINCIPAL)?,
            crucible_campaign::CampaignName::new(CAMPAIGN)?,
            crucible_campaign::CampaignSnapshotId::parse(&snapshot)?,
            crucible_campaign::FindingId::parse(&finding_id)?,
            crucible_campaign::CampaignFindingObjectKind::Reproduction,
        )?;
        let stream = UnixStream::connect(&fixture.socket)?;
        let service = crucible_daemon::LoopbackCampaignService::new(stream)?;
        let response = service.get_campaign_finding_object(&request)?;
        response.validate_for(&request)?;
        Ok(response
            .finding()
            .latest_candidate_bundle()
            .map(|_| response))
    })?;
    found.ok_or_else(|| {
        format!(
            "packaged policy timeout produced no retained finding for {observation}: {last_findings:?}"
        )
        .into()
    })
}
