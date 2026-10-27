//! Authenticated replay of campaign-retained finding reproductions.

use super::*;

use serde::Serialize;

const CAMPAIGN_REPLAY_REPORT_SCHEMA: &str = "crucible.cli.campaign-replay.v2";

#[derive(Serialize)]
pub(super) struct CampaignReplayReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    snapshot: String,
    finding: String,
    reproduction: String,
    minimized: bool,
    artifact: String,
    scenario: String,
    configuration: String,
    replayed_state: String,
    authenticated: bool,
}

pub(super) fn validate_campaign_replay_command(command: &CampaignCommand) -> Result<(), CliError> {
    let CampaignCommand::Replay(args) = command else {
        return Err(backend_error(
            "non-replay campaign command reached replay validation",
        ));
    };
    campaign_name(&args.name)?;
    crucible_campaign::CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid campaign replay snapshot: {error}")))?;
    crucible_campaign::FindingId::parse(&args.finding)
        .map_err(|error| usage_error(format!("invalid campaign replay finding: {error}")))?;
    Ok(())
}

pub(super) fn query_campaign_replay<S>(
    client: &crucible_campaign::CampaignClient<S>,
    principal: crucible_campaign::CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignReplayReport, CliError>
where
    S: crucible_campaign::CampaignService,
    S::Error: crucible_campaign::CampaignServiceFailureSource,
{
    let CampaignCommand::Replay(args) = command else {
        return Err(backend_error(
            "non-replay campaign command reached replay execution",
        ));
    };
    let campaign = campaign_name(&args.name)?;
    let snapshot = crucible_campaign::CampaignSnapshotId::parse(&args.snapshot)
        .map_err(|error| usage_error(format!("invalid campaign replay snapshot: {error}")))?;
    let finding = crucible_campaign::FindingId::parse(&args.finding)
        .map_err(|error| usage_error(format!("invalid campaign replay finding: {error}")))?;
    let kind = if args.minimized {
        crucible_campaign::CampaignFindingObjectKind::MinimizedReproduction
    } else {
        crucible_campaign::CampaignFindingObjectKind::Reproduction
    };
    let request = crucible_campaign::GetCampaignFindingObjectRequest::new(
        principal.clone(),
        campaign.clone(),
        snapshot,
        finding,
        kind,
    )
    .map_err(|error| usage_error(format!("invalid campaign replay query: {error}")))?;
    let response = client
        .get_campaign_finding_object(&request)
        .map_err(|error| backend_error(format!("campaign replay query failed: {error}")))?;
    let reproduction = match (args.minimized, response.object()) {
        (false, crucible_campaign::CampaignFindingObject::Reproduction(value))
        | (true, crucible_campaign::CampaignFindingObject::MinimizedReproduction(value)) => value,
        _ => {
            return Err(backend_error(
                "campaign replay response carried another finding dependency kind",
            ));
        }
    };

    let scope = crate::cli_triage_debug::campaign_evidence::CampaignFindingCaptureScope {
        principal,
        campaign: campaign.clone(),
        snapshot,
        finding,
    };
    let artifact = crate::cli_triage_debug::campaign_evidence::fetch_campaign_reproduction(
        client,
        &scope,
        args.minimized,
        reproduction,
    )?;
    replay_finding_object(
        &campaign,
        snapshot,
        finding,
        args.minimized,
        reproduction,
        &artifact,
    )
}

/// Replays one authenticated reproduction and constructs its CLI report.
///
/// `artifact` is the Crucible artifact decoded from the reproduction's
/// authenticated payload segments.
///
/// # Errors
///
/// Returns an error when the stored payload or replayed semantic binding is invalid.
pub(super) fn replay_finding_object(
    campaign: &crucible_campaign::CampaignName,
    snapshot: crucible_campaign::CampaignSnapshotId,
    finding: crucible_campaign::FindingId,
    minimized: bool,
    reproduction: &crucible_campaign::ReproductionArtifact,
    artifact: &crucible_engine::ReproductionArtifact,
) -> Result<CampaignReplayReport, CliError> {
    let replayed = authenticate_and_replay(reproduction, artifact)?;
    let reproduction_id = reproduction.id().map_err(|error| {
        backend_error(format!(
            "campaign reproduction identity is invalid after replay: {error}"
        ))
    })?;

    Ok(CampaignReplayReport {
        schema: CAMPAIGN_REPLAY_REPORT_SCHEMA,
        operation: "replay-finding",
        campaign: campaign.as_str().to_owned(),
        snapshot: snapshot.to_string(),
        finding: finding.to_string(),
        reproduction: reproduction_id.to_string(),
        minimized,
        artifact: replayed.artifact,
        scenario: replayed.scenario,
        configuration: replayed.configuration,
        replayed_state: replayed.replayed_state,
        authenticated: true,
    })
}

struct AuthenticatedCampaignReplay {
    artifact: String,
    scenario: String,
    configuration: String,
    replayed_state: String,
}

/// Replays `artifact` and checks it against the campaign record's bindings.
///
/// The artifact must re-derive the record's exact payload, so it is the one
/// the record names and not merely a semantically equal reproduction.
fn authenticate_and_replay(
    reproduction: &crucible_campaign::ReproductionArtifact,
    artifact: &crucible_engine::ReproductionArtifact,
) -> Result<AuthenticatedCampaignReplay, CliError> {
    if reproduction.payload_schema() != crucible_daemon::CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V5 {
        return Err(backend_error(
            "campaign reproduction payload uses an unsupported schema",
        ));
    }
    let replay = artifact
        .replay()
        .map_err(|error| backend_error(format!("campaign reproduction replay failed: {error}")))?;
    let scenario = artifact.scenario_form().id().to_hex();
    let configuration = reproduction.configuration().to_hex();
    let reproduced_configuration = crucible_engine::Configuration {
        def: artifact.scenario_def(),
        schedule: artifact.schedule().clone(),
    }
    .id()
    .to_hex();
    let payload_matches = crucible_daemon::crucible_reproduction_payload(artifact)
        .is_ok_and(|payload| &payload == reproduction.reproduction_payload());
    if scenario != reproduction.scenario().to_hex()
        || reproduced_configuration != configuration
        || !payload_matches
    {
        return Err(backend_error(
            "campaign reproduction payload disagrees with its authenticated semantic binding",
        ));
    }

    Ok(AuthenticatedCampaignReplay {
        artifact: artifact.id().to_hex(),
        scenario,
        configuration,
        replayed_state: replay.state.to_hex(),
    })
}

pub(super) fn render_campaign_replay(
    report: &CampaignReplayReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign replay encoding failed: {error}"))),
        OutputFormat::Table => Ok(format!(
            "campaign={} snapshot={} finding={} reproduction={} minimized={} artifact={} scenario={} configuration={} replayed-state={} authenticated={}",
            report.campaign,
            report.snapshot,
            report.finding,
            report.reproduction,
            report.minimized,
            report.artifact,
            report.scenario,
            report.configuration,
            report.replayed_state,
            report.authenticated,
        )),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| campaign | `{}` |\n| snapshot | `{}` |\n| finding | `{}` |\n| reproduction | `{}` |\n| minimized | {} |\n| artifact | `{}` |\n| scenario | `{}` |\n| configuration | `{}` |\n| replayed state | `{}` |\n| authenticated | {} |",
            report.campaign,
            report.snapshot,
            report.finding,
            report.reproduction,
            report.minimized,
            report.artifact,
            report.scenario,
            report.configuration,
            report.replayed_state,
            report.authenticated,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campaign_replay_authenticates_the_wrapper_semantic_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let scenario_fixture = crucible_engine::happy_path_scenario()?;
        let scenario = crucible_engine::ScenarioDefForm::from_components(
            scenario_fixture.scenario.world(),
            &crucible_engine::Plan::empty(),
            &crucible_engine::Properties::empty(),
            scenario_fixture.scenario.seed(),
        )?;
        let artifact = crucible_engine::ReproductionArtifact::capture(
            &scenario,
            &crucible_engine::Schedule::empty(),
        )?;
        let replay = artifact.replay()?;
        let payload = crucible_daemon::crucible_reproduction_payload(&artifact)?;
        let scenario_id = crucible_campaign::ScenarioDefId::parse(&scenario.id().to_hex())?;
        let configuration = crucible_engine::Configuration {
            def: artifact.scenario_def(),
            schedule: artifact.schedule().clone(),
        };
        let configuration_id =
            crucible_campaign::ConfigurationId::parse(&configuration.id().to_hex())?;
        let reproduction = crucible_campaign::ReproductionArtifact::new(
            crucible_campaign::ReproductionArtifactBasis::new(
                scenario_id,
                crucible_campaign::ScenarioArtifactId::parse(&format!(
                    "crucible.campaign.scenario-artifact@{}",
                    crucible_daemon::campaign_store_composition::ContentId::for_bytes(
                        crucible_daemon::campaign_store_composition::ObjectKind::Scenario,
                        1,
                        b"campaign replay scenario artifact",
                    )
                ))?,
                configuration_id,
                crucible_campaign::ConfigurationArtifactId::parse(&format!(
                    "crucible.campaign.configuration-artifact@{}",
                    crucible_daemon::campaign_store_composition::ContentId::for_bytes(
                        crucible_daemon::campaign_store_composition::ObjectKind::Configuration,
                        1,
                        b"campaign replay configuration artifact",
                    )
                ))?,
                crucible_campaign::CampaignHash::derive(
                    "crucible.cli.campaign-replay-test.finding",
                    b"campaign replay finding",
                ),
            ),
            payload.clone(),
        )?;

        let authenticated = authenticate_and_replay(&reproduction, &artifact)?;
        assert_eq!(authenticated.artifact, artifact.id().to_hex());
        assert_eq!(authenticated.configuration, configuration.id().to_hex());
        assert_eq!(authenticated.replayed_state, replay.state.to_hex());

        let mismatched = crucible_campaign::ReproductionArtifact::new(
            crucible_campaign::ReproductionArtifactBasis::new(
                scenario_id,
                reproduction.scenario_artifact(),
                crucible_campaign::ConfigurationId::from_hash(
                    crucible_campaign::CampaignHash::derive(
                        "crucible.cli.campaign-replay-test.configuration",
                        b"another configuration",
                    ),
                ),
                reproduction.configuration_artifact(),
                reproduction.finding_fingerprint(),
            ),
            payload.clone(),
        )?;
        let error = authenticate_and_replay(&mismatched, &artifact)
            .err()
            .ok_or("mismatched campaign replay unexpectedly authenticated")?;
        assert!(error.to_string().contains("semantic binding"));

        let mismatched_scenario = crucible_campaign::ReproductionArtifact::new(
            crucible_campaign::ReproductionArtifactBasis::new(
                crucible_campaign::ScenarioDefId::from_hash(
                    crucible_campaign::CampaignHash::derive(
                        "crucible.cli.campaign-replay-test.scenario",
                        b"another scenario",
                    ),
                ),
                reproduction.scenario_artifact(),
                configuration_id,
                reproduction.configuration_artifact(),
                reproduction.finding_fingerprint(),
            ),
            payload.clone(),
        )?;
        let error = authenticate_and_replay(&mismatched_scenario, &artifact)
            .err()
            .ok_or("scenario-mismatched campaign replay unexpectedly authenticated")?;
        assert!(error.to_string().contains("semantic binding"));

        let wrong_schema = crucible_campaign::ReproductionArtifact::new(
            crucible_campaign::ReproductionArtifactBasis::new(
                scenario_id,
                reproduction.scenario_artifact(),
                configuration_id,
                reproduction.configuration_artifact(),
                reproduction.finding_fingerprint(),
            ),
            crucible_campaign::ReproductionPayload::new(
                crucible_daemon::CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V5 + 1,
                payload.bytes().to_vec(),
                payload.segments().to_vec(),
            )?,
        )?;
        let error = authenticate_and_replay(&wrong_schema, &artifact)
            .err()
            .ok_or("wrong-schema campaign replay unexpectedly authenticated")?;
        assert!(error.to_string().contains("unsupported schema"));
        Ok(())
    }
}
