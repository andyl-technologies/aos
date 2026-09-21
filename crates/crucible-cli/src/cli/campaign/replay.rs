//! Authenticated replay of campaign-retained finding reproductions.

use super::*;

use serde::Serialize;

const CAMPAIGN_REPLAY_REPORT_SCHEMA: &str = "crucible.cli.campaign-replay.v1";

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
    replayed_configuration: String,
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
        principal,
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

    let replayed = authenticate_and_replay(reproduction)?;
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
        minimized: args.minimized,
        artifact: replayed.artifact,
        scenario: replayed.scenario,
        configuration: replayed.configuration,
        replayed_configuration: replayed.replayed_configuration,
        authenticated: true,
    })
}

struct AuthenticatedCampaignReplay {
    artifact: String,
    scenario: String,
    configuration: String,
    replayed_configuration: String,
}

fn authenticate_and_replay(
    reproduction: &crucible_campaign::ReproductionArtifact,
) -> Result<AuthenticatedCampaignReplay, CliError> {
    if reproduction.payload_schema() != crucible_daemon::CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3 {
        return Err(backend_error(
            "campaign reproduction payload uses an unsupported schema",
        ));
    }
    let artifact = crucible::ReproductionArtifact::from_compact_binary(reproduction.payload())
        .map_err(|error| {
            backend_error(format!(
                "campaign reproduction payload is not a current replay artifact: {error}"
            ))
        })?;
    let replay = artifact
        .replay()
        .map_err(|error| backend_error(format!("campaign reproduction replay failed: {error}")))?;
    let scenario = artifact.scenario_form().id().to_hex();
    let configuration = reproduction.configuration().to_hex();
    let replayed_configuration = replay.state.to_hex();
    if scenario != reproduction.scenario().to_hex()
        || replayed_configuration != configuration
        || artifact.id().to_hex()
            != crucible::ContentHash::from_bytes(reproduction.payload()).to_hex()
    {
        return Err(backend_error(
            "campaign reproduction payload disagrees with its authenticated semantic binding",
        ));
    }

    Ok(AuthenticatedCampaignReplay {
        artifact: artifact.id().to_hex(),
        scenario,
        configuration,
        replayed_configuration,
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
            "campaign={} snapshot={} finding={} reproduction={} minimized={} artifact={} scenario={} configuration={} replayed-configuration={} authenticated={}",
            report.campaign,
            report.snapshot,
            report.finding,
            report.reproduction,
            report.minimized,
            report.artifact,
            report.scenario,
            report.configuration,
            report.replayed_configuration,
            report.authenticated,
        )),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| campaign | `{}` |\n| snapshot | `{}` |\n| finding | `{}` |\n| reproduction | `{}` |\n| minimized | {} |\n| artifact | `{}` |\n| scenario | `{}` |\n| configuration | `{}` |\n| replayed configuration | `{}` |\n| authenticated | {} |",
            report.campaign,
            report.snapshot,
            report.finding,
            report.reproduction,
            report.minimized,
            report.artifact,
            report.scenario,
            report.configuration,
            report.replayed_configuration,
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
        let scenario_fixture = crucible::happy_path_scenario()?;
        let scenario = crucible::ScenarioDefForm::from_components(
            scenario_fixture.scenario.world(),
            &crucible::Plan::empty(),
            &crucible::Properties::empty(),
            scenario_fixture.scenario.seed(),
        )?;
        let artifact =
            crucible::ReproductionArtifact::capture(&scenario, &crucible::Schedule::empty())?;
        let replay = artifact.replay()?;
        let scenario_id = crucible_campaign::ScenarioDefId::parse(&scenario.id().to_hex())?;
        let configuration_id = crucible_campaign::ConfigurationId::parse(&replay.state.to_hex())?;
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
            crucible_daemon::CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3,
            artifact.to_compact_binary(),
        )?;

        let authenticated = authenticate_and_replay(&reproduction)?;
        assert_eq!(authenticated.artifact, artifact.id().to_hex());
        assert_eq!(authenticated.configuration, replay.state.to_hex());

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
            crucible_daemon::CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3,
            artifact.to_compact_binary(),
        )?;
        let error = authenticate_and_replay(&mismatched)
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
            crucible_daemon::CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3,
            artifact.to_compact_binary(),
        )?;
        let error = authenticate_and_replay(&mismatched_scenario)
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
            crucible_daemon::CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3 + 1,
            artifact.to_compact_binary(),
        )?;
        let error = authenticate_and_replay(&wrong_schema)
            .err()
            .ok_or("wrong-schema campaign replay unexpectedly authenticated")?;
        assert!(error.to_string().contains("unsupported schema"));
        Ok(())
    }
}
