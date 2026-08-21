//! Thin local client for authenticated lazy-campaign inspection.

use super::*;

use std::os::unix::net::UnixStream;

use crucible_campaign::{
    CampaignClient, CampaignName, CampaignPrincipal, CampaignService, CampaignServiceFailureSource,
    CampaignSnapshotId, CampaignState, GetCampaignRequest, WatchCampaignRequest,
};
use crucible_daemon::LoopbackCampaignService;
use serde::Serialize;

const CAMPAIGN_HEAD_REPORT_SCHEMA: &str = "crucible.cli.campaign-head.v1";

#[derive(Serialize)]
struct CampaignHeadReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    snapshot: String,
    lineage: String,
    policy: String,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    advanced: Option<bool>,
}

pub(super) fn run_campaign_invocation(cli: &Cli, args: &CampaignArgs) -> Result<(), CliError> {
    let principal = CampaignPrincipal::new(args.principal.clone())
        .map_err(|error| usage_error(format!("invalid campaign principal: {error}")))?;
    let stream = UnixStream::connect(&args.socket).map_err(|error| {
        CliError::Io(io::Error::new(
            error.kind(),
            format!(
                "could not connect to campaign service at {}: {error}",
                args.socket.display()
            ),
        ))
    })?;
    let service = LoopbackCampaignService::new(stream)
        .map_err(|error| backend_error(format!("campaign transport setup failed: {error}")))?;
    let client = CampaignClient::new(service);
    let report = query_campaign_head(&client, principal, &args.command)?;

    println!("{}", render_campaign_head(&report, cli.output_format())?);
    Ok(())
}

fn query_campaign_head<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignHeadReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    match command {
        CampaignCommand::Status(status) => {
            let campaign = campaign_name(&status.name)?;
            let request =
                GetCampaignRequest::new(principal, campaign.clone()).map_err(|error| {
                    usage_error(format!("invalid campaign status request: {error}"))
                })?;
            let response = client
                .get_campaign(&request)
                .map_err(|error| backend_error(format!("campaign status failed: {error}")))?;
            Ok(CampaignHeadReport {
                schema: CAMPAIGN_HEAD_REPORT_SCHEMA,
                operation: "status",
                campaign: campaign.as_str().to_owned(),
                snapshot: response.snapshot().to_string(),
                lineage: response.lineage().to_string(),
                policy: response.policy().to_string(),
                state: campaign_state_label(response.state()),
                advanced: None,
            })
        }
        CampaignCommand::Watch(watch) => {
            let campaign = campaign_name(&watch.name)?;
            let after = watch
                .after
                .as_deref()
                .map(CampaignSnapshotId::parse)
                .transpose()
                .map_err(|error| usage_error(format!("invalid campaign watch cursor: {error}")))?;
            let request = WatchCampaignRequest::new(principal, campaign.clone(), after)
                .map_err(|error| usage_error(format!("invalid campaign watch request: {error}")))?;
            let response = client
                .watch_campaign(&request)
                .map_err(|error| backend_error(format!("campaign watch failed: {error}")))?;
            Ok(CampaignHeadReport {
                schema: CAMPAIGN_HEAD_REPORT_SCHEMA,
                operation: "watch",
                campaign: campaign.as_str().to_owned(),
                snapshot: response.snapshot().to_string(),
                lineage: response.lineage().to_string(),
                policy: response.policy().to_string(),
                state: campaign_state_label(response.state()),
                advanced: Some(response.advanced()),
            })
        }
    }
}

fn campaign_name(value: &str) -> Result<CampaignName, CliError> {
    CampaignName::new(value.to_owned())
        .map_err(|error| usage_error(format!("invalid campaign name: {error}")))
}

const fn campaign_state_label(state: CampaignState) -> &'static str {
    match state {
        CampaignState::Created => "created",
        CampaignState::Running => "running",
        CampaignState::Paused => "paused",
        CampaignState::Completed => "completed",
        CampaignState::Sealed => "sealed",
    }
}

fn render_campaign_head(
    report: &CampaignHeadReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => {
            let mut rows = vec![
                ("campaign", report.campaign.as_str()),
                ("snapshot", report.snapshot.as_str()),
                ("lineage", report.lineage.as_str()),
                ("policy", report.policy.as_str()),
                ("state", report.state),
            ];
            let advanced;
            if let Some(value) = report.advanced {
                advanced = value.to_string();
                rows.push(("advanced", advanced.as_str()));
            }
            Ok(rows
                .into_iter()
                .map(|(field, value)| format!("{field:<10} {value}"))
                .collect::<Vec<_>>()
                .join("\n"))
        }
        OutputFormat::Markdown => {
            let mut output = String::from("| Field | Value |\n| --- | --- |\n");
            for (field, value) in [
                ("campaign", report.campaign.as_str()),
                ("snapshot", report.snapshot.as_str()),
                ("lineage", report.lineage.as_str()),
                ("policy", report.policy.as_str()),
                ("state", report.state),
            ] {
                output.push_str(&format!("| {field} | {value} |\n"));
            }
            if let Some(advanced) = report.advanced {
                output.push_str(&format!("| advanced | {advanced} |\n"));
            }
            Ok(output.trim_end().to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    use std::convert::Infallible;
    use std::thread;

    use crucible_campaign::*;
    use crucible_cas::content_store::{ContentId, ObjectKind};
    use crucible_daemon::serve_loopback_campaign_once;

    #[derive(Clone, Copy)]
    struct FixedHeadService;

    impl CampaignService for FixedHeadService {
        type Error = Infallible;

        fn create_campaign(
            &self,
            _request: &CreateCampaignRequest,
        ) -> Result<CreateCampaignResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn derive_campaign(
            &self,
            _request: &DeriveCampaignRequest,
        ) -> Result<DeriveCampaignResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign(
            &self,
            request: &GetCampaignRequest,
        ) -> Result<GetCampaignResponse, Self::Error> {
            Ok(GetCampaignResponse::new(
                request,
                snapshot("current"),
                lineage("lineage"),
                policy("policy"),
                CampaignState::Running,
            )
            .expect("fixed get response"))
        }

        fn get_campaign_snapshot(
            &self,
            _request: &GetCampaignSnapshotRequest,
        ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn watch_campaign(
            &self,
            request: &WatchCampaignRequest,
        ) -> Result<WatchCampaignResponse, Self::Error> {
            Ok(WatchCampaignResponse::new(
                request,
                snapshot("current"),
                lineage("lineage"),
                policy("policy"),
                CampaignState::Running,
            )
            .expect("fixed watch response"))
        }

        fn query_campaign_graph(
            &self,
            _request: &QueryCampaignGraphRequest,
        ) -> Result<QueryCampaignGraphResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign_graph_object(
            &self,
            _request: &GetCampaignGraphObjectRequest,
        ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn query_campaign_choices(
            &self,
            _request: &QueryCampaignChoicesRequest,
        ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn query_campaign_frontier(
            &self,
            _request: &QueryCampaignFrontierRequest,
        ) -> Result<QueryCampaignFrontierResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign_frontier_object(
            &self,
            _request: &GetCampaignFrontierObjectRequest,
        ) -> Result<GetCampaignFrontierObjectResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn get_campaign_choice_object(
            &self,
            _request: &GetCampaignChoiceObjectRequest,
        ) -> Result<GetCampaignChoiceObjectResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn apply_campaign_command(
            &self,
            _request: &ApplyCampaignCommandRequest,
        ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }

        fn submit_branch_request(
            &self,
            _request: &SubmitCampaignBranchRequest,
        ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
            unreachable!("unused campaign-service operation")
        }
    }

    #[test]
    fn campaign_head_report_renders_machine_and_human_forms() {
        let report = CampaignHeadReport {
            schema: CAMPAIGN_HEAD_REPORT_SCHEMA,
            operation: "watch",
            campaign: "example".to_owned(),
            snapshot: "snapshot".to_owned(),
            lineage: "lineage".to_owned(),
            policy: "policy".to_owned(),
            state: "running",
            advanced: Some(true),
        };

        let json = render_campaign_head(&report, OutputFormat::Json).expect("JSON report");
        let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(decoded["schema"], CAMPAIGN_HEAD_REPORT_SCHEMA);
        assert_eq!(decoded["advanced"], true);

        let table = render_campaign_head(&report, OutputFormat::Table).expect("table report");
        assert!(table.contains("campaign   example"));
        assert!(table.contains("advanced   true"));

        let markdown =
            render_campaign_head(&report, OutputFormat::Markdown).expect("Markdown report");
        assert!(markdown.contains("| state | running |"));
    }

    #[test]
    fn campaign_status_and_watch_use_the_checked_loopback_transport() {
        let status = CampaignCommand::Status(CampaignStatusArgs {
            name: "example".to_owned(),
        });
        let status_report = query_over_loopback(&status);
        assert_eq!(status_report.operation, "status");
        assert_eq!(status_report.snapshot, snapshot("current").to_string());
        assert_eq!(status_report.advanced, None);

        let watch = CampaignCommand::Watch(CampaignWatchArgs {
            name: "example".to_owned(),
            after: Some(snapshot("previous").to_string()),
        });
        let watch_report = query_over_loopback(&watch);
        assert_eq!(watch_report.operation, "watch");
        assert_eq!(watch_report.state, "running");
        assert_eq!(watch_report.advanced, Some(true));
    }

    #[test]
    fn campaign_status_and_watch_parse_under_the_nested_cli() {
        let status = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "status",
            "example",
        ])
        .expect("campaign status arguments");
        assert!(matches!(
            status.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Status(CampaignStatusArgs { ref name }),
                ..
            }) if name == "example"
        ));

        let cursor = snapshot("cursor").to_string();
        let watch = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "watch",
            "example",
            "--after",
            &cursor,
        ])
        .expect("campaign watch arguments");
        assert!(matches!(
            watch.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Watch(CampaignWatchArgs { after: Some(_), .. }),
                ..
            })
        ));
    }

    fn query_over_loopback(command: &CampaignCommand) -> CampaignHeadReport {
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
                .expect("serve one campaign request");
        });
        let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
        let client = CampaignClient::new(service);
        let report = query_campaign_head(
            &client,
            CampaignPrincipal::new("operator").expect("campaign principal"),
            command,
        )
        .expect("checked campaign query");
        server.join().expect("campaign server thread");
        report
    }

    fn snapshot(label: &str) -> CampaignSnapshotId {
        CampaignSnapshotId::parse(&format!(
            "crucible.campaign.snapshot@{}",
            ContentId::for_bytes(ObjectKind::CampaignSnapshot, 2, label.as_bytes()).encode()
        ))
        .expect("snapshot id")
    }

    fn lineage(label: &str) -> CampaignLineageId {
        CampaignLineageId::parse(&format!(
            "crucible.campaign.lineage@{}",
            ContentId::for_bytes(ObjectKind::CampaignFact, 1, label.as_bytes()).encode()
        ))
        .expect("lineage id")
    }

    fn policy(label: &str) -> CampaignPolicyId {
        CampaignPolicyId::parse(&format!(
            "crucible.campaign.policy@{}",
            ContentId::for_bytes(ObjectKind::Policy, 1, label.as_bytes()).encode()
        ))
        .expect("policy id")
    }
}
