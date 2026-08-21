//! Thin local client for authenticated lazy-campaign inspection and control.

use super::*;

use std::os::unix::net::UnixStream;

use crucible_campaign::{
    ActiveAttemptPolicy, ApplyCampaignCommandRequest, BudgetGrant, CampaignClient,
    CampaignCommandId, CampaignControlAction, CampaignName, CampaignPolicyId, CampaignPrincipal,
    CampaignService, CampaignServiceFailureSource, CampaignSnapshotId, CampaignState,
    ControlRequest, GetCampaignRequest, WatchCampaignRequest,
};
use crucible_daemon::LoopbackCampaignService;
use serde::Serialize;

const CAMPAIGN_HEAD_REPORT_SCHEMA: &str = "crucible.cli.campaign-head.v1";
const CAMPAIGN_MUTATION_REPORT_SCHEMA: &str = "crucible.cli.campaign-mutation.v1";

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

#[derive(Serialize)]
struct CampaignMutationReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    command: String,
    prior_snapshot: String,
    new_snapshot: String,
    replayed: bool,
}

#[derive(Clone, Copy)]
struct CampaignMutationBasisRef<'a> {
    name: &'a str,
    expected: &'a str,
    command: &'a str,
}

pub(super) fn run_campaign_invocation(cli: &Cli, args: &CampaignArgs) -> Result<(), CliError> {
    let principal = CampaignPrincipal::new(args.principal.clone())
        .map_err(|error| usage_error(format!("invalid campaign principal: {error}")))?;
    validate_campaign_command(&args.command)?;
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
    let rendered = match &args.command {
        CampaignCommand::Status(_) | CampaignCommand::Watch(_) => {
            let report = query_campaign_head(&client, principal, &args.command)?;
            render_campaign_head(&report, cli.output_format())?
        }
        _ => {
            let report = apply_campaign_mutation(&client, principal, &args.command)?;
            render_campaign_mutation(&report, cli.output_format())?
        }
    };

    println!("{rendered}");
    Ok(())
}

fn validate_campaign_command(command: &CampaignCommand) -> Result<(), CliError> {
    match command {
        CampaignCommand::Status(status) => campaign_name(&status.name).map(|_| ()),
        CampaignCommand::Watch(watch) => {
            campaign_name(&watch.name)?;
            watch
                .after
                .as_deref()
                .map(CampaignSnapshotId::parse)
                .transpose()
                .map_err(|error| usage_error(format!("invalid campaign watch cursor: {error}")))?;
            Ok(())
        }
        _ => {
            let (basis, _, _) = campaign_mutation_spec(command)?;
            campaign_name(basis.name)?;
            CampaignCommandId::parse(basis.command)
                .map_err(|error| usage_error(format!("invalid campaign command ID: {error}")))?;
            CampaignSnapshotId::parse(basis.expected).map_err(|error| {
                usage_error(format!("invalid campaign snapshot precondition: {error}"))
            })?;
            Ok(())
        }
    }
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
        _ => Err(backend_error(
            "campaign mutation reached the read-only command path",
        )),
    }
}

fn apply_campaign_mutation<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    command: &CampaignCommand,
) -> Result<CampaignMutationReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let (basis, operation, action) = campaign_mutation_spec(command)?;
    let campaign = campaign_name(basis.name)?;
    let command_id = CampaignCommandId::parse(basis.command)
        .map_err(|error| usage_error(format!("invalid campaign command ID: {error}")))?;
    let expected_snapshot = CampaignSnapshotId::parse(basis.expected)
        .map_err(|error| usage_error(format!("invalid campaign snapshot precondition: {error}")))?;
    let control = ControlRequest {
        command: command_id,
        expected_snapshot,
        action,
    };
    let request = ApplyCampaignCommandRequest::new(principal, campaign.clone(), control)
        .map_err(|error| usage_error(format!("invalid campaign mutation request: {error}")))?;
    let response = client
        .apply_campaign_command(&request)
        .map_err(|error| backend_error(format!("campaign {operation} failed: {error}")))?;

    Ok(CampaignMutationReport {
        schema: CAMPAIGN_MUTATION_REPORT_SCHEMA,
        operation,
        campaign: campaign.as_str().to_owned(),
        command: command_id.to_string(),
        prior_snapshot: response.prior_snapshot().to_string(),
        new_snapshot: response.new_snapshot().to_string(),
        replayed: response.replayed(),
    })
}

fn campaign_mutation_spec(
    command: &CampaignCommand,
) -> Result<
    (
        CampaignMutationBasisRef<'_>,
        &'static str,
        CampaignControlAction,
    ),
    CliError,
> {
    match command {
        CampaignCommand::Resume(basis) => Ok((
            mutation_basis_ref(basis),
            "resume",
            CampaignControlAction::Resume,
        )),
        CampaignCommand::Pause(pause) => Ok((
            mutation_basis_ref(&pause.basis),
            "pause",
            CampaignControlAction::Pause(pause.active.control_policy()),
        )),
        CampaignCommand::Stop(stop) => Ok((
            mutation_basis_ref(&stop.basis),
            if stop.seal { "seal" } else { "stop" },
            if stop.seal {
                CampaignControlAction::Seal
            } else {
                CampaignControlAction::Complete
            },
        )),
        CampaignCommand::Unseal(basis) => Ok((
            mutation_basis_ref(basis),
            "unseal",
            CampaignControlAction::Unseal,
        )),
        CampaignCommand::Budget(budget) => {
            let CampaignBudgetCommand::Add(add) = &budget.operation;
            let grant = BudgetGrant::new(add.proposals, add.attempts)
                .map_err(|error| usage_error(format!("invalid campaign budget grant: {error}")))?;
            Ok((
                CampaignMutationBasisRef {
                    name: &budget.name,
                    expected: &budget.expected,
                    command: &budget.command,
                },
                "budget-add",
                CampaignControlAction::GrantBudget(grant),
            ))
        }
        CampaignCommand::Steer(steer) => {
            let policy = CampaignPolicyId::parse(&steer.policy)
                .map_err(|error| usage_error(format!("invalid campaign policy ID: {error}")))?;
            Ok((
                mutation_basis_ref(&steer.basis),
                "steer",
                CampaignControlAction::ActivatePolicy(policy),
            ))
        }
        CampaignCommand::Status(_) | CampaignCommand::Watch(_) => Err(backend_error(
            "campaign read reached the mutation command path",
        )),
    }
}

fn mutation_basis_ref(basis: &CampaignMutationBasisArgs) -> CampaignMutationBasisRef<'_> {
    CampaignMutationBasisRef {
        name: &basis.name,
        expected: &basis.expected,
        command: &basis.command,
    }
}

impl CampaignPausePolicyArg {
    const fn control_policy(self) -> ActiveAttemptPolicy {
        match self {
            Self::Drain => ActiveAttemptPolicy::Drain,
            Self::Checkpoint => ActiveAttemptPolicy::ExactCheckpoint,
            Self::Retry => ActiveAttemptPolicy::CancelAndRetry,
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

fn render_campaign_mutation(
    report: &CampaignMutationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("campaign JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok([
            format!("{:<15} {}", "campaign", report.campaign),
            format!("{:<15} {}", "operation", report.operation),
            format!("{:<15} {}", "command", report.command),
            format!("{:<15} {}", "prior_snapshot", report.prior_snapshot),
            format!("{:<15} {}", "new_snapshot", report.new_snapshot),
            format!("{:<15} {}", "replayed", report.replayed),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| campaign | {} |\n| operation | {} |\n| command | {} |\n| prior_snapshot | {} |\n| new_snapshot | {} |\n| replayed | {} |",
            report.campaign,
            report.operation,
            report.command,
            report.prior_snapshot,
            report.new_snapshot,
            report.replayed
        )),
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
            request: &ApplyCampaignCommandRequest,
        ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
            assert!(matches!(
                request.command().action,
                CampaignControlAction::Pause(ActiveAttemptPolicy::ExactCheckpoint)
            ));
            Ok(ApplyCampaignCommandResponse::new(
                request,
                CampaignCommandResult {
                    prior_snapshot: request.command().expected_snapshot,
                    new_snapshot: snapshot("mutated"),
                    replayed: false,
                },
            )
            .expect("fixed campaign mutation response"))
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
    fn campaign_mutation_report_renders_exact_transition_basis() {
        let report = CampaignMutationReport {
            schema: CAMPAIGN_MUTATION_REPORT_SCHEMA,
            operation: "pause",
            campaign: "example".to_owned(),
            command: hash("pause").to_hex(),
            prior_snapshot: snapshot("prior").to_string(),
            new_snapshot: snapshot("next").to_string(),
            replayed: true,
        };

        let json = render_campaign_mutation(&report, OutputFormat::Json).expect("JSON report");
        let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(decoded["schema"], CAMPAIGN_MUTATION_REPORT_SCHEMA);
        assert_eq!(decoded["prior_snapshot"], report.prior_snapshot);
        assert_eq!(decoded["new_snapshot"], report.new_snapshot);
        assert_eq!(decoded["replayed"], true);

        let table = render_campaign_mutation(&report, OutputFormat::Table).expect("table report");
        assert!(table.contains("operation       pause"));
        assert!(table.contains("replayed        true"));

        let markdown =
            render_campaign_mutation(&report, OutputFormat::Markdown).expect("Markdown report");
        assert!(markdown.contains("| prior_snapshot |"));
        assert!(markdown.contains("| new_snapshot |"));
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
    fn campaign_mutation_uses_the_checked_loopback_transport() {
        let command = CampaignCommand::Pause(CampaignPauseArgs {
            basis: mutation_basis("pause"),
            active: CampaignPausePolicyArg::Checkpoint,
        });
        let report = mutate_over_loopback(&command);

        assert_eq!(report.operation, "pause");
        assert_eq!(report.command, hash("pause").to_hex());
        assert_eq!(report.prior_snapshot, snapshot("current").to_string());
        assert_eq!(report.new_snapshot, snapshot("mutated").to_string());
        assert!(!report.replayed);
    }

    #[test]
    fn campaign_mutation_actions_preserve_exact_operator_intent() {
        let resume = CampaignCommand::Resume(mutation_basis("resume"));
        assert!(matches!(
            campaign_mutation_spec(&resume).expect("resume mutation").2,
            CampaignControlAction::Resume
        ));

        for (active, expected) in [
            (CampaignPausePolicyArg::Drain, ActiveAttemptPolicy::Drain),
            (
                CampaignPausePolicyArg::Checkpoint,
                ActiveAttemptPolicy::ExactCheckpoint,
            ),
            (
                CampaignPausePolicyArg::Retry,
                ActiveAttemptPolicy::CancelAndRetry,
            ),
        ] {
            let pause = CampaignCommand::Pause(CampaignPauseArgs {
                basis: mutation_basis("pause"),
                active,
            });
            assert!(matches!(
                campaign_mutation_spec(&pause).expect("pause mutation").2,
                CampaignControlAction::Pause(policy) if policy == expected
            ));
        }

        let stop = CampaignCommand::Stop(CampaignStopArgs {
            basis: mutation_basis("stop"),
            seal: false,
        });
        assert!(matches!(
            campaign_mutation_spec(&stop).expect("stop mutation").2,
            CampaignControlAction::Complete
        ));
        let seal = CampaignCommand::Stop(CampaignStopArgs {
            basis: mutation_basis("seal"),
            seal: true,
        });
        assert!(matches!(
            campaign_mutation_spec(&seal).expect("seal mutation").2,
            CampaignControlAction::Seal
        ));

        let unseal = CampaignCommand::Unseal(mutation_basis("unseal"));
        assert!(matches!(
            campaign_mutation_spec(&unseal).expect("unseal mutation").2,
            CampaignControlAction::Unseal
        ));

        let budget = CampaignCommand::Budget(CampaignBudgetArgs {
            name: "example".to_owned(),
            expected: snapshot("current").to_string(),
            command: hash("budget").to_hex(),
            operation: CampaignBudgetCommand::Add(CampaignBudgetAddArgs {
                attempts: 11,
                proposals: 13,
            }),
        });
        assert!(matches!(
            campaign_mutation_spec(&budget).expect("budget mutation").2,
            CampaignControlAction::GrantBudget(grant)
                if grant.attempts() == 11 && grant.proposals() == 13
        ));
        let empty_budget = CampaignCommand::Budget(CampaignBudgetArgs {
            name: "example".to_owned(),
            expected: snapshot("current").to_string(),
            command: hash("empty-budget").to_hex(),
            operation: CampaignBudgetCommand::Add(CampaignBudgetAddArgs {
                attempts: 0,
                proposals: 0,
            }),
        });
        assert!(campaign_mutation_spec(&empty_budget).is_err());

        let steer = CampaignCommand::Steer(CampaignSteerArgs {
            basis: mutation_basis("steer"),
            policy: policy("next").to_string(),
        });
        assert!(matches!(
            campaign_mutation_spec(&steer).expect("steer mutation").2,
            CampaignControlAction::ActivatePolicy(next) if next == policy("next")
        ));
    }

    #[test]
    fn campaign_inputs_fail_before_transport_setup() {
        let bad_watch = CampaignCommand::Watch(CampaignWatchArgs {
            name: "example".to_owned(),
            after: Some("not-a-snapshot".to_owned()),
        });
        assert!(validate_campaign_command(&bad_watch).is_err());

        let mut bad_command_basis = mutation_basis("bad-command");
        bad_command_basis.command = "not-a-command".to_owned();
        assert!(validate_campaign_command(&CampaignCommand::Resume(bad_command_basis)).is_err());

        let empty_budget = CampaignCommand::Budget(CampaignBudgetArgs {
            name: "example".to_owned(),
            expected: snapshot("current").to_string(),
            command: hash("empty-budget-validation").to_hex(),
            operation: CampaignBudgetCommand::Add(CampaignBudgetAddArgs {
                attempts: 0,
                proposals: 0,
            }),
        });
        assert!(validate_campaign_command(&empty_budget).is_err());
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

        let expected = snapshot("current").to_string();
        let command = hash("pause").to_hex();
        let pause = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "pause",
            "example",
            "--expected",
            &expected,
            "--command",
            &command,
            "--active",
            "checkpoint",
        ])
        .expect("campaign pause arguments");
        assert!(matches!(
            pause.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Pause(CampaignPauseArgs {
                    active: CampaignPausePolicyArg::Checkpoint,
                    ..
                }),
                ..
            })
        ));

        let budget = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "budget",
            "example",
            "--expected",
            &expected,
            "--command",
            &hash("budget").to_hex(),
            "add",
            "11",
            "--proposals",
            "13",
        ])
        .expect("campaign budget arguments");
        assert!(matches!(
            budget.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Budget(CampaignBudgetArgs {
                    operation: CampaignBudgetCommand::Add(CampaignBudgetAddArgs {
                        attempts: 11,
                        proposals: 13,
                    }),
                    ..
                }),
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

    fn mutate_over_loopback(command: &CampaignCommand) -> CampaignMutationReport {
        let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
        let server = thread::spawn(move || {
            serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
                .expect("serve one campaign mutation");
        });
        let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
        let client = CampaignClient::new(service);
        let report = apply_campaign_mutation(
            &client,
            CampaignPrincipal::new("operator").expect("campaign principal"),
            command,
        )
        .expect("checked campaign mutation");
        server.join().expect("campaign server thread");
        report
    }

    fn mutation_basis(label: &str) -> CampaignMutationBasisArgs {
        CampaignMutationBasisArgs {
            name: "example".to_owned(),
            expected: snapshot("current").to_string(),
            command: hash(label).to_hex(),
        }
    }

    fn hash(label: &str) -> CampaignHash {
        CampaignHash::derive("crucible-cli-campaign-test", label.as_bytes())
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
