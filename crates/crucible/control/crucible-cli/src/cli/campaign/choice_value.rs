//! Authenticated named tuple encoding for public atomic group selections.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crucible_campaign::{
    AlternativeId, CampaignChoiceObject, CampaignChoiceObjectKind, ChoiceDomain, ChoiceGroup,
    ChoiceTuple, ChoiceValue, GetCampaignChoiceObjectRequest, IntegerRepresentation, IntegerValue,
    SelectableId,
};

use super::*;

const CAMPAIGN_CHOICE_VALUE_REPORT_SCHEMA: &str = "crucible.cli.campaign-choice-value.v1";
const MAX_GROUP_MEMBER_ASSIGNMENTS: usize = 64;
const MAX_GROUP_MEMBER_ASSIGNMENT_BYTES: usize = 4_096;

#[derive(Serialize)]
pub(super) struct CampaignChoiceValueReport {
    schema: &'static str,
    operation: &'static str,
    campaign: String,
    snapshot: String,
    opportunity: String,
    domain: String,
    group: String,
    value: String,
}

pub(super) fn validate_campaign_choice_value(
    args: &CampaignChoiceValueArgs,
) -> Result<(), CliError> {
    let CampaignChoiceValueCommand::Encode(encode) = &args.command;
    campaign_name(&encode.name)?;
    CampaignSnapshotId::parse(&encode.snapshot)
        .map_err(|error| usage_error(format!("invalid choice-value snapshot: {error}")))?;
    ChoiceOpportunityId::parse(&encode.opportunity)
        .map_err(|error| usage_error(format!("invalid choice-value opportunity: {error}")))?;
    parse_member_assignments(&encode.member)?;
    Ok(())
}

pub(super) fn encode_campaign_choice_value<S>(
    client: &CampaignClient<S>,
    principal: CampaignPrincipal,
    args: &CampaignChoiceValueArgs,
) -> Result<CampaignChoiceValueReport, CliError>
where
    S: CampaignService,
    S::Error: CampaignServiceFailureSource,
{
    let CampaignChoiceValueCommand::Encode(encode) = &args.command;
    let campaign = campaign_name(&encode.name)?;
    let snapshot = CampaignSnapshotId::parse(&encode.snapshot)
        .map_err(|error| usage_error(format!("invalid choice-value snapshot: {error}")))?;
    let opportunity = ChoiceOpportunityId::parse(&encode.opportunity)
        .map_err(|error| usage_error(format!("invalid choice-value opportunity: {error}")))?;
    let assignments = parse_member_assignments(&encode.member)?;

    let request = GetCampaignChoiceObjectRequest::new(
        principal,
        campaign.clone(),
        snapshot,
        opportunity,
        CampaignChoiceObjectKind::Domain,
    )
    .map_err(|error| usage_error(format!("invalid choice-value domain query: {error}")))?;
    let response = client
        .get_campaign_choice_object(&request)
        .map_err(|error| {
            backend_error(format!(
                "authenticated choice-value domain query failed: {error}"
            ))
        })?;
    let CampaignChoiceObject::Domain(domain) = response.object() else {
        return Err(backend_error(
            "authenticated choice-value query returned another object kind",
        ));
    };
    let domain_id = domain.id().map_err(|error| {
        backend_error(format!(
            "authenticated choice-value domain is invalid: {error}"
        ))
    })?;
    if response.opportunity().domain() != domain_id
        || response.opportunity().id().map_err(|error| {
            backend_error(format!(
                "authenticated choice-value opportunity is invalid: {error}"
            ))
        })? != opportunity
    {
        return Err(backend_error(
            "authenticated choice-value domain differs from its opportunity",
        ));
    }
    let ChoiceDomain::Group(group) = domain else {
        return Err(usage_error(
            "choice-value encode requires an atomic group domain",
        ));
    };
    let value = encode_named_group_tuple(group, &assignments)?;
    let group_id = group.id().map_err(|error| {
        backend_error(format!(
            "authenticated choice group identity is invalid: {error}"
        ))
    })?;

    Ok(CampaignChoiceValueReport {
        schema: CAMPAIGN_CHOICE_VALUE_REPORT_SCHEMA,
        operation: "encode",
        campaign: campaign.as_str().to_owned(),
        snapshot: snapshot.to_string(),
        opportunity: opportunity.to_string(),
        domain: domain_id.to_string(),
        group: group_id.to_string(),
        value: object::campaign_choice_value_label(&value),
    })
}

fn parse_member_assignments(values: &[String]) -> Result<Vec<(&str, &str)>, CliError> {
    if values.is_empty() || values.len() > MAX_GROUP_MEMBER_ASSIGNMENTS {
        return Err(usage_error(format!(
            "choice-value encode requires 1..={MAX_GROUP_MEMBER_ASSIGNMENTS} members"
        )));
    }
    let mut seen = BTreeSet::new();
    values
        .iter()
        .map(|assignment| {
            if assignment.len() > MAX_GROUP_MEMBER_ASSIGNMENT_BYTES {
                return Err(usage_error("choice-value member assignment is too long"));
            }
            let (name, value) = assignment
                .split_once('=')
                .ok_or_else(|| usage_error("choice-value member must use NAME=VALUE"))?;
            if name.is_empty() || value.is_empty() || !seen.insert(name) {
                return Err(usage_error("choice-value member is empty or duplicated"));
            }
            Ok((name, value))
        })
        .collect()
}

fn encode_named_group_tuple(
    group: &ChoiceGroup,
    assignments: &[(&str, &str)],
) -> Result<ChoiceValue, CliError> {
    if assignments.len() != group.declarations().len() {
        return Err(usage_error(format!(
            "choice-value group requires exactly {} member assignments",
            group.declarations().len()
        )));
    }
    let domains = match group.domain() {
        crucible_campaign::ChoiceGroupDomain::Finite { members, .. }
        | crucible_campaign::ChoiceGroupDomain::Cartesian { members, .. } => members,
    };
    let mut values = BTreeMap::new();
    for (name, raw_value) in assignments {
        let id = resolve_member(group, name)?;
        let domain = domains
            .get(&id)
            .ok_or_else(|| backend_error("authenticated group member has no narrowed domain"))?;
        let value = parse_member_value(domain, raw_value)?;
        if values.insert(id, value).is_some() {
            return Err(usage_error(format!(
                "choice-value member {name} was assigned twice"
            )));
        }
    }
    group
        .select(ChoiceTuple::new(values))
        .map(ChoiceValue::Group)
        .map_err(|error| {
            usage_error(format!(
                "choice-value tuple violates the group domain: {error}"
            ))
        })
}

fn resolve_member(group: &ChoiceGroup, name: &str) -> Result<SelectableId, CliError> {
    if let Some(id) = name.strip_prefix("id:") {
        let id = SelectableId::parse(id)
            .map_err(|error| usage_error(format!("invalid group member ID: {error}")))?;
        if group.declarations().contains_key(&id) {
            return Ok(id);
        }
        return Err(usage_error(
            "group member ID is not in the authenticated domain",
        ));
    }
    let mut matches = group
        .declarations()
        .iter()
        .filter(|(_, declaration)| declaration.name() == name);
    let (id, _) = matches
        .next()
        .ok_or_else(|| usage_error(format!("unknown group member name {name}")))?;
    if matches.next().is_some() {
        return Err(usage_error(format!(
            "group member name {name} is ambiguous; use id:SELECTABLE_ID"
        )));
    }
    Ok(*id)
}

fn parse_member_value(domain: &ChoiceDomain, raw: &str) -> Result<ChoiceValue, CliError> {
    let value = match domain {
        ChoiceDomain::Boolean(_) => match raw {
            "true" => ChoiceValue::Boolean(true),
            "false" => ChoiceValue::Boolean(false),
            _ => return Err(usage_error("Boolean group member must be true or false")),
        },
        ChoiceDomain::Discrete(discrete) => {
            let id = if let Some(id) = raw.strip_prefix("discrete:") {
                AlternativeId::parse(id).map_err(|error| {
                    usage_error(format!("invalid discrete group member ID: {error}"))
                })?
            } else {
                let mut matches = discrete
                    .alternatives()
                    .iter()
                    .filter(|(_, alternative)| alternative.label() == raw);
                let (id, _) = matches.next().ok_or_else(|| {
                    usage_error(format!("unknown discrete group member label {raw}"))
                })?;
                if matches.next().is_some() {
                    return Err(usage_error(format!(
                        "discrete group member label {raw} is ambiguous; use discrete:ALTERNATIVE_ID"
                    )));
                }
                *id
            };
            ChoiceValue::Discrete(id)
        }
        ChoiceDomain::Integer(integer) => match integer.representation() {
            IntegerRepresentation::Signed64 => {
                let body = raw.strip_prefix("i64:").unwrap_or(raw);
                let number = body.parse::<i64>().map_err(|error| {
                    usage_error(format!("invalid signed group member: {error}"))
                })?;
                ChoiceValue::Integer(IntegerValue::Signed(number))
            }
            IntegerRepresentation::Unsigned64 => {
                let body = raw.strip_prefix("u64:").unwrap_or(raw);
                let number = body.parse::<u64>().map_err(|error| {
                    usage_error(format!("invalid unsigned group member: {error}"))
                })?;
                ChoiceValue::Integer(IntegerValue::Unsigned(number))
            }
        },
        ChoiceDomain::Group(_) => {
            return Err(backend_error(
                "authenticated group has a nested group member",
            ));
        }
    };
    if !domain.contains(&value) {
        return Err(usage_error(
            "group member value is outside its narrowed domain",
        ));
    }
    Ok(value)
}

pub(super) fn render_campaign_choice_value(
    report: &CampaignChoiceValueReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| backend_error(format!("choice-value JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| backend_error(format!("choice-value JSON encoding failed: {error}"))),
        OutputFormat::Table => Ok(format!(
            "campaign    {}\nsnapshot    {}\nopportunity {}\ndomain      {}\ngroup       {}\nvalue       {}",
            report.campaign,
            report.snapshot,
            report.opportunity,
            report.domain,
            report.group,
            report.value,
        )),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| campaign | {} |\n| snapshot | {} |\n| opportunity | {} |\n| domain | {} |\n| group | {} |\n| value | {} |",
            report.campaign,
            report.snapshot,
            report.opportunity,
            report.domain,
            report.group,
            report.value,
        )),
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture construction fails at the offending value.
    #![allow(clippy::expect_used)]

    use crucible_campaign::{
        BooleanDomain, CampaignHash, ChoiceClassContext, ChoiceGroupApplication, ChoiceGroupDomain,
        ChoiceRelationalConstraint, ChoiceSource, DiscreteAlternative, DiscreteDomain,
        ExactRational, IntegerDomain,
    };

    use super::*;

    fn equal_boolean_group() -> ChoiceGroup {
        let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain"));
        let class =
            ChoiceClassContext::new(BTreeSet::from(["fault".to_owned()])).expect("choice class");
        let mut declarations = BTreeMap::new();
        let mut members = BTreeMap::new();
        for name in ["fault.primary", "fault.backup"] {
            let declaration = SelectableDeclaration::new(
                name,
                ChoiceSource::Workload {
                    producer: "network-controller".to_owned(),
                },
                domain.clone(),
                ChoiceValue::Boolean(false),
                class.clone(),
                BTreeSet::new(),
                true,
            )
            .expect("member declaration");
            let id = declaration.id().expect("member ID");
            declarations.insert(id, declaration);
            members.insert(id, domain.clone());
        }
        let primary = declarations
            .iter()
            .find(|(_, declaration)| declaration.name() == "fault.primary")
            .map(|(id, _)| *id)
            .expect("primary ID");
        let backup = declarations
            .iter()
            .find(|(_, declaration)| declaration.name() == "fault.backup")
            .map(|(id, _)| *id)
            .expect("backup ID");
        ChoiceGroup::new(
            &declarations,
            ChoiceGroupDomain::Cartesian {
                members,
                constraints: BTreeSet::from([ChoiceRelationalConstraint::Equal(primary, backup)]),
            },
            ChoiceGroupApplication::new("network-controller", 1).expect("application"),
        )
        .expect("equal Boolean group")
    }

    #[test]
    fn named_group_tuple_round_trips_through_branch_value() {
        let group = equal_boolean_group();
        let assignments = [("fault.primary", "true"), ("fault.backup", "true")];
        let selected = encode_named_group_tuple(&group, &assignments).expect("selected tuple");
        let label = object::campaign_choice_value_label(&selected);
        assert_eq!(
            super::super::parse_campaign_choice_value(&label).expect("branch value"),
            selected
        );

        let primary = group
            .declarations()
            .iter()
            .find(|(_, declaration)| declaration.name() == "fault.primary")
            .map(|(id, _)| *id)
            .expect("primary ID");
        let by_id = format!("id:{primary}");
        assert_eq!(
            encode_named_group_tuple(
                &group,
                &[(by_id.as_str(), "true"), ("fault.backup", "true")]
            )
            .expect("exact-ID selection"),
            selected
        );
    }

    #[test]
    fn named_group_tuple_rejects_missing_duplicate_and_illegal_members() {
        let group = equal_boolean_group();
        for assignments in [
            vec![("fault.primary", "true")],
            vec![("fault.primary", "true"), ("fault.primary", "false")],
            vec![("fault.primary", "true"), ("fault.unknown", "true")],
            vec![("fault.primary", "true"), ("fault.backup", "false")],
            vec![("fault.primary", "truthy"), ("fault.backup", "true")],
        ] {
            assert!(encode_named_group_tuple(&group, &assignments).is_err());
        }
        assert!(
            parse_member_assignments(&[
                "fault.primary=true".to_owned(),
                "fault.primary=false".to_owned()
            ])
            .is_err()
        );
        assert!(parse_member_assignments(&["fault.primary".to_owned()]).is_err());
        assert!(
            parse_member_assignments(&vec![
                "fault.primary=true".to_owned();
                MAX_GROUP_MEMBER_ASSIGNMENTS + 1
            ])
            .is_err()
        );
    }

    #[test]
    fn named_group_values_resolve_labels_and_reject_ambiguity() {
        let first = AlternativeId::from_hash(CampaignHash::derive("fixture", b"first"));
        let second = AlternativeId::from_hash(CampaignHash::derive("fixture", b"second"));
        let discrete = ChoiceDomain::Discrete(
            DiscreteDomain::new(
                1,
                BTreeMap::from([
                    (
                        first,
                        DiscreteAlternative::new(first, "packet_loss", None).expect("first"),
                    ),
                    (
                        second,
                        DiscreteAlternative::new(second, "latency_step", None).expect("second"),
                    ),
                ]),
            )
            .expect("discrete domain"),
        );
        assert_eq!(
            parse_member_value(&discrete, "packet_loss").expect("label"),
            ChoiceValue::Discrete(first)
        );
        assert_eq!(
            parse_member_value(&discrete, &format!("discrete:{second}")).expect("exact ID"),
            ChoiceValue::Discrete(second)
        );

        let ambiguous = ChoiceDomain::Discrete(
            DiscreteDomain::new(
                1,
                BTreeMap::from([
                    (
                        first,
                        DiscreteAlternative::new(first, "same", None).expect("first"),
                    ),
                    (
                        second,
                        DiscreteAlternative::new(second, "same", None).expect("second"),
                    ),
                ]),
            )
            .expect("ambiguous labels"),
        );
        assert!(parse_member_value(&ambiguous, "same").is_err());
        assert!(parse_member_value(&ambiguous, &format!("discrete:{first}")).is_ok());

        let integer = ChoiceDomain::Integer(
            IntegerDomain::new(
                1,
                IntegerRepresentation::Unsigned64,
                IntegerValue::Unsigned(1_000),
                IntegerValue::Unsigned(2_000),
                1_000,
                None,
                ExactRational::new(1, 1).expect("scale"),
                Vec::new(),
            )
            .expect("integer domain"),
        );
        assert_eq!(
            parse_member_value(&integer, "2000").expect("integer"),
            ChoiceValue::Integer(IntegerValue::Unsigned(2_000))
        );
        assert!(parse_member_value(&integer, "1500").is_err());
    }

    #[test]
    fn public_choice_value_command_accepts_named_assignments() {
        let cli = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "choice-value",
            "encode",
            "demo",
            "--snapshot",
            "snapshot",
            "--opportunity",
            "opportunity",
            "--member",
            "fault.kind=packet_loss",
            "--member",
            "fault.duration_us=1000000",
        ])
        .expect("public group encoder arguments");
        assert!(matches!(
            cli.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::ChoiceValue(CampaignChoiceValueArgs {
                    command: CampaignChoiceValueCommand::Encode(CampaignChoiceValueEncodeArgs { member, .. }),
                }),
                ..
            }) if member == ["fault.kind=packet_loss", "fault.duration_us=1000000"]
        ));
    }
}
