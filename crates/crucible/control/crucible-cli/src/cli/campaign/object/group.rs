//! Bounded public inspection of authenticated atomic choice groups.

use serde::Serialize;

use crucible_campaign::{
    ChoiceDomain, ChoiceGroup, ChoiceGroupDomain, ChoiceRelationalConstraint, ChoiceTuple,
    ChoiceValue, IntegerRepresentation, SelectableId,
};

use super::{
    CliError, backend_error, campaign_choice_domain_kind, campaign_choice_source_label,
    campaign_choice_value_label,
};

const MAX_GROUP_VIEW_MEMBERS: usize = 64;
const MAX_GROUP_VIEW_CONSTRAINTS: usize = 256;
const MAX_GROUP_VIEW_TUPLES: usize = 4_096;

#[derive(Serialize)]
pub(super) struct CampaignGroupView {
    id: String,
    schema_version: u32,
    application: CampaignGroupApplicationView,
    shape: &'static str,
    members: Vec<CampaignGroupMemberView>,
    constraints: Vec<CampaignGroupConstraintView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finite_tuples: Option<Vec<Vec<CampaignGroupTupleValueView>>>,
}

#[derive(Serialize)]
struct CampaignGroupApplicationView {
    adapter: String,
    version: u32,
}

#[derive(Serialize)]
struct CampaignGroupMemberView {
    id: String,
    declaration_semantics: String,
    name: String,
    source: String,
    required: bool,
    semantic_tags: Vec<String>,
    default: String,
    declared_domain: String,
    declared_domain_semantics: String,
    narrowed_domain_id: String,
    narrowed_domain_semantics: String,
    narrowed_domain: CampaignMemberDomainView,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CampaignMemberDomainView {
    Boolean {
        semantic_version: u32,
    },
    Discrete {
        semantic_version: u32,
        alternatives: Vec<CampaignAlternativeView>,
    },
    Integer {
        semantic_version: u32,
        representation: &'static str,
        minimum: String,
        maximum: String,
        step: String,
        unit: Option<String>,
        scale: CampaignScaleView,
        landmarks: Vec<String>,
    },
}

#[derive(Serialize)]
struct CampaignAlternativeView {
    id: String,
    label: String,
    description: Option<String>,
}

#[derive(Serialize)]
struct CampaignScaleView {
    numerator: String,
    denominator: String,
}

#[derive(Serialize)]
struct CampaignGroupMemberRef {
    id: String,
    name: String,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum CampaignGroupConstraintView {
    Equal {
        left: CampaignGroupMemberRef,
        right: CampaignGroupMemberRef,
    },
    LessThan {
        left: CampaignGroupMemberRef,
        right: CampaignGroupMemberRef,
    },
    Member {
        member: CampaignGroupMemberRef,
        admitted: Vec<String>,
    },
    Implies {
        if_member: CampaignGroupMemberRef,
        if_alternative: String,
        then_member: CampaignGroupMemberRef,
        allowed: Vec<String>,
    },
}

#[derive(Serialize)]
struct CampaignGroupTupleValueView {
    member: CampaignGroupMemberRef,
    value: String,
}

pub(super) fn campaign_group_view(group: &ChoiceGroup) -> Result<CampaignGroupView, CliError> {
    if group.declarations().len() > MAX_GROUP_VIEW_MEMBERS {
        return Err(backend_error(
            "authenticated choice group exceeds the report member bound",
        ));
    }

    let (shape, domains, constraints, finite_tuples) = match group.domain() {
        ChoiceGroupDomain::Cartesian {
            members,
            constraints,
        } => {
            if constraints.len() > MAX_GROUP_VIEW_CONSTRAINTS {
                return Err(backend_error(
                    "authenticated choice group exceeds the report constraint bound",
                ));
            }
            let views = constraints
                .iter()
                .map(|constraint| campaign_constraint_view(group, constraint))
                .collect::<Result<Vec<_>, _>>()?;
            ("cartesian", members, views, None)
        }
        ChoiceGroupDomain::Finite { members, tuples } => {
            if tuples.len() > MAX_GROUP_VIEW_TUPLES {
                return Err(backend_error(
                    "authenticated choice group exceeds the report tuple bound",
                ));
            }
            let views = tuples
                .iter()
                .map(|tuple| campaign_tuple_view(group, tuple))
                .collect::<Result<Vec<_>, _>>()?;
            ("finite", members, Vec::new(), Some(views))
        }
    };

    let members = domains
        .iter()
        .map(|(id, domain)| campaign_member_view(group, *id, domain))
        .collect::<Result<Vec<_>, _>>()?;
    let id = group.id().map_err(|error| {
        backend_error(format!(
            "authenticated choice group identity is invalid: {error}"
        ))
    })?;

    Ok(CampaignGroupView {
        id: id.to_string(),
        schema_version: group.schema_version(),
        application: CampaignGroupApplicationView {
            adapter: group.application().adapter().to_owned(),
            version: group.application().version(),
        },
        shape,
        members,
        constraints,
        finite_tuples,
    })
}

fn campaign_member_view(
    group: &ChoiceGroup,
    id: SelectableId,
    domain: &ChoiceDomain,
) -> Result<CampaignGroupMemberView, CliError> {
    let declaration = group.declarations().get(&id).ok_or_else(|| {
        backend_error("authenticated choice group is missing a member declaration")
    })?;
    let declared_domain = declaration.domain();
    let declared_domain_id = declared_domain.id().map_err(|error| {
        backend_error(format!(
            "authenticated group member domain is invalid: {error}"
        ))
    })?;
    let narrowed_domain_id = domain.id().map_err(|error| {
        backend_error(format!(
            "authenticated narrowed group member domain is invalid: {error}"
        ))
    })?;

    Ok(CampaignGroupMemberView {
        id: id.to_string(),
        declaration_semantics: declaration.semantic_id().to_string(),
        name: declaration.name().to_owned(),
        source: campaign_choice_source_label(declaration.source()),
        required: declaration.required(),
        semantic_tags: declaration.semantic_tags().iter().cloned().collect(),
        default: campaign_choice_value_label(declaration.default()),
        declared_domain: declared_domain_id.to_string(),
        declared_domain_semantics: declared_domain.semantic_id().to_string(),
        narrowed_domain_id: narrowed_domain_id.to_string(),
        narrowed_domain_semantics: domain.semantic_id().to_string(),
        narrowed_domain: campaign_member_domain_view(domain)?,
    })
}

fn campaign_member_domain_view(
    domain: &ChoiceDomain,
) -> Result<CampaignMemberDomainView, CliError> {
    match domain {
        ChoiceDomain::Boolean(value) => Ok(CampaignMemberDomainView::Boolean {
            semantic_version: value.semantic_version(),
        }),
        ChoiceDomain::Discrete(value) => Ok(CampaignMemberDomainView::Discrete {
            semantic_version: value.semantic_version(),
            alternatives: value
                .alternatives()
                .iter()
                .map(|(id, alternative)| CampaignAlternativeView {
                    id: id.to_string(),
                    label: alternative.label().to_owned(),
                    description: alternative.description().map(str::to_owned),
                })
                .collect(),
        }),
        ChoiceDomain::Integer(value) => Ok(CampaignMemberDomainView::Integer {
            semantic_version: value.semantic_version(),
            representation: match value.representation() {
                IntegerRepresentation::Signed64 => "signed-64",
                IntegerRepresentation::Unsigned64 => "unsigned-64",
            },
            minimum: campaign_choice_value_label(&ChoiceValue::Integer(value.minimum())),
            maximum: campaign_choice_value_label(&ChoiceValue::Integer(value.maximum())),
            step: value.step().to_string(),
            unit: value.unit().map(str::to_owned),
            scale: CampaignScaleView {
                numerator: value.scale().numerator().to_string(),
                denominator: value.scale().denominator().to_string(),
            },
            landmarks: value
                .landmarks()
                .iter()
                .map(|landmark| campaign_choice_value_label(&ChoiceValue::Integer(*landmark)))
                .collect(),
        }),
        ChoiceDomain::Group(_) => Err(backend_error(format!(
            "authenticated group member has nested {} domain",
            campaign_choice_domain_kind(domain)
        ))),
    }
}

fn campaign_member_ref(
    group: &ChoiceGroup,
    id: SelectableId,
) -> Result<CampaignGroupMemberRef, CliError> {
    let declaration = group.declarations().get(&id).ok_or_else(|| {
        backend_error("authenticated choice-group constraint names an unknown member")
    })?;
    Ok(CampaignGroupMemberRef {
        id: id.to_string(),
        name: declaration.name().to_owned(),
    })
}

fn campaign_constraint_view(
    group: &ChoiceGroup,
    constraint: &ChoiceRelationalConstraint,
) -> Result<CampaignGroupConstraintView, CliError> {
    let values = |values: &std::collections::BTreeSet<ChoiceValue>| {
        values.iter().map(campaign_choice_value_label).collect()
    };
    match constraint {
        ChoiceRelationalConstraint::Equal(left, right) => Ok(CampaignGroupConstraintView::Equal {
            left: campaign_member_ref(group, *left)?,
            right: campaign_member_ref(group, *right)?,
        }),
        ChoiceRelationalConstraint::LessThan(left, right) => {
            Ok(CampaignGroupConstraintView::LessThan {
                left: campaign_member_ref(group, *left)?,
                right: campaign_member_ref(group, *right)?,
            })
        }
        ChoiceRelationalConstraint::Member(member, admitted) => {
            Ok(CampaignGroupConstraintView::Member {
                member: campaign_member_ref(group, *member)?,
                admitted: values(admitted),
            })
        }
        ChoiceRelationalConstraint::Implies {
            if_member,
            if_alternative,
            then_member,
            allowed,
        } => Ok(CampaignGroupConstraintView::Implies {
            if_member: campaign_member_ref(group, *if_member)?,
            if_alternative: if_alternative.to_string(),
            then_member: campaign_member_ref(group, *then_member)?,
            allowed: values(allowed),
        }),
    }
}

fn campaign_tuple_view(
    group: &ChoiceGroup,
    tuple: &ChoiceTuple,
) -> Result<Vec<CampaignGroupTupleValueView>, CliError> {
    tuple
        .values()
        .iter()
        .map(|(id, value)| {
            Ok(CampaignGroupTupleValueView {
                member: campaign_member_ref(group, *id)?,
                value: campaign_choice_value_label(value),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixtures abort at the malformed operation.
    #![allow(clippy::expect_used)]

    use std::collections::{BTreeMap, BTreeSet};

    use crucible_campaign::{
        AlternativeId, BooleanDomain, CampaignHash, ChoiceClassContext, ChoiceGroupApplication,
        ChoiceSource, DiscreteAlternative, DiscreteDomain, IntegerDomain, IntegerRepresentation,
        IntegerValue, SelectableDeclaration,
    };

    use super::*;
    use crate::OutputFormat;
    use crate::cli_campaign::object::{
        CAMPAIGN_CHOICE_OBJECT_REPORT_SCHEMA, CampaignObjectReport, CampaignOpportunityView,
        campaign_declaration_view, campaign_domain_view, render_campaign_object,
    };

    fn group_fixture() -> (ChoiceGroup, SelectableDeclaration) {
        let packet_loss = AlternativeId::from_hash(CampaignHash::derive("fixture", b"packet-loss"));
        let latency_step =
            AlternativeId::from_hash(CampaignHash::derive("fixture", b"latency-step"));
        let kind_domain = ChoiceDomain::Discrete(
            DiscreteDomain::new(
                1,
                BTreeMap::from([
                    (
                        packet_loss,
                        DiscreteAlternative::new(packet_loss, "packet_loss", None)
                            .expect("packet loss alternative"),
                    ),
                    (
                        latency_step,
                        DiscreteAlternative::new(latency_step, "latency_step", None)
                            .expect("latency alternative"),
                    ),
                ]),
            )
            .expect("kind domain"),
        );
        let duration_domain = ChoiceDomain::Integer(
            IntegerDomain::new(
                1,
                IntegerRepresentation::Unsigned64,
                IntegerValue::Unsigned(1_000),
                IntegerValue::Unsigned(2_000),
                1_000,
                Some("us".to_owned()),
                crucible_campaign::ExactRational::new(1, 1).expect("scale"),
                vec![IntegerValue::Unsigned(2_000)],
            )
            .expect("duration domain"),
        );
        let class =
            ChoiceClassContext::new(BTreeSet::from(["network".to_owned()])).expect("choice class");
        let source = ChoiceSource::Workload {
            producer: "network-controller".to_owned(),
        };
        let kind = SelectableDeclaration::new(
            "fault.kind",
            source.clone(),
            kind_domain.clone(),
            ChoiceValue::Discrete(packet_loss),
            class.clone(),
            BTreeSet::from(["fault".to_owned()]),
            true,
        )
        .expect("kind declaration");
        let duration = SelectableDeclaration::new(
            "fault.duration_us",
            source.clone(),
            duration_domain.clone(),
            ChoiceValue::Integer(IntegerValue::Unsigned(1_000)),
            class.clone(),
            BTreeSet::from(["fault".to_owned()]),
            true,
        )
        .expect("duration declaration");
        let kind_id = kind.id().expect("kind ID");
        let duration_id = duration.id().expect("duration ID");
        let group = ChoiceGroup::new(
            &BTreeMap::from([(kind_id, kind), (duration_id, duration)]),
            ChoiceGroupDomain::Cartesian {
                members: BTreeMap::from([(kind_id, kind_domain), (duration_id, duration_domain)]),
                constraints: BTreeSet::from([ChoiceRelationalConstraint::Implies {
                    if_member: kind_id,
                    if_alternative: packet_loss,
                    then_member: duration_id,
                    allowed: BTreeSet::from([ChoiceValue::Integer(IntegerValue::Unsigned(1_000))]),
                }]),
            },
            ChoiceGroupApplication::new("network-controller", 2).expect("application"),
        )
        .expect("group");
        let default = group
            .select(ChoiceTuple::new(BTreeMap::from([
                (kind_id, ChoiceValue::Discrete(packet_loss)),
                (
                    duration_id,
                    ChoiceValue::Integer(IntegerValue::Unsigned(1_000)),
                ),
            ])))
            .expect("group default");
        let declaration = SelectableDeclaration::new(
            "fault.network",
            source,
            ChoiceDomain::Group(Box::new(group.clone())),
            ChoiceValue::Group(default),
            class,
            BTreeSet::from(["fault".to_owned()]),
            true,
        )
        .expect("group declaration");
        (group, declaration)
    }

    fn opportunity_view() -> CampaignOpportunityView {
        CampaignOpportunityView {
            opportunity: "opportunity".to_owned(),
            semantic_opportunity: "semantic-opportunity".to_owned(),
            scenario: "scenario".to_owned(),
            class: "class".to_owned(),
            source: "workload:network-controller".to_owned(),
            declaration: "declaration".to_owned(),
            declaration_semantics: "declaration-semantics".to_owned(),
            domain: "domain".to_owned(),
            domain_semantics: "domain-semantics".to_owned(),
            scheduler_coordinate: "scheduler".to_owned(),
            producer_coordinate: "producer".to_owned(),
            instance: "first".to_owned(),
            default: "default".to_owned(),
            model_prior: None,
        }
    }

    #[test]
    fn group_choice_object_exposes_typed_members_and_constraints() {
        let (group, declaration) = group_fixture();
        let domain = ChoiceDomain::Group(Box::new(group.clone()));
        let domain_object = campaign_domain_view(opportunity_view(), &domain).expect("domain view");
        let declaration_object =
            campaign_declaration_view(opportunity_view(), &declaration).expect("declaration view");
        let report = CampaignObjectReport {
            schema: CAMPAIGN_CHOICE_OBJECT_REPORT_SCHEMA,
            operation: "choice-object",
            campaign: "fixture".to_owned(),
            snapshot: "snapshot".to_owned(),
            object: domain_object,
        };
        let json = render_campaign_object(&report, OutputFormat::Json).expect("group JSON");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse group JSON");
        assert_eq!(
            value["object"]["group"]["id"],
            group.id().expect("group ID").to_string()
        );
        assert_eq!(
            value["object"]["group"]["application"]["adapter"],
            "network-controller"
        );
        assert_eq!(value["object"]["group"]["application"]["version"], 2);
        assert_eq!(value["object"]["group"]["shape"], "cartesian");
        assert_eq!(
            value["object"]["group"]["members"]
                .as_array()
                .expect("members")
                .len(),
            2
        );
        assert!(
            value["object"]["group"]["members"]
                .as_array()
                .expect("members")
                .iter()
                .any(|member| {
                    member["name"] == "fault.kind"
                        && member["narrowed_domain"]["kind"] == "discrete"
                        && member["narrowed_domain"]["alternatives"]
                            .as_array()
                            .expect("alternatives")
                            .iter()
                            .any(|alternative| alternative["label"] == "packet_loss")
                })
        );
        assert!(
            value["object"]["group"]["members"]
                .as_array()
                .expect("members")
                .iter()
                .any(|member| {
                    member["name"] == "fault.duration_us"
                        && member["default"] == "u64:1000"
                        && member["narrowed_domain"]["minimum"] == "u64:1000"
                        && member["narrowed_domain"]["maximum"] == "u64:2000"
                })
        );
        assert_eq!(
            value["object"]["group"]["constraints"][0]["kind"],
            "implies"
        );
        assert_eq!(
            value["object"]["group"]["constraints"][0]["if_member"]["name"],
            "fault.kind"
        );
        assert_eq!(
            value["object"]["group"]["constraints"][0]["then_member"]["name"],
            "fault.duration_us"
        );
        assert_eq!(
            value["object"]["group"]["constraints"][0]["allowed"][0],
            "u64:1000"
        );

        let declaration_json = serde_json::to_value(&declaration_object).expect("declaration JSON");
        let default = declaration_json["default"].as_str().expect("group default");
        assert_eq!(
            crate::cli_campaign::parse_campaign_choice_value(default)
                .expect("parse displayed default"),
            declaration.default().clone()
        );
    }

    #[test]
    fn scalar_choice_object_uses_current_schema() {
        let scalar = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
        let object = campaign_domain_view(opportunity_view(), &scalar).expect("scalar view");
        let report = CampaignObjectReport {
            schema: CAMPAIGN_CHOICE_OBJECT_REPORT_SCHEMA,
            operation: "choice-object",
            campaign: "fixture".to_owned(),
            snapshot: "snapshot".to_owned(),
            object,
        };
        let value = serde_json::to_value(&report).expect("scalar JSON");
        assert_eq!(value["schema"], CAMPAIGN_CHOICE_OBJECT_REPORT_SCHEMA);
        assert!(value["object"].get("group").is_none());
    }

    #[test]
    fn finite_group_choice_object_lists_every_admitted_tuple() {
        let (cartesian, _) = group_fixture();
        let declarations = cartesian.declarations().clone();
        let members = declarations
            .iter()
            .map(|(id, declaration)| (*id, declaration.domain().clone()))
            .collect();
        let tuple = ChoiceTuple::new(
            declarations
                .iter()
                .map(|(id, declaration)| (*id, declaration.default().clone()))
                .collect(),
        );
        let finite = ChoiceGroup::new(
            &declarations,
            ChoiceGroupDomain::Finite {
                members,
                tuples: BTreeSet::from([tuple]),
            },
            cartesian.application().clone(),
        )
        .expect("finite group");

        let value = serde_json::to_value(campaign_group_view(&finite).expect("finite view"))
            .expect("finite JSON");
        assert_eq!(value["shape"], "finite");
        assert_eq!(value["finite_tuples"].as_array().expect("tuples").len(), 1);
        assert_eq!(
            value["finite_tuples"][0].as_array().expect("tuple").len(),
            2
        );
        assert!(
            value["finite_tuples"][0]
                .as_array()
                .expect("tuple")
                .iter()
                .any(|entry| entry["member"]["name"] == "fault.kind")
        );
    }

    #[test]
    fn group_view_is_limited_by_validated_member_count() {
        let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
        let class =
            ChoiceClassContext::new(BTreeSet::from(["network".to_owned()])).expect("choice class");
        let mut declarations = BTreeMap::new();
        let mut members = BTreeMap::new();
        for ordinal in 0..=MAX_GROUP_VIEW_MEMBERS {
            let declaration = SelectableDeclaration::new(
                format!("fault.member.{ordinal}"),
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
        assert!(
            ChoiceGroup::new(
                &declarations,
                ChoiceGroupDomain::Cartesian {
                    members,
                    constraints: BTreeSet::new(),
                },
                ChoiceGroupApplication::new("network-controller", 1).expect("application"),
            )
            .is_err()
        );
    }
}
