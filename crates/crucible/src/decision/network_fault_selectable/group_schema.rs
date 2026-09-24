//! Closed group schema for the scenario-owned network disruption.

use super::*;

fn member_declarations() -> Result<Vec<SelectableDeclaration>, CampaignCodecError> {
    let source = fault_source();
    let context = fault_context()?;
    let integer = |minimum, maximum, unit: &str, landmarks: Vec<u64>| {
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(minimum),
            IntegerValue::Unsigned(maximum),
            1,
            Some(String::from(unit)),
            ExactRational::new(1, 1)?,
            landmarks.into_iter().map(IntegerValue::Unsigned).collect(),
        )
        .map(ChoiceDomain::Integer)
    };
    let fields = [
        (
            FAULT_KIND,
            discrete_domain(
                FAULT_KIND,
                &[
                    "link_down",
                    "packet_loss",
                    "latency_step",
                    "asymmetric_partition",
                ],
            )?,
            discrete_value(FAULT_KIND, "packet_loss"),
        ),
        (
            AFFECTED_PATH,
            discrete_domain(AFFECTED_PATH, &["primary", "backup", "both"])?,
            discrete_value(AFFECTED_PATH, "primary"),
        ),
        (
            DURATION_US,
            integer(1_000, 30_000_000, "us", vec![1_000, 1_000_000, 30_000_000])?,
            ChoiceValue::Integer(IntegerValue::Unsigned(1_000_000)),
        ),
        (
            LOSS_BPS,
            integer(0, 10_000, "basis_points", vec![0, 100, 1_000, 10_000])?,
            ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        ),
        (
            LATENCY_US,
            integer(0, 2_000_000, "us", vec![0, 1_000, 100_000, 2_000_000])?,
            ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        ),
    ];
    fields
        .into_iter()
        .map(|(name, domain, default)| {
            SelectableDeclaration::new(
                name,
                source.clone(),
                domain,
                default,
                context.clone(),
                BTreeSet::from([
                    String::from("network-fault"),
                    String::from("scenario-owned"),
                ]),
                false,
            )
        })
        .collect()
}

pub(super) fn fault_source() -> ChoiceSource {
    ChoiceSource::Environment {
        adapter: String::from(NETWORK_FAULT_CAMPAIGN_ADAPTER),
        target: CampaignHash::derive(
            "crucible.worked-network-fault.target.v1",
            b"virtual-network-fabric",
        ),
    }
}

pub(super) fn fault_context() -> Result<ChoiceClassContext, CampaignCodecError> {
    ChoiceClassContext::new(BTreeSet::from([
        String::from("environment-fault"),
        String::from("network"),
    ]))
}

pub(super) fn fault_group() -> Result<ChoiceGroup, CampaignCodecError> {
    let declarations = member_declarations()?
        .into_iter()
        .map(|declaration| declaration.id().map(|id| (id, declaration)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let domains = declarations
        .iter()
        .map(|(id, declaration)| (*id, declaration.domain().clone()))
        .collect();
    let member_id = |name: &str| {
        declarations
            .iter()
            .find(|(_, declaration)| declaration.name() == name)
            .map(|(id, _)| *id)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "network fault group is missing a member",
            })
    };
    let kind = member_id(FAULT_KIND)?;
    let loss = member_id(LOSS_BPS)?;
    let latency = member_id(LATENCY_US)?;
    let zero = BTreeSet::from([ChoiceValue::Integer(IntegerValue::Unsigned(0))]);
    let inactive = [
        ("link_down", loss),
        ("link_down", latency),
        ("asymmetric_partition", loss),
        ("asymmetric_partition", latency),
        ("packet_loss", latency),
        ("latency_step", loss),
    ];
    let constraints = inactive
        .into_iter()
        .map(|(kind_name, member)| ChoiceRelationalConstraint::Implies {
            if_member: kind,
            if_alternative: alternative_id(FAULT_KIND, kind_name),
            then_member: member,
            allowed: zero.clone(),
        })
        .collect();
    ChoiceGroup::new(
        &declarations,
        ChoiceGroupDomain::Cartesian {
            members: domains,
            constraints,
        },
        ChoiceGroupApplication::new(NETWORK_FAULT_CAMPAIGN_ADAPTER, 1)?,
    )
}
