//! Typed worked-network choices and effect replay contracts.

use std::error::Error;

use super::*;
use crate::NodeId;
use crate::model::{
    FaultCoordinate, FaultOperation, Icount, NodeTemplate, OpportunityPayload, Plan, Properties,
    ReadyPoint, ScenarioSelectableLimits, ScenarioSelectables, Seed, SignalId, WhiteBoxPolicy,
    World, WorldFaultDomain, WorldNode,
};

fn scenario() -> Result<ScenarioDefForm, Box<dyn Error>> {
    let world = World::from_nodes(vec![WorldNode {
        id: NodeId {
            name: String::from("router-a"),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("network-choice-test"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let base = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(20),
    )?;
    let selectables = ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::default(),
        vec![NetworkFaultSelectable::declaration()?],
    )?;
    Ok(base.with_selectables(selectables)?)
}

fn select_next(
    scenario: &ScenarioDefForm,
    parent: &Configuration,
    phase: NetworkFaultPhase,
    at: VirtualTime,
    prior: &[NetworkFaultCampaignBranch],
    value: ChoiceValue,
) -> Result<NetworkFaultCampaignBranch, Box<dyn Error>> {
    let selectable = NetworkFaultSelectable::next(scenario, parent, phase, at, prior)?
        .ok_or("expected an atomic network choice")?;
    let selection = selectable.branch_selection(value)?;
    Ok(selectable.resolve_branch(&selection)?)
}

fn selected_fault(
    scenario: &ScenarioDefForm,
    phase: NetworkFaultPhase,
    at: VirtualTime,
    kind: &str,
    path: &str,
    parameter: Option<u64>,
) -> Result<(Configuration, Vec<NetworkFaultCampaignBranch>), Box<dyn Error>> {
    let value = NetworkFaultSelectable::selected_value(
        kind,
        path,
        1_000,
        if kind == "packet_loss" {
            parameter.unwrap_or(0)
        } else {
            0
        },
        if kind == "latency_step" {
            parameter.unwrap_or(0)
        } else {
            0
        },
    )?;
    let parent = Configuration::genesis(scenario.scenario_def());
    let branch = select_next(scenario, &parent, phase, at, &[], value)?;
    Ok((branch.selected().clone(), vec![branch]))
}

fn opportunity(
    segment: &str,
    direction: FaultDirection,
    at: u64,
) -> Result<FaultOpportunity, Box<dyn Error>> {
    Ok(FaultOpportunity::new(
        ResolvedFaultTarget::NetworkSegment {
            segment: FaultObjectId::parse(segment)?,
            direction,
        },
        FaultOperation::NetworkTraverse,
        FaultPhase::Resolve,
        FaultCoordinate {
            virtual_nanos: at,
            retired_instructions: None,
        },
        1,
        Some(direction),
        OpportunityPayload::NetworkFrame {
            producer: FaultObjectId::parse("router-a")?,
            destination: FaultObjectId::parse("router-b")?,
            producer_sequence: 1,
            protocol_expansion_path: Vec::new(),
            generated_response_depth: 0,
            generated_response_cause: None,
            forwarding_mutation_path: Vec::new(),
            length_bytes: 64,
            payload_digest: ContentHash::from_bytes(b"packet"),
        },
    )?)
}

fn topology() -> Result<WorldFaultTopology, Box<dyn Error>> {
    let domain = |name: &str, segment: &str| -> Result<WorldFaultDomain, Box<dyn Error>> {
        let segment = SignalId::parse(segment)?;
        Ok(WorldFaultDomain {
            id: SignalId::parse(name)?,
            targets: [FaultDirection::AToB, FaultDirection::BToA]
                .into_iter()
                .map(|direction| WorldFaultTargetRef::NetworkSegment {
                    segment: segment.clone(),
                    direction,
                })
                .collect(),
        })
    };
    Ok(WorldFaultTopology {
        fault_domains: vec![
            domain("primary", "segment-primary")?,
            domain("backup", "segment-backup")?,
        ],
        ..WorldFaultTopology::default()
    })
}

#[test]
fn group_keeps_full_integer_domains_and_phase_identity() -> Result<(), Box<dyn Error>> {
    let scenario = scenario()?;
    let declaration = NetworkFaultSelectable::declaration()?;
    let ChoiceDomain::Group(group) = declaration.domain() else {
        return Err("network fault was not a group".into());
    };
    let declarations = group.declarations();
    assert_eq!(declarations.len(), 5);
    for (name, lower, upper) in [
        (LOSS_BPS, 0, 10_000),
        (LATENCY_US, 0, 2_000_000),
        (DURATION_US, 1_000, 30_000_000),
    ] {
        let ChoiceDomain::Integer(domain) = declarations
            .values()
            .find(|declaration| declaration.name() == name)
            .ok_or("missing integer declaration")?
            .domain()
        else {
            return Err("network parameter was not an integer domain".into());
        };
        assert_eq!(domain.minimum(), IntegerValue::Unsigned(lower));
        assert_eq!(domain.maximum(), IntegerValue::Unsigned(upper));
    }

    let parent = Configuration::genesis(scenario.scenario_def());
    let at = VirtualTime { ticks: 10_000 };
    let first =
        NetworkFaultSelectable::next(&scenario, &parent, NetworkFaultPhase::First, at, &[])?
            .ok_or("missing first opportunity")?;
    let first_branch =
        first.resolve_branch(&first.branch_selection(declaration.default().clone())?)?;
    let first_selected = first_branch.selected().clone();
    let followup = NetworkFaultSelectable::next(
        &scenario,
        &first_selected,
        NetworkFaultPhase::Followup,
        VirtualTime { ticks: 20_000 },
        &[first_branch],
    )?
    .ok_or("missing follow-up opportunity")?;
    assert_ne!(first.opportunity().id()?, followup.opportunity().id()?);
    assert_eq!(
        NetworkFaultSelectable::from_records(
            &scenario,
            &parent,
            first.declaration_ref(),
            first.opportunity(),
            first.domain(),
        )?,
        first
    );
    Ok(())
}

#[test]
fn group_constraints_reject_inactive_parameters() -> Result<(), Box<dyn Error>> {
    let scenario = scenario()?;
    let at = VirtualTime { ticks: 10_000 };
    for (kind, parameter) in [
        ("link_down", None),
        ("asymmetric_partition", None),
        ("packet_loss", Some(500)),
        ("latency_step", Some(1_000)),
    ] {
        let (selected, branches) = selected_fault(
            &scenario,
            NetworkFaultPhase::First,
            at,
            kind,
            "primary",
            parameter,
        )?;
        assert_eq!(branches.len(), 1);
        assert!(
            NetworkFaultSelectable::next(
                &scenario,
                &selected,
                NetworkFaultPhase::First,
                at,
                &branches,
            )?
            .is_none()
        );
        NetworkFaultCampaignReplayPlan::new(selected, branches)?;
    }
    assert!(
        NetworkFaultSelectable::selected_value("packet_loss", "primary", 1_000, 500, 1).is_err()
    );
    assert!(
        NetworkFaultSelectable::selected_value("latency_step", "primary", 1_000, 1, 500).is_err()
    );
    assert!(NetworkFaultSelectable::selected_value("link_down", "primary", 1_000, 1, 0).is_err());
    assert!(NetworkFaultSelectable::selected_value("packet_loss", "primary", 999, 0, 0).is_err());
    Ok(())
}

#[test]
fn progressive_group_candidates_reach_nonzero_fault_parameters() -> Result<(), Box<dyn Error>> {
    let declaration = NetworkFaultSelectable::declaration()?;
    let ChoiceDomain::Group(group) = declaration.domain() else {
        return Err("network fault was not a group".into());
    };
    assert!(group.supports_progressive_generation(4_096));

    let mut loss = false;
    let mut latency = false;
    let mut identities = BTreeSet::new();
    for ordinal in 1..=64 {
        let value = ChoiceValue::Group(group.progressive_candidate(ordinal, 4_096)?);
        let parameters = selected_parameters(declaration.domain(), &value)?;
        loss |= parameters.kind == "packet_loss" && parameters.loss_bps > 0;
        latency |= parameters.kind == "latency_step" && parameters.latency_us > 0;
        assert!(identities.insert(value.canonical_bytes()));
    }
    assert!(
        loss,
        "packet loss must be reachable through ordinary proposals"
    );
    assert!(
        latency,
        "latency must be reachable through ordinary proposals"
    );
    Ok(())
}

#[test]
fn selected_link_fault_projects_exact_typed_path_and_duration() -> Result<(), Box<dyn Error>> {
    let scenario = scenario()?;
    let at = VirtualTime { ticks: 10_000 };
    let (selected, branches) = selected_fault(
        &scenario,
        NetworkFaultPhase::First,
        at,
        "link_down",
        "primary",
        None,
    )?;
    let replay = NetworkFaultCampaignReplayPlan::new(selected, branches)?;
    let topology = topology()?;
    let primary = opportunity("segment-primary", FaultDirection::AToB, 11_000)?;
    let actions = replay.actions_for_opportunity(&topology, &primary)?;
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].opportunity, Some(primary.id()));
    assert!(matches!(
        actions[0].effect.specification(),
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Down,
            queued_policy: NetworkInFlightPolicy::Drop,
            in_flight_policy: NetworkInFlightPolicy::Drop,
        })
    ));
    assert!(
        replay
            .actions_for_opportunity(
                &topology,
                &opportunity("segment-backup", FaultDirection::AToB, 11_000)?
            )?
            .is_empty()
    );
    assert!(
        replay
            .actions_for_opportunity(
                &topology,
                &opportunity("segment-primary", FaultDirection::AToB, 1_010_000)?
            )?
            .is_empty()
    );
    Ok(())
}

#[test]
fn atomic_fault_activates_at_authenticated_time() -> Result<(), Box<dyn Error>> {
    let scenario = scenario()?;
    let at = VirtualTime { ticks: 10_000 };
    let topology = topology()?;
    let parent = Configuration::genesis(scenario.scenario_def());
    let inactive = NetworkFaultCampaignReplayPlan::new(parent.clone(), Vec::new())?;
    assert!(
        inactive
            .actions_for_opportunity(
                &topology,
                &opportunity("segment-primary", FaultDirection::AToB, 11_000)?,
            )?
            .is_empty()
    );
    let value = NetworkFaultSelectable::selected_value("packet_loss", "primary", 1_000, 10_000, 0)?;
    let branch = select_next(&scenario, &parent, NetworkFaultPhase::First, at, &[], value)?;
    let replay = NetworkFaultCampaignReplayPlan::new(branch.selected().clone(), vec![branch])?;
    assert!(
        replay
            .actions_for_opportunity(
                &topology,
                &opportunity("segment-primary", FaultDirection::AToB, 9_999)?,
            )?
            .is_empty()
    );
    assert_eq!(
        replay
            .actions_for_opportunity(
                &topology,
                &opportunity("segment-primary", FaultDirection::AToB, 10_000)?,
            )?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn latency_and_asymmetric_kinds_project_distinct_network_effects() -> Result<(), Box<dyn Error>> {
    let scenario = scenario()?;
    let at = VirtualTime { ticks: 10_000 };
    let topology = topology()?;
    let (latency_target, latency_branches) = selected_fault(
        &scenario,
        NetworkFaultPhase::First,
        at,
        "latency_step",
        "backup",
        Some(1_500),
    )?;
    let latency = NetworkFaultCampaignReplayPlan::new(latency_target, latency_branches)?;
    let backup = opportunity("segment-backup", FaultDirection::AToB, 11_000)?;
    let actions = latency.actions_for_opportunity(&topology, &backup)?;
    assert_eq!(actions.len(), 1);
    assert!(matches!(
        actions[0].effect.specification(),
        EffectSpecification::Network(NetworkEffectSpecification::PropagationDelay {
            delay_nanos: Some(delay),
            ..
        }) if delay.get() == 1_500_000
    ));
    assert!(
        latency
            .actions_for_opportunity(
                &topology,
                &opportunity("segment-primary", FaultDirection::AToB, 11_000)?,
            )?
            .is_empty()
    );

    let (partition_target, partition_branches) = selected_fault(
        &scenario,
        NetworkFaultPhase::First,
        at,
        "asymmetric_partition",
        "primary",
        None,
    )?;
    let partition = NetworkFaultCampaignReplayPlan::new(partition_target, partition_branches)?;
    assert_eq!(
        partition
            .actions_for_opportunity(
                &topology,
                &opportunity("segment-primary", FaultDirection::AToB, 11_000)?,
            )?
            .len(),
        1
    );
    assert!(
        partition
            .actions_for_opportunity(
                &topology,
                &opportunity("segment-primary", FaultDirection::BToA, 11_000)?,
            )?
            .is_empty()
    );
    Ok(())
}

#[test]
fn followup_fault_activates_only_after_its_own_boundary() -> Result<(), Box<dyn Error>> {
    let scenario = scenario()?;
    let parent = Configuration::genesis(scenario.scenario_def());
    let first = select_next(
        &scenario,
        &parent,
        NetworkFaultPhase::First,
        VirtualTime { ticks: 10_000 },
        &[],
        NetworkFaultSelectable::selected_value("packet_loss", "primary", 1_000, 0, 0)?,
    )?;
    let followup = select_next(
        &scenario,
        first.selected(),
        NetworkFaultPhase::Followup,
        VirtualTime { ticks: 20_000 },
        std::slice::from_ref(&first),
        NetworkFaultSelectable::selected_value("link_down", "backup", 1_000, 0, 0)?,
    )?;
    let replay =
        NetworkFaultCampaignReplayPlan::new(followup.selected().clone(), vec![first, followup])?;
    let topology = topology()?;

    assert!(
        replay
            .actions_for_opportunity(
                &topology,
                &opportunity("segment-backup", FaultDirection::AToB, 19_999)?,
            )?
            .is_empty()
    );
    assert_eq!(
        replay
            .actions_for_opportunity(
                &topology,
                &opportunity("segment-backup", FaultDirection::AToB, 20_000)?,
            )?
            .len(),
        1
    );
    assert!(
        replay
            .actions_for_opportunity(
                &topology,
                &opportunity("segment-primary", FaultDirection::AToB, 20_000)?,
            )?
            .is_empty()
    );
    Ok(())
}
