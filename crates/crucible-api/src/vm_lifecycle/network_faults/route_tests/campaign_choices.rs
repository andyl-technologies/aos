//! Production frame outcomes for exact scenario-owned fault selections.

use std::error::Error;

use super::*;
use crucible::model::{
    FaultDirection, FaultOperation, FaultReplayMode, Icount, OpportunityPayload, Plan, Properties,
    ReadyPoint, ResolvedEffectTrace, ResolvedReplayWorkItem, ScenarioSelectableLimits,
    ScenarioSelectables, Seed, SignalId, WhiteBoxPolicy, World, WorldFaultDomain,
    WorldFaultTargetRef, WorldFaultTopology, WorldNode,
};
use crucible::{
    Configuration, Decision, NetworkFaultCampaignBranch, NetworkFaultCampaignReplayPlan,
    NetworkFaultPhase, NetworkFaultSelectable, NodeId, ScenarioDefForm, VirtualTime,
};

fn scenario() -> Result<ScenarioDefForm, Box<dyn Error>> {
    let world = World::from_nodes(vec![WorldNode {
        id: NodeId {
            name: String::from("router-a"),
        },
        arch: crucible::NodeTemplate::DEFAULT_ARCH,
        memory_mib: crucible::NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("campaign-network-frame-test"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        icount_shift: crucible::NodeTemplate::DEFAULT_ICOUNT_SHIFT,
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
    Ok(base.with_selectables(ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::default(),
        vec![NetworkFaultSelectable::declaration()?],
    )?)?)
}

fn selected_loss(
    scenario: &ScenarioDefForm,
    path: &str,
) -> Result<
    (
        NetworkFaultCampaignReplayPlan,
        Vec<NetworkFaultCampaignBranch>,
    ),
    Box<dyn Error>,
> {
    let parent = Configuration::genesis(scenario.scenario_def());
    let at = VirtualTime { ticks: 10_000 };
    let selectable =
        NetworkFaultSelectable::next(scenario, &parent, NetworkFaultPhase::First, at, &[])?
            .ok_or("missing active network group")?;
    let value = NetworkFaultSelectable::selected_value("packet_loss", path, 1_000, 10_000, 0)?;
    let branch = selectable.resolve_branch(&selectable.branch_selection(value)?)?;
    Ok((
        NetworkFaultCampaignReplayPlan::new(branch.selected().clone(), vec![branch.clone()])?,
        vec![branch],
    ))
}

fn selected_fault(
    scenario: &ScenarioDefForm,
    kind: &str,
    path: &str,
) -> Result<NetworkFaultCampaignReplayPlan, Box<dyn Error>> {
    let parent = Configuration::genesis(scenario.scenario_def());
    let at = VirtualTime { ticks: 10_000 };
    let selectable =
        NetworkFaultSelectable::next(scenario, &parent, NetworkFaultPhase::First, at, &[])?
            .ok_or("missing network choice")?;
    let value = NetworkFaultSelectable::selected_value(kind, path, 1_000, 0, 0)?;
    let branch = selectable.resolve_branch(&selectable.branch_selection(value)?)?;
    Ok(NetworkFaultCampaignReplayPlan::new(
        branch.selected().clone(),
        vec![branch],
    )?)
}

fn topology() -> WorldFaultTopology {
    let domain = |name: &str, segment: &str| WorldFaultDomain {
        id: SignalId::parse(name).expect("test domain"),
        targets: vec![WorldFaultTargetRef::NetworkSegment {
            segment: SignalId::parse(segment).expect("test segment"),
            direction: FaultDirection::AToB,
        }],
    };
    WorldFaultTopology {
        fault_domains: vec![
            domain("primary", "segment-primary"),
            domain("backup", "segment-backup"),
        ],
        ..WorldFaultTopology::default()
    }
}

fn frame(segment: &str) -> FaultOpportunity {
    FaultOpportunity::new(
        ResolvedFaultTarget::NetworkSegment {
            segment: id(segment),
            direction: FaultDirection::AToB,
        },
        FaultOperation::NetworkTraverse,
        FaultPhase::Resolve,
        FaultCoordinate {
            virtual_nanos: 11_000,
            retired_instructions: None,
        },
        1,
        Some(FaultDirection::AToB),
        OpportunityPayload::NetworkFrame {
            producer: id("router-a"),
            destination: id("router-b"),
            producer_sequence: 1,
            protocol_expansion_path: Vec::new(),
            generated_response_depth: 0,
            generated_response_cause: None,
            forwarding_mutation_path: Vec::new(),
            length_bytes: 64,
            payload_digest: ContentHash::from_bytes(b"frame"),
        },
    )
    .expect("test frame")
}

fn modeled_drop(
    replay: &NetworkFaultCampaignReplayPlan,
    topology: &WorldFaultTopology,
    segment: &str,
) -> Result<bool, Box<dyn Error>> {
    let opportunity = frame(segment);
    let actions = replay.actions_for_opportunity(topology, &opportunity)?;
    let mut payload = vec![0x45; 64];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    apply_network_frame_actions_with_limits(
        &mut payload,
        &mut effects,
        &actions,
        &opportunity,
        replay.target().def.id(),
        topology,
        &mut NetworkEffectRuntimeState::default(),
        &mut Vec::new(),
        None,
        None,
        FaultResourceLimits::compiled_maximum(),
    )?;
    Ok(effects.is_dropped())
}

#[test]
fn primary_and_backup_selections_change_modeled_frames_and_replay_exactly()
-> Result<(), Box<dyn Error>> {
    let scenario = scenario()?;
    let topology = topology();
    for (path, primary_drop, backup_drop) in [("primary", true, false), ("backup", false, true)] {
        let (selected, original_branches) = selected_loss(&scenario, path)?;
        assert!(
            validate_campaign_replay_restore(Some(selected.identity()), Some(&selected), None)
                .is_ok()
        );
        assert!(validate_campaign_replay_restore(None, Some(&selected), None).is_err());
        assert!(
            validate_campaign_replay_restore(
                None,
                Some(&selected),
                Some(VirtualTime { ticks: 10_000 }),
            )
            .is_ok(),
            "the selected child extends its exact parent checkpoint at the fork frontier"
        );
        assert!(
            validate_campaign_replay_restore(
                None,
                Some(&selected),
                Some(VirtualTime { ticks: 10_001 }),
            )
            .is_err(),
            "a branch selected away from the restored frontier cannot be installed"
        );
        assert!(
            validate_campaign_replay_restore(
                Some(ContentHash::from_bytes(b"different")),
                Some(&selected),
                None
            )
            .is_err()
        );
        assert_eq!(
            modeled_drop(&selected, &topology, "segment-primary")?,
            primary_drop
        );
        assert_eq!(
            modeled_drop(&selected, &topology, "segment-backup")?,
            backup_drop
        );

        let mut parent = Configuration::genesis(scenario.scenario_def());
        let mut replayed_branches = Vec::new();
        for original in &original_branches {
            let selectable = NetworkFaultSelectable::next(
                &scenario,
                &parent,
                NetworkFaultPhase::First,
                VirtualTime { ticks: 10_000 },
                &replayed_branches,
            )?
            .ok_or("missing replay opportunity")?;
            let Decision::Selection(decision) = original.decision() else {
                return Err("network branch was not a selection".into());
            };
            let replayed = selectable.resolve_branch(&decision.selection()?)?;
            assert_eq!(&replayed, original);
            parent = replayed.selected().clone();
            replayed_branches.push(replayed);
        }
        let replayed = NetworkFaultCampaignReplayPlan::new(parent, replayed_branches)?;
        assert_eq!(replayed, selected);
        assert_eq!(
            modeled_drop(&replayed, &topology, "segment-primary")?,
            primary_drop
        );
        assert_eq!(
            modeled_drop(&replayed, &topology, "segment-backup")?,
            backup_drop
        );
    }
    Ok(())
}

#[test]
fn selected_link_down_is_a_typed_bounded_availability_outage() -> Result<(), Box<dyn Error>> {
    let scenario = scenario()?;
    let topology = topology();
    let replay = selected_fault(&scenario, "link_down", "primary")?;
    let affected = replay.actions_for_opportunity(&topology, &frame("segment-primary"))?;
    let unaffected = replay.actions_for_opportunity(&topology, &frame("segment-backup"))?;

    assert_eq!(affected.len(), 1);
    assert!(unaffected.is_empty());
    assert_eq!(affected[0].kind, BindingActionKind::UpsertPersistent);
    assert!(matches!(
        affected[0].effect.specification(),
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Down,
            queued_policy: NetworkInFlightPolicy::Drop,
            in_flight_policy: NetworkInFlightPolicy::Drop,
        })
    ));
    assert!(!availability_allows(
        NetworkAvailabilityState::Down,
        FaultDirection::AToB
    ));
    assert_eq!(
        replay.active_outages(&topology, 11_000)?,
        vec![(frame("segment-primary").target().clone(), 1_010_000)]
    );
    assert!(replay.active_outages(&topology, 1_010_000)?.is_empty());
    Ok(())
}

#[test]
fn campaign_effect_trace_keeps_its_own_fingerprint_and_replays_canonically()
-> Result<(), Box<dyn Error>> {
    let scenario = scenario()?;
    let (replay, _) = selected_loss(&scenario, "primary")?;
    let opportunity = frame("segment-primary");
    let action = replay
        .actions_for_opportunity(&topology(), &opportunity)?
        .into_iter()
        .next()
        .ok_or("missing selected frame action")?;
    let campaign = ResolvedEffectRecord::from_committed_action(
        &action,
        Some(&opportunity),
        7,
        action.mapped_digest,
        Some(ContentHash::from_bytes(b"before")),
        ContentHash::from_bytes(b"after"),
    )?;
    let signal_fingerprint = ContentHash::from_bytes(b"independent-signal-continuation");
    let signal_item = ResolvedReplayWorkItem {
        coordinate: opportunity.coordinate(),
        same_coordinate_sequence: 7,
        opportunity: Some(opportunity.id()),
        target: Some(opportunity.target().clone()),
        operation: Some(opportunity.operation()),
        direction: opportunity.direction(),
        phase: Some(opportunity.phase()),
        network_frame_key: opportunity.network_frame_key(),
        network_producer_direction_key: opportunity.network_producer_direction_key(),
        derivation_fingerprint: signal_fingerprint,
        records: Vec::new(),
    };
    let signal = ResolvedEffectTrace {
        mode: FaultReplayMode::RecomputedCause,
        work_items: vec![signal_item.clone()],
        cursor: 0,
    };
    let combined = trace_with_campaign_network_records(
        Some(signal),
        &[campaign.clone()],
        FaultResourceLimits::default(),
        FaultReplayMode::RecomputedCause,
    )?
    .ok_or("missing combined effect trace")?;
    assert_eq!(combined.work_items.len(), 2);
    assert_eq!(
        combined.work_items[0].derivation_fingerprint,
        signal_fingerprint
    );
    assert_eq!(
        combined.work_items[1].derivation_fingerprint,
        action.mapped_digest
    );
    assert_eq!(combined.work_items[1].records, vec![campaign.clone()]);

    let decoded = ResolvedEffectTrace::from_canonical_bytes(
        &combined.canonical_bytes()?,
        FaultResourceLimits::default(),
    )?;
    assert_eq!(decoded, combined);
    let (signal_replay, campaign_replay) = split_campaign_network_trace(decoded, true)?;
    assert_eq!(signal_replay.work_items, vec![signal_item]);
    assert_eq!(campaign_replay, vec![campaign]);
    Ok(())
}
