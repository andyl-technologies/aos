//! Focused tests for physical choice boundaries and replay cleanup.

use super::*;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crucible::{
    Decision, NodeId, NodeTemplate, Plan, Properties, ReadyPoint, RngDecision, RngStreamId,
    ScenarioSelectableLimits, ScenarioSelectables, Seed, SelectionDecision, WhiteBoxPolicy, World,
    WorldNode,
};
use crucible_campaign::{
    BooleanDomain, ChoiceClassContext, ChoiceDomain, ChoiceSource, ChoiceValue,
    SelectableDeclaration, Selection,
};
use crucible_protocol::SelectionRequest;

struct ScriptedPhysicalReplay {
    node: NodeId,
    upcoming: VecDeque<SelectablePlanPendingRequest>,
    pending: Option<SelectablePlanPendingRequest>,
    replies: Vec<SelectionReply>,
    advances: Vec<Icount>,
}

impl GuardedReplayPhysicalNode for ScriptedPhysicalReplay {
    type Observation = Icount;

    fn node(&self) -> &NodeId {
        &self.node
    }

    fn current_icount(
        &mut self,
        state: &Self::Observation,
    ) -> Result<Icount, QemuVmRealizationError> {
        Ok(*state)
    }

    fn advance_to_ceiling(
        &mut self,
        state: Self::Observation,
        ceiling: Icount,
    ) -> Result<Self::Observation, QemuVmRealizationError> {
        if ceiling.retired <= state.retired || self.pending.is_some() {
            return Err(invalid_replay_selection(
                "scripted physical advance is invalid",
            ));
        }
        self.advances.push(ceiling);
        if let Some(request) = self.upcoming.front() {
            let paused = request.icount().saturating_add(1);
            if paused <= ceiling.retired {
                self.pending = self.upcoming.pop_front();
                return Ok(Icount { retired: paused });
            }
        }
        Ok(ceiling)
    }

    fn drain_pending(
        &mut self,
    ) -> Result<Vec<SelectablePlanPendingRequest>, QemuVmRealizationError> {
        Ok(self.pending.take().into_iter().collect())
    }

    fn enqueue_reply(
        &mut self,
        pending: &SelectablePlanPendingRequest,
        reply: &SelectionReply,
    ) -> Result<(), QemuVmRealizationError> {
        if pending.request().sequence() != reply.sequence() {
            return Err(invalid_replay_selection("scripted reply sequence drifted"));
        }
        self.replies.push(reply.clone());
        Ok(())
    }
}

fn replay_choice_fixture()
-> Result<(ScenarioDefForm, NodeId, [SelectablePlanPendingRequest; 2]), Box<dyn std::error::Error>>
{
    let node = NodeId {
        name: String::from("choice-node"),
    };
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("guarded replay choice test"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let declaration = SelectableDeclaration::new(
        "campaign.recovery-policy",
        ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1)?),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new())?,
        BTreeSet::from([String::from("recovery")]),
        true,
    )?;
    let selectables = ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::new(4, 8, 16, 32)?,
        vec![declaration],
    )?;
    let source = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(7),
    )?
    .with_selectables(selectables)?;
    let first = SelectablePlanPendingRequest::new(
        SelectionRequest::new(1, "campaign.recovery-policy", "first", None, 256)?,
        41,
        0,
        0x1000,
    );
    let second = SelectablePlanPendingRequest::new(
        SelectionRequest::new(2, "campaign.recovery-policy", "second", None, 256)?,
        81,
        0,
        0x2000,
    );
    Ok((source, node, [first, second]))
}

#[test]
fn guarded_replay_reaches_two_recorded_guest_choices_and_rejects_drift()
-> Result<(), Box<dyn std::error::Error>> {
    let (source, node, [first, second]) = replay_choice_fixture()?;
    let scenario = ScenarioDefId::from_hash(CampaignHash::from_bytes(source.id().bytes));
    let first_discovery = resolve_guest_selectable(scenario, &source, &node, &first)?;
    let second_discovery = resolve_guest_selectable(scenario, &source, &node, &second)?;
    let first_selection = Selection::new(
        first_discovery.opportunity(),
        first_discovery.domain(),
        ChoiceValue::Boolean(false),
        SelectionOrigin::Default,
    )?;
    let genesis = Configuration::genesis(source.scenario_def());
    let after_rng = crucible::try_step(
        &genesis,
        Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("before-guest-choice"),
            value: 7,
        }),
    )?;
    let first_decision = Decision::Selection(SelectionDecision::new(&first_selection));
    let after_first = crucible::try_step(&after_rng, first_decision)?;

    let parent = ConfigurationId::from_hash(CampaignHash::from_bytes(after_first.id().bytes));
    let branch_point = second_discovery.opportunity().branch_point_id(parent);
    let second_selection = Selection::new_campaign_branch(
        second_discovery.opportunity(),
        second_discovery.domain(),
        ChoiceValue::Boolean(true),
        branch_point,
    )?;
    let second_decision = Decision::Selection(SelectionDecision::new(&second_selection));
    let target = crucible::try_step(&after_first, second_decision)?;
    let discoveries = BTreeMap::from([
        (first_discovery.opportunity().id()?, first_discovery),
        (second_discovery.opportunity().id()?, second_discovery),
    ]);
    let closure = GuardedCampaignReplayClosure::from_owned_discoveries(
        &source,
        &target.schedule,
        &discoveries,
    )?;
    let first_record = closure
        .selection_for_decision(1, &target.schedule)?
        .ok_or("first choice record is absent")?;
    let second_record = closure
        .selection_for_decision(2, &target.schedule)?
        .ok_or("second choice record is absent")?;
    let mut replay = ScriptedPhysicalReplay {
        node: node.clone(),
        upcoming: VecDeque::from([first.clone(), second.clone()]),
        pending: None,
        replies: Vec::new(),
        advances: Vec::new(),
    };

    let after_rng_icount = replay_one_nonselection_boundary(
        &mut replay,
        Icount { retired: 0 },
        Icount { retired: 100 },
    )?;
    assert_eq!(after_rng_icount.retired, 1);
    let after_first_icount = replay_one_local_guest_choice(
        &mut replay,
        after_rng_icount,
        Icount { retired: 100 },
        &source,
        &after_rng,
        first_record,
    )?;
    let after_second_icount = replay_one_local_guest_choice(
        &mut replay,
        after_first_icount,
        Icount { retired: 100 },
        &source,
        &after_first,
        second_record,
    )?;
    assert_eq!(after_second_icount.retired, 82);
    assert_eq!(replay.advances.len(), 3);
    assert_eq!(replay.replies.len(), 2);
    assert_eq!(replay.replies[0].sequence(), 1);
    assert_eq!(replay.replies[1].sequence(), 2);
    assert_ne!(
        replay.replies[0].selected_value(),
        replay.replies[1].selected_value()
    );

    let divergent = SelectablePlanPendingRequest::new(
        second.request().clone(),
        second.icount() + 1,
        second.vcpu_index(),
        second.guest_virtual_address(),
    );
    let mut divergent_replay = ScriptedPhysicalReplay {
        node: node.clone(),
        upcoming: VecDeque::from([divergent]),
        pending: None,
        replies: Vec::new(),
        advances: Vec::new(),
    };
    assert!(
        replay_one_local_guest_choice(
            &mut divergent_replay,
            after_first_icount,
            Icount { retired: 100 },
            &source,
            &after_first,
            second_record,
        )
        .is_err()
    );
    assert!(divergent_replay.replies.is_empty());

    let mut missing_replay = ScriptedPhysicalReplay {
        node,
        upcoming: VecDeque::new(),
        pending: None,
        replies: Vec::new(),
        advances: Vec::new(),
    };
    assert!(
        replay_one_local_guest_choice(
            &mut missing_replay,
            after_first_icount,
            Icount { retired: 100 },
            &source,
            &after_first,
            second_record,
        )
        .is_err()
    );
    assert!(missing_replay.replies.is_empty());

    let mut extra_replay = ScriptedPhysicalReplay {
        node: replay.node.clone(),
        upcoming: VecDeque::new(),
        pending: Some(first.clone()),
        replies: Vec::new(),
        advances: Vec::new(),
    };
    assert!(
        replay_one_nonselection_boundary(
            &mut extra_replay,
            Icount { retired: 0 },
            Icount { retired: 100 },
        )
        .is_err()
    );
    extra_replay.pending = Some(second.clone());
    assert!(reject_unrecorded_local_request(&mut extra_replay).is_err());
    extra_replay.pending = Some(first.clone());
    assert!(verify_target_pending_request(&mut extra_replay, Some(&first)).is_ok());
    extra_replay.pending = Some(second);
    assert!(verify_target_pending_request(&mut extra_replay, Some(&first)).is_err());
    let mut stalled_reissues = 0;
    assert_eq!(
        next_replay_ceiling(
            Icount {
                retired: 10_000_005,
            },
            Icount {
                retired: 30_000_000,
            },
            Some(Icount {
                retired: 10_000_005,
            }),
            &mut stalled_reissues,
        )?
        .retired,
        20_000_005
    );
    assert!(
        next_replay_ceiling(
            Icount { retired: 5 },
            Icount {
                retired: 30_000_000,
            },
            Some(Icount {
                retired: 20_000_000,
            }),
            &mut stalled_reissues,
        )
        .is_err()
    );
    for retry in 1..=MAX_REPLAY_STALLED_REISSUES {
        assert_eq!(
            next_replay_ceiling(
                Icount { retired: 5 },
                Icount {
                    retired: 30_000_000,
                },
                Some(Icount {
                    retired: 10_000_005,
                }),
                &mut stalled_reissues,
            )?
            .retired,
            10_000_005
        );
        assert_eq!(stalled_reissues, retry);
    }
    assert!(
        next_replay_ceiling(
            Icount { retired: 5 },
            Icount {
                retired: 30_000_000,
            },
            Some(Icount {
                retired: 10_000_005,
            }),
            &mut stalled_reissues,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn replay_quarantine_starts_with_bounded_initiating_failure() {
    let cause = QemuVmRealizationError::Executor {
        operation: "load exact fat probe",
        message: "realization failed ".to_owned() + &"界".repeat(2_000),
    };
    let cleanup = QemuVmRealizationError::ReapQuarantined {
        operation: "finish guarded replay-oracle comparison",
        message: String::from("process authority was quarantined"),
    };

    let result = replay_quarantine_with_cause(cause, cleanup);
    let QemuVmRealizationError::ReapQuarantined { operation, message } = result else {
        panic!("failed cleanup must remain quarantine classified");
    };
    assert_eq!(operation, "finish guarded replay-oracle comparison");
    assert!(message.starts_with(
            "replay comparison failed: load exact fat probe executor operation failed: realization failed"
        ));
    assert!(message.ends_with(REPLAY_QUARANTINE_TRUNCATION_SUFFIX));
    assert!(message.len() <= MAX_REPLAY_QUARANTINE_DETAIL_BYTES);
}

#[test]
fn replay_realization_cause_survives_failing_operational_boundary() {
    let cause = QemuVmRealizationError::Executor {
        operation: "load exact fat probe",
        message: String::from("original realization failure"),
    };
    let boundary = QemuVmRealizationError::Executor {
        operation: "check QEMU attempt resources",
        message: String::from("secondary boundary failure"),
    };

    let result = match observed_realization::<()>(Err(cause), Err(boundary)) {
        Ok(()) => panic!("realization must fail"),
        Err(error) => error,
    };
    assert!(matches!(
        result,
        QemuVmRealizationError::Executor { operation: "load exact fat probe", message }
            if message == "original realization failure"
    ));

    let cause = QemuVmRealizationError::Executor {
        operation: "load exact fat probe",
        message: String::from("original realization failure"),
    };
    let boundary = QemuVmRealizationError::ReapQuarantined {
        operation: "check QEMU attempt resources",
        message: String::from("boundary quarantined"),
    };
    let result = match observed_realization::<()>(Err(cause), Err(boundary)) {
        Ok(()) => panic!("quarantine must remain terminal"),
        Err(error) => error,
    };
    let QemuVmRealizationError::ReapQuarantined { message, .. } = result else {
        panic!("boundary quarantine classification must survive");
    };
    assert!(message.starts_with("replay comparison failed: load exact fat probe"));
    assert!(message.contains("boundary quarantined"));
}

#[test]
fn replay_comparison_cause_survives_non_quarantine_cleanup_error() {
    let cause = QemuVmRealizationError::Executor {
        operation: "compare replay oracle",
        message: String::from("original mismatch"),
    };
    let cleanup = QemuVmRealizationError::Executor {
        operation: "finish replay guard",
        message: String::from("secondary cleanup failure"),
    };

    let result = replay_quarantine_with_cause(cause, cleanup);
    assert!(matches!(
        result,
        QemuVmRealizationError::Executor { operation: "compare replay oracle", message }
            if message == "original mismatch"
    ));
}
