//! Focused tests for physical choice boundaries and replay cleanup.

use super::*;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crucible::{
    BackendInput, Decision, DeliveryOrderDecision, Icount, IrqVector, NodeId, NodeTemplate, Plan,
    PreemptionDecision, PreemptionKind, Properties, ReadyPoint, RngDecision, RngStreamId,
    ScenarioSelectableLimits, ScenarioSelectables, Seed, SelectionDecision, VcpuId, VirtualTime,
    WhiteBoxPolicy, World, WorldNode,
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
    inputs: Vec<(crucible::SimInstant, Vec<u8>)>,
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
    ) -> Result<ReplayPhysicalAdvance<Self::Observation>, QemuVmRealizationError> {
        if ceiling.retired <= state.retired || self.pending.is_some() {
            return Err(invalid_replay_selection(
                "scripted physical advance is invalid",
            ));
        }
        self.advances.push(ceiling);
        if let Some(request) = self.upcoming.front() {
            let paused = request.trap_tick_ps().saturating_add(50);
            if paused <= ceiling.retired {
                self.pending = self.upcoming.pop_front();
                return Ok(ReplayPhysicalAdvance {
                    state: Icount { retired: paused },
                    outcome: AdvanceOutcome::Paused {
                        at: Icount { retired: paused },
                    },
                    idle_deadline: None,
                });
            }
        }
        Ok(ReplayPhysicalAdvance {
            state: ceiling,
            outcome: AdvanceOutcome::ReachedHorizon,
            idle_deadline: None,
        })
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

    fn enqueue_input(
        &mut self,
        state: Self::Observation,
        input: BackendInput,
        delivery: crucible::SimInstant,
    ) -> Result<Self::Observation, QemuVmRealizationError> {
        if input.node != self.node || delivery.ticks < state.retired {
            return Err(invalid_replay_selection(
                "scripted input crossed physical count",
            ));
        }
        self.inputs.push((delivery, input.payload));
        Ok(state)
    }
}

struct TickCalibratedReplay {
    physical: ScriptedPhysicalReplay,
    raw_instructions: u64,
    bias_ps: u64,
}

impl GuardedReplayPhysicalNode for TickCalibratedReplay {
    type Observation = Icount;

    fn node(&self) -> &NodeId {
        self.physical.node()
    }

    fn current_icount(
        &mut self,
        state: &Self::Observation,
    ) -> Result<Icount, QemuVmRealizationError> {
        self.physical.current_icount(state)
    }

    fn advance_to_ceiling(
        &mut self,
        state: Self::Observation,
        ceiling: Icount,
    ) -> Result<ReplayPhysicalAdvance<Self::Observation>, QemuVmRealizationError> {
        let advance = self.physical.advance_to_ceiling(state, ceiling)?;
        // This models the pre-cutover trace: a sub-instruction ceiling moved
        // the exact clock without retiring an instruction.
        self.raw_instructions +=
            (advance.state.retired - state.retired) / crucible::SIM_TICKS_PER_INSTRUCTION;
        self.bias_ps =
            advance.state.retired - self.raw_instructions * crucible::SIM_TICKS_PER_INSTRUCTION;
        Ok(advance)
    }

    fn drain_pending(
        &mut self,
    ) -> Result<Vec<SelectablePlanPendingRequest>, QemuVmRealizationError> {
        self.physical.drain_pending()
    }

    fn enqueue_reply(
        &mut self,
        pending: &SelectablePlanPendingRequest,
        reply: &SelectionReply,
    ) -> Result<(), QemuVmRealizationError> {
        self.physical.enqueue_reply(pending, reply)
    }

    fn enqueue_input(
        &mut self,
        state: Self::Observation,
        input: BackendInput,
        delivery: crucible::SimInstant,
    ) -> Result<Self::Observation, QemuVmRealizationError> {
        self.physical.enqueue_input(state, input, delivery)
    }
}

fn empty_physical_replay() -> ScriptedPhysicalReplay {
    ScriptedPhysicalReplay {
        node: NodeId {
            name: String::from("choice-node"),
        },
        upcoming: VecDeque::new(),
        pending: None,
        replies: Vec::new(),
        advances: Vec::new(),
        inputs: Vec::new(),
    }
}

#[test]
fn nonselection_instruction_steps_preserve_source_clock_calibration()
-> Result<(), Box<dyn std::error::Error>> {
    // These common second-choice and target coordinates belong to the joined
    // source/fat/thin generations in the exact-workload diagnostic.
    let after_choice_ps = 555_283_890_250;
    let target_ps = 555_377_677_100;
    let initial_raw_instructions = 5_823_692_702;
    let initial_bias_ps = 264_099_255_150;
    let mut reference = TickCalibratedReplay {
        physical: empty_physical_replay(),
        raw_instructions: initial_raw_instructions,
        bias_ps: initial_bias_ps,
    };
    let mut partitioned = TickCalibratedReplay {
        physical: empty_physical_replay(),
        raw_instructions: initial_raw_instructions,
        bias_ps: initial_bias_ps,
    };
    let target = Icount { retired: target_ps };
    let initial = Icount {
        retired: after_choice_ps,
    };

    reference.advance_to_ceiling(initial, target)?;
    let mut state = initial;
    for _ in 0..5 {
        state = replay_one_nonselection_boundary(&mut partitioned, state, target)?;
    }
    partitioned.advance_to_ceiling(state, target)?;

    assert_eq!(reference.raw_instructions, 5_825_568_439);
    assert_eq!(reference.bias_ps, initial_bias_ps);
    assert_eq!(partitioned.raw_instructions, reference.raw_instructions);
    assert_eq!(partitioned.bias_ps, reference.bias_ps);
    Ok(())
}

#[test]
fn nonselection_instruction_step_rejects_overflow_and_target_crossing() {
    for (at_ps, target_ps) in [(100, 149), (u64::MAX - 25, u64::MAX)] {
        let mut replay = empty_physical_replay();
        let result = replay_one_nonselection_boundary(
            &mut replay,
            Icount { retired: at_ps },
            Icount { retired: target_ps },
        );

        assert!(result.is_err());
        assert!(replay.advances.is_empty());
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
        (41) * 50,
        0,
        0x1000,
    );
    let second = SelectablePlanPendingRequest::new(
        SelectionRequest::new(2, "campaign.recovery-policy", "second", None, 256)?,
        81,
        (81) * 50,
        0,
        0x2000,
    );
    Ok((source, node, [first, second]))
}

#[test]
fn delivery_order_keeps_interleaved_inputs_at_their_physical_counts()
-> Result<(), Box<dyn std::error::Error>> {
    let first_delivery_ps = SIM_TICKS_PER_INSTRUCTION;
    let second_delivery_ps = 2 * SIM_TICKS_PER_INSTRUCTION;
    let target_ps = 3 * SIM_TICKS_PER_INSTRUCTION;
    let node = NodeId {
        name: String::from("receiver"),
    };
    let mut replay = ScriptedPhysicalReplay {
        node: node.clone(),
        upcoming: VecDeque::new(),
        pending: None,
        replies: Vec::new(),
        advances: Vec::new(),
        inputs: Vec::new(),
    };
    let first = BackendInput {
        node: node.clone(),
        payload: b"first".to_vec(),
    };
    let second = BackendInput {
        node: node.clone(),
        payload: b"second".to_vec(),
    };
    let delivery_order = Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime {
            ticks: first_delivery_ps,
        },
        order: Vec::new(),
    });
    let preemption = Decision::Preemption(PreemptionDecision {
        node,
        at: crucible::SimInstant {
            ticks: first_delivery_ps,
        },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: 32 },
        },
    });

    let state = replay.enqueue_input(
        Icount {
            retired: first_delivery_ps,
        },
        first,
        crucible::SimInstant {
            ticks: first_delivery_ps,
        },
    )?;
    let state = replay_one_nonselection_decision_boundary(
        &mut replay,
        state,
        Icount { retired: target_ps },
        &delivery_order,
    )?;
    assert_eq!(state.retired, first_delivery_ps);
    let state = replay_one_nonselection_decision_boundary(
        &mut replay,
        state,
        Icount { retired: target_ps },
        &preemption,
    )?;
    assert_eq!(state.retired, second_delivery_ps);
    let state = replay.enqueue_input(
        state,
        second,
        crucible::SimInstant {
            ticks: second_delivery_ps,
        },
    )?;

    assert_eq!(state.retired, second_delivery_ps);
    assert_eq!(
        replay.advances,
        vec![Icount {
            retired: second_delivery_ps,
        }]
    );
    assert_eq!(
        replay.inputs,
        vec![
            (
                crucible::SimInstant {
                    ticks: first_delivery_ps,
                },
                b"first".to_vec()
            ),
            (
                crucible::SimInstant {
                    ticks: second_delivery_ps,
                },
                b"second".to_vec()
            )
        ]
    );
    Ok(())
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
        inputs: Vec::new(),
    };

    let after_rng_icount = replay_one_nonselection_boundary(
        &mut replay,
        Icount { retired: 0 },
        Icount { retired: 5_000 },
    )?;
    assert_eq!(after_rng_icount.retired, SIM_TICKS_PER_INSTRUCTION);
    let after_first_icount = replay_one_local_guest_choice(
        &mut replay,
        after_rng_icount,
        Icount { retired: 5_000 },
        &source,
        &after_rng,
        first_record,
    )?;
    let after_second_icount = replay_one_local_guest_choice(
        &mut replay,
        after_first_icount,
        Icount { retired: 5_000 },
        &source,
        &after_first,
        second_record,
    )?;
    assert_eq!(after_second_icount.retired, 4_100);
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
        second.raw_icount() + 1,
        second.trap_tick_ps() + 50,
        second.vcpu_index(),
        second.guest_virtual_address(),
    );
    let mut divergent_replay = ScriptedPhysicalReplay {
        node: node.clone(),
        upcoming: VecDeque::from([divergent]),
        pending: None,
        replies: Vec::new(),
        advances: Vec::new(),
        inputs: Vec::new(),
    };
    assert!(
        replay_one_local_guest_choice(
            &mut divergent_replay,
            after_first_icount,
            Icount { retired: 5_000 },
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
        inputs: Vec::new(),
    };
    assert!(
        replay_one_local_guest_choice(
            &mut missing_replay,
            after_first_icount,
            Icount { retired: 5_000 },
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
        inputs: Vec::new(),
    };
    assert!(
        replay_one_nonselection_boundary(
            &mut extra_replay,
            Icount { retired: 0 },
            Icount { retired: 5_000 },
        )
        .is_err()
    );
    extra_replay.pending = Some(second.clone());
    assert!(reject_unrecorded_local_request(&mut extra_replay).is_err());
    extra_replay.pending = Some(first.clone());
    assert!(
        verify_target_pending_request(&mut extra_replay, Icount { retired: 2_100 }, Some(&first))
            .is_ok()
    );
    extra_replay.pending = Some(first.clone());
    assert!(
        verify_target_pending_request(&mut extra_replay, Icount { retired: 2_101 }, Some(&first))
            .is_err()
    );
    extra_replay.pending = Some(second);
    assert!(
        verify_target_pending_request(&mut extra_replay, Icount { retired: 4_100 }, Some(&first))
            .is_err()
    );
    let mut progress = ReplayPhysicalProgress::new(Icount { retired: 5 });
    assert_eq!(
        progress.next_ceiling(Icount {
            retired: 3_000_000_000
        })?,
        Icount {
            retired: 10_000_005
        }
    );
    let first = Icount {
        retired: 10_000_005,
    };
    progress.observe(
        Icount { retired: 5 },
        first,
        AdvanceOutcome::Paused {
            at: Icount { retired: 5 },
        },
        Some(Icount {
            retired: 2_500_000_000,
        }),
    )?;
    assert_eq!(
        progress.next_ceiling(Icount {
            retired: 3_000_000_000
        })?,
        Icount {
            retired: 1_010_000_005
        }
    );
    progress.observe(
        Icount { retired: 5 },
        Icount {
            retired: 1_010_000_005,
        },
        AdvanceOutcome::Paused {
            at: Icount { retired: 5 },
        },
        Some(Icount {
            retired: 2_500_000_000,
        }),
    )?;
    assert_eq!(
        progress.next_ceiling(Icount {
            retired: 3_000_000_000
        })?,
        Icount {
            retired: 2_010_000_005
        }
    );
    progress.observe(
        Icount { retired: 5 },
        Icount {
            retired: 2_010_000_005,
        },
        AdvanceOutcome::Paused {
            at: Icount { retired: 5 },
        },
        Some(Icount {
            retired: 2_500_000_000,
        }),
    )?;
    let deadline = Icount {
        retired: 2_500_000_000,
    };
    assert_eq!(
        progress.next_ceiling(Icount {
            retired: 3_000_000_000
        })?,
        deadline
    );
    progress.observe(deadline, deadline, AdvanceOutcome::ReachedHorizon, None)?;
    assert_eq!(
        progress.next_ceiling(Icount {
            retired: 3_000_000_000
        })?,
        Icount {
            retired: 2_510_000_000
        }
    );
    assert!(
        progress
            .next_ceiling(Icount {
                retired: 2_500_000_000
            })
            .is_err()
    );
    let mut stalled = ReplayPhysicalProgress::new(Icount { retired: 5 });
    for _ in 0..MAX_REPLAY_STALLED_REISSUES {
        let ceiling = stalled.next_ceiling(Icount {
            retired: 750_000_000,
        })?;
        assert_eq!(
            ceiling,
            Icount {
                retired: 10_000_005
            }
        );
        stalled.observe(
            Icount { retired: 5 },
            ceiling,
            AdvanceOutcome::Paused {
                at: Icount { retired: 5 },
            },
            Some(ceiling),
        )?;
    }
    let ceiling = stalled.next_ceiling(Icount {
        retired: 750_000_000,
    })?;
    assert!(
        stalled
            .observe(
                Icount { retired: 5 },
                ceiling,
                AdvanceOutcome::Paused {
                    at: Icount { retired: 5 },
                },
                Some(ceiling),
            )
            .is_err()
    );
    Ok(())
}

fn replay_parked_timer_then_choice(
    parked_advance: u64,
) -> Result<(CampaignHash, Vec<Icount>), Box<dyn std::error::Error>> {
    let mut progress =
        ReplayPhysicalProgress::with_parked_advance(Icount { retired: 0 }, parked_advance);
    let timer = Icount {
        retired: 20_000_000,
    };
    let choice_trap = Icount {
        retired: 70_000_000,
    };
    let choice_pause = Icount {
        retired: choice_trap.retired + SELECTABLE_NATIVE_HANDOFF_TICKS_PS,
    };
    let mut physical = Icount { retired: 0 };
    let mut ceilings = Vec::new();
    let mut events = Vec::new();

    loop {
        let ceiling = progress.next_ceiling(Icount {
            retired: 80_000_000,
        })?;
        ceilings.push(ceiling);
        let (at, outcome, idle_deadline) =
            if physical.retired == 0 && ceiling.retired < timer.retired {
                (
                    physical,
                    AdvanceOutcome::Paused { at: physical },
                    Some(timer),
                )
            } else if physical.retired == 0 {
                events.push(format!("timer@{}", timer.retired));
                (timer, AdvanceOutcome::ReachedHorizon, None)
            } else if physical == timer && ceiling.retired < choice_trap.retired {
                (
                    physical,
                    AdvanceOutcome::Paused { at: physical },
                    Some(choice_trap),
                )
            } else if physical == timer {
                (choice_trap, AdvanceOutcome::ReachedHorizon, None)
            } else {
                events.push(format!("choice@{}", choice_pause.retired));
                (
                    choice_pause,
                    AdvanceOutcome::Paused { at: choice_pause },
                    None,
                )
            };
        progress.observe(at, ceiling, outcome, idle_deadline)?;
        physical = at;
        if physical == choice_pause {
            break;
        }
    }

    Ok((
        CampaignHash::derive("guarded-replay-test-oracle", events.join("|").as_bytes()),
        ceilings,
    ))
}

#[test]
fn parked_replay_clips_timer_and_choice_and_matches_ten_microsecond_oracle()
-> Result<(), Box<dyn std::error::Error>> {
    let (reference_hash, reference_ceilings) =
        replay_parked_timer_then_choice(MAX_GUARDED_REPLAY_ADVANCE_ICOUNT)?;
    let (optimized_hash, optimized_ceilings) =
        replay_parked_timer_then_choice(MAX_GUARDED_REPLAY_PARKED_ADVANCE_ICOUNT)?;

    assert_eq!(optimized_hash, reference_hash);
    assert!(optimized_ceilings.len() < reference_ceilings.len());
    assert!(optimized_ceilings.contains(&Icount {
        retired: 20_000_000
    }));
    assert!(optimized_ceilings.contains(&Icount {
        retired: 70_000_000
    }));
    Ok(())
}

#[test]
fn inbound_wake_inside_parked_ceiling_resumes_runnable_cap()
-> Result<(), Box<dyn std::error::Error>> {
    let target = Icount {
        retired: 120_000_000,
    };
    let mut progress = ReplayPhysicalProgress::new(Icount { retired: 0 });
    let initial = progress.next_ceiling(target)?;
    progress.observe(
        Icount { retired: 0 },
        initial,
        AdvanceOutcome::Paused {
            at: Icount { retired: 0 },
        },
        Some(Icount {
            retired: 100_000_000,
        }),
    )?;

    let parked_ceiling = progress.next_ceiling(target)?;
    assert_eq!(parked_ceiling.retired, 100_000_000);
    progress.observe(
        Icount {
            retired: 40_000_000,
        },
        parked_ceiling,
        AdvanceOutcome::Paused {
            at: Icount {
                retired: 40_000_000,
            },
        },
        None,
    )?;

    assert_eq!(
        progress.next_ceiling(target)?,
        Icount {
            retired: 50_000_000
        }
    );
    Ok(())
}

#[test]
fn runnable_replay_keeps_ring_drain_cap_and_rejects_unrecorded_choice()
-> Result<(), Box<dyn std::error::Error>> {
    let (_, node, _) = replay_choice_fixture()?;
    let request = SelectablePlanPendingRequest::new(
        SelectionRequest::new(3, "campaign.recovery-policy", "unexpected", None, 256)?,
        300_000,
        15_000_000,
        0,
        0x3000,
    );
    let mut replay = ScriptedPhysicalReplay {
        node,
        upcoming: VecDeque::from([request]),
        pending: None,
        replies: Vec::new(),
        advances: Vec::new(),
        inputs: Vec::new(),
    };
    let mut progress = ReplayPhysicalProgress::new(Icount { retired: 0 });
    let first = progress.next_ceiling(Icount {
        retired: 100_000_000,
    })?;
    let first_advance = replay.advance_to_ceiling(Icount { retired: 0 }, first)?;
    progress.observe(
        first_advance.state,
        first,
        first_advance.outcome,
        first_advance.idle_deadline,
    )?;

    let second = progress.next_ceiling(Icount {
        retired: 100_000_000,
    })?;
    let second_advance = replay.advance_to_ceiling(first_advance.state, second)?;
    assert_eq!(first.retired, 10_000_000);
    assert_eq!(second.retired, 20_000_000);
    assert_eq!(second_advance.state.retired, 15_000_050);
    assert!(reject_unrecorded_local_request(&mut replay).is_err());
    assert!(replay.replies.is_empty());
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
