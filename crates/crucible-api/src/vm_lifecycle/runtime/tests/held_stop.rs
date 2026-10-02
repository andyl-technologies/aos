//! Production reply settlement and canonical retained-peer publication.

use super::*;
use crucible::{AppRandomSelectable, BackendRngEvidence, RngStreamId};
use crucible_protocol::SelectableRegister;
use crucible_qemu::{
    QemuTestHotForkOutcome, QemuTestQuantumBoundary, scripted_hot_fork_source_with_script_for_test,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn stopped_lifecycle(
    peers: usize,
) -> Result<ProductionVmLifecycleLoop, Box<dyn std::error::Error>> {
    stopped_lifecycle_with_kind(peers, false)
}

fn stopped_lifecycle_with_kind(
    peers: usize,
    marker: bool,
) -> Result<ProductionVmLifecycleLoop, Box<dyn std::error::Error>> {
    let mut source = nonterminal_signal_replay_scenario();
    if marker {
        let declarations = crucible::model::ScenarioSelectables::new(
            source.world(),
            crucible::model::ScenarioSelectableLimits::default(),
            vec![crucible::NetworkFaultSelectable::declaration()?],
        )?;
        source = source.with_selectables(declarations)?;
    }
    let mut lifecycle = production_loop_without_backends(&source);
    let scenario = SchedulerLivenessScenario::from_runnable_world(
        &source.scenario_def().id().to_hex(),
        5_000,
        SimInstant { ticks: 100_000 },
        0,
        source.world(),
    )
    .with_scenario_def(source.scenario_def());
    let mut scheduler = SingleScheduler::new(scenario)?;
    let mut nodes = QemuNodeSet::new();
    for (index, vm) in source.world().vm_nodes().iter().enumerate() {
        if index > peers {
            scheduler.set_vm_node_activity(&vm.id, SchedulerNodeActivity::Done)?;
            continue;
        }
        scheduler.set_vm_node_activity(&vm.id, SchedulerNodeActivity::Runnable)?;
        let declaration = SelectablePlanDeclaration::new(
            "app.random",
            vec![1, 2],
            vec![1],
            vec![String::from("test")],
            SelectablePlanPresence::Required,
        )?;
        let mut plan = SelectableCatalogPlan::new(
            SelectablePlanLimits::new(1, 8, 8)?,
            vec![declaration],
            SelectablePlanContinuation::cold(),
        )?;
        plan.apply_registration(&SelectableRegister::new(
            1,
            "app.random",
            vec![1, 2],
            vec![1],
            vec![String::from("test")],
        )?)?;
        plan.apply_freeze()?;
        let pending = SelectablePlanPendingRequest::new(
            SelectionRequest::new(7, "app.random", "pairing", None, 192)?,
            0,
            0,
            0,
            0x1000,
        );
        let mut backend = scripted_hot_fork_source_with_script_for_test(
            QemuTestHotForkOutcome::Forked,
            if marker {
                vec![ObservableEvent::guest_marker(
                    Icount { retired: 0 },
                    vm.id.clone(),
                    crucible::MarkerId::from_name("fault.transport.ready"),
                )]
            } else {
                Vec::new()
            },
            if marker { None } else { Some(plan) },
            if marker {
                VecDeque::new()
            } else {
                VecDeque::from([pending])
            },
            VecDeque::from([QemuTestQuantumBoundary::Paused {
                at: 50,
                next_deadline: None,
            }]),
        )?;
        backend.bind_scripted_io_inventory_for_test(source.world(), &vm.id)?;
        nodes.insert(vm.id.clone(), backend);
    }
    let network = lifecycle.inner.network_output_interceptor().clone();
    lifecycle.inner =
        BackendQuantumLoop::with_network_output_interceptor(scheduler, nodes, network);
    lifecycle.initial_lifecycle_observations_pending = false;
    let request = QuantumRequest {
        configuration: lifecycle.inner.loop_impl().configuration().clone(),
        control: Vec::new(),
    };
    let outcomes = crucible_session::drive_engine_concurrent_quantum(
        &mut lifecycle.inner,
        request,
        peers + 1,
    )?;
    assert!(!outcomes.outcomes.is_empty());
    assert!(lifecycle.inner.held_host_stop_witness().is_some());
    Ok(lifecycle)
}

fn reply_for(
    lifecycle: &ProductionVmLifecycleLoop,
    pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
) -> Result<
    (
        Configuration,
        SelectionDecision,
        Configuration,
        SelectionReply,
    ),
    Box<dyn std::error::Error>,
> {
    let parent = lifecycle.inner.loop_impl().configuration().clone();
    let evidence = BackendRngEvidence {
        node: pending.node().clone(),
        stream: RngStreamId::from_name(format!(
            "app-random/node:{}:{}/stream:7:pairing",
            pending.node().name.len(),
            pending.node().name
        )),
        request_id: 19,
        width: 64,
        value: 7,
    };
    let selection =
        AppRandomSelectable::from_decision(&parent.def, &evidence)?.branch_selection(&parent, 7)?;
    let reply = SelectionReply::selected(
        pending.pending().request().sequence(),
        selection.opportunity().content_id().digest(),
        selection.domain().content_id().digest(),
        selection.value().canonical_bytes(),
    )?;
    let decision = SelectionDecision::new(&selection);
    let selected = try_step(&parent, Decision::Selection(decision.clone()))?;
    Ok((parent, decision, selected, reply))
}

#[test]
fn production_reply_releases_zero_peer_hold_before_network_settlement() -> TestResult {
    let mut lifecycle = stopped_lifecycle(0)?;
    let pending = lifecycle.drain_pending_selectable_requests()?.remove(0);
    let (parent, decision, selected, reply) = reply_for(&lifecycle, &pending)?;
    assert!(
        lifecycle
            .inner
            .settle_pending_network_outputs_at_current_frontier()
            .is_err()
    );

    assert!(lifecycle.capture_checkpoint(&parent).is_err());
    assert!(lifecycle.capture_hot_fork_world_continuation().is_err());
    let entries =
        lifecycle.apply_selectable_reply(&parent, decision, &selected, &pending, &reply)?;

    assert!(!entries.is_empty());
    assert!(!lifecycle.inner.has_unsettled_host_continuation());
    assert!(lifecycle.pending_held_host_outcomes.is_none());
    lifecycle
        .inner
        .settle_pending_network_outputs_at_current_frontier()?;
    lifecycle.shutdown()?;
    Ok(())
}

#[test]
fn production_network_preselection_hides_requests_without_consuming_them() -> TestResult {
    let mut stopped = stopped_lifecycle(0)?;
    let pending = stopped.drain_pending_selectable_requests()?.remove(0);
    let (parent, decision, selected, reply) = reply_for(&stopped, &pending)?;
    let mut lifecycle = production_queued_broadcast_lifecycle();
    let configuration = lifecycle.inner.loop_impl().configuration().clone();
    lifecycle.drive_quantum(QuantumRequest {
        configuration,
        control: Vec::new(),
    })?;
    let choice = lifecycle
        .live_network_preselection()
        .ok_or("network preselection absent")?;

    // Move the original paused backend and its retained request together; the
    // reader must leave that physical capability private during this reservation.
    std::mem::swap(stopped.inner.backend_mut(), lifecycle.inner.backend_mut());
    let queued = lifecycle.inner.pending_network_output_count();
    let offset = lifecycle.inner.loop_impl().event_log_offset();

    assert!(lifecycle.drain_pending_selectable_requests()?.is_empty());
    assert!(lifecycle.drain_pending_selectable_requests()?.is_empty());
    assert!(
        lifecycle
            .apply_selectable_reply(&parent, decision, &selected, &pending, &reply)
            .is_err()
    );

    assert_eq!(lifecycle.live_network_preselection(), Some(choice.clone()));
    assert_eq!(lifecycle.inner.pending_network_output_count(), queued);
    assert_eq!(lifecycle.inner.loop_impl().event_log_offset(), offset);
    assert_eq!(
        lifecycle
            .inner
            .backend_mut()
            .drain_pending_selectable_requests()?,
        vec![pending]
    );
    std::mem::swap(stopped.inner.backend_mut(), lifecycle.inner.backend_mut());
    lifecycle.handoff_live_network_preselection(&choice)?;
    lifecycle.shutdown()?;
    stopped.shutdown()?;
    Ok(())
}

#[test]
fn production_reply_keeps_peer_request_private_until_once_only_publication() -> TestResult {
    let mut lifecycle = stopped_lifecycle(1)?;
    assert_eq!(
        lifecycle
            .inner
            .backend_mut()
            .drain_pending_selectable_requests()?
            .len(),
        2
    );
    let pending = lifecycle.drain_pending_selectable_requests()?;
    assert_eq!(pending.len(), 1);
    let pending = &pending[0];
    let (parent, decision, selected, reply) = reply_for(&lifecycle, pending)?;

    lifecycle.apply_selectable_reply(&parent, decision, &selected, pending, &reply)?;
    assert!(lifecycle.pending_held_host_outcomes.is_some());
    assert!(lifecycle.capture_checkpoint(&selected).is_err());
    assert!(lifecycle.capture_hot_fork_world_continuation().is_err());
    assert!(lifecycle.drain_pending_selectable_requests()?.is_empty());
    let quanta = lifecycle.completed_quanta();
    let outcome = lifecycle.drive_quantum(QuantumRequest {
        configuration: selected,
        control: Vec::new(),
    })?;

    assert!(lifecycle.pending_held_host_outcomes.is_none());
    assert_eq!(lifecycle.completed_quanta(), quanta);
    assert_eq!(
        outcome.configuration,
        *lifecycle.inner.loop_impl().configuration()
    );
    let peer = lifecycle.drain_pending_selectable_requests()?;
    assert_eq!(peer.len(), 1);
    assert_ne!(peer[0].node(), pending.node());
    let (parent, decision, selected, reply) = reply_for(&lifecycle, &peer[0])?;
    lifecycle.apply_selectable_reply(&parent, decision, &selected, &peer[0], &reply)?;
    assert!(lifecycle.pending_held_host_outcomes.is_none());
    lifecycle
        .inner
        .settle_pending_network_outputs_at_current_frontier()?;
    lifecycle.shutdown()?;
    Ok(())
}

#[test]
fn production_reply_refusal_retains_original_stop_and_request() -> TestResult {
    let mut lifecycle = stopped_lifecycle(0)?;
    let witness = lifecycle
        .inner
        .held_host_stop_witness()
        .ok_or("held stop absent")?;
    let pending = lifecycle.drain_pending_selectable_requests()?.remove(0);
    let (parent, decision, selected, reply) = reply_for(&lifecycle, &pending)?;
    let stale = crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(
        pending.node().clone(),
        SelectablePlanPendingRequest::new(pending.pending().request().clone(), 0, 0, 0, 0x2000),
    );

    assert!(
        lifecycle
            .apply_selectable_reply(&parent, decision.clone(), &selected, &stale, &reply)
            .is_err()
    );
    lifecycle.inner.validate_held_host_stop(&witness)?;
    assert_eq!(lifecycle.drain_pending_selectable_requests()?.len(), 1);
    lifecycle.apply_selectable_reply(&parent, decision, &selected, &pending, &reply)?;
    assert!(!lifecycle.inner.has_unsettled_host_continuation());
    lifecycle.shutdown()?;
    Ok(())
}

#[test]
fn production_pending_pause_uses_admitted_clock_mapping() -> TestResult {
    let source = nonterminal_signal_replay_scenario();
    let mut lifecycle = production_loop_without_backends(&source);
    let node = source
        .world()
        .vm_nodes()
        .iter()
        .next()
        .ok_or("test World has no VM")?
        .id
        .clone();
    lifecycle
        .inner
        .loop_impl_mut()
        .rebase_restarted_backend_counter(&node, crucible::NodeCounter { ticks: 1_000 })?;
    let pending = crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(
        node,
        SelectablePlanPendingRequest::new(
            SelectionRequest::new(7, "app.random", "pairing", None, 192)?,
            20,
            1_000,
            0,
            0x1000,
        ),
    );

    assert_eq!(
        lifecycle.pending_selectable_request_time(&pending)?,
        VirtualTime { ticks: 50 }
    );
    Ok(())
}

struct PublicationBoundaryLauncher {
    checks: usize,
}

impl ProductionVmNodeLauncher for PublicationBoundaryLauncher {
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        self.checks += 1;
        if self.checks == 2 {
            return Err(loop_factory_error(
                "injected post-publication operational refusal",
            ));
        }
        Ok(())
    }

    fn launch_fresh(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _qemu: &Path,
        _root: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(loop_factory_error(
            "publication test cannot launch another process",
        ))
    }

    fn launch_restored(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _admission: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(loop_factory_error(
            "publication test cannot restore another process",
        ))
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(loop_factory_error(
            "publication test cannot mint a replay owner",
        ))
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }
}

#[test]
fn production_peer_publication_failure_retains_evidence_and_refuses_republication() -> TestResult {
    let mut lifecycle = stopped_lifecycle(1)?;
    let pending = lifecycle.drain_pending_selectable_requests()?.remove(0);
    let (parent, decision, selected, reply) = reply_for(&lifecycle, &pending)?;
    lifecycle.apply_selectable_reply(&parent, decision, &selected, &pending, &reply)?;
    let retained = lifecycle
        .pending_held_host_outcomes
        .as_ref()
        .ok_or("peer outcomes absent")?
        .outcomes
        .clone();
    lifecycle.trigger_graph = EventGraph::builder()
        .event("publication-effect")
        .when(crucible::Condition::at(
            lifecycle.inner.loop_impl().frontier(),
        ))
        .action(Action::arm_timer(
            crucible::TimerId {
                name: String::from("published"),
            },
            SimDuration { ticks: 10 },
        ))
        .build_for_world(&lifecycle.trigger_world)?;
    lifecycle.node_launcher = Box::new(PublicationBoundaryLauncher { checks: 0 });
    let request = QuantumRequest {
        configuration: selected,
        control: Vec::new(),
    };
    let before = lifecycle.inner.loop_impl().event_log_offset();

    assert!(lifecycle.drive_quantum(request.clone()).is_err());
    let after = lifecycle.inner.loop_impl().event_log_offset();
    assert!(after.events > before.events);
    assert_eq!(
        lifecycle
            .pending_held_host_outcomes
            .as_ref()
            .ok_or("failed publication lost evidence")?
            .outcomes,
        retained
    );
    let error = lifecycle
        .drive_quantum(request)
        .err()
        .ok_or("failed publication was retried")?;
    assert!(error.to_string().contains("retirement is required"));
    assert_eq!(lifecycle.inner.loop_impl().event_log_offset(), after);
    assert!(lifecycle.drain_pending_selectable_requests()?.is_empty());
    assert!(!lifecycle.exact_checkpoint_ready()?);
    let current = lifecycle.inner.loop_impl().configuration().clone();
    assert!(lifecycle.capture_checkpoint(&current).is_err());
    assert!(lifecycle.capture_hot_fork_world_continuation().is_err());
    lifecycle.shutdown()?;
    Ok(())
}

#[test]
fn production_marker_release_settles_zero_peer_hold_and_retains_refused_park() -> TestResult {
    let mut lifecycle = stopped_lifecycle_with_kind(0, true)?;
    let witness = lifecycle
        .inner
        .held_host_stop_witness()
        .ok_or("marker hold absent")?;
    assert_eq!(witness.kind(), crucible::HeldHostStopKind::CampaignMarker);
    let node = witness.node().clone();
    let parent = lifecycle.inner.loop_impl().configuration().clone();
    let selectable = crucible::NetworkFaultSelectable::next(
        &lifecycle.source,
        &parent,
        crucible::NetworkFaultPhase::First,
        lifecycle.inner.loop_impl().frontier(),
        &[],
    )?
    .ok_or("network selectable absent")?;
    let value =
        crucible::NetworkFaultSelectable::selected_value("link_down", "primary", 1_000, 0, 0)?;
    let branch = selectable.resolve_branch(&selectable.branch_selection(value)?)?;
    let selected = branch.selected().id();
    let replay =
        crucible::NetworkFaultCampaignReplayPlan::new(branch.selected().clone(), vec![branch])?;
    lifecycle
        .inner
        .network_transaction_parts_mut()
        .2
        .install_campaign_replay(Some(replay), None)?;

    assert!(
        lifecycle
            .release_parked_campaign_marker(&node, "fault.followup.ready", selected)
            .is_err()
    );
    assert!(
        lifecycle
            .release_parked_campaign_marker(
                &node,
                "fault.transport.ready",
                ContentHash::from_bytes(b"foreign")
            )
            .is_err()
    );
    lifecycle.inner.validate_held_host_stop(&witness)?;
    assert!(lifecycle.parked_campaign_marker(&node)?.is_some());
    assert!(!lifecycle.campaign_marker_release_committed(&node, "fault.transport.ready", selected));

    lifecycle.release_parked_campaign_marker(&node, "fault.transport.ready", selected)?;

    assert!(!lifecycle.inner.has_unsettled_host_continuation());
    assert!(lifecycle.parked_campaign_marker(&node)?.is_none());
    assert!(lifecycle.campaign_marker_release_committed(&node, "fault.transport.ready", selected));
    assert!(
        lifecycle
            .release_parked_campaign_marker(&node, "fault.transport.ready", selected)
            .is_err()
    );
    lifecycle
        .inner
        .settle_pending_network_outputs_at_current_frontier()?;
    lifecycle.shutdown()?;
    Ok(())
}
