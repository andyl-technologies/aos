//! Actual World/IoCore and scheduler ownership with explicit physical models.
//!
//! The backend current callbacks model missing native Source/transport issuers.
//! These cases establish core transaction behavior, not physical activation.

// crucible-lint: allow panic-shortcut -- fixture refusals intentionally fail the test.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::scheduler::device_group_selection::DeviceGroupSelectionController;
use crate::{BackendDeviceGroupObservation, BackendDeviceGroupOwner};
use crucible_protocol::DeviceGroupOpportunity;

fn opportunity(ticks: u64) -> DeviceGroupOpportunity {
    let mut member = [0; 144];
    member[..4].copy_from_slice(&1_u32.to_le_bytes());
    member[4..8].copy_from_slice(&112_u32.to_le_bytes());
    member[8..16].copy_from_slice(&1_u64.to_le_bytes());
    let mut actor = [0; 112];
    actor[24..32].copy_from_slice(&1_u64.to_le_bytes());
    actor[32..64].copy_from_slice(&DIGEST);
    actor[72..80].copy_from_slice(&ticks.to_le_bytes());
    ok(DeviceGroupOpportunity::new(
        19,
        [101, 7, 11, 13],
        6,
        actor,
        vec![member],
    ))
}

const DIGEST: [u8; 32] = [
    228, 53, 130, 117, 117, 38, 30, 235, 11, 42, 85, 194, 26, 188, 12, 41, 21, 2, 85, 58, 165, 132,
    105, 159, 142, 192, 65, 139, 232, 103, 188, 159,
];

fn observed(
    scheduler: &SingleScheduler,
    queue: &IoCore,
    pipeline: &crucible_device::block::BlockFaultState,
) -> BackendDeviceGroupObservation {
    BackendDeviceGroupObservation::new(
        observation(scheduler, queue, pipeline),
        BackendDeviceGroupOwner::new(),
        BackendDeviceGroupOwner::new(),
        opportunity(scheduler.nodes[0].counter.ticks),
    )
}

#[test]
fn group_owner_preserves_actual_world_input_and_exact_reissue() {
    let (mut scheduler, queue, pipeline) = fixture();
    let observation = observed(&scheduler, &queue, &pipeline);
    ok(scheduler.import_initial_io_inventory(observation.input_inventory().clone()));
    let before = ok(ok(scheduler.checkpoint()).canonical_bytes());
    let mut controller = DeviceGroupSelectionController::default();
    let prepared = ok(controller.prepare(&scheduler, observation.clone()));
    let reissued = ok(controller.prepare(&scheduler, observation));

    assert!(prepared.retains_same_owner(&reissued));
    assert_eq!(
        prepared.input_inventory().next_input(),
        Some(NodeCounter { ticks: 30 })
    );
    assert_eq!(prepared.control_token().get(), 1);
    assert_ne!(prepared.context(), [0; 4]);
    assert_eq!(ok(ok(scheduler.checkpoint()).canonical_bytes()), before);
    assert!(scheduler.ceiling_publications.is_empty());
    ok(controller.current(&scheduler, &prepared));
}

#[test]
fn group_owner_keeps_armed_zero_and_refuses_unknown_native_input() {
    let (mut scheduler, queue, pipeline) = fixture();
    let mut input = observation(&scheduler, &queue, &pipeline);
    input.native_caps.input = BackendIoNativeCap::Armed(NodeCounter { ticks: 0 });
    ok(scheduler.import_initial_io_inventory(input.clone()));
    let observed = BackendDeviceGroupObservation::new(
        input.clone(),
        BackendDeviceGroupOwner::new(),
        BackendDeviceGroupOwner::new(),
        opportunity(0),
    );
    let mut controller = DeviceGroupSelectionController::default();
    let prepared = ok(controller.prepare(&scheduler, observed));
    assert_eq!(
        prepared.input_inventory().next_input(),
        Some(NodeCounter { ticks: 0 })
    );

    input.native_caps.input = BackendIoNativeCap::Unknown;
    let unknown = BackendDeviceGroupObservation::new(
        input,
        BackendDeviceGroupOwner::new(),
        BackendDeviceGroupOwner::new(),
        opportunity(0),
    );
    let mut fresh = DeviceGroupSelectionController::default();
    assert!(fresh.prepare(&scheduler, unknown).is_err());
    assert!(!fresh.is_retained());
}

#[test]
fn copied_bytes_cannot_replace_either_original_backend_owner() {
    let (mut scheduler, queue, pipeline) = fixture();
    let observation = observed(&scheduler, &queue, &pipeline);
    ok(scheduler.import_initial_io_inventory(observation.input_inventory().clone()));
    let mut controller = DeviceGroupSelectionController::default();
    let prepared = ok(controller.prepare(&scheduler, observation.clone()));
    for source in [true, false] {
        let replacement = BackendDeviceGroupObservation::new(
            observation.input_inventory().clone(),
            if source {
                BackendDeviceGroupOwner::new()
            } else {
                observation.source_owner().clone()
            },
            if source {
                observation.opportunity_owner().clone()
            } else {
                BackendDeviceGroupOwner::new()
            },
            observation.opportunity().clone(),
        );
        assert!(controller.prepare(&scheduler, replacement).is_err());
        ok(controller.current(&scheduler, &prepared));
    }
    let alias = BackendDeviceGroupObservation::new(
        observation.input_inventory().clone(),
        observation.source_owner().clone(),
        observation.source_owner().clone(),
        observation.opportunity().clone(),
    );
    assert!(
        DeviceGroupSelectionController::default()
            .prepare(&scheduler, alias)
            .is_err()
    );
}

#[test]
fn foreign_controller_and_changed_world_refuse_the_original_owner() {
    let (mut scheduler, queue, pipeline) = fixture();
    let observation = observed(&scheduler, &queue, &pipeline);
    ok(scheduler.import_initial_io_inventory(observation.input_inventory().clone()));
    let mut controller = DeviceGroupSelectionController::default();
    let prepared = ok(controller.prepare(&scheduler, observation.clone()));
    let mut fork = controller.clone();
    assert!(fork.is_retained());
    assert!(fork.current(&scheduler, &prepared).is_err());
    assert!(fork.prepare(&scheduler, observation).is_err());
    scheduler.nodes[0].counter = NodeCounter { ticks: 1 };
    assert!(controller.current(&scheduler, &prepared).is_err());
    assert!(controller.is_retained());
}

#[derive(Clone)]
struct GroupBackend {
    model: crate::MockSimulationBackend,
    original: BackendDeviceGroupObservation,
    calls: usize,
    refuse_at: Option<usize>,
    shutdown_refuses: bool,
    runs: usize,
    queue_calls: usize,
    queue_effects: usize,
    queued_owner: Option<crate::PreparedDeviceGroupSelection>,
    lose_first_queue_ack: bool,
    held: bool,
}

impl SimulationBackend for GroupBackend {
    fn observe_device_group_opportunity(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<BackendDeviceGroupObservation>, BackendError> {
        if node != &self.original.input_inventory().node {
            return Err(BackendError::Rejected {
                message: "foreign modeled node".into(),
            });
        }
        Ok(Some(self.original.clone()))
    }

    fn device_group_opportunity_current(
        &mut self,
        observation: &BackendDeviceGroupObservation,
    ) -> Result<(), BackendError> {
        self.calls += 1;
        if !self.held
            || self.refuse_at == Some(self.calls)
            || !observation
                .source_owner()
                .retains_same_owner(self.original.source_owner())
            || !observation
                .opportunity_owner()
                .retains_same_owner(self.original.opportunity_owner())
            || observation.input_inventory() != self.original.input_inventory()
            || observation.opportunity() != self.original.opportunity()
        {
            return Err(BackendError::Rejected {
                message: "modeled physical current refusal".into(),
            });
        }
        Ok(())
    }

    fn queue_device_group_selection(
        &mut self,
        prepared: &crate::PreparedDeviceGroupSelection,
    ) -> Result<(), BackendError> {
        self.queue_calls += 1;
        if let Some(original) = &self.queued_owner {
            if !original.retains_same_owner(prepared) {
                return Err(BackendError::Rejected {
                    message: "foreign modeled pending command".into(),
                });
            }
            return Ok(());
        }
        if !self.held {
            return Err(BackendError::Rejected {
                message: "missing modeled original physical Held".into(),
            });
        }
        self.queued_owner = Some(prepared.clone());
        self.queue_effects += 1;
        self.held = false;
        if self.lose_first_queue_ack {
            return Err(BackendError::Rejected {
                message: "modeled lost actual queued reply".into(),
            });
        }
        Ok(())
    }

    fn step_to(&mut self, at: VirtualTime) -> Result<crate::StepObservation, BackendError> {
        self.model.step_to(at)
    }
    fn apply(
        &mut self,
        effect: &crate::BackendEffect,
        at: VirtualTime,
    ) -> Result<(), BackendError> {
        self.model.apply(effect, at)
    }
    fn snapshot(&mut self) -> Result<crate::BackendSnapshot, BackendError> {
        self.model.snapshot()
    }
    fn restore(&mut self, snapshot: &crate::BackendSnapshot) -> Result<(), BackendError> {
        self.model.restore(snapshot)
    }
    fn now(&self) -> VirtualTime {
        self.model.now()
    }
    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
        self.model.fingerprint(node)
    }
    fn shutdown(&mut self) -> Result<(), BackendError> {
        if self.shutdown_refuses {
            return Err(BackendError::Rejected {
                message: "modeled shutdown refusal".into(),
            });
        }
        self.model.shutdown()
    }
}

impl crate::ConcurrentSimulationBackend for GroupBackend {
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<crate::ConcurrentBackendRun>,
        max_host_workers: usize,
    ) -> Result<Vec<crate::ConcurrentBackendRunResult>, BackendError> {
        self.runs += 1;
        self.model.execute_concurrent_runs(runs, max_host_workers)
    }
}

fn actor(refuse_at: Option<usize>) -> crate::BackendQuantumLoop<SingleScheduler, GroupBackend> {
    let (scheduler, queue, pipeline) = fixture();
    let original = observed(&scheduler, &queue, &pipeline);
    crate::BackendQuantumLoop::new(
        scheduler,
        GroupBackend {
            model: crate::MockSimulationBackend::new(),
            original,
            calls: 0,
            refuse_at,
            shutdown_refuses: false,
            runs: 0,
            queue_calls: 0,
            queue_effects: 0,
            queued_owner: None,
            lose_first_queue_ack: false,
            held: true,
        },
    )
}

#[test]
fn suffix_refusal_retains_original_selection_and_blocks_run_and_fixed_input() {
    let mut actor = actor(Some(2));
    assert!(actor.prepare_device_group_selection(&id("a")).is_err());
    assert!(actor.settle_current_fixed_input().is_err());
    let request = crate::QuantumRequest {
        configuration: actor.loop_impl().configuration().clone(),
        control: Vec::new(),
    };
    assert!(actor.drive_quantum(request).is_err());
    assert_eq!(actor.backend().runs, 0);
    actor.backend_mut().refuse_at = None;
    let prepared = ok(actor.prepare_device_group_selection(&id("a"))).unwrap();
    let reissued = ok(actor.prepare_device_group_selection(&id("a"))).unwrap();
    assert!(prepared.retains_same_owner(&reissued));
    ok(actor.device_group_selection_current(&prepared));
    assert!(actor.loop_impl().ceiling_publications.is_empty());
}

#[test]
fn unavailable_physical_prefix_never_registers_selection() {
    let mut actor = actor(Some(1));
    let before = ok(ok(actor.loop_impl().checkpoint()).canonical_bytes());
    assert!(actor.prepare_device_group_selection(&id("a")).is_err());
    assert_eq!(
        ok(ok(actor.loop_impl().checkpoint()).canonical_bytes()),
        before
    );
    actor.backend_mut().refuse_at = None;
    let prepared = ok(actor.prepare_device_group_selection(&id("a"))).unwrap();
    assert_eq!(prepared.control_token().get(), 1);
}

#[test]
fn selection_current_requires_backend_suffix_and_retains_shutdown_refusal() {
    let mut actor = actor(None);
    let prepared = ok(actor.prepare_device_group_selection(&id("a"))).unwrap();
    actor.backend_mut().refuse_at = Some(3);
    assert!(actor.device_group_selection_current(&prepared).is_err());
    actor.backend_mut().refuse_at = None;
    ok(actor.device_group_selection_current(&prepared));
    actor.backend_mut().shutdown_refuses = true;
    assert!(actor.shutdown().is_err());
    assert!(actor.prepare_device_group_selection(&id("a")).is_err());
    assert!(actor.device_group_selection_current(&prepared).is_err());
    actor.backend_mut().shutdown_refuses = false;
    ok(actor.shutdown());
    assert!(actor.device_group_selection_current(&prepared).is_err());
}

#[test]
fn missing_backend_provider_refuses_even_well_formed_public_descriptor() {
    let (scheduler, _, _) = fixture();
    let mut actor = crate::BackendQuantumLoop::new(scheduler, crate::MockSimulationBackend::new());
    assert!(actor.prepare_device_group_selection(&id("a")).is_err());
}

#[test]
fn incomplete_world_or_mismatched_actor_refuses_before_selection_publication() {
    for incomplete in [true, false] {
        let mut actor = actor(None);
        let original = actor.backend().original.clone();
        let mut input = original.input_inventory().clone();
        if incomplete {
            input.queues.clear();
        }
        actor.backend_mut().original = BackendDeviceGroupObservation::new(
            input,
            original.source_owner().clone(),
            original.opportunity_owner().clone(),
            if incomplete {
                original.opportunity().clone()
            } else {
                opportunity(1)
            },
        );
        let before = ok(ok(actor.loop_impl().checkpoint()).canonical_bytes());
        assert!(actor.prepare_device_group_selection(&id("a")).is_err());
        assert_eq!(
            ok(ok(actor.loop_impl().checkpoint()).canonical_bytes()),
            before
        );
        assert!(actor.loop_impl().ceiling_publications.is_empty());
        actor.backend_mut().original = original;
        let prepared = ok(actor.prepare_device_group_selection(&id("a"))).unwrap();
        assert_eq!(prepared.control_token().get(), 1);
    }
}

#[test]
fn retained_selection_blocks_control_and_survives_a_foreign_loop_clone() {
    let mut actor = actor(None);
    let prepared = ok(actor.prepare_device_group_selection(&id("a"))).unwrap();
    let before = ok(ok(actor.loop_impl().checkpoint()).canonical_bytes());
    assert!(actor.apply_control_at_boundary(Vec::new()).is_err());
    assert_eq!(
        ok(ok(actor.loop_impl().checkpoint()).canonical_bytes()),
        before
    );
    let mut fork = actor.clone();
    assert!(fork.device_group_selection_current(&prepared).is_err());
    assert!(fork.prepare_device_group_selection(&id("a")).is_err());
    ok(actor.device_group_selection_current(&prepared));
}

#[test]
fn publication_joins_original_loop_and_caches_actual_queue_ack_once() {
    let mut actor = actor(None);
    let prepared = ok(actor.prepare_device_group_selection(&id("a"))).unwrap();
    let mut fork = actor.clone();
    assert!(fork.publish_device_group_selection(&prepared).is_err());
    assert_eq!(fork.backend().queue_calls, 0);
    assert_eq!(
        ok(actor.publish_device_group_selection(&prepared)),
        crate::DeviceGroupSelectionPublication::Queued
    );
    assert!(!actor.backend().held);
    assert!(actor.device_group_selection_current(&prepared).is_err());
    assert_eq!(
        ok(actor.publish_device_group_selection(&prepared)),
        crate::DeviceGroupSelectionPublication::Queued
    );
    assert_eq!(actor.backend().queue_calls, 1);
    assert_eq!(actor.backend().queue_effects, 1);
}

#[test]
fn uncertain_publication_retains_original_pending_owner_after_held_ends() {
    let mut actor = actor(None);
    let prepared = ok(actor.prepare_device_group_selection(&id("a"))).unwrap();
    actor.backend_mut().lose_first_queue_ack = true;
    assert!(actor.publish_device_group_selection(&prepared).is_err());
    assert!(!actor.backend().held);
    assert!(actor.prepare_device_group_selection(&id("a")).is_err());
    assert_eq!(
        ok(actor.publish_device_group_selection(&prepared)),
        crate::DeviceGroupSelectionPublication::Queued
    );
    assert_eq!(actor.backend().queue_calls, 2);
    assert_eq!(actor.backend().queue_effects, 1);
    ok(actor.publish_device_group_selection(&prepared));
    assert_eq!(actor.backend().queue_calls, 2);
    assert!(actor.apply_control_at_boundary(Vec::new()).is_err());
}

#[test]
fn unavailable_first_publication_current_refuses_before_queue_effects() {
    let mut actor = actor(None);
    let prepared = ok(actor.prepare_device_group_selection(&id("a"))).unwrap();
    actor.backend_mut().held = false;
    assert!(actor.publish_device_group_selection(&prepared).is_err());
    assert_eq!(actor.backend().queue_calls, 0);
    assert_eq!(actor.backend().queue_effects, 0);
    actor.backend_mut().held = true;
    ok(actor.publish_device_group_selection(&prepared));
    assert_eq!(actor.backend().queue_effects, 1);
}
