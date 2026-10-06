//! Independent control during a genuine authenticated, fault-blocked page read.
//!
//! The existing admitted source worker holds a real page and proof before its
//! response. While the guest waits in userfaultfd and the lifecycle waits for
//! its original quantum, that worker uses the independent controller to update
//! policy or shorten the original cap. No additional thread, root, deadline or
//! native control arena is manufactured by this fixture.

use super::super::hot_fork_native::{enqueue_promoted_resume, fork_resources, native_repository};
use super::accepted_promotion::{extend_native_operations, promote_accepted_checkpoint};
use super::lazy_restore::discover_target;
use super::*;
use crate::packaged_qemu_executor::hot_fork::retained_service::RetainedTemplateServiceFactory;
use crate::packaged_qemu_executor::preparation::PackagedPreparation;
use crate::{
    AttemptExecutionInput, AttemptExecutionModel, AttemptExecutionProduct, RepositoryAttemptWorker,
    decode_crucible_attempt_execution,
};
use crucible_api::host_operational::{HostOuterCapTarget, HostResourceVector};
use crucible_api::vm_lifecycle::ProductionRamSourceDecorator;
use crucible_campaign::CampaignExecutorStore;
use crucible_linux_resource::host_supervision::{HostOperationState, HostOperationSupervisor};
use crucible_qemu::ram_source::{QemuRamBacking, QemuRamSourceError};
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Reference,
    Policy,
    Expiry,
    Cancellation,
}

struct Action {
    case: Case,
    target: HostRamTarget,
    cap: HostOuterCapTarget,
    supervisor: HostOperationSupervisor,
    cancellation: ExecutionCancellation,
}

#[derive(Debug)]
struct HeldEvidence {
    region_ordinal: usize,
    page_index: u64,
    policy_accepted: bool,
    cap_amendment_accepted: bool,
    original_anchor_preserved: bool,
    late_completion_refused: bool,
    installed_before_response: u64,
}

#[derive(Default)]
struct GateState {
    action: Option<Action>,
    evidence: Option<HeldEvidence>,
}

struct SourceGate {
    registry: crate::HostOperationalRegistry,
    state: Mutex<GateState>,
    // The actual namespace loan precedes these allocations and outlives every
    // backing wrapper, including an uncertain source-worker terminal outcome.
    _credit: Arc<dyn Send + Sync>,
}

// The decorator itself shares the precharged gate; no read clones the root or
// the page/proof. The returned tuple remains owned by the original source call.
struct GateDecorator(Arc<SourceGate>);

impl ProductionRamSourceDecorator for GateDecorator {
    fn decorate(
        &self,
        backing: Arc<dyn QemuRamBacking>,
    ) -> Result<Arc<dyn QemuRamBacking>, QemuRamSourceError> {
        Ok(Arc::new(HeldBacking {
            backing,
            gate: Arc::clone(&self.0),
        }))
    }
}

struct HeldBacking {
    backing: Arc<dyn QemuRamBacking>,
    gate: Arc<SourceGate>,
}

impl QemuRamBacking for HeldBacking {
    fn root_object_id(&self) -> &str {
        self.backing.root_object_id()
    }

    fn root_record(&self) -> &crucible_ram::RootRecord {
        self.backing.root_record()
    }

    fn read_page_with_proof(
        &self,
        region: &str,
        page: u64,
        boundary: &mut dyn FnMut() -> Result<(), QemuRamSourceError>,
    ) -> Result<(Vec<u8>, crucible_ram::PageProof), QemuRamSourceError> {
        let result = self.backing.read_page_with_proof(region, page, boundary)?;
        let action = self
            .gate
            .state
            .lock()
            .map_err(|_| QemuRamSourceError::Ownership)?
            .action
            .take();
        if let Some(action) = action {
            let ordinal = self
                .root_record()
                .topology()
                .regions()
                .iter()
                .position(|candidate| candidate.id() == region)
                .ok_or(QemuRamSourceError::Ownership)?;
            self.gate
                .control_while_held(action, ordinal, page, boundary)?;
        }
        boundary()?;
        Ok(result)
    }
}

impl SourceGate {
    fn control_while_held(
        &self,
        action: Action,
        region_ordinal: usize,
        page_index: u64,
        boundary: &mut dyn FnMut() -> Result<(), QemuRamSourceError>,
    ) -> Result<(), QemuRamSourceError> {
        boundary()?;
        let before = status(&self.registry, action.target);
        let original_page_operation = before
            .outstanding_operations
            .iter()
            .find(|operation| {
                operation.class == HostOperationClass::PageIn
                    && operation.state == HostOperationState::Running
            })
            .expect("the genuinely held request retains its original PageIn guard");
        let installed_before_response = before
            .activity
            .expect("live fault counters")
            .successful_missing_installs;
        let anchor = action.supervisor.outer_cap_binding()?.original_monotonic_ns;
        let mut evidence = HeldEvidence {
            region_ordinal,
            page_index,
            policy_accepted: false,
            cap_amendment_accepted: false,
            original_anchor_preserved: false,
            late_completion_refused: false,
            installed_before_response,
        };

        match action.case {
            Case::Reference => {}
            Case::Policy => {
                let mut policy = before.requested_policy;
                policy.latency.classes[HostOperationClass::PageIn as usize] =
                    HostOperationBudget::finite(Duration::from_secs(301));
                let response = self
                    .registry
                    .execute(
                        OPERATOR,
                        HostOperationalRequest::UpdatePolicy {
                            target: action.target,
                            expected_policy_revision: before.policy_revision,
                            idempotency_key: [0xb1; 32],
                            policy: Box::new(policy),
                            reservation_amendment: None,
                        },
                    )
                    .expect("live independent policy update while UFFD is blocked");
                evidence.policy_accepted = matches!(
                    &*response,
                    HostOperationalResponse::PolicyUpdate {
                        disposition: HostOperationalDisposition::Accepted,
                        ..
                    }
                );
                assert!(evidence.policy_accepted);
                let after = status(&self.registry, action.target);
                assert_eq!(after.policy_revision, before.policy_revision + 1);
                assert_eq!(after.reservation_revision, before.reservation_revision);
                assert_eq!(after.admitted_resources, before.admitted_resources);
                let still_held = after
                    .outstanding_operations
                    .iter()
                    .find(|operation| {
                        operation.operation_id == original_page_operation.operation_id
                    })
                    .expect("live tuning retains the original held PageIn operation");
                assert_eq!(
                    still_held.started_policy_revision,
                    original_page_operation.started_policy_revision
                );
                assert!(
                    still_held.applied_policy_revision
                        > original_page_operation.applied_policy_revision
                );
                assert_eq!(
                    after
                        .activity
                        .expect("live blocked counters")
                        .successful_missing_installs,
                    installed_before_response
                );
            }
            Case::Expiry => {
                let cap = action.supervisor.outer_cap_status()?;
                let response = self
                    .registry
                    .execute(
                        OPERATOR,
                        HostOperationalRequest::AmendOuterCap {
                            target: action.cap,
                            expected_cap_revision: cap.revision,
                            idempotency_key: [0xb2; 32],
                            allowance: Some(Duration::from_nanos(1)),
                        },
                    )
                    .expect("broadcast original-start expiry while UFFD is blocked");
                evidence.cap_amendment_accepted = matches!(
                    &*response,
                    HostOperationalResponse::OuterCapAmendment {
                        disposition: HostOperationalDisposition::Accepted,
                        ..
                    }
                );
                assert!(evidence.cap_amendment_accepted);
                assert_eq!(
                    action.supervisor.outer_cap_status()?.state,
                    HostOperationState::Expired
                );
            }
            Case::Cancellation => {
                action.cancellation.cancel();
                action.supervisor.cancel()?;
                assert_eq!(
                    action.supervisor.outer_cap_status()?.state,
                    HostOperationState::Canceled
                );
            }
        }
        evidence.original_anchor_preserved =
            action.supervisor.outer_cap_binding()?.original_monotonic_ns == anchor;
        assert!(evidence.original_anchor_preserved);

        if matches!(action.case, Case::Expiry | Case::Cancellation) {
            // A deliberately held completion outlasts terminal authority. This
            // delay neither renews a guard nor reports progress. The original
            // boundary must refuse before a page response can be published.
            std::thread::sleep(Duration::from_millis(20));
            let refusal = boundary();
            evidence.late_completion_refused = refusal.is_err();
            assert!(evidence.late_completion_refused);
            self.state
                .lock()
                .map_err(|_| QemuRamSourceError::Ownership)?
                .evidence = Some(evidence);
            return refusal;
        }
        self.state
            .lock()
            .map_err(|_| QemuRamSourceError::Ownership)?
            .evidence = Some(evidence);
        boundary()
    }
}

struct LaneEvidence {
    boundary: Option<Boundary>,
    held: HeldEvidence,
}

#[test]
#[ignore = "requires isolated native paging VM, authenticated cold restore and original Service control"]
fn production_blocked_pager_control_preserves_identity_and_refuses_late_completion() {
    let source = paging_scenario();
    let reference = run_lane(&source, Case::Reference, "blocked-reference", 61_000);
    let policy = run_lane(&source, Case::Policy, "blocked-policy", 61_100);
    let expiry = run_lane(&source, Case::Expiry, "blocked-expiry", 61_200);
    let cancel = run_lane(&source, Case::Cancellation, "blocked-cancel", 61_300);
    assert_eq!(reference.boundary, policy.boundary);
    assert!(policy.held.policy_accepted);
    assert!(expiry.held.cap_amendment_accepted);
    assert!(expiry.held.late_completion_refused);
    assert!(cancel.held.late_completion_refused);
    for lane in [&reference, &policy, &expiry, &cancel] {
        assert!(lane.held.original_anchor_preserved);
        println!(
            "blocked_pager_coordinate={}:{}",
            lane.held.region_ordinal, lane.held.page_index
        );
        println!(
            "blocked_pager_installs_before_response={}",
            lane.held.installed_before_response
        );
    }
    println!("blocked_pager_live_policy_identity=true");
    println!("blocked_pager_original_cap_expiry=true");
    println!("blocked_pager_cancellation_before_response=true");
    println!("blocked_pager_late_completion_refused=true");
    println!("blocked_pager_full_vector_cleanup=true");
    println!("BLOCKED_PAGER_NATIVE_PASS");
}

fn available(prepared: &PackagedPreparation) -> HostResourceVector {
    prepared
        .actor
        .with_supervisor(|actor| {
            actor
                .host_resource_availability()
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)
        })
        .expect("genuine all-eight resource accounting")
}

fn run_lane(source: &ScenarioDefForm, case: Case, lane: &str, project: u32) -> LaneEvidence {
    environment::with_native_repository_environment(
        lane,
        project,
        |root, storage| native_repository(source, root, storage),
        fork_resources,
        |prepared, config, repository| {
            let capacity = available(prepared);
            let promoted =
                promote_accepted_checkpoint(prepared, config, Arc::clone(&repository), source);
            assert_eq!(available(prepared), capacity);
            let queued = enqueue_promoted_resume(
                prepared,
                &promoted,
                AssignmentId::from_bytes(
                    [match case {
                        Case::Reference => 0xb0,
                        Case::Policy => 0xb1,
                        Case::Expiry => 0xb2,
                        Case::Cancellation => 0xb3,
                    }; 16],
                )
                .expect("fresh resumed assignment"),
            );
            let store = CampaignExecutorStore::new(Arc::clone(&repository));
            let mut worker = RepositoryAttemptWorker::new(
                store.clone(),
                ControlModel {
                    store,
                    repository,
                    config: config.clone(),
                    prepared,
                    case,
                    checkpoint: promoted.checkpoint,
                    evidence: None,
                },
            );
            let (queued, outcome) = worker.execute(queued).into_parts();
            assert!(matches!(outcome, Err(AttemptWorkerFailure::Canceled(_))));
            prepared
                .actor
                .with_supervisor(|actor| {
                    actor
                        .stage_and_reconcile_cancellation(&queued)
                        .map_err(|_| {
                            crucible_api::host_operational::HostOperationalError::Unavailable
                        })
                })
                .expect("durable cancellation only after physical cleanup");
            assert_eq!(available(prepared), capacity);
            worker
                .model_mut()
                .evidence
                .take()
                .expect("actual held-page evidence")
        },
    )
}

struct ControlModel<'a> {
    store: CampaignExecutorStore,
    repository: Arc<CampaignRepository>,
    config: PackagedQemuExecutorConfig,
    prepared: &'a PackagedPreparation,
    case: Case,
    checkpoint: ExactCheckpointId,
    evidence: Option<LaneEvidence>,
}

impl AttemptExecutionModel for ControlModel<'_> {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        extend_native_operations(context);
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("authenticated actual resumed scenario");
        let original_available = available(self.prepared);
        let mut selected = context.take_selected_checkpoint();
        let service = RetainedTemplateServiceFactory::new(self.prepared, &self.config)
            .start_for_resume(input.scenario(), self.checkpoint, context, &mut selected)
            .expect("fresh Service consumes genuine accepted selection once");
        assert!(selected.is_none());
        extend_native_operations(service.context());
        let authority = self
            .repository
            .blob_backend()
            .metadata_resources()
            .expect("original admitted catalog authority");
        let gate_bytes = std::mem::size_of::<SourceGate>()
            + std::mem::size_of::<HeldBacking>()
            + std::mem::size_of::<GateDecorator>()
            + 6 * std::mem::size_of::<usize>()
            + control_snapshot_bytes();
        let credit = authority
            .reserve_resources(0, gate_bytes as u64)
            .expect("gate storage charged before allocation");
        let gate = Arc::new(SourceGate {
            registry: self.prepared.host_operational_registry.clone(),
            state: Mutex::new(GateState::default()),
            _credit: credit,
        });
        let lifecycle_config = self
            .config
            .admitted_lifecycle_config()
            .expect("mutable observer projection under original catalog credit")
            .with_ram_source_decorator_for_test(Arc::new(GateDecorator(Arc::clone(&gate))));
        let host = LinuxQemuAttemptHostResourceFactory::open(self.config.host.clone())
            .expect("actual cgroup/project quota containment");
        let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
            Arc::new(lifecycle_config),
            ComposedQemuAttemptResourceGuardFactory::new(host),
        );
        let scenario = input.scenario().scenario_def();
        let initial = match input.start() {
            crate::CrucibleResolvedAttemptStart::Branch { parent, .. } => parent,
            _ => input.start().configuration(),
        };
        let mut lifecycle = factory
            .begin_resume(
                &self.prepared.checkpoints,
                self.checkpoint,
                crate::QemuExactResumeBasis::new(&scenario, input.scenario(), initial, None),
                service.context(),
            )
            .expect("genuine cold exact restore");
        let registry = &self.prepared.host_operational_registry;
        let target = discover_target(registry, service.context());
        registry
            .apply_native_qualification_policy(target, 0)
            .expect("real cold placement under unqualified full-peak contract");
        let before = status(registry, target);
        let cap = before
            .outer_caps
            .iter()
            .find(|cap| {
                cap.target.cap_id
                    == service
                        .context()
                        .host_operation_supervisor()
                        .expect("original supervisor")
                        .cap_id()
            })
            .expect("exact registered Service cap")
            .target;
        gate.state.lock().expect("gate lock").action = Some(Action {
            case: self.case,
            target,
            cap,
            supervisor: service
                .context()
                .host_operation_supervisor()
                .expect("original Service supervisor")
                .clone(),
            cancellation: service.context().cancellation().clone(),
        });
        let published = lifecycle
            .resume_state()
            .expect("restored scheduler cut")
            .into_parts();
        let original_configuration = published.0.id();
        let original_frontier = published.4;
        let scheduler_before = lifecycle
            .canonical_scheduler_evidence()
            .expect("original scheduler identity")
            .0;
        let result = QemuFreshAttemptLifecycleOwner::drive_quantum(
            &mut lifecycle,
            QuantumRequest {
                configuration: published.0,
                control: Vec::new(),
            },
        );
        let observed = if matches!(self.case, Case::Reference | Case::Policy) {
            result.expect("first cold quantum despite independent policy control");
            let after = status(registry, target);
            assert!(
                after
                    .activity
                    .expect("actual installed counter")
                    .successful_missing_installs
                    > before
                        .activity
                        .expect("pre-quantum counter")
                        .successful_missing_installs
            );
            assert_eq!(before.admitted_resources, after.admitted_resources);
            assert_eq!(before.reservation_revision, after.reservation_revision);
            Some(boundary(&mut lifecycle))
        } else {
            assert!(
                result.is_err(),
                "terminal source must not publish a guest outcome"
            );
            let after = lifecycle
                .resume_state()
                .expect("last published scheduler cut")
                .into_parts();
            assert_eq!(after.0.id(), original_configuration);
            assert_eq!(after.4, original_frontier);
            assert!(
                after.6.is_none(),
                "host terminal authority is not a guest verdict"
            );
            assert_eq!(
                lifecycle
                    .canonical_scheduler_evidence()
                    .expect("last published scheduler evidence")
                    .0,
                scheduler_before
            );
            None
        };
        let held = gate
            .state
            .lock()
            .expect("gate lock")
            .evidence
            .take()
            .expect("real authenticated request reached the held completion");
        // No release is attempted until both the native process and its held
        // source have their ordinary shutdown/reap/join proof.
        let shutdown = QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle);
        if matches!(self.case, Case::Reference | Case::Policy) {
            shutdown.expect("original Cleanup scope reaps process and joins source");
        } else if let Err(error) = shutdown {
            // A terminal source can report its original failure after a real
            // join. Final world destruction closes the remaining borrowers;
            // the Service's cleanup ledger below still refuses uncertain proof.
            println!("blocked_pager_terminal_cleanup={error:?}");
        }
        drop(lifecycle);
        service
            .release_after_world_cleanup()
            .expect("proof-bound Service discharge");
        assert_eq!(available(self.prepared), original_available);
        assert!(
            registry
                .execute(OPERATOR, HostOperationalRequest::Status { target })
                .is_err(),
            "retired source generation cannot select a live controller"
        );
        self.evidence = Some(LaneEvidence {
            boundary: observed,
            held,
        });
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
            "operator cancellation after actual blocked-source cleanup",
        )))
    }
}

fn control_snapshot_bytes() -> usize {
    // Two returned statuses overlap in the policy lane. Each has at most the
    // fixed twelve operations, one Service cap, and the six closed limitation
    // strings (longest fifteen bytes). Vec growth is bounded separately from
    // retained elements; both request and response can own a policy box.
    use crucible_api::host_operational::{HostOuterCapObservation, HostRamPolicy};
    use crucible_linux_resource::host_supervision::{HostOperationStatus, MAX_HOST_OPERATIONS};

    2 * (std::mem::size_of::<HostRamStatus>()
        + 2 * MAX_HOST_OPERATIONS * std::mem::size_of::<HostOperationStatus>()
        + 4 * std::mem::size_of::<HostOuterCapObservation>()
        + 8 * std::mem::size_of::<String>()
        + 6 * 15)
        + 2 * std::mem::size_of::<HostRamPolicy>()
        + std::mem::size_of::<HostOperationalRequest>()
        + std::mem::size_of::<HostOperationalResponse>()
}
