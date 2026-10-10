//! Rejects damaged completions from a genuinely leased cold RAM page source.
//!
//! Each lane uses accepted capture, production replay promotion, and a fresh
//! admitted restore. The adversary changes the actual completed page buffer,
//! retaining its original proof and root. The host source must refuse it before
//! sending a response. Separate transport cases damage the actual encoded
//! response after normal host authentication. Neither group is evidence for
//! kernel pins or independently killed native fault workers. A separate lane
//! changes the actual stored CAS inode after admission and requires its normal
//! authenticated read to fail before the source sends any page response.

use super::super::hot_fork_native::{enqueue_promoted_resume, fork_resources, native_repository};
use super::accepted_promotion::{extend_native_operations, promote_accepted_checkpoint};
use super::lazy_restore::discover_target;
use super::*;
use crate::packaged_qemu_executor::{
    RetainedTemplateServiceFactory, preparation::PackagedPreparation,
};
use crate::{
    AttemptExecutionInput, AttemptExecutionModel, AttemptExecutionProduct, RepositoryAttemptWorker,
    decode_crucible_attempt_execution,
};
use crucible_api::host_operational::HostResourceVector;
use crucible_api::vm_lifecycle::ProductionRamSourceDecorator;
use crucible_campaign::CampaignExecutorStore;
use crucible_qemu::ram_source::{QemuRamBacking, QemuRamResponseFault, QemuRamSourceError};
use std::sync::Mutex;

#[path = "source_failures/actor_exit.rs"]
mod actor_exit;
#[path = "source_failures/stored_corruption.rs"]
mod stored_corruption;
use stored_corruption::{StoredCorruption, corrupted_object_in_chain};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompletionCase {
    Reference,
    ChangedByte,
    ShortPage,
    ChangedWireByte,
    PartialWireBody,
    SourceDisconnect,
    StaleSourceGeneration,
    StoredCasCorruption,
    FaultActorExit,
}

impl CompletionCase {
    fn lane(self) -> &'static str {
        match self {
            Self::Reference => "source-reference",
            Self::ChangedByte => "source-changed-byte",
            Self::ShortPage => "source-short-page",
            Self::ChangedWireByte => "source-changed-wire-byte",
            Self::PartialWireBody => "source-partial-wire-body",
            Self::SourceDisconnect => "source-disconnect",
            Self::StaleSourceGeneration => "source-stale-generation",
            Self::StoredCasCorruption => "source-stored-cas-corruption",
            Self::FaultActorExit => "fault-actor-exit",
        }
    }

    fn rejects_before_transport(self) -> bool {
        matches!(self, Self::ChangedByte | Self::ShortPage)
    }

    fn transport_fault(self) -> Option<QemuRamResponseFault> {
        match self {
            Self::ChangedWireByte => Some(QemuRamResponseFault::ChangedPageByte),
            Self::PartialWireBody => Some(QemuRamResponseFault::TruncatedBody),
            Self::SourceDisconnect => Some(QemuRamResponseFault::DisconnectBeforeHeader),
            Self::StaleSourceGeneration => Some(QemuRamResponseFault::StaleSourceGeneration),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct CompletionEvidence {
    region_ordinal: usize,
    page_index: u64,
    authentic_length: usize,
    proof_rejected: bool,
    transport_applied: bool,
    stored_object: Option<crucible_cas::content_store::ContentId>,
}

#[derive(Default)]
struct CompletionState {
    armed: bool,
    evidence: Option<CompletionEvidence>,
    transport: Option<QemuRamResponseFault>,
    actor: Option<actor_exit::ActorExitProbe>,
}

struct CompletionGate {
    case: CompletionCase,
    stored: Option<StoredCorruption>,
    // Arming occurs only after restore and cold-placement policy finish. Earlier
    // device pre-load reads remain ordinary authenticated source completions.
    state: Mutex<CompletionState>,
    _credit: crucible_cas::owned_decode::ResourceLoan,
}

struct CompletionDecorator(Arc<CompletionGate>);

impl ProductionRamSourceDecorator for CompletionDecorator {
    fn decorate(
        &self,
        backing: Arc<dyn QemuRamBacking>,
    ) -> Result<Arc<dyn QemuRamBacking>, QemuRamSourceError> {
        Ok(Arc::new(ObservedBacking {
            backing,
            gate: Arc::clone(&self.0),
        }))
    }
}

struct ObservedBacking {
    backing: Arc<dyn QemuRamBacking>,
    gate: Arc<CompletionGate>,
}

impl QemuRamBacking for ObservedBacking {
    fn root_object_id(&self) -> &str {
        self.backing.root_object_id()
    }

    fn root_record(&self) -> &crucible_ram::RootRecord {
        self.backing.root_record()
    }

    fn with_page_response(
        &self,
        region_id: &str,
        page_index: u64,
        boundary: &mut dyn FnMut()
            -> Result<(), crucible_qemu::ram_source::QemuRamReadBoundaryError>,
        consumer: &mut crucible_qemu::ram_source::QemuRamResponseConsumer<'_>,
    ) -> Result<(), QemuRamSourceError> {
        let damage_storage = {
            let mut state = self
                .gate
                .state
                .lock()
                .map_err(|_| QemuRamSourceError::Ownership)?;
            if state.armed && self.gate.case == CompletionCase::StoredCasCorruption {
                state.armed = false;
                true
            } else {
                false
            }
        };
        if damage_storage {
            let storage = self
                .gate
                .stored
                .as_ref()
                .ok_or(QemuRamSourceError::Ownership)?;
            let (object, length) = storage.damage_requested_page(
                self.backing.as_ref(),
                region_id,
                page_index,
                boundary,
            )?;
            let mut unexpected_completion = false;
            let result =
                self.backing
                    .with_page_response(region_id, page_index, boundary, &mut |_, _| {
                        unexpected_completion = true
                    });
            if unexpected_completion {
                return Err(QemuRamSourceError::Ownership);
            }
            let error = match result {
                Err(error) if corrupted_object_in_chain(&error) == Some(object) => error,
                _ => return Err(QemuRamSourceError::Ownership),
            };
            self.gate
                .state
                .lock()
                .map_err(|_| QemuRamSourceError::Ownership)?
                .evidence = Some(CompletionEvidence {
                region_ordinal: self
                    .root_record()
                    .topology()
                    .regions()
                    .iter()
                    .position(|region| region.id() == region_id)
                    .ok_or(QemuRamSourceError::Ownership)?,
                page_index,
                authentic_length: length,
                proof_rejected: false,
                transport_applied: false,
                stored_object: Some(object),
            });
            return Err(error);
        }
        let mut first = None;
        let result = self.backing.with_page_response(
            region_id,
            page_index,
            boundary,
            &mut |mut page, boundary| {
                if first.is_some() {
                    return;
                }
                let outcome = (|| {
                    boundary()?;
                    let mut state = self
                        .gate
                        .state
                        .lock()
                        .map_err(|_| QemuRamSourceError::Ownership)?;
                    if !state.armed {
                        drop(state);
                        consumer(page, boundary);
                        return Ok(());
                    }
                    state.armed = false;
                    page.proof()
                        .verify(
                            page.bytes(),
                            self.root_record(),
                            self.root_record().digest(),
                        )
                        .map_err(|error| QemuRamSourceError::Proof(error.to_string()))?;
                    let authentic_length = page.bytes().len();
                    match self.gate.case {
                        CompletionCase::Reference
                        | CompletionCase::ChangedWireByte
                        | CompletionCase::PartialWireBody
                        | CompletionCase::SourceDisconnect
                        | CompletionCase::StaleSourceGeneration
                        | CompletionCase::StoredCasCorruption => {}
                        CompletionCase::FaultActorExit => state
                            .actor
                            .as_ref()
                            .ok_or(QemuRamSourceError::Ownership)?
                            .request_before_response()?,
                        CompletionCase::ChangedByte => {
                            page = page
                                .with_flipped_first_byte_for_test()
                                .map_err(|_| QemuRamSourceError::Ownership)?;
                        }
                        CompletionCase::ShortPage => {
                            page = page
                                .with_truncated_page_for_test()
                                .map_err(|_| QemuRamSourceError::Ownership)?;
                        }
                    }
                    let proof_rejected = page
                        .proof()
                        .verify(
                            page.bytes(),
                            self.root_record(),
                            self.root_record().digest(),
                        )
                        .is_err();
                    assert_eq!(proof_rejected, self.gate.case.rejects_before_transport());
                    state.transport = self.gate.case.transport_fault();
                    state.evidence = Some(CompletionEvidence {
                        region_ordinal: self
                            .root_record()
                            .topology()
                            .regions()
                            .iter()
                            .position(|region| region.id() == region_id)
                            .ok_or(QemuRamSourceError::Ownership)?,
                        page_index,
                        authentic_length,
                        proof_rejected,
                        transport_applied: false,
                        stored_object: None,
                    });
                    // Release the gate before the worker observes the armed transport
                    // fault. The backing still retains the original page/proof custody.
                    drop(state);
                    boundary()?;
                    consumer(page, boundary);
                    Ok(())
                })();
                if let Err(error) = outcome {
                    first = Some(error);
                }
            },
        );
        match first {
            Some(error) => Err(error),
            None => result,
        }
    }

    fn take_response_fault_for_test(&self) -> Option<QemuRamResponseFault> {
        let mut state = self.gate.state.lock().ok()?;
        let fault = state.transport.take()?;
        state.evidence.as_mut()?.transport_applied = true;
        Some(fault)
    }
}

#[test]
#[ignore = "requires the isolated AOS paging VM and genuine accepted cold restore"]
fn production_cold_source_rejects_damaged_page_completions_without_publishing_a_cut() {
    let source = paging_scenario();
    for (ordinal, case) in [
        CompletionCase::Reference,
        CompletionCase::ChangedByte,
        CompletionCase::ShortPage,
        CompletionCase::ChangedWireByte,
        CompletionCase::PartialWireBody,
        CompletionCase::SourceDisconnect,
        CompletionCase::StaleSourceGeneration,
        CompletionCase::StoredCasCorruption,
    ]
    .into_iter()
    .enumerate()
    {
        run_lane(
            &source,
            case,
            55_000 + u32::try_from(ordinal).expect("eight lanes") * 100,
        );
    }
    println!("cold_source_genuine_accepted_restore=true");
    println!("cold_source_changed_byte_proof_refused=true");
    println!("cold_source_short_page_proof_refused=true");
    println!("cold_source_changed_wire_page_refused=true");
    println!("cold_source_partial_wire_body_refused=true");
    println!("cold_source_response_disconnect_refused=true");
    println!("cold_source_stale_response_generation_refused=true");
    println!("cold_source_stored_cas_corruption_after_admission_refused=true");
    println!("cold_source_stored_cas_original_cause_retained=true");
    println!("cold_source_stored_inode_restored_after_join=true");
    println!("cold_source_damaged_response_no_install=true");
    println!("cold_source_failed_quantum_cut_unpublished=true");
    println!("cold_source_worker_join_before_full_vector_discharge=true");
    println!("COLD_SOURCE_COMPLETION_FAILURE_NATIVE_PASS");
}

#[test]
#[ignore = "requires isolated AOS paging VM and genuine accepted native fault service"]
fn production_fault_actor_returns_without_releasing_controller_or_publishing_a_cut() {
    run_lane(&paging_scenario(), CompletionCase::FaultActorExit, 55_800);
    println!("fault_actor_wrong_entitlement_no_effect=true");
    println!("fault_actor_wrong_generation_no_effect=true");
    println!("fault_actor_pending_authenticated_page_before_exit=true");
    println!("fault_actor_original_terminal_cause_retained=true");
    println!("fault_actor_role1_membership_released_controller_alive=true");
    println!("fault_actor_no_install_or_guest_cut=true");
    println!("fault_actor_original_eight_dimension_owner_retained_until_cleanup=true");
    println!("FAULT_ACTOR_TERMINAL_NATIVE_PASS");
}

fn available(prepared: &PackagedPreparation) -> HostResourceVector {
    prepared
        .actor
        .with_supervisor(|actor| {
            actor
                .host_resource_availability()
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)
        })
        .expect("actual complete eight-dimension capacity accounting")
}

fn run_lane(source: &ScenarioDefForm, case: CompletionCase, project: u32) {
    environment::with_native_repository_storage(
        case.lane(),
        project,
        environment::NativeCatalogBudget::default(),
        |root, storage| native_repository(source, root, storage),
        |repository, _, _| repository.blob_backend(),
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
                        CompletionCase::Reference => 0xd0,
                        CompletionCase::ChangedByte => 0xd1,
                        CompletionCase::ShortPage => 0xd2,
                        CompletionCase::ChangedWireByte => 0xd3,
                        CompletionCase::PartialWireBody => 0xd4,
                        CompletionCase::SourceDisconnect => 0xd5,
                        CompletionCase::StaleSourceGeneration => 0xd6,
                        CompletionCase::StoredCasCorruption => 0xd7,
                        CompletionCase::FaultActorExit => 0xd8,
                    }; 16],
                )
                .expect("fresh independent resumed assignment"),
            );
            let backend = repository.blob_backend();
            let store = CampaignExecutorStore::new(repository);
            let mut worker = RepositoryAttemptWorker::new(
                store.clone(),
                CompletionModel {
                    store,
                    backend,
                    config: config.clone(),
                    prepared,
                    checkpoint: promoted.checkpoint,
                    case,
                    completed: false,
                },
            );
            let (queued, outcome) = worker.execute(queued).into_parts();
            assert!(matches!(outcome, Err(AttemptWorkerFailure::Canceled(_))));
            assert!(worker.model_mut().completed);
            prepared
                .actor
                .with_supervisor(|actor| {
                    actor
                        .stage_and_reconcile_cancellation(&queued)
                        .map_err(|_| {
                            crucible_api::host_operational::HostOperationalError::Unavailable
                        })
                })
                .expect("durable reconciliation after actual source and process cleanup");
            assert_eq!(available(prepared), capacity);
        },
    );
}

struct CompletionModel<'a> {
    store: CampaignExecutorStore,
    backend: Arc<dyn crucible_cas::content_store::ImmutableBlobBackend>,
    config: PackagedQemuExecutorConfig,
    prepared: &'a PackagedPreparation,
    checkpoint: ExactCheckpointId,
    case: CompletionCase,
    completed: bool,
}

impl AttemptExecutionModel for CompletionModel<'_> {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        extend_native_operations(context);
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("authenticated accepted resumed execution");
        let before_service = available(self.prepared);
        let mut selected = context.take_selected_checkpoint();
        let service = RetainedTemplateServiceFactory::new(self.prepared, &self.config)
            .start_for_resume(input.scenario(), self.checkpoint, context, &mut selected)
            .expect("fresh full-vector Service consumes the real selected claim");
        assert!(selected.is_none());
        extend_native_operations(service.context());
        let bytes = std::mem::size_of::<CompletionGate>()
            + std::mem::size_of::<CompletionDecorator>()
            + std::mem::size_of::<ObservedBacking>()
            + std::mem::size_of::<StoredCorruption>()
            + 4096
            + 6 * std::mem::size_of::<usize>();
        let credit = self
            .store
            .metadata_resources()
            .expect("original catalog resource authority")
            .reserve_resources(0, bytes as u64)
            .expect("observer ownership admitted before allocation");
        let gate = Arc::new(CompletionGate {
            case: self.case,
            stored: (self.case == CompletionCase::StoredCasCorruption).then(|| {
                StoredCorruption::new(
                    Arc::clone(&self.backend),
                    self.config
                        .ram_catalog()
                        .expect("actual quota catalog")
                        .root()
                        .join("campaign-repository")
                        .join("objects"),
                )
            }),
            state: Mutex::new(CompletionState::default()),
            _credit: credit,
        });
        let mut lifecycle_config = self
            .config
            .admitted_lifecycle_config()
            .expect("projection under original catalog credit")
            .with_ram_source_decorator_for_test(Arc::new(CompletionDecorator(Arc::clone(&gate))));
        if self.case == CompletionCase::FaultActorExit {
            lifecycle_config = lifecycle_config
                .with_fault_actor_test_entitlement_for_test(actor_exit::ENTITLEMENT)
                .expect("separately authored actor-only terminal test entitlement");
        }
        let host = LinuxQemuAttemptHostResourceFactory::open(self.config.host.clone())
            .expect("real cgroup and physical quota containment");
        let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
            lifecycle_config,
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
            .expect("actual native cold restore with independent page namespace");
        let registry = &self.prepared.host_operational_registry;
        let target = discover_target(registry, service.context());
        registry
            .apply_native_qualification_policy(target, 0)
            .expect("actual cold placement beneath the public capability gate");
        let before = status(registry, target);
        let cut = lifecycle
            .resume_state()
            .expect("restored published cut")
            .into_parts();
        let original_configuration = cut.0.id();
        let original_frontier = cut.4;
        let original_scheduler = lifecycle
            .canonical_scheduler_evidence()
            .expect("restored scheduler evidence")
            .0;
        {
            let mut state = gate.state.lock().expect("observer lock");
            if self.case == CompletionCase::FaultActorExit {
                state.actor = Some(actor_exit::ActorExitProbe::new(registry.clone(), target));
            }
            state.armed = true;
        }
        let result = QemuFreshAttemptLifecycleOwner::drive_quantum(
            &mut lifecycle,
            QuantumRequest {
                configuration: cut.0,
                control: Vec::new(),
            },
        );
        if self.case == CompletionCase::Reference {
            result
                .as_ref()
                .expect("authentic page completion permits the first cold quantum");
            let after = status(registry, target);
            assert!(
                after
                    .activity
                    .expect("native installs")
                    .successful_missing_installs
                    > before
                        .activity
                        .expect("original installs")
                        .successful_missing_installs
            );
        } else {
            assert!(
                result.is_err(),
                "damaged source cannot produce a guest outcome"
            );
            let failed_owner = status(registry, target);
            assert_eq!(failed_owner.admitted_resources, before.admitted_resources);
            assert_eq!(
                failed_owner.reservation_revision,
                before.reservation_revision
            );
            assert_eq!(
                failed_owner
                    .activity
                    .expect("actual failed-owner counters")
                    .successful_missing_installs,
                before
                    .activity
                    .expect("pre-response native counters")
                    .successful_missing_installs,
                "a damaged first response must not install any guest page",
            );
            let after = lifecycle
                .resume_state()
                .expect("last published cut")
                .into_parts();
            assert_eq!(after.0.id(), original_configuration);
            assert_eq!(after.4, original_frontier);
            assert_eq!(
                lifecycle
                    .canonical_scheduler_evidence()
                    .expect("last published scheduler evidence")
                    .0,
                original_scheduler
            );
        }
        if self.case == CompletionCase::FaultActorExit {
            let error = match &result {
                Err(error) => error,
                Ok(_) => panic!("isolated actor failure permits the pending quantum"),
            };
            assert!(actor_exit::original_actor_cause(error));
            let state = gate.state.lock().expect("actor evidence lock");
            state
                .actor
                .as_ref()
                .expect("actual actor probe")
                .verify_actual_return(
                    service
                        .context()
                        .host_operation_supervisor()
                        .expect("same original Service cap"),
                );
        }
        let observed = gate
            .state
            .lock()
            .expect("observer lock")
            .evidence
            .take()
            .expect("actual first cold page reached the completion adversary");
        assert!(observed.authentic_length > 0);
        assert_eq!(
            observed.stored_object.is_some(),
            self.case == CompletionCase::StoredCasCorruption
        );
        if let Some(object) = observed.stored_object {
            let error = match &result {
                Err(error) => error,
                Ok(_) => panic!("stored corruption permits the pending quantum"),
            };
            assert_eq!(corrupted_object_in_chain(error), Some(object));
        }
        assert_eq!(
            observed.proof_rejected,
            self.case.rejects_before_transport()
        );
        assert_eq!(
            observed.transport_applied,
            self.case.transport_fault().is_some()
        );
        println!(
            "cold_source_completion={:?}:{}:{}:{}",
            self.case, observed.region_ordinal, observed.page_index, observed.authentic_length
        );

        // A terminal source error is reported by the first join, even when the
        // worker was physically joined. A second ordinary cleanup completes
        // retained source disposition; it neither reruns the guest nor reopens
        // its endpoint. Missing proof preserves the complete actual custody.
        if QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).is_err()
            && let Err(error) = QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle)
        {
            service.retain_after_unknown_cleanup();
            std::mem::forget(lifecycle);
            panic!("source failure cleanup retains its charged world: {error}");
        }
        drop(lifecycle);
        drop(factory);
        // The error observer may retain the original source's resources. Its
        // final close precedes any claim that the actual Service can discharge.
        drop(result);
        if let Some(storage) = &gate.stored {
            let cleanup = match service
                .context()
                .host_operation_supervisor()
                .expect("same live Service cap")
                .begin(crucible_linux_resource::host_supervision::HostOperationClass::Cleanup)
            {
                Ok(cleanup) => cleanup,
                Err(error) => {
                    service.retain_after_unknown_cleanup();
                    std::mem::forget(gate);
                    panic!(
                        "stored inode restoration retains its original expired authority: {error}"
                    );
                }
            };
            let restore = storage.restore_after_join(&mut || {
                cleanup
                    .wait_slice()
                    .map(|_| ())
                    .map_err(crucible_qemu::ram_source::QemuRamReadBoundaryError::from)
            });
            if let Err(error) = restore {
                service.retain_after_unknown_cleanup();
                std::mem::forget(gate);
                panic!("actual corrupted inode and charged authority retained: {error}");
            }
            if let Err(error) = cleanup.complete() {
                service.retain_after_unknown_cleanup();
                std::mem::forget(gate);
                panic!("stored restoration cannot declare success after its original cap: {error}");
            }
        }
        drop(gate);
        service
            .release_after_world_cleanup()
            .expect("proof-bound full-vector Service discharge");
        assert_eq!(available(self.prepared), before_service);
        assert!(
            registry
                .execute(OPERATOR, HostOperationalRequest::Status { target })
                .is_err()
        );
        self.completed = true;
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
            "operator cancellation after authentic cold-source completion evidence",
        )))
    }
}
