//! Binds bounded continuation waits to their actual Original and custody paths.
//!
//! Contracts remove only the exact reviewed expressions and identifier census.
//! Missing caller/helper observations or changed occurrence counts fail closed.
//! Passing these source checks does not qualify native lifecycle integration.

use super::operational_target_cleanup;
use super::{
    compact_code, expression_offsets, identifier_count, mask_expression, mask_identifier,
    source_pattern,
};

#[path = "operational_operations/cache.rs"]
mod cache;
#[path = "operational_operations/cleanup_delegation.rs"]
mod cleanup_delegation;
#[path = "operational_operations/construction_endpoint.rs"]
mod construction_endpoint;
#[path = "operational_operations/constructor_continuations.rs"]
mod constructor_continuations;
#[path = "operational_operations/generic_mutations.rs"]
mod generic_mutations;
#[path = "operational_operations/hot_fork_retirement.rs"]
mod hot_fork_retirement;
#[path = "operational_operations/host_physical_custody.rs"]
mod host_physical_custody;
#[path = "operational_operations/lifecycle_retirement.rs"]
mod lifecycle_retirement;
#[path = "operational_operations/native_registration.rs"]
mod native_registration;
#[path = "operational_operations/owned_process_controls.rs"]
mod owned_process_controls;
#[path = "operational_operations/pager_placement.rs"]
mod pager_placement;
#[path = "operational_operations/production_publication.rs"]
mod production_publication;
#[path = "operational_operations/refused_publication.rs"]
mod refused_publication;
#[path = "operational_operations/retained_continuations.rs"]
mod retained_continuations;
#[path = "operational_operations/service_continuations.rs"]
mod service_continuations;
#[path = "operational_operations/source_world_admission.rs"]
mod source_world_admission;
#[path = "operational_operations/worker_custody.rs"]
mod worker_custody;

struct Companion {
    path: &'static str,
    required: &'static [(&'static str, usize)],
}

struct Contract {
    package: &'static str,
    target: &'static str,
    required: &'static [(&'static str, usize)],
    expressions: &'static [(&'static str, usize)],
    identifiers: &'static [(&'static str, usize)],
    companions: &'static [Companion],
}

const TARGET_CLEANUP_REQUIRED: &[(&str, usize)] = &operational_target_cleanup::REQUIRED;

const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-daemon",
        target: "src/host_operational_registry/checkpoint",
        required: &[
            (r#"loan: crucible_qemu_host::CheckpointArmLoan<'_>"#, 1),
            (
                r#"let owner = loop { let slice = loan.wait_slice()?; match self.shared.state.try_lock()"#,
                1,
            ),
            (
                r#"if state.retired.contains(&loan.target()) { return Err(unavailable()); }"#,
                1,
            ),
            (
                r#".nodes.get(&loan.target()).cloned().ok_or_else(unavailable)?"#,
                1,
            ),
            (
                r#"Err(TryLockError::Poisoned(_)) => return Err(unavailable()),"#,
                2,
            ),
            (
                r#"if !loan.matches_supervisor(&owner.supervisor) { return Err(unavailable()); }"#,
                1,
            ),
            (
                r#"let mut client = loop { let slice = loan.wait_slice()?; match owner.client.try_lock()"#,
                1,
            ),
            (
                r#"client.as_mut().ok_or_else(unavailable)?.checkpoint_arm(loan)"#,
                1,
            ),
        ],
        expressions: &[(
            r#"std::thread::sleep(slice.min(Duration::from_millis(1)));"#,
            2,
        )],
        identifiers: &[],
        companions: &[
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-host/src/node/exact_snapshot/capture_original.rs",
                required: &[
                    (
                        r#"pub struct CheckpointArmLoan<'a> { original: &'a CheckpointOriginalLoan,"#,
                        1,
                    ),
                    (
                        r#"pub fn matches_supervisor(&self, supervisor: &HostOperationSupervisor) -> bool { self.supervisor == supervisor }"#,
                        1,
                    ),
                    (
                        r#"pub fn wait_slice(&self) -> Result<Duration, CheckpointOriginalError> { self.original.check().map_err(|source| { CheckpointOriginalError::before(CheckpointOriginalCause::Original(source)) })?; self.original.guard().wait_slice().map_err(|source| { CheckpointOriginalError::before(CheckpointOriginalCause::Original(source)) }) }"#,
                        1,
                    ),
                ],
            },
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-host/src/ram_control/checkpoint.rs",
                required: &[
                    (
                        r#"let original = loan.original().clone(); let work = self.checkpoint_arm_exchange(&mut loan); let original_after = original.check().err();"#,
                        1,
                    ),
                    (
                        r#"first.original_after = first.original_after.or(original_after); Err(first)"#,
                        1,
                    ),
                    (
                        r#"(Ok(_), Some(source)) => Err(CheckpointOriginalError { source: CheckpointOriginalCause::Original(source), original_after: Some(source), }),"#,
                        1,
                    ),
                    (
                        r#"if !self.usable || self.target != target_to_wire(loan.target()) || self.supervisor.as_ref().is_none_or(|owner| !loan.matches_supervisor(owner))"#,
                        1,
                    ),
                ],
            },
        ],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/node/host_policy",
        required: &[
            (
                r#"if let Some(service) = retained.take() && let Err(error) = service.stop() { *retained = Some(error.service);"#,
                1,
            ),
            (
                r#"let observation = self.supervisor.begin(HostOperationClass::Preparation)?; loop { match self.retained.as_ref().unwrap().check_health()"#,
                1,
            ),
            (
                r#"Err(QemuRamSourceError::WorkerFailed(_)) => break, Err(source) => return Err(source.into()),"#,
                1,
            ),
            (r#"observation.complete()?;"#, 1),
            (r#"assert!(fixture.task_is_retained());"#, 4),
            (r#"assert_eq!(source, &original);"#, 1),
            (
                r#"drop(worker); assert!(fixture.task_is_retained()); drop(scheduler); assert!(fixture.services.reserve_resources(1, 0, 0).is_ok());"#,
                1,
            ),
            (
                r#"Err(HostSupervisionError::CapacityExhausted) => break,"#,
                1,
            ),
            (
                r#"if matches!(source.source_failure(), QemuRamSourceError::Supervision(HostSupervisionError::CapacityExhausted))"#,
                1,
            ),
            (r#"assert!(fixture.retained.is_some());"#, 1),
            (
                r#"drop(guards); finish_ram_source_cleanup(&mut fixture.retained, "join retained RAM source")?; assert!(fixture.retained.is_none());"#,
                1,
            ),
        ],
        expressions: &[(
            r#"std::thread::sleep(observation.wait_slice()?.min(Duration::from_millis(1)))"#,
            1,
        )],
        identifiers: &[(
            r#"cleanup_admission_refusal_retains_service_and_credit_until_retry"#,
            1,
        )],
        companions: &[Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/ram_source.rs",
            required: &[
                (
                    r#"pub fn stop(mut self) -> Result<(), QemuRamSourceStopError> { self.cancel(); let cleanup = match self.supervisor.begin(HostOperationClass::Cleanup)"#,
                    1,
                ),
                (
                    r#"while self.worker.as_ref().is_some_and(|worker| !worker.is_finished()) { match cleanup.wait_slice()"#,
                    1,
                ),
                (r#"service: Box::new(self), source: error.into(),"#, 3),
                (
                    r#"if let Some(worker) = self.worker.take() { let result = worker.join();"#,
                    1,
                ),
                (r#"source: QemuRamSourceError::WorkerFailed(source),"#, 1),
                (
                    r#"match cleanup.complete() { Ok(_) => Ok(()), Err(error) => Err(QemuRamSourceStopError { service: Box::new(self), source: error.into(), }), }"#,
                    1,
                ),
            ],
        }],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/paged_ram/engine/ordinary_capture",
        required: &[
            (
                r#"if serial == 0 || (self.identity != 0 && self.identity != serial)"#,
                1,
            ),
            (
                r#"!matches!(class, SourceOperationClass::FingerprintInitialization | SourceOperationClass::FingerprintUpdate)"#,
                1,
            ),
            (
                r#".original_class.is_some_and(|previous| previous != class)"#,
                1,
            ),
            (
                r#"self.identity = serial; self.original_class = Some(class);"#,
                1,
            ),
            (
                r#"if Arc::ptr_eq(active, service) && Arc::ptr_eq(&self.owner.operations, &service.operations)"#,
                1,
            ),
            (
                r#"pub(crate) fn settle(&mut self, operation: &dyn SourceOperation) -> Result<(), RamError> { self.check_allocation()?; if self.original_class.is_none()"#,
                1,
            ),
            (
                r#"if !self.pause_requested { service.capture_work.request_ordinary_pause(self.identity)?; self.pause_requested = true; }"#,
                1,
            ),
            (
                r#"while !service.capture_work.ordinary_pause_acknowledged(self.identity) { let slice = operation.wait_slice_for_observation().map_err(super::super::source::SourceFetchError::from).map_err(|error| self.retain_source_error(error))?;"#,
                1,
            ),
            (
                r#"if service.failed.load(Ordering::Acquire) || service.stop.load(Ordering::Acquire)"#,
                1,
            ),
            (
                r#"states.hold_ordinary(self.identity)?; self.pages_held = true;"#,
                1,
            ),
            (
                r#"if protected { operation.wait_slice_for_observation().map_err(super::super::source::SourceFetchError::from).map_err(|error| self.retain_source_error(error))?; }"#,
                1,
            ),
            (
                r#"if let Some(class) = self.original_class { if let Some(original) = original { self.owner.retain_operational_source_failure(class, original); } else { self.owner.retain_operational_failure_owned(class, cause); } }"#,
                1,
            ),
        ],
        expressions: &[(
            r#"std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));"#,
            1,
        )],
        identifiers: &[],
        companions: &[
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-plugin/src/ram_fingerprint/original/retirement.rs",
                required: &[
                    (
                        r#"state.retirement = self.custody.take(); state.retirement_busy = false;"#,
                        1,
                    ),
                    (
                        r#".is_some_and(|custody| custody.loan == context.key())"#,
                        1,
                    ),
                    (
                        r#"let result = (self.apis.retirement_observe)(self.plugin_id, loan as *mut crate::runtime::FingerprintLoan, selector as *mut Operation, &mut observed, );"#,
                        1,
                    ),
                    (
                        r#"if state.selector.load(Ordering::Acquire) as usize != selector || !valid_evidence(&observed, state.evidence.as_ref())"#,
                        1,
                    ),
                    (
                        r#"fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> { self.owner.retirement_sample(self.loan).map(|observed| Duration::from_nanos(observed.bounded_ns)) }"#,
                        1,
                    ),
                    (
                        r#"let operation = LiveOriginal { owner, loan: context.key(), };"#,
                        2,
                    ),
                    (
                        r#"let evidence = match owner.retirement_sample(context.key())"#,
                        1,
                    ),
                    (
                        r#"if let Err(error) = custody.physical.bind_original(evidence.serial, class) { custody.failure = Some(error); return -libc::EPROTO; }"#,
                        1,
                    ),
                    (r#"match custody.physical.settle(&operation)"#, 1),
                    (
                        r#"if custody.physical.return_identity().is_err() { return -libc::EBUSY; }"#,
                        1,
                    ),
                    (
                        r#"if consumed { work.custody = None; unsafe { supplied.write(std::ptr::null_mut()); } }"#,
                        1,
                    ),
                ],
            },
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-plugin/src/ram_fingerprint/original.rs",
                required: &[
                    (
                        r#"current.serial != 0 && matches!(current.class, 4 | 5) && current.bounded_ns != 0 && current.bounded_ns <= i64::MAX as u64"#,
                        1,
                    ),
                    (
                        r#"current.capability == previous.capability && current.origin_ns == previous.origin_ns && current.serial == previous.serial && current.start_ns == previous.start_ns && current.class == previous.class && current.progress_ns >= previous.progress_ns"#,
                        1,
                    ),
                ],
            },
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-plugin/src/ram_fingerprint/original/retirement/placement.rs",
                required: &[
                    (
                        r#"Self::Paging(paging) => paging.bind_original(serial, class),"#,
                        1,
                    ),
                    (r#"Self::Paging(paging) => paging.settle(operation),"#, 1),
                    (r#"Self::Paging(paging) => paging.return_identity(),"#, 1),
                ],
            },
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-plugin/src/paged_ram/engine/service/capture_work/pause.rs",
                required: &[
                    (
                        r#"if identity == 0 || self.requested.load(Ordering::Acquire) != 0"#,
                        1,
                    ),
                    (
                        r#"if current != 0 || identity <= self.ordinary_issued.load(Ordering::Acquire)"#,
                        1,
                    ),
                    (
                        r#"self.ordinary_issued.store(identity, Ordering::Release); self.ordinary_requested.store(identity, Ordering::Release);"#,
                        1,
                    ),
                    (
                        r#"identity != 0 && self.ordinary_requested.load(Ordering::Acquire) == identity && self.ordinary_acknowledged.load(Ordering::Acquire) == identity"#,
                        1,
                    ),
                    (
                        r#".compare_exchange(identity, 0, Ordering::AcqRel, Ordering::Acquire)"#,
                        1,
                    ),
                ],
            },
        ],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/qmp/parent_park_drain/transport",
        required: &[
            (
                r#"let session = self.parent_park_session.as_mut().ok_or(QmpError::InvalidBound"#,
                1,
            ),
            (r#"let encoded = request.encode(&mut session.frame)?;"#, 1),
            (
                r#"let mut written = 0; while written < frame.len() { let remaining = deadline.remaining(kind.wire_name())?;"#,
                1,
            ),
            (r#".set_qmp_write_timeout(remaining)"#, 1),
            (
                r#"let count = match stream.get_mut().write(&frame[written..])"#,
                1,
            ),
            (r#"if count == 0 { return Err(QmpError::Io"#, 1),
            (r#"written += count;"#, 1),
            (
                r#"let limit = policy_limit.min(frame.len()); let mut length = 0; while length < limit { let remaining = deadline.remaining(kind.wire_name())?;"#,
                1,
            ),
            (r#"if stream.buffer().is_empty()"#, 1),
            (r#".set_qmp_read_timeout(remaining)"#, 1),
            (r#"let buffered = match stream.fill_buf()"#, 1),
            (r#"if buffered.is_empty() { return Err(QmpError::Io"#, 1),
            (r#"let available = buffered.len().min(limit - length);"#, 1),
            (
                r#"frame[length..length + consumed].copy_from_slice(&buffered[..consumed]); stream.consume(consumed); length += consumed;"#,
                1,
            ),
            (
                r#"if skipped_events > self.io_timeout_policy.max_async_events_per_command"#,
                1,
            ),
            (
                r#"if result.as_ref().is_err_and(|first| !matches!(first, QmpError::Command { .. })) { self.poison_parent_park_drain(); }"#,
                1,
            ),
        ],
        expressions: &[(
            r#"Err(error) if deadline.retry_slice(&error) => continue,"#,
            2,
        )],
        identifiers: &[],
        companions: &[
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-host/src/qmp.rs",
                required: &[
                    (
                        r#"if let Some(original) = &self.checkpoint_loan { return checkpoint_original_wait::wait_slice(original.guard(), operation); }"#,
                        1,
                    ),
                    (
                        r#"if let Some(original) = self.checkpoint_original { return checkpoint_original_wait::wait_slice(original, operation); }"#,
                        1,
                    ),
                    (
                        r#"return parent_park_drain::paired_wait_slice(actor, family, operation);"#,
                        1,
                    ),
                    (
                        r#"if let Some(guard) = self.borrowed { return guard.wait_slice().map_err"#,
                        1,
                    ),
                    (
                        r#"if let Some(guard) = &self.shared { return guard.wait_slice().map_err"#,
                        1,
                    ),
                    (r#"let Some(remaining) = supervision.remaining() else"#, 1),
                    (r#"if remaining.is_zero() { Err(QmpError::Timeout"#, 1),
                    (
                        r#"fn retry_slice(&self, error: &io::Error) -> bool { let supervised = self.shared.is_some();"#,
                        1,
                    ),
                    (
                        r#"supervised || self.checkpoint_original.is_some() || self.checkpoint_loan.is_some();"#,
                        1,
                    ),
                    (
                        r#"let supervised = supervised || self.borrowed.is_some();"#,
                        1,
                    ),
                    (
                        r#"supervised && matches!(error.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut)"#,
                        1,
                    ),
                ],
            },
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-host/src/qmp/parent_park_drain.rs",
                required: &[
                    (
                        r#"let actor_slice = checked_wait_slice(actor); let family_slice = checked_wait_slice(family); actor_slice.and_then(|actor| family_slice.map(|family| actor.min(family)))"#,
                        1,
                    ),
                    (
                        r#"guard.check_original_quiescence_cancellation()?; let slice = guard.wait_slice()?; guard.check_original_quiescence_cancellation()?;"#,
                        1,
                    ),
                    (
                        r#"supervision: None, timeout: self.io_timeout_policy.command_timeout, shared: None, checkpoint_original: None, checkpoint_loan: None, borrowed: Some(actor), paired: Some(family),"#,
                        1,
                    ),
                    (
                        r#"paired_wait_slice(actor, family, operation).map(|_| ())"#,
                        1,
                    ),
                    (
                        r#".state.begin_attempted = true; let deadline = self.pair_deadline(actor, family); let result = self.exchange_parent_park(request, &deadline)?;"#,
                        1,
                    ),
                    (
                        r#"if let Err(first) = deadline.complete(request.kind().wire_name()) { self.poison_parent_park_drain(); return Err(first); }"#,
                        1,
                    ),
                ],
            },
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-host/src/qmp/checkpoint_original_wait.rs",
                required: &[
                    (
                        r#"original.check_original_quiescence_cancellation()?; let slice = original.wait_slice()?; original.check_original_quiescence_cancellation()?;"#,
                        1,
                    ),
                    (
                        r#"let work = self.checkpoint_exchange(command, original); let original_after = checked_slice(original).err();"#,
                        1,
                    ),
                    (
                        r#"(Err(source), original_after) => Err(CheckpointExchangeError { source, original_after, }),"#,
                        1,
                    ),
                ],
            },
        ],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/linux_attempt_host/original_roster",
        required: &[
            (
                r#"for slot in &mut state.slots { fork_target::retry_unsettled_target(slot)?; if slot.fork_target.is_owned() || slot.unsettled.is_none() { continue; }"#,
                1,
            ),
            (
                r#"let cleanup = retain_cleanup(slot).map_err(original_error)?; slot.unsettled.as_mut().ok_or_else(|| original_error(OriginalActorAccountError::Unavailable))?.finish(&cleanup)?; close_slot(slot).map_err(original_error)?; slot.unsettled = None;"#,
                1,
            ),
            (r#"if slot.cleanup.is_none()"#, 1),
            (
                r#"slot.cleanup = Some(Arc::new(credit.begin_cleanup()?));"#,
                1,
            ),
            (r#"cleanup.wait_slice()?; Ok(Arc::clone(cleanup))"#, 1),
            (r#"process.finish_under_original(cleanup)?;"#, 1),
            (r#"group.remove_under_original(cleanup)?;"#, 1),
            (
                r#"if result.is_ok() { self.storage = None; } after_cleanup(result, cleanup)"#,
                1,
            ),
            (
                r#"let closed = control.close(); let after = cleanup.wait_slice(); if let Err(source) = closed { return Err(OriginalActorAccountError::NativeControlBoundary { source, original: after.err(), }); } after?;"#,
                1,
            ),
            (r#"cleanup.complete()?; slot.cleanup = None;"#, 1),
            (
                r#"slot.installed_process = None; slot.source_control_payer = None; slot.active = None;"#,
                1,
            ),
            (
                r#"after_boundary(result, cleanup.wait_slice().map(|_| ()).map_err(Into::into))"#,
                1,
            ),
            (
                r#"(Err(primary), Err(original)) => Err(QemuVmRealizationError::ModelCopy { source: Box::new(NativeAccountBoundaryError { primary: Some(primary), original, }), }),"#,
                1,
            ),
            (r#"assert!(roster.retry_unsettled().is_err());"#, 1),
            (
                r#"assert!(std::fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());"#,
                2,
            ),
            (
                r#"assert!(binding.claim(1, 512 << 20, 1 << 30).is_err()); assert!(attempt.close_vector().is_err());"#,
                1,
            ),
            (
                r#"assert_eq!(state.slots[0].active, Some(attempt.generation)); assert!(state.slots[0].unsettled.as_ref().unwrap().storage.is_some());"#,
                1,
            ),
        ],
        expressions: &[
            (r#"roster.retry_unsettled()"#, 2),
            (r#"fork_target::retry_unsettled_target(slot)?;"#, 1),
        ],
        identifiers: &[
            (r#"retry_unsettled"#, 3),
            (
                r#"terminal_cleanup_refuses_retry_and_keeps_actual_storage_and_generation"#,
                1,
            ),
        ],
        companions: &[Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster/fork_target.rs",
            required: TARGET_CLEANUP_REQUIRED,
        }],
    },
    Contract {
        package: "crucible-daemon",
        target: "src/managed_qemu_hot_fork_source_world_pool/pool",
        required: &[
            (
                r#"let Some((template, _, _)) = self.checked_out.get(&provider) else"#,
                1,
            ),
            (
                r#"if world.invalidated || world.parent_park_owned() || world.fork_target_owned() { return; }"#,
                2,
            ),
            (
                r#"let Some(source) = world.source.take() else { return; }; self.restore_for(provider, source);"#,
                1,
            ),
            (
                r#"if record.abandoned || record.returned_lease.is_none() { return; }"#,
                1,
            ),
            (
                r#".and_then(|record| record.returned_lease.take()) else { return; }; self.restore_lease_for(provider, lease);"#,
                1,
            ),
            (
                r#"if self.checked_out.contains_key(&provider) || self.leased_out.contains_key(&provider) { return Err(ManagedQemuHotForkSourceWorldCheckoutError::PriorCheckoutPending); }"#,
                2,
            ),
            (
                r#"if !identity.matches(&source) { let _ = source.retire(); return; }"#,
                1,
            ),
            (r#"if source.fork_target_is_owned()"#, 1),
            (r#"world.source = Some(source);"#, 2),
            (
                r#"match QemuHotForkSourceWorldLease::exclusive(manager_source_key(key), source, identity) {
                    Ok(lease) => Ok(Some(lease)),
                    Err(source) => {
                        if let Some(world) = self.worlds.get_mut(&manager_source_key(key)) {
                            world.source = Some(source);
                            world.invalidated = true;
                        } else { drop(source); }
                        Err(ManagedQemuHotForkSourceWorldCheckoutError::SourcePoisoned)
                    }
                }"#,
                1,
            ),
            (
                r#"if source.fork_target_is_owned() {
                    if let Some((template, _, _)) = self.checked_out.get(&provider)
                        && let Some(world) = self.worlds.get_mut(template)
                    { world.source = Some(source); } else { drop(source); }
                    return;
                }"#,
                1,
            ),
            (
                r#"let matching_receipt = Some(record.lease) == lease.managed_lease && record.template == lease.template && record.identity == lease.identity;"#,
                1,
            ),
            (
                r#"let matching_source = record.source.upgrade().is_some_and(|source| {
                    lease.source_owner_ref().is_some_and(|actual| Arc::ptr_eq(&source, actual))
                });"#,
                1,
            ),
            (r#"if !matching_receipt || !matching_source"#, 1),
            (
                r#"let Some(source_owner) = lease.source_owner() else {
                    if let Some(record) = self.leased_out.get_mut(&provider)
                        && record.returned_lease.is_none()
                    { record.returned_lease = Some(lease); }
                    return;
                };"#,
                1,
            ),
            (r#"let mut source = match source_owner.try_lock()"#, 1),
            (
                r#"if let Some(record) = self.leased_out.get_mut(&provider) && record.returned_lease.is_none() { record.returned_lease = Some(lease); }"#,
                3,
            ),
            (r#"if abandoned || source.fork_target_is_owned()"#, 1),
            (
                r#"let source_reusable = record_identity.matches(&source) && source.restore_retained_service_supervisor().is_ok() && source.fork_continuation().is_ok();"#,
                1,
            ),
        ],
        expressions: &[
            (r#"self.retry_returned_source_for(provider);"#, 2),
            (r#"self.retry_returned_lease_for(provider);"#, 2),
        ],
        identifiers: &[
            (r#"retry_returned_source_for"#, 3),
            (r#"retry_returned_lease_for"#, 3),
        ],
        companions: &[Companion {
            path: "crates/crucible/control/crucible-daemon/src/managed_qemu_hot_fork_source_world_pool/tests/leases.rs",
            required: &[
                (
                    r#"assert_eq!(record.lease, sequence); assert_eq!(record._permit.ordinal(), ordinal);"#,
                    3,
                ),
                (
                    r#"assert_eq!(pool.source_lease_usage(), before_usage); assert!(record.returned_lease.is_some()); assert!(!record.abandoned);"#,
                    1,
                ),
                (
                    r#"assert_eq!(returned.managed_lease, Some(sequence)); assert!(Arc::ptr_eq(returned.source_owner_ref().unwrap(), &source_owner));"#,
                    1,
                ),
                (
                    r#"assert_eq!(pool.next_lease, next_lease); assert_eq!(pool.source_lease_usage(), charge); assert_eq!(pool.leased_out.len(), 1);"#,
                    1,
                ),
                (
                    r#"assert!(pool.checkout_lease_for(1, &key).is_err()); assert_eq!(pool.source_lease_usage(), charge); assert_eq!(pool.leased_out.get(&1).unwrap().lease, sequence);"#,
                    2,
                ),
            ],
        }],
    },
];

fn contracts() -> impl Iterator<Item = &'static Contract> {
    CONTRACTS
        .iter()
        .chain(cache::CONTRACTS)
        .chain(cleanup_delegation::CONTRACTS)
        .chain(refused_publication::CONTRACTS)
        .chain(production_publication::CONTRACTS)
        .chain(worker_custody::CONTRACTS)
        .chain(lifecycle_retirement::CONTRACTS)
        .chain(host_physical_custody::CONTRACTS)
        .chain(hot_fork_retirement::CONTRACTS)
        .chain(pager_placement::CONTRACTS)
        .chain(native_registration::CONTRACTS)
        .chain(native_registration::REQUIRED_WORKER_CONTRACTS)
        .chain(owned_process_controls::CONTRACTS)
        .chain(retained_continuations::CONTRACTS)
        .chain(constructor_continuations::CONTRACTS)
        .chain(construction_endpoint::CONTRACTS)
        .chain(service_continuations::CONTRACTS)
}

pub(super) fn mask(package: &str, target: &str, code: &str) -> String {
    let Some(contract) =
        contracts().find(|contract| contract.package == package && contract.target == target)
    else {
        return code.to_owned();
    };
    let Ok(companions) = read_companions(contract) else {
        return code.to_owned();
    };
    mask_contract(contract, code, &companions)
}

fn read_companions(contract: &Contract) -> std::io::Result<Vec<String>> {
    let root = super::super::super::workspace_root();
    contract
        .companions
        .iter()
        .map(|binding| std::fs::read_to_string(root.join(binding.path)))
        .collect()
}

fn matches_required(required: &[(&str, usize)], code: &str) -> bool {
    let compact = compact_code(code);
    required
        .iter()
        .all(|(part, count)| compact.match_indices(&source_pattern(part)).count() == *count)
}

fn mask_contract(contract: &Contract, code: &str, companions: &[String]) -> String {
    let local_matches = matches_required(contract.required, code)
        && contract.expressions.iter().all(|(expression, count)| {
            expression_offsets(code, &source_pattern(expression)).len() == *count
        })
        && contract
            .identifiers
            .iter()
            .all(|(name, count)| identifier_count(code, name) == *count);
    let companions_match = companions.len() == contract.companions.len()
        && contract
            .companions
            .iter()
            .zip(companions)
            .all(|(binding, source)| {
                matches_required(
                    binding.required,
                    &super::super::scrub_comments_and_strings(source),
                )
            });
    if !local_matches || !companions_match {
        return code.to_owned();
    }

    let mut masked = code.to_owned();
    for (expression, count) in contract.expressions {
        mask_expression(&mut masked, &source_pattern(expression), *count);
    }
    for (name, _) in contract.identifiers {
        masked = mask_identifier(&masked, name);
    }
    masked
}

// Preserve identifier boundaries outside the removed multiline obligation.
fn replace_one_obligation(code: &str, obligation: &str, replacement: &str) -> String {
    let offsets = code
        .char_indices()
        .filter(|(_, character)| !character.is_whitespace())
        .flat_map(|(offset, character)| std::iter::repeat_n(offset, character.len_utf8()))
        .collect::<Vec<_>>();
    let compact = compact_code(code);
    let Some(offset) = compact.find(obligation) else {
        return code.to_owned();
    };
    let start = offsets[offset];
    let end = offsets[offset + obligation.len() - 1] + 1;
    let mut changed = code.to_owned();
    changed.replace_range(start..end, replacement);
    changed
}
