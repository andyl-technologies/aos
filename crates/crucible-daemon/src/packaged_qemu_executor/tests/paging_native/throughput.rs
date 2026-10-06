//! Completed campaign throughput across real managed placement and concurrency.
//!
//! Every row submits new canonical campaigns through the production planner and
//! original full-vector actor. Only newly durable `Completed` ledger rows count;
//! repeated observations, canceled workers and ready children never count. The
//! test retains full native peaks at every target, including zero safely
//! evictable residency. It exercises the mechanism beneath its public gate.

use super::*;
use crate::packaged_qemu_executor::guarded::{GuardedCampaignOwner, PackagedGuardedState};
use crate::qemu_campaign_lifecycle::{
    GuardedDefaultCampaignRunRequest, NativeCampaignProbe, run_native_throughput_campaign,
};
use crate::{QemuFreshAttemptLifecycle, SharedQemuAttemptHostResourceFactory};
use crucible_api::host_operational::{HostOperationalError, HostResourceVector};
use crucible_campaign::{DebuggerAuthorityKey, PlannerAuthorityKey, StopCondition};
use crucible_linux_resource::host_services::HostServiceAllocator;
use crucible_linux_resource::host_supervision::HostOperationSupervisor;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

mod corpus;
mod report;
mod workers;

const PARALLEL: [usize; 3] = [1, 2, 4];
const TARGET_DIVISORS: [u64; 3] = [1, 2, 0];
const REPEATS: usize = 3;
const QUANTA_PER_ATTEMPT: u64 = 32;

#[test]
#[ignore = "requires pinned AOS host/storage, real ten-CPU full peaks, UFFD and quota namespaces"]
fn completed_campaign_throughput_matrix() {
    let source = corpus::source();
    let catalog = corpus::catalog_budget();
    environment::with_native_repository_environment_with_catalog(
        "campaign-throughput",
        56_000,
        catalog,
        |_, storage| corpus::repository(&source, storage),
        corpus::resources,
        |prepared, config, repository| {
            let state = PackagedGuardedState {
                actor: prepared.actor.campaign_port(),
                config: config.clone(),
                checkpoints: prepared.checkpoints.clone(),
                host: Some(SharedQemuAttemptHostResourceFactory::new(
                    LinuxQemuAttemptHostResourceFactory::open(config.host.clone())
                        .expect("actual Linux allocator"),
                )),
            };
            let owner = GuardedCampaignOwner::from_packaged(
                &state,
                repository,
                PlannerAuthorityKey::from_bytes([0x31; 32]).expect("actual planner key"),
            )
            .expect("same prepared actor, durable catalog and immutable compatibility");
            let controller = workers::WorkerService::admit(&owner, config);
            let _report_loan = controller.reserve_report();
            let pin = report::PinnedInputs::read(&controller)
                .expect("explicit pinned benchmark environment");
            let before = report::availability(&owner);
            let mut rows = Vec::new();

            for divisor in TARGET_DIVISORS {
                for parallel in PARALLEL {
                    for repeat in 0..REPEATS {
                        let row = run_row(&owner, &controller, &source, divisor, parallel, repeat);
                        report::publish_row(&row);
                        if row.failures.is_empty() {
                            for sample in &row.samples {
                                if divisor == 0 {
                                    let activity = sample
                                        .activity
                                        .expect("native cold placement activity is measured");
                                    assert!(
                                        activity.physical_discards > 0,
                                        "zero safely evictable target must physically converge"
                                    );
                                    assert!(
                                        activity.successful_missing_installs > 0,
                                        "the accepted guest must encounter real authenticated missing pages"
                                    );
                                }
                                assert!(corpus::SEEDS.contains(&sample.seed));
                            }
                        }
                        assert_eq!(
                            report::availability(&owner),
                            before,
                            "durable completion must follow physical cleanup of every row"
                        );
                        rows.push(row);
                        controller
                            .completed_row(u64::try_from(rows.len()).expect("fixed row count"));
                    }
                }
            }
            let mut observed = [false; corpus::SEEDS.len()];
            for sample in rows.iter().flat_map(|row| &row.samples) {
                let index = corpus::SEEDS
                    .iter()
                    .position(|seed| *seed == sample.seed)
                    .expect("receipt belongs to the authenticated corpus");
                assert!(
                    !observed[index],
                    "no completed reproduction can count as a fresh corpus attempt"
                );
                observed[index] = true;
            }
            report::publish(&pin, &source, config, &rows);
            let succeeded = rows.iter().all(|row| row.failures.is_empty());
            if succeeded {
                assert_eq!(
                    rows.iter().map(|row| row.completed).sum::<u64>(),
                    corpus::SEEDS.len() as u64
                );
                assert!(observed.into_iter().all(|used| used));
            }
            drop(rows);
            drop(pin);
            drop(_report_loan);
            controller.release_after_joined_workers();
            assert!(
                succeeded,
                "every admitted row must report its failures before the gate fails"
            );
            println!("COMPLETED_CAMPAIGN_THROUGHPUT_MATRIX_NATIVE_PASS");
        },
    );
}

fn run_row(
    owner: &GuardedCampaignOwner,
    controller: &workers::WorkerService,
    source: &ScenarioDefForm,
    divisor: u64,
    parallel: usize,
    repeat: usize,
) -> report::Row {
    let probe = Arc::new(PlacementProbe {
        divisor,
        parallel,
        arrived: AtomicUsize::new(0),
        aborted: AtomicBool::new(false),
        owner: owner.clone(),
        initial_available: report::availability(owner),
        samples: Mutex::new(Vec::with_capacity(parallel)),
        started: Mutex::new(Vec::with_capacity(parallel)),
        peaks: Mutex::new(HostResourceVector::default()),
    });
    let before = report::completed_count(owner);
    let start = report::now();
    let outcomes = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(parallel);
        for worker in 0..parallel {
            let seed = corpus::seed(divisor, parallel, repeat, worker);
            let permit = controller.reserve_worker();
            let probe = probe.clone();
            let owner = owner.clone();
            handles.push(
                std::thread::Builder::new()
                    .name("native-campaign-throughput".into())
                    .stack_size(workers::WORKER_STACK)
                    .spawn_scoped(scope, move || {
                        let _permit = permit;
                        let result = (|| {
                            let input = owner.inner.config.admitted_lifecycle_config().map_err(
                                |error| -> Box<dyn std::error::Error + Send> { Box::new(error) },
                            )?;
                            let _input_scope = input.enter_input_custody();
                            let source = corpus::seeded_source(source, seed).map_err(
                                |error| -> Box<dyn std::error::Error + Send> { Box::new(error) },
                            )?;
                            let request = GuardedDefaultCampaignRunRequest::new(
                                source,
                                Seed::from_u64(seed),
                                "crucible-test",
                                corpus::qemu_build(),
                                owner,
                            )
                            .map_err(|error| -> Box<dyn std::error::Error + Send> {
                                Box::new(error)
                            })?
                            .with_discovery_stop(
                                StopCondition::ExecutionQuanta(QUANTA_PER_ATTEMPT),
                            );
                            run_native_throughput_campaign(
                                request,
                                probe.clone(),
                                controller.cancellation(),
                            )
                            .map_err(
                                |error| -> Box<dyn std::error::Error + Send> { Box::new(error) },
                            )
                        })();
                        if result.is_err() {
                            probe.aborted.store(true, Ordering::Release);
                        }
                        result.map(|run| run.terminal().id())
                    })
                    .expect("permit before bounded host worker spawn"),
            );
        }
        handles
            .into_iter()
            .map(|handle| handle.join())
            .collect::<Vec<_>>()
    });
    let elapsed_ns = report::now()
        .checked_sub(start)
        .expect("monotonic row duration");
    let completed = report::completed_count(owner)
        .checked_sub(before)
        .expect("completed states cannot disappear during this retention interval");
    let mut failures = Vec::new();
    for outcome in outcomes {
        match outcome {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => failures.push(error.to_string()),
            Err(panic) => {
                // A panic is not a physical cleanup certificate. The actual
                // controller/capacity owner remains retained for quarantine.
                controller.quarantine();
                failures.push(format!("worker panicked: {panic:?}"));
            }
        }
    }
    if failures.is_empty() && completed != u64::try_from(parallel).expect("bounded parallelism") {
        failures.push(format!(
            "durable completion count {completed} differs from {parallel} new attempts"
        ));
    }
    report::Row {
        target_divisor: divisor,
        parallel,
        repeat,
        elapsed_ns,
        completed,
        completed_attempts_per_host_hour: report::rate(completed, elapsed_ns),
        failures,
        samples: std::mem::take(&mut *probe.samples.lock().expect("probe samples")),
        reservation_peak: *probe
            .peaks
            .lock()
            .expect("actual reservation high-water mark"),
    }
}

struct PlacementProbe {
    divisor: u64,
    parallel: usize,
    arrived: AtomicUsize,
    aborted: AtomicBool,
    owner: GuardedCampaignOwner,
    initial_available: HostResourceVector,
    samples: Mutex<Vec<report::Sample>>,
    started: Mutex<Vec<([u8; 32], u64)>>,
    peaks: Mutex<HostResourceVector>,
}

impl NativeCampaignProbe for PlacementProbe {
    fn before_drive(
        &self,
        _lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<(), HostOperationalError> {
        if !corpus::SEEDS
            .iter()
            .any(|seed| Seed::from_u64(*seed) == input.scenario().seed())
        {
            return Err(HostOperationalError::Unavailable);
        }
        let target = report::target(context)?;
        let registry = context
            .host_operational_registry()
            .ok_or(HostOperationalError::Unavailable)?;
        let response =
            registry.execute(OPERATOR, HostOperationalRequest::Capabilities { target })?;
        let logical_bytes = match response.value() {
            HostOperationalResponse::Capabilities { capabilities, .. } => {
                capabilities.logical_ram_bytes
            }
            _ => return Err(HostOperationalError::Unavailable),
        };
        let target_bytes = logical_bytes.checked_div(self.divisor).unwrap_or(0);
        registry.apply_native_qualification_policy(target, target_bytes)?;
        self.arrived.fetch_add(1, Ordering::AcqRel);
        let original = context
            .host_operation_supervisor()
            .ok_or(HostOperationalError::Unavailable)?;
        let wait = original
            .begin(HostOperationClass::Quiescence)
            .map_err(|_| HostOperationalError::Unavailable)?;
        while self.arrived.load(Ordering::Acquire) != self.parallel {
            if self.aborted.load(Ordering::Acquire) {
                return Err(HostOperationalError::Unavailable);
            }
            wait.wait_for_change()
                .map_err(|_| HostOperationalError::Unavailable)?;
        }
        wait.complete()
            .map_err(|_| HostOperationalError::Unavailable)?;
        report::observe_peak(
            &self.owner,
            self.initial_available,
            &mut *self
                .peaks
                .lock()
                .map_err(|_| HostOperationalError::Unavailable)?,
        );
        let mut started = self
            .started
            .lock()
            .map_err(|_| HostOperationalError::Unavailable)?;
        if started.len() >= self.parallel {
            return Err(HostOperationalError::Unavailable);
        }
        started.push((target.owner_id, report::now()));
        Ok(())
    }

    fn after_drive(
        &self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<(), HostOperationalError> {
        let target = report::target(context)?;
        let registry = context
            .host_operational_registry()
            .ok_or(HostOperationalError::Unavailable)?;
        let observation = report::status(registry, target)?;
        let HostOperationalResponse::Status(status) = observation.value() else {
            return Err(HostOperationalError::Unavailable);
        };
        let started = self
            .started
            .lock()
            .map_err(|_| HostOperationalError::Unavailable)?
            .iter()
            .find_map(|(owner, started)| (*owner == target.owner_id).then_some(*started))
            .ok_or(HostOperationalError::Unavailable)?;
        let guest_drive_ns = report::now()
            .checked_sub(started)
            .ok_or(HostOperationalError::Unavailable)?;
        let faults = lifecycle
            .fault_evidence_snapshot()
            .map_err(|_| HostOperationalError::Unavailable)?;
        let start = report::now();
        let fingerprint = lifecycle
            .sample_fingerprint(NodeId {
                name: "memory".into(),
            })
            .map_err(|_| HostOperationalError::Unavailable)?
            .fingerprint
            .hash
            .bytes;
        let fingerprint_ns = report::now()
            .checked_sub(start)
            .ok_or(HostOperationalError::Unavailable)?;
        let mut samples = self
            .samples
            .lock()
            .map_err(|_| HostOperationalError::Unavailable)?;
        if samples.len() >= self.parallel {
            return Err(HostOperationalError::Unavailable);
        }
        samples.push(report::Sample {
            seed: *corpus::SEEDS
                .iter()
                .find(|seed| Seed::from_u64(**seed) == input.scenario().seed())
                .ok_or(HostOperationalError::Unavailable)?,
            scenario: input.scenario().id().bytes,
            fingerprint,
            fingerprint_ns,
            guest_drive_ns,
            charged_physical_quanta: context.consumed_execution_quanta(),
            emitted_signal_events: u64::try_from(faults.emitted_events.len())
                .map_err(|_| HostOperationalError::Unavailable)?,
            fault_work_items: faults
                .resolved_effect_trace
                .as_ref()
                .map(|trace| trace.work_items.len()),
            requested_target_bytes: status.requested_policy.resident_target_bytes,
            effective_target_bytes: status.effective_resident_target_bytes,
            activity: status.activity,
            resources: status.admitted_resources,
        });
        Ok(())
    }
}
