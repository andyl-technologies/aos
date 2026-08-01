//! Adversarial determinism comparison and host-fixture utilities.
//!
//! This module hosts two pieces of the host-hostile runner. The comparison core
//! checks completed runs after they have produced a canonical log hash and final
//! fingerprint. The host-adversary fixture builds deterministic work plans that
//! cover seeded scheduling, logical affinity, injected load, and
//! producer/consumer skew without making test results depend on wall-clock time.

use std::error::Error;
use std::fmt;

const HOST_ADVERSARY_MATRIX: [HostAdversaryProfile; 4] = [
    HostAdversaryProfile::quiet_single_core(),
    HostAdversaryProfile::loaded_single_core(),
    HostAdversaryProfile::reordered_two_core(),
    HostAdversaryProfile::loaded_many_core(),
];

/// One hostile host profile used for an adversarial run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostileProfile {
    /// Stable profile name used in diagnostics.
    pub name: String,
}

/// One completed run under a hostile host profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdversarialRun {
    /// Hostile profile used for this run.
    pub profile: HostileProfile,
    /// Canonical event-log bytes or a content hash of those bytes.
    pub canonical_log: Vec<u8>,
    /// Final execution fingerprint bytes.
    pub final_fingerprint: Vec<u8>,
}

/// A deterministic scenario in the adversarial determinism corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdversarialScenario {
    /// Stable scenario name included in canonical log material.
    pub name: String,
    /// Deterministic scenario seed.
    pub seed: u64,
    /// Canonical operation stream for the scenario.
    pub operations: Vec<AdversarialScenarioOperation>,
}

/// One canonical operation in an adversarial determinism scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdversarialScenarioOperation {
    /// A modeled message delivery between two nodes.
    Deliver {
        /// Virtual tick at which the message is delivered.
        at_tick: u64,
        /// Source node name.
        from: String,
        /// Destination node name.
        to: String,
        /// Stable message sequence number.
        sequence: u64,
    },
    /// A modeled fault application or heal at a virtual tick.
    Fault {
        /// Virtual tick at which the fault changes state.
        at_tick: u64,
        /// Fault target name.
        target: String,
        /// Whether the fault is active after this operation.
        active: bool,
    },
    /// A modeled host-side I/O operation whose timing must not affect state.
    HostIo {
        /// Virtual tick at which the modeled I/O result is observed.
        at_tick: u64,
        /// Stable resource name.
        resource: String,
        /// Deterministic byte count.
        bytes: u64,
    },
}

/// Successful result of `gate:adversarial-determinism`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdversarialGateReport {
    /// Number of scenarios in the fixed corpus.
    pub scenario_count: usize,
    /// Number of hostile profiles used.
    pub profile_count: usize,
    /// Runs compared across the hostile profile matrix.
    pub runs: Vec<AdversarialRun>,
}

/// Failure returned by `gate:adversarial-determinism`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdversarialGateError {
    /// No scenarios were supplied.
    EmptyScenarioCorpus,
    /// A scenario has no operations to compare.
    EmptyScenario {
        /// Empty scenario name.
        scenario: String,
    },
    /// No hostile host profiles were supplied.
    EmptyProfileMatrix,
    /// The hostile host fixture could not run.
    HostAdversary(HostAdversaryError),
    /// Runs diverged across hostile host profiles.
    Comparison(AdversarialComparisonError),
}

/// One observed operation after running it through a hostile host profile.
#[derive(Clone, Copy, Debug)]
pub struct AdversarialObservation<'a> {
    /// Host profile used for this observation.
    pub profile: HostAdversaryProfile,
    /// Scenario that owns the observed operation.
    pub scenario: &'a AdversarialScenario,
    /// Canonical operation index inside the scenario.
    pub operation_index: usize,
    /// Operation being projected into canonical log material.
    pub operation: &'a AdversarialScenarioOperation,
    /// Host task metadata produced by the adversarial fixture.
    pub task: AdversarialTask,
    /// Producer/consumer role that ran first under this profile.
    pub first_role: ProducerConsumerRole,
    /// Producer-side deterministic observation.
    pub producer: &'a str,
    /// Consumer-side deterministic observation.
    pub consumer: &'a str,
}

/// A failed adversarial comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdversarialComparisonError {
    /// No runs were provided, so no comparison can be made.
    EmptyCorpus,
    /// A run diverged from the first run in the corpus.
    Mismatch(AdversarialMismatch),
}

/// The first run that diverged from the baseline adversarial run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdversarialMismatch {
    /// Baseline hostile profile.
    pub baseline_profile: String,
    /// Divergent hostile profile.
    pub divergent_profile: String,
    /// The field that differed.
    pub kind: AdversarialMismatchKind,
}

/// The adversarial output field that differed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdversarialMismatchKind {
    /// The canonical log bytes or log hash differed.
    CanonicalLog,
    /// The final fingerprint bytes differed.
    FinalFingerprint,
}

/// One deterministic host-adversary profile used to exercise a gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostAdversaryProfile {
    /// Stable profile name used in diagnostics and evidence output.
    pub name: &'static str,
    /// Number of worker threads used to execute the fixture plan.
    pub worker_count: usize,
    /// Deterministic order used to assign logical tasks to workers.
    pub task_order: HostTaskOrder,
    /// Logical affinity layout applied to tasks in the plan.
    pub affinity: HostAffinity,
    /// Deterministic load injected around each task.
    pub load: HostLoad,
    /// Deterministic producer/consumer timing skew applied around each task.
    pub producer_consumer_skew: ProducerConsumerSkew,
}

impl HostAdversaryProfile {
    /// Returns the quiet single-worker baseline profile.
    #[must_use]
    pub const fn quiet_single_core() -> Self {
        Self {
            name: "quiet-single-core",
            worker_count: 1,
            task_order: HostTaskOrder::Forward,
            affinity: HostAffinity::SingleCore,
            load: HostLoad::quiet(),
            producer_consumer_skew: ProducerConsumerSkew::None,
        }
    }

    /// Returns a single-worker profile with injected load and yield jitter.
    #[must_use]
    pub const fn loaded_single_core() -> Self {
        Self {
            name: "loaded-single-core",
            worker_count: 1,
            task_order: HostTaskOrder::Reverse,
            affinity: HostAffinity::SingleCore,
            load: HostLoad::spinning(4096, 2),
            producer_consumer_skew: ProducerConsumerSkew::ProducerFast,
        }
    }

    /// Returns a two-worker profile with seeded scheduling and affinity.
    #[must_use]
    pub const fn reordered_two_core() -> Self {
        Self {
            name: "reordered-two-core",
            worker_count: 2,
            task_order: HostTaskOrder::SeededPermutation {
                seed: 0x5eed_0010_0002,
            },
            affinity: HostAffinity::Seeded {
                logical_cores: 2,
                seed: 0xaff1_0010_0002,
            },
            load: HostLoad::spinning(2048, 1),
            producer_consumer_skew: ProducerConsumerSkew::ConsumerFast,
        }
    }

    /// Returns a many-worker profile with heavier load and alternating skew.
    #[must_use]
    pub const fn loaded_many_core() -> Self {
        Self {
            name: "loaded-many-core",
            worker_count: 4,
            task_order: HostTaskOrder::Strided { stride: 3 },
            affinity: HostAffinity::RoundRobin { logical_cores: 4 },
            load: HostLoad::spinning(4096, 1),
            producer_consumer_skew: ProducerConsumerSkew::Alternating,
        }
    }
}

/// The deterministic task order used by a host-adversary profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostTaskOrder {
    /// Keeps task indexes in ascending order.
    Forward,
    /// Reverses the ascending task order.
    Reverse,
    /// Rotates the ascending task order left by one position.
    Rotated,
    /// Walks task indexes by a deterministic stride, then appends leftovers.
    Strided {
        /// Positive stride used to visit task indexes.
        stride: usize,
    },
    /// Applies a seeded pseudo-random permutation.
    SeededPermutation {
        /// Stable seed used to reproduce the permutation.
        seed: u64,
    },
}

/// The logical affinity model used by a host-adversary profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostAffinity {
    /// Assigns every task to logical core zero.
    SingleCore,
    /// Assigns tasks to logical cores in task-plan order.
    RoundRobin {
        /// Number of logical cores in the profile.
        logical_cores: usize,
    },
    /// Assigns tasks to logical cores through a seeded pseudo-random mapping.
    Seeded {
        /// Number of logical cores in the profile.
        logical_cores: usize,
        /// Stable seed used to reproduce the logical affinity assignment.
        seed: u64,
    },
}

impl HostAffinity {
    fn logical_core_for(
        self,
        profile: HostAdversaryProfile,
        task_index: usize,
        plan_ordinal: usize,
    ) -> Result<usize, HostAdversaryError> {
        match self {
            Self::SingleCore => Ok(0),
            Self::RoundRobin { logical_cores } => {
                if logical_cores == 0 {
                    return Err(HostAdversaryError::EmptyLogicalCoreSet {
                        profile: profile.name,
                    });
                }
                Ok(plan_ordinal % logical_cores)
            }
            Self::Seeded {
                logical_cores,
                seed,
            } => {
                if logical_cores == 0 {
                    return Err(HostAdversaryError::EmptyLogicalCoreSet {
                        profile: profile.name,
                    });
                }
                Ok(seeded_index(seed, task_index, plan_ordinal) % logical_cores)
            }
        }
    }
}

/// Deterministic background load injected around host-adversary tasks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostLoad {
    /// Number of spin-loop iterations to run for each task.
    pub iterations: u64,
    /// Yield cadence for the load loop; zero disables explicit yields.
    pub yield_every: u64,
}

impl HostLoad {
    /// Returns a profile load that injects no background work.
    #[must_use]
    pub const fn quiet() -> Self {
        Self {
            iterations: 0,
            yield_every: 0,
        }
    }

    /// Returns a spin-loop load profile with optional yield cadence.
    #[must_use]
    pub const fn spinning(iterations: u64, yield_every: u64) -> Self {
        Self {
            iterations,
            yield_every,
        }
    }

    /// Returns true when the profile injects no background work.
    #[must_use]
    pub const fn is_quiet(self) -> bool {
        self.iterations == 0
    }
}

/// Producer/consumer timing skew applied around task execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProducerConsumerSkew {
    /// Leaves producer and consumer timing unskewed.
    None,
    /// Lets producer-side work run without an initial yield.
    ProducerFast,
    /// Yields before the task so consumer-side work can run first.
    ConsumerFast,
    /// Alternates producer-fast and consumer-fast behavior by task index.
    Alternating,
}

impl ProducerConsumerSkew {
    fn for_task(self, task_index: usize) -> Self {
        match self {
            Self::Alternating if task_index.is_multiple_of(2) => Self::ProducerFast,
            Self::Alternating => Self::ConsumerFast,
            other => other,
        }
    }
}

/// A role in a producer/consumer host-timing pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProducerConsumerRole {
    /// The producer side of the pair.
    Producer,
    /// The consumer side of the pair.
    Consumer,
}

/// One logical task in an adversarial execution plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdversarialTask {
    /// Original canonical task index.
    pub index: usize,
    /// Worker thread assigned to the task.
    pub worker_index: usize,
    /// Logical core assigned by the profile's affinity model.
    pub logical_core: usize,
    /// Producer/consumer skew assigned to this task.
    pub producer_consumer_skew: ProducerConsumerSkew,
}

/// The result of one profiled producer/consumer task pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducerConsumerPair<P, C> {
    /// Task metadata used to execute the pair.
    pub task: AdversarialTask,
    /// Role that was intentionally allowed to run first for this task.
    pub first_role: ProducerConsumerRole,
    /// Result returned by the producer action.
    pub producer: P,
    /// Result returned by the consumer action.
    pub consumer: C,
}

/// A deterministic execution plan for one host-adversary profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdversarialExecutionPlan {
    /// Profile used to create the plan.
    pub profile: HostAdversaryProfile,
    /// Tasks in the profile's scheduled order.
    pub ordered_tasks: Vec<AdversarialTask>,
    /// Tasks partitioned by worker thread.
    pub worker_tasks: Vec<Vec<AdversarialTask>>,
}

/// A host-adversary fixture failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostAdversaryError {
    /// The profile requested zero worker threads.
    EmptyWorkerSet {
        /// Profile that requested zero workers.
        profile: &'static str,
    },
    /// The profile requested zero logical cores for an affinity layout.
    EmptyLogicalCoreSet {
        /// Profile that requested zero logical cores.
        profile: &'static str,
    },
    /// A worker thread panicked while running the fixture.
    WorkerPanicked {
        /// Profile being executed.
        profile: &'static str,
        /// Worker that panicked.
        worker_index: usize,
    },
    /// A background load thread panicked while running the fixture.
    LoadWorkerPanicked {
        /// Profile being executed.
        profile: &'static str,
        /// Task whose load worker panicked.
        task_index: usize,
    },
    /// The fixture completed without producing a canonical task result.
    MissingTaskResult {
        /// Profile being executed.
        profile: &'static str,
        /// Task missing from the canonical result vector.
        task_index: usize,
    },
}

impl fmt::Display for HostAdversaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyWorkerSet { profile } => {
                write!(
                    formatter,
                    "host adversary profile `{profile}` has no workers"
                )
            }
            Self::EmptyLogicalCoreSet { profile } => write!(
                formatter,
                "host adversary profile `{profile}` has no logical cores"
            ),
            Self::WorkerPanicked {
                profile,
                worker_index,
            } => write!(
                formatter,
                "host adversary profile `{profile}` worker {worker_index} panicked"
            ),
            Self::LoadWorkerPanicked {
                profile,
                task_index,
            } => write!(
                formatter,
                "host adversary profile `{profile}` load worker for task {task_index} panicked"
            ),
            Self::MissingTaskResult {
                profile,
                task_index,
            } => write!(
                formatter,
                "host adversary profile `{profile}` produced no result for task {task_index}"
            ),
        }
    }
}

impl Error for HostAdversaryError {}

impl fmt::Display for AdversarialGateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScenarioCorpus => {
                write!(formatter, "adversarial determinism gate requires scenarios")
            }
            Self::EmptyScenario { scenario } => {
                write!(
                    formatter,
                    "adversarial scenario `{scenario}` has no operations"
                )
            }
            Self::EmptyProfileMatrix => {
                write!(
                    formatter,
                    "adversarial determinism gate requires host profiles"
                )
            }
            Self::HostAdversary(error) => write!(formatter, "{error}"),
            Self::Comparison(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for AdversarialGateError {}

impl From<HostAdversaryError> for AdversarialGateError {
    fn from(error: HostAdversaryError) -> Self {
        Self::HostAdversary(error)
    }
}

impl From<AdversarialComparisonError> for AdversarialGateError {
    fn from(error: AdversarialComparisonError) -> Self {
        Self::Comparison(error)
    }
}

impl fmt::Display for AdversarialComparisonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCorpus => write!(
                formatter,
                "adversarial comparison requires at least one run"
            ),
            Self::Mismatch(mismatch) => write!(
                formatter,
                "adversarial run `{}` diverged from baseline `{}` in {:?}",
                mismatch.divergent_profile, mismatch.baseline_profile, mismatch.kind
            ),
        }
    }
}

impl Error for AdversarialComparisonError {}

/// Returns the canonical adversarial host profile matrix shared by gates.
#[must_use]
pub fn canonical_host_adversary_matrix() -> &'static [HostAdversaryProfile] {
    &HOST_ADVERSARY_MATRIX
}

/// Returns the fixed corpus used by `gate:adversarial-determinism`.
#[must_use]
pub fn representative_adversarial_corpus() -> Vec<AdversarialScenario> {
    vec![
        AdversarialScenario {
            name: String::from("two-node-partition-recovery"),
            seed: 0x0010_ad00_0001,
            operations: vec![
                AdversarialScenarioOperation::Deliver {
                    at_tick: 5,
                    from: String::from("client"),
                    to: String::from("server"),
                    sequence: 1,
                },
                AdversarialScenarioOperation::Fault {
                    at_tick: 13,
                    target: String::from("client-server-link"),
                    active: true,
                },
                AdversarialScenarioOperation::HostIo {
                    at_tick: 21,
                    resource: String::from("checkpoint-segment"),
                    bytes: 4096,
                },
                AdversarialScenarioOperation::Fault {
                    at_tick: 34,
                    target: String::from("client-server-link"),
                    active: false,
                },
                AdversarialScenarioOperation::Deliver {
                    at_tick: 55,
                    from: String::from("server"),
                    to: String::from("client"),
                    sequence: 2,
                },
            ],
        },
        AdversarialScenario {
            name: String::from("storage-read-stall"),
            seed: 0x0010_ad00_0002,
            operations: vec![
                AdversarialScenarioOperation::HostIo {
                    at_tick: 3,
                    resource: String::from("object-store-read"),
                    bytes: 8192,
                },
                AdversarialScenarioOperation::Deliver {
                    at_tick: 8,
                    from: String::from("primary"),
                    to: String::from("replica"),
                    sequence: 3,
                },
                AdversarialScenarioOperation::Deliver {
                    at_tick: 21,
                    from: String::from("replica"),
                    to: String::from("primary"),
                    sequence: 4,
                },
            ],
        },
    ]
}

/// Runs the adversarial determinism gate over a fixed scenario corpus.
///
/// Each scenario is executed under every hostile host profile. The fixture varies
/// task order, worker count, logical affinity, producer/consumer timing skew,
/// and injected host load, while the default canonical projection ignores
/// host-profile metadata that must not affect execution state.
///
/// # Errors
///
/// Returns [`AdversarialGateError`] if the scenario corpus or profile matrix is
/// empty, a scenario contains no operations, the host-adversary fixture fails, or
/// any hostile run produces different canonical log or fingerprint bytes.
pub fn run_adversarial_determinism_gate(
    scenarios: &[AdversarialScenario],
    profiles: &[HostAdversaryProfile],
) -> Result<AdversarialGateReport, AdversarialGateError> {
    run_adversarial_determinism_gate_with_observer(
        scenarios,
        profiles,
        canonical_adversarial_observation,
    )
}

/// Runs the adversarial determinism gate with a custom observation projection.
///
/// This entry point is primarily used by negative controls. A projection that
/// leaks host-profile metadata into canonical material must make the gate fail,
/// proving that the gate runner compares evidence produced after hostile-profile
/// execution instead of only comparing manually assembled [`AdversarialRun`]
/// values.
///
/// # Errors
///
/// Returns [`AdversarialGateError`] if the scenario corpus or profile matrix is
/// empty, a scenario contains no operations, the host-adversary fixture fails, or
/// the projection produces different canonical log or fingerprint bytes across
/// hostile profiles.
pub fn run_adversarial_determinism_gate_with_observer<F>(
    scenarios: &[AdversarialScenario],
    profiles: &[HostAdversaryProfile],
    observe: F,
) -> Result<AdversarialGateReport, AdversarialGateError>
where
    F: Fn(AdversarialObservation<'_>) -> String,
{
    if scenarios.is_empty() {
        return Err(AdversarialGateError::EmptyScenarioCorpus);
    }
    if profiles.is_empty() {
        return Err(AdversarialGateError::EmptyProfileMatrix);
    }
    for scenario in scenarios {
        if scenario.operations.is_empty() {
            return Err(AdversarialGateError::EmptyScenario {
                scenario: scenario.name.clone(),
            });
        }
    }

    let mut runs = Vec::with_capacity(profiles.len());
    for profile in profiles {
        runs.push(run_adversarial_profile(scenarios, *profile, &observe)?);
    }

    compare_adversarial_runs(&runs)?;
    Ok(AdversarialGateReport {
        scenario_count: scenarios.len(),
        profile_count: profiles.len(),
        runs,
    })
}

/// Builds a deterministic execution plan for a host-adversary profile.
///
/// # Errors
///
/// Returns [`HostAdversaryError::EmptyWorkerSet`] if the profile has no workers
/// or [`HostAdversaryError::EmptyLogicalCoreSet`] if an affinity profile has no
/// logical cores.
pub fn adversarial_execution_plan(
    profile: HostAdversaryProfile,
    task_count: usize,
) -> Result<AdversarialExecutionPlan, HostAdversaryError> {
    if profile.worker_count == 0 {
        return Err(HostAdversaryError::EmptyWorkerSet {
            profile: profile.name,
        });
    }

    let ordered_indexes = ordered_task_indexes(task_count, profile.task_order);
    let mut ordered_tasks = Vec::with_capacity(task_count);
    let mut worker_tasks = (0..profile.worker_count)
        .map(|_| Vec::new())
        .collect::<Vec<_>>();

    for (plan_ordinal, task_index) in ordered_indexes.into_iter().enumerate() {
        let logical_core = profile
            .affinity
            .logical_core_for(profile, task_index, plan_ordinal)?;
        let worker_index = logical_core % profile.worker_count;
        let task = AdversarialTask {
            index: task_index,
            worker_index,
            logical_core,
            producer_consumer_skew: profile.producer_consumer_skew.for_task(task_index),
        };
        ordered_tasks.push(task);
        worker_tasks[worker_index].push(task);
    }

    Ok(AdversarialExecutionPlan {
        profile,
        ordered_tasks,
        worker_tasks,
    })
}

/// Returns canonical task indexes in the order requested by a profile.
#[must_use]
pub fn ordered_task_indexes(task_count: usize, order: HostTaskOrder) -> Vec<usize> {
    let mut indexes = (0..task_count).collect::<Vec<_>>();
    match order {
        HostTaskOrder::Forward => {}
        HostTaskOrder::Reverse => indexes.reverse(),
        HostTaskOrder::Rotated => {
            if !indexes.is_empty() {
                indexes.rotate_left(1);
            }
        }
        HostTaskOrder::Strided { stride } => {
            indexes = strided_task_indexes(task_count, stride);
        }
        HostTaskOrder::SeededPermutation { seed } => {
            deterministic_shuffle(&mut indexes, seed);
        }
    }
    indexes
}

/// Runs logical tasks under a host-adversary profile.
///
/// Results are returned in canonical task-index order even when the profile
/// schedules them in another order.
///
/// # Errors
///
/// Returns [`HostAdversaryError`] when the profile is invalid, a worker panics,
/// a background load worker panics, or a canonical task result is missing.
pub fn run_profiled_tasks<T, F>(
    profile: HostAdversaryProfile,
    task_count: usize,
    f: F,
) -> Result<Vec<T>, HostAdversaryError>
where
    T: Send,
    F: Fn(AdversarialTask) -> T + Sync,
{
    let plan = adversarial_execution_plan(profile, task_count)?;

    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for (worker_index, tasks) in plan.worker_tasks.iter().cloned().enumerate() {
            let task_fn = &f;
            handles.push((
                worker_index,
                scope.spawn(move || {
                    let mut results = Vec::with_capacity(tasks.len());
                    for task in tasks {
                        let result = with_profiled_host_load(profile, task, || task_fn(task))?;
                        results.push((task.index, result));
                    }
                    Ok::<Vec<(usize, T)>, HostAdversaryError>(results)
                }),
            ));
        }

        let mut results = (0..task_count).map(|_| None).collect::<Vec<_>>();
        for (worker_index, handle) in handles {
            let worker_results = match handle.join() {
                Ok(Ok(worker_results)) => worker_results,
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    return Err(HostAdversaryError::WorkerPanicked {
                        profile: profile.name,
                        worker_index,
                    });
                }
            };

            for (task_index, result) in worker_results {
                if task_index < results.len() {
                    results[task_index] = Some(result);
                }
            }
        }

        collect_task_results(profile, results)
    })
}

/// Runs paired producer/consumer tasks under a host-adversary profile.
///
/// Results are returned in canonical task-index order. Each pair records the
/// role that the fixture intentionally ran first for the task, allowing gates to
/// verify producer-fast, consumer-fast, and alternating skew without coupling
/// their assertions to host wall-clock timing.
///
/// # Errors
///
/// Returns [`HostAdversaryError`] when the underlying profiled task runner
/// cannot execute the profile.
pub fn run_profiled_producer_consumer_tasks<P, C, PF, CF>(
    profile: HostAdversaryProfile,
    task_count: usize,
    producer: PF,
    consumer: CF,
) -> Result<Vec<ProducerConsumerPair<P, C>>, HostAdversaryError>
where
    P: Send,
    C: Send,
    PF: Fn(AdversarialTask) -> P + Sync,
    CF: Fn(AdversarialTask) -> C + Sync,
{
    run_profiled_tasks(profile, task_count, |task| {
        run_producer_consumer_pair(task, &producer, &consumer)
    })
}

/// Injects deterministic host load for a profile and task.
pub fn inject_host_load(profile: HostAdversaryProfile, task: AdversarialTask) {
    let mut accumulator = (task.index as u64)
        ^ ((task.worker_index as u64) << 32)
        ^ ((task.logical_core as u64) << 48)
        ^ profile.load.iterations;
    for iteration in 0..profile.load.iterations {
        accumulator = accumulator.rotate_left(3) ^ iteration.wrapping_mul(0x9e37_79b9);
        std::hint::spin_loop();
        if profile.load.yield_every != 0 && iteration.is_multiple_of(profile.load.yield_every) {
            std::thread::yield_now();
        }
    }
    std::hint::black_box(accumulator);
}

/// Runs one task while injecting the profile's load and timing skew.
///
/// # Errors
///
/// Returns [`HostAdversaryError::LoadWorkerPanicked`] when the background load
/// worker panics.
pub fn with_profiled_host_load<T, F>(
    profile: HostAdversaryProfile,
    task: AdversarialTask,
    f: F,
) -> Result<T, HostAdversaryError>
where
    F: FnOnce() -> T,
{
    apply_skew_before_task(task);

    let result = if profile.load.is_quiet() {
        f()
    } else {
        std::thread::scope(|scope| {
            let load_handle = scope.spawn(move || inject_host_load(profile, task));
            std::thread::yield_now();
            let result = f();
            match load_handle.join() {
                Ok(()) => Ok(result),
                Err(_) => Err(HostAdversaryError::LoadWorkerPanicked {
                    profile: profile.name,
                    task_index: task.index,
                }),
            }
        })?
    };

    apply_skew_after_task(task);
    Ok(result)
}

/// Compares adversarial runs against the first run as a deterministic baseline.
///
/// # Errors
///
/// Returns [`AdversarialComparisonError::EmptyCorpus`] when no runs are supplied,
/// or [`AdversarialComparisonError::Mismatch`] for the first canonical-log or
/// final-fingerprint difference.
pub fn compare_adversarial_runs(runs: &[AdversarialRun]) -> Result<(), AdversarialComparisonError> {
    let Some(baseline) = runs.first() else {
        return Err(AdversarialComparisonError::EmptyCorpus);
    };

    for run in &runs[1..] {
        if run.canonical_log != baseline.canonical_log {
            return Err(AdversarialComparisonError::Mismatch(AdversarialMismatch {
                baseline_profile: baseline.profile.name.clone(),
                divergent_profile: run.profile.name.clone(),
                kind: AdversarialMismatchKind::CanonicalLog,
            }));
        }

        if run.final_fingerprint != baseline.final_fingerprint {
            return Err(AdversarialComparisonError::Mismatch(AdversarialMismatch {
                baseline_profile: baseline.profile.name.clone(),
                divergent_profile: run.profile.name.clone(),
                kind: AdversarialMismatchKind::FinalFingerprint,
            }));
        }
    }

    Ok(())
}

fn run_adversarial_profile(
    scenarios: &[AdversarialScenario],
    profile: HostAdversaryProfile,
    observe: &impl Fn(AdversarialObservation<'_>) -> String,
) -> Result<AdversarialRun, HostAdversaryError> {
    let mut log = AdversarialCanonicalMaterial::new();
    log.record(
        "log",
        &[AdversarialCanonicalField::Str("crucible.adversarial.v1")],
    );

    for scenario in scenarios {
        append_profiled_scenario_log(&mut log, scenario, profile, observe)?;
    }

    let canonical_log = log.finish().into_bytes();
    let fingerprint_material = String::from_utf8_lossy(&canonical_log);
    let final_fingerprint =
        stable_digest("crucible.adversarial.fingerprint.v1", &fingerprint_material);

    Ok(AdversarialRun {
        profile: HostileProfile {
            name: profile.name.to_string(),
        },
        canonical_log,
        final_fingerprint,
    })
}

fn append_profiled_scenario_log(
    log: &mut AdversarialCanonicalMaterial,
    scenario: &AdversarialScenario,
    profile: HostAdversaryProfile,
    observe: &impl Fn(AdversarialObservation<'_>) -> String,
) -> Result<(), HostAdversaryError> {
    let pairs = run_profiled_producer_consumer_tasks(
        profile,
        scenario.operations.len(),
        |task| format!("producer:{}", task.index),
        |task| format!("consumer:{}", task.index),
    )?;

    log.record(
        "scenario",
        &[
            AdversarialCanonicalField::Str(&scenario.name),
            AdversarialCanonicalField::U64(scenario.seed),
        ],
    );
    for pair in pairs {
        let operation = &scenario.operations[pair.task.index];
        let observed = observe(AdversarialObservation {
            profile,
            scenario,
            operation_index: pair.task.index,
            operation,
            task: pair.task,
            first_role: pair.first_role,
            producer: &pair.producer,
            consumer: &pair.consumer,
        });
        log.record(
            "event",
            &[
                AdversarialCanonicalField::U64(pair.task.index as u64),
                AdversarialCanonicalField::Str(&pair.producer),
                AdversarialCanonicalField::Str(&pair.consumer),
            ],
        );
        log.record("observation", &[AdversarialCanonicalField::Str(&observed)]);
        append_operation_record(log, operation);
    }

    Ok(())
}

fn canonical_adversarial_observation(observation: AdversarialObservation<'_>) -> String {
    match observation.operation {
        AdversarialScenarioOperation::Deliver {
            at_tick,
            from,
            to,
            sequence,
        } => format!(
            "{}:{}:deliver:{}:{}:{}:{}",
            observation.scenario.name, observation.operation_index, at_tick, from, to, sequence
        ),
        AdversarialScenarioOperation::Fault {
            at_tick,
            target,
            active,
        } => format!(
            "{}:{}:fault:{}:{}:{}",
            observation.scenario.name, observation.operation_index, at_tick, target, active
        ),
        AdversarialScenarioOperation::HostIo {
            at_tick,
            resource,
            bytes,
        } => format!(
            "{}:{}:host-io:{}:{}:{}",
            observation.scenario.name, observation.operation_index, at_tick, resource, bytes
        ),
    }
}

fn append_operation_record(
    log: &mut AdversarialCanonicalMaterial,
    operation: &AdversarialScenarioOperation,
) {
    match operation {
        AdversarialScenarioOperation::Deliver {
            at_tick,
            from,
            to,
            sequence,
        } => log.record(
            "operation.deliver",
            &[
                AdversarialCanonicalField::U64(*at_tick),
                AdversarialCanonicalField::Str(from),
                AdversarialCanonicalField::Str(to),
                AdversarialCanonicalField::U64(*sequence),
            ],
        ),
        AdversarialScenarioOperation::Fault {
            at_tick,
            target,
            active,
        } => log.record(
            "operation.fault",
            &[
                AdversarialCanonicalField::U64(*at_tick),
                AdversarialCanonicalField::Str(target),
                AdversarialCanonicalField::Bool(*active),
            ],
        ),
        AdversarialScenarioOperation::HostIo {
            at_tick,
            resource,
            bytes,
        } => log.record(
            "operation.host-io",
            &[
                AdversarialCanonicalField::U64(*at_tick),
                AdversarialCanonicalField::Str(resource),
                AdversarialCanonicalField::U64(*bytes),
            ],
        ),
    }
}

struct AdversarialCanonicalMaterial {
    output: String,
}

impl AdversarialCanonicalMaterial {
    fn new() -> Self {
        Self {
            output: String::new(),
        }
    }

    fn record(&mut self, tag: &str, fields: &[AdversarialCanonicalField<'_>]) {
        self.length_prefixed(tag);
        self.output.push(' ');
        self.output.push_str(&fields.len().to_string());
        for field in fields {
            self.output.push(' ');
            match field {
                AdversarialCanonicalField::Str(value) => self.length_prefixed(value),
                AdversarialCanonicalField::U64(value) => self.length_prefixed(&value.to_string()),
                AdversarialCanonicalField::Bool(value) => {
                    self.length_prefixed(if *value { "true" } else { "false" });
                }
            }
        }
        self.output.push('\n');
    }

    fn finish(self) -> String {
        self.output
    }

    fn length_prefixed(&mut self, value: &str) {
        self.output.push_str(&value.len().to_string());
        self.output.push(':');
        self.output.push_str(value);
    }
}

enum AdversarialCanonicalField<'a> {
    Str(&'a str),
    U64(u64),
    Bool(bool),
}

fn stable_digest(domain: &str, material: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    for lane in 0..4 {
        let mut state = 0xcbf2_9ce4_8422_2325u64 ^ lane;
        for byte in domain.bytes().chain([0xff]).chain(material.bytes()) {
            state ^= u64::from(byte);
            state = state.wrapping_mul(0x0000_0100_0000_01b3);
            state ^= state.rotate_left(17);
        }
        bytes.extend_from_slice(&state.to_be_bytes());
    }
    bytes
}

fn strided_task_indexes(task_count: usize, stride: usize) -> Vec<usize> {
    if task_count == 0 {
        return Vec::new();
    }

    let stride = stride.max(1);
    let mut visited = vec![false; task_count];
    let mut indexes = Vec::with_capacity(task_count);
    let mut cursor = 0;

    for _ in 0..task_count {
        if !visited[cursor] {
            visited[cursor] = true;
            indexes.push(cursor);
        }
        cursor = (cursor + stride) % task_count;
    }

    for (index, was_visited) in visited.into_iter().enumerate() {
        if !was_visited {
            indexes.push(index);
        }
    }

    indexes
}

fn deterministic_shuffle(indexes: &mut [usize], seed: u64) {
    if indexes.len() < 2 {
        return;
    }

    let mut state = seed ^ (indexes.len() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for index in (1..indexes.len()).rev() {
        let random = splitmix64(&mut state);
        let selected = (random as usize) % (index + 1);
        indexes.swap(index, selected);
    }
}

fn seeded_index(seed: u64, task_index: usize, plan_ordinal: usize) -> usize {
    let mut state =
        seed ^ ((task_index as u64) << 17) ^ ((plan_ordinal as u64) << 41) ^ 0x94d0_49bb_1331_11eb;
    splitmix64(&mut state) as usize
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn apply_skew_before_task(task: AdversarialTask) {
    match task.producer_consumer_skew {
        ProducerConsumerSkew::ConsumerFast => std::thread::yield_now(),
        ProducerConsumerSkew::ProducerFast
        | ProducerConsumerSkew::Alternating
        | ProducerConsumerSkew::None => {}
    }
}

fn apply_skew_after_task(task: AdversarialTask) {
    match task.producer_consumer_skew {
        ProducerConsumerSkew::ProducerFast => std::thread::yield_now(),
        ProducerConsumerSkew::ConsumerFast
        | ProducerConsumerSkew::Alternating
        | ProducerConsumerSkew::None => {}
    }
}

fn run_producer_consumer_pair<P, C, PF, CF>(
    task: AdversarialTask,
    producer: &PF,
    consumer: &CF,
) -> ProducerConsumerPair<P, C>
where
    PF: Fn(AdversarialTask) -> P,
    CF: Fn(AdversarialTask) -> C,
{
    match task.producer_consumer_skew.for_task(task.index) {
        ProducerConsumerSkew::ConsumerFast => {
            let consumer_result = consumer(task);
            std::thread::yield_now();
            let producer_result = producer(task);
            ProducerConsumerPair {
                task,
                first_role: ProducerConsumerRole::Consumer,
                producer: producer_result,
                consumer: consumer_result,
            }
        }
        ProducerConsumerSkew::None
        | ProducerConsumerSkew::ProducerFast
        | ProducerConsumerSkew::Alternating => {
            let producer_result = producer(task);
            std::thread::yield_now();
            let consumer_result = consumer(task);
            ProducerConsumerPair {
                task,
                first_role: ProducerConsumerRole::Producer,
                producer: producer_result,
                consumer: consumer_result,
            }
        }
    }
}

fn collect_task_results<T>(
    profile: HostAdversaryProfile,
    results: Vec<Option<T>>,
) -> Result<Vec<T>, HostAdversaryError> {
    let mut collected = Vec::with_capacity(results.len());
    for (task_index, result) in results.into_iter().enumerate() {
        match result {
            Some(result) => collected.push(result),
            None => {
                return Err(HostAdversaryError::MissingTaskResult {
                    profile: profile.name,
                    task_index,
                });
            }
        }
    }
    Ok(collected)
}
