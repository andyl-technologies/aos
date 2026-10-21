//! RFC-0010 SCHED-12 regression: RUN ceilings never perturb the guest.
//!
//! A ceiling is an upper bound. A node stops at its last retirement at or
//! below the ceiling unless its own timer inside the remaining gap permits a
//! time-only advance (TIME-4), and it attests settlement through the ceiling
//! separately from its actual clock. A running node takes a frame at its
//! first boundary at or after the delivery tick; a halted node wakes exactly
//! there. These tests drive the real
//! [`SingleScheduler`] through the bounded-control host path with a costed
//! test double whose retirements cost picoseconds and cannot land on an
//! arbitrary ceiling:
//!
//! - every retirement costs 50 ps on one node and cycles through 30, 50 and
//!   70 ps on the other;
//! - each node arms a periodic timer with a picosecond phase and periodically
//!   halts until its next timer or inbound frame;
//! - each node emits frames to its peer at fixed retirements, and every frame
//!   is delivered at its exact link-latency tick. An off-lattice latency makes
//!   those deliveries land between the receiver's boundaries.
//!
//! The same scenario runs under different ceiling schedules: a 250 µs
//! rendezvous, a 10 µs rendezvous, and no rendezvous with attempt and branch
//! caps every 10 µs at odd picosecond offsets. Every per-node event, its raw
//! retirement count and logical tick, the resolved scheduler deliveries and
//! the final node state must be identical. A negative control restores the
//! legacy behavior that credited the sub-retirement remainder up to every
//! ceiling; it must diverge, proving the comparison can see the defect.
//!
//! A three-node scenario adds a fault-timed link partition at a picosecond
//! phase (SCHED-39), which the scheduler declares an exact event for the two
//! partitioned nodes only. A halted partitioned node arrives exactly at the
//! activation tick; a running one settles through it at its last boundary
//! below (TIME-30). The third node treats the activation as a bound, so its
//! trajectory must match a run without the fault.

// crucible-lint: allow panic-shortcut -- deterministic fixtures use panic assertions.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::{
    AdvanceOutcome, BackendEffect, BackendError, BackendNetworkOutput, BackendPhysicalStop,
    BackendQuantumLoop, BackendSnapshot, ConcurrentBackendRun, ConcurrentBackendRunOutcome,
    ConcurrentBackendRunResult, ConcurrentQuantumLoop, ConcurrentSimulationBackend, Decision,
    FingerprintSample, Icount, LinkDef, LinkLossProbability, NodeId, NodeTemplate, Plan,
    Properties, QuantumRequest, ReadyPoint, RunCeilingStop, ScenarioDefForm, ScheduledEvent,
    SchedulerLivenessScenario, SchedulerLookaheadEdgeEndpoint, SchedulerNodeId,
    SchedulerTopologyChange, SchedulingNodeKind, Seed, SimDuration, SimInstant, SimulationBackend,
    SingleScheduler, StepObservation, VirtualTime, WhiteBoxPolicy, World, WorldNode,
};

const MICROSECOND: u64 = 1_000_000;

// Costed node model

/// How a node ends a RUN whose next retirement does not fit its ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopModel {
    /// SCHED-12: stop at the last retirement and attest settlement.
    Bound,
    /// Negative control: credit the remainder and land on every ceiling.
    LegacyCredit,
}

/// Deterministic guest program for one costed node.
#[derive(Clone, Debug)]
struct Program {
    /// Retirement costs in picoseconds, cycled by retirement index.
    costs: Vec<u64>,
    /// First timer deadline, in picoseconds.
    timer_phase: u64,
    /// Timer period, in picoseconds.
    timer_period: u64,
    /// Retirements between frame emissions.
    emit_every: u64,
    /// Every this many timer fires, the node halts until its next wake.
    halt_every: u64,
}

/// A guest-visible event observed by one node.
#[derive(Clone, Debug, PartialEq, Eq)]
enum TraceKind {
    Timer {
        fired: u64,
    },
    Halt,
    Wake,
    Emit {
        sequence: u64,
    },
    /// A frame was taken at this coordinate; `due` is its delivery tick.
    ///
    /// A halted node wakes exactly at `due`. A running node takes the frame
    /// at its first retirement boundary at or after `due`.
    Receive {
        sequence: u64,
        due: u64,
    },
    /// The node ended an exact-event RUN at its ceiling.
    ///
    /// `from` is the clock before a time-only advance onto the ceiling, or
    /// the ceiling itself when a retirement or real event landed there.
    ExactArrival {
        from: u64,
    },
    /// A running node settled an exact-event RUN below its ceiling.
    ///
    /// Its next retirement would end past `ceiling`, and a running node never
    /// moves its clock without one, so it stays at its last boundary and takes
    /// the event at its next one (TIME-30).
    ExactSettle {
        ceiling: u64,
    },
}

/// One guest-visible event and the exact coordinate at which it occurred.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TraceEvent {
    raw: u64,
    tick: u64,
    kind: TraceKind,
}

/// One costed node: a retirement grid, a timer and an inbound queue.
#[derive(Clone, Debug)]
struct CostedNode {
    id: NodeId,
    peer: NodeId,
    program: Program,
    model: StopModel,
    raw: u64,
    now: u64,
    timer: u64,
    timers_fired: u64,
    halted: bool,
    next_emit_raw: u64,
    emitted: u64,
    arrivals: u64,
    inbound: BTreeMap<(u64, u64), u64>,
    trace: Vec<TraceEvent>,
}

/// Comparable final node state.
#[derive(Clone, Debug, PartialEq, Eq)]
struct NodeState {
    raw: u64,
    now: u64,
    timer: u64,
    timers_fired: u64,
    halted: bool,
    emitted: u64,
    arrivals: u64,
}

impl CostedNode {
    fn new(id: &str, peer: &str, program: Program, model: StopModel) -> Self {
        Self {
            id: node_id(id),
            peer: node_id(peer),
            model,
            raw: 0,
            now: 0,
            timer: program.timer_phase,
            timers_fired: 0,
            halted: false,
            next_emit_raw: program.emit_every,
            emitted: 0,
            arrivals: 0,
            inbound: BTreeMap::new(),
            trace: Vec::new(),
            program,
        }
    }

    fn state(&self) -> NodeState {
        NodeState {
            raw: self.raw,
            now: self.now,
            timer: self.timer,
            timers_fired: self.timers_fired,
            halted: self.halted,
            emitted: self.emitted,
            arrivals: self.arrivals,
        }
    }

    fn cost(&self, raw: u64) -> u64 {
        let index = usize::try_from(raw % self.program.costs.len() as u64).unwrap();
        self.program.costs[index]
    }

    fn record(&mut self, kind: TraceKind) {
        self.trace.push(TraceEvent {
            raw: self.raw,
            tick: self.now,
            kind,
        });
    }

    fn next_inbound(&self) -> Option<u64> {
        self.inbound.keys().next().map(|(tick, _)| *tick)
    }

    /// Returns the earliest real wake of a halted node: its timer or next frame.
    fn next_wake(&self) -> u64 {
        self.next_inbound()
            .map_or(self.timer, |inbound| inbound.min(self.timer))
    }

    /// Handles every event due at the current tick.
    ///
    /// Frames are due once their delivery tick is at or below the clock, so a
    /// running node takes a frame delivered between two of its boundaries at
    /// the later one.
    fn service_due_events(&mut self) {
        while let Some(((tick, order), sequence)) = self
            .inbound
            .first_key_value()
            .map(|(key, sequence)| (*key, *sequence))
            .filter(|((tick, _), _)| *tick <= self.now)
        {
            self.inbound.remove(&(tick, order));
            self.record(TraceKind::Receive {
                sequence,
                due: tick,
            });
            if self.halted {
                self.halted = false;
                self.record(TraceKind::Wake);
            }
        }
        if self.timer == self.now {
            self.timers_fired += 1;
            self.timer += self.program.timer_period;
            self.record(TraceKind::Timer {
                fired: self.timers_fired,
            });
            if self.halted {
                self.halted = false;
                self.record(TraceKind::Wake);
            } else if self.timers_fired.is_multiple_of(self.program.halt_every) {
                self.halted = true;
                self.record(TraceKind::Halt);
            }
        }
    }

    /// Retires as many whole cost cycles as fit before `limit` and the next emission.
    fn retire_whole_cycles(&mut self, limit: u64) {
        let length = self.program.costs.len() as u64;
        if !self.raw.is_multiple_of(length) {
            return;
        }
        let cycle: u64 = self.program.costs.iter().sum();
        let by_time = (limit - self.now) / cycle;
        let by_emission = (self.next_emit_raw - self.raw - 1) / length;
        let cycles = by_time.min(by_emission);
        self.raw += cycles * length;
        self.now += cycles * cycle;
    }

    /// Executes one RUN toward `ceiling` and reports how it returned control.
    ///
    /// A halted node advances time only to its real wake or to an exact-event
    /// ceiling (TIME-4). A running node moves its clock by retirements, and by
    /// a time-only advance only onto its own timer inside the final gap. It
    /// takes frames at its first boundary at or after their delivery, and
    /// settles an exact-event ceiling it cannot land on (TIME-30).
    fn run(
        &mut self,
        ceiling: u64,
        stop: RunCeilingStop,
    ) -> (StepObservation, Vec<BackendNetworkOutput>) {
        assert!(
            self.now <= ceiling,
            "{} started beyond its ceiling",
            self.id.name
        );
        let ceiling_time = VirtualTime { ticks: ceiling };
        let exact = stop == RunCeilingStop::ExactEvent;
        // The clock before a time-only advance onto an exact-event ceiling.
        let mut arrival_from = None;
        loop {
            self.service_due_events();
            if exact && self.now == ceiling {
                let from = arrival_from.unwrap_or(self.now);
                self.record(TraceKind::ExactArrival { from });
                return (self.settle(ceiling_time), Vec::new());
            }
            if self.halted {
                let mut event = self.next_wake();
                assert!(event > self.now, "exact event left behind");
                if exact {
                    event = event.min(ceiling);
                }
                if event <= ceiling {
                    // TIME-4: a halted vCPU advances only to its real wake.
                    if event == ceiling {
                        arrival_from = Some(self.now);
                    }
                    self.now = event;
                    continue;
                }
                return (self.park(ceiling_time), Vec::new());
            }

            let timer = self.timer;
            assert!(timer > self.now, "timer left behind");
            let bound = ceiling.min(timer);
            // Whole cycles stop short of a pending delivery so that the frame
            // is taken at the first boundary at or after it.
            let cycle_limit = self
                .next_inbound()
                .map_or(bound, |delivery| bound.min(delivery));
            self.retire_whole_cycles(cycle_limit);
            let next_retirement = self.now + self.cost(self.raw);
            if next_retirement <= bound {
                self.raw += 1;
                self.now = next_retirement;
                if self.raw == self.next_emit_raw {
                    return self.emit(ceiling_time);
                }
                continue;
            }
            if timer <= ceiling {
                // TIME-4: the gap holds the node's own timer and no retirement.
                if timer == ceiling {
                    arrival_from = Some(self.now);
                }
                self.now = timer;
                continue;
            }
            if exact {
                self.record(TraceKind::ExactSettle { ceiling });
            }
            return (self.settle(ceiling_time), Vec::new());
        }
    }

    /// Ends a RUN with no retirement and no exact event left in the gap.
    fn settle(&mut self, ceiling: VirtualTime) -> StepObservation {
        if self.model == StopModel::LegacyCredit || self.now == ceiling.ticks {
            self.now = ceiling.ticks;
            return StepObservation::from_advance_outcome(ceiling, AdvanceOutcome::ReachedHorizon);
        }
        StepObservation::settled_below_ceiling(ceiling, VirtualTime { ticks: self.now })
    }

    /// Parks a halted node whose next wake lies beyond the ceiling.
    fn park(&mut self, ceiling: VirtualTime) -> StepObservation {
        if self.model == StopModel::LegacyCredit || self.now == ceiling.ticks {
            self.now = ceiling.ticks;
            return StepObservation::from_advance_outcome(ceiling, AdvanceOutcome::ReachedHorizon);
        }
        StepObservation {
            requested_ceiling: ceiling,
            reached: VirtualTime { ticks: self.now },
            settled_through: ceiling,
            outcome: AdvanceOutcome::Paused {
                at: Icount { retired: self.now },
            },
            physical_stop: BackendPhysicalStop::Idle,
            applied_preemptions: Vec::new(),
        }
    }

    /// Emits one frame at the current retirement and yields the RUN there.
    fn emit(&mut self, ceiling: VirtualTime) -> (StepObservation, Vec<BackendNetworkOutput>) {
        let sequence = self.emitted;
        self.emitted += 1;
        self.next_emit_raw += self.program.emit_every;
        self.record(TraceKind::Emit { sequence });

        let mut payload = vec![0_u8; 60];
        payload[..6].copy_from_slice(&crucible::deterministic_node_mac(&self.peer));
        payload[16..24].copy_from_slice(&sequence.to_le_bytes());
        let output = BackendNetworkOutput {
            source: self.id.clone(),
            destination: node_id("net-router"),
            emit_icount: Icount { retired: self.now },
            sequence,
            payload,
            route: None,
            fault_continuation: Default::default(),
        };
        let mut step = StepObservation::from_advance_outcome(
            ceiling,
            AdvanceOutcome::Paused {
                at: Icount { retired: self.now },
            },
        );
        step.physical_stop = BackendPhysicalStop::NetworkOutput;
        (step, vec![output])
    }

    /// Queues one scheduler-delivered frame at its exact delivery tick.
    fn deliver(&mut self, payload: &[u8], at: u64) -> Result<(), BackendError> {
        if at < self.now {
            return Err(BackendError::Rejected {
                message: format!(
                    "{} received a frame at {} behind its clock {}",
                    self.id.name, at, self.now
                ),
            });
        }
        let sequence = u64::from_le_bytes(payload[16..24].try_into().unwrap());
        self.inbound.insert((at, self.arrivals), sequence);
        self.arrivals += 1;
        Ok(())
    }
}

// Bounded-control test backend

/// Rewrites a settled-below-ceiling step to probe scheduler validation.
type Tamper = fn(&mut StepObservation, &mut Vec<BackendNetworkOutput>);

struct CostedBackend {
    nodes: BTreeMap<NodeId, CostedNode>,
    tamper: Option<Tamper>,
    /// Negative control: run exact-event ceilings as bounds.
    ignore_exact_events: bool,
    runs: u64,
    settled_below_ceiling: u64,
    idle_parks: u64,
}

impl SimulationBackend for CostedBackend {
    fn dispatch_contract(&self) -> crucible::BackendDispatchContract {
        crucible::BackendDispatchContract::BoundedControl
    }

    fn step_to(&mut self, _ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        Err(BackendError::Unsupported {
            capability: "costed fixture requires concurrent RUNs",
        })
    }

    fn apply(&mut self, _effect: &BackendEffect, _at: VirtualTime) -> Result<(), BackendError> {
        Err(BackendError::Unsupported {
            capability: "costed fixture routes effects to nodes",
        })
    }

    fn apply_to_node(
        &mut self,
        node: &NodeId,
        effect: &BackendEffect,
        at: VirtualTime,
    ) -> Result<(), BackendError> {
        let target = self
            .nodes
            .get_mut(node)
            .ok_or_else(|| BackendError::Rejected {
                message: format!("costed fixture has no node `{}`", node.name),
            })?;
        match effect {
            BackendEffect::DeliverInput(input) => target.deliver(&input.payload, at.ticks),
            BackendEffect::Noop => Ok(()),
            other => Err(BackendError::Rejected {
                message: format!("costed fixture cannot apply {other:?}"),
            }),
        }
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        Err(BackendError::Unsupported {
            capability: "snapshot",
        })
    }

    fn restore(&mut self, _snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        Err(BackendError::Unsupported {
            capability: "restore",
        })
    }

    fn now(&self) -> VirtualTime {
        VirtualTime {
            ticks: self.nodes.values().map(|node| node.now).min().unwrap_or(0),
        }
    }

    fn node_now(&self, node: &NodeId) -> Result<VirtualTime, BackendError> {
        self.nodes
            .get(node)
            .map(|node| VirtualTime { ticks: node.now })
            .ok_or_else(|| BackendError::Rejected {
                message: format!("costed fixture has no node `{}`", node.name),
            })
    }

    fn fingerprint(&mut self, _node: NodeId) -> Result<FingerprintSample, BackendError> {
        Err(BackendError::Unsupported {
            capability: "fingerprint",
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
}

impl ConcurrentSimulationBackend for CostedBackend {
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<ConcurrentBackendRun>,
        _max_host_workers: usize,
    ) -> Result<Vec<ConcurrentBackendRunResult>, BackendError> {
        let mut results = Vec::with_capacity(runs.len());
        for run in runs {
            if !run.preemptions.is_empty() {
                return Err(BackendError::Unsupported {
                    capability: "costed fixture has no preemption",
                });
            }
            let node = self
                .nodes
                .get_mut(run.node())
                .ok_or_else(|| BackendError::Rejected {
                    message: format!("costed fixture has no node `{}`", run.node().name),
                })?;
            let stop = if self.ignore_exact_events {
                RunCeilingStop::Bound
            } else {
                run.ceiling_stop()
            };
            let (mut step, mut network_outputs) = node.run(run.ceiling().ticks, stop);
            if step.reached < step.settled_through
                && let Some(tamper) = self.tamper
            {
                tamper(&mut step, &mut network_outputs);
            }
            self.runs += 1;
            if step.reached < step.settled_through {
                self.settled_below_ceiling += 1;
            }
            if step.physical_stop == BackendPhysicalStop::Idle {
                self.idle_parks += 1;
            }
            results.push(ConcurrentBackendRunResult::Completed(
                ConcurrentBackendRunOutcome {
                    node: run.node().clone(),
                    step,
                    rng_evidence: Vec::new(),
                    network_outputs,
                    observations: Vec::new(),
                },
            ));
        }
        Ok(results)
    }
}

// Scenario and drive

/// One ceiling schedule imposed on an otherwise identical scenario.
#[derive(Clone, Debug)]
struct CeilingSchedule {
    rendezvous: Option<u64>,
    /// Attempt-stop caps every `interval` ticks, first at `interval + offset`.
    attempt_caps: Option<(u64, u64)>,
    /// Branch-frontier caps every `interval` ticks, first at `interval + offset`.
    branch_caps: Option<(u64, u64)>,
}

impl CeilingSchedule {
    const fn unconstrained() -> Self {
        Self {
            rendezvous: None,
            attempt_caps: None,
            branch_caps: None,
        }
    }

    const fn rendezvous(interval: u64) -> Self {
        Self {
            rendezvous: Some(interval),
            attempt_caps: None,
            branch_caps: None,
        }
    }
}

/// Everything a run produces that must not depend on its ceiling schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Trajectory {
    traces: BTreeMap<String, Vec<TraceEvent>>,
    states: BTreeMap<String, NodeState>,
    resolved: Vec<ScheduledEvent>,
    decisions: Vec<Decision>,
}

impl Trajectory {
    fn first_timer_raw(&self, node: &str) -> Option<u64> {
        self.traces[node]
            .iter()
            .find(|event| matches!(event.kind, TraceKind::Timer { .. }))
            .map(|event| event.raw)
    }
}

/// Counters that prove a drive exercised the cases under test.
#[derive(Clone, Copy, Debug, Default)]
struct DriveStats {
    runs: u64,
    settled_below_ceiling: u64,
    idle_parks: u64,
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn world_node(name: &str) -> WorldNode {
    WorldNode {
        id: node_id(name),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn programs() -> (Program, Program) {
    let fixed = Program {
        costs: vec![50],
        timer_phase: 3 * MICROSECOND + 17,
        timer_period: 7 * MICROSECOND + 333,
        emit_every: 1_100_003,
        halt_every: 4,
    };
    let variable = Program {
        costs: vec![30, 50, 70],
        timer_phase: 5 * MICROSECOND + 41,
        timer_period: 11 * MICROSECOND + 7,
        emit_every: 700_001,
        halt_every: 3,
    };
    (fixed, variable)
}

/// One costed node: its name, the peer its frames address, and its program.
struct NodeSpec {
    name: &'static str,
    peer: &'static str,
    program: Program,
}

/// A fault-timed partition of every directed edge between two nodes.
#[derive(Clone, Copy, Debug)]
struct LinkFault {
    between: (&'static str, &'static str),
    at: u64,
}

/// A complete costed scenario, independent of its ceiling schedule.
struct Scenario {
    nodes: Vec<NodeSpec>,
    links: Vec<(&'static str, &'static str)>,
    latency: u64,
    time_limit: u64,
    fault: Option<LinkFault>,
}

/// Two nodes that exchange frames over one link.
fn two_node_scenario(latency: u64, time_limit: u64) -> Scenario {
    let (fixed, variable) = programs();
    Scenario {
        nodes: vec![
            NodeSpec {
                name: "vm-a",
                peer: "vm-b",
                program: fixed,
            },
            NodeSpec {
                name: "vm-b",
                peer: "vm-a",
                program: variable,
            },
        ],
        links: vec![("vm-a", "vm-b")],
        latency,
        time_limit,
        fault: None,
    }
}

fn scheduler(scenario: &Scenario, schedule: &CeilingSchedule) -> SingleScheduler {
    let links = scenario
        .links
        .iter()
        .map(|(left, right)| {
            LinkDef::with_transport(
                node_id(left),
                node_id(right),
                SimDuration {
                    ticks: scenario.latency,
                },
                SimDuration::default(),
                LinkLossProbability::from_millionths(0).unwrap(),
                None,
            )
            .unwrap()
        })
        .collect();
    let world = World::from_nodes_and_links(
        scenario
            .nodes
            .iter()
            .map(|spec| world_node(spec.name))
            .collect(),
        links,
    )
    .unwrap();
    let form = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(12),
    )
    .unwrap();
    let mut liveness = SchedulerLivenessScenario::from_runnable_world(
        "sched-12-frequency-independence",
        1 << 40,
        SimInstant {
            ticks: scenario.time_limit,
        },
        0,
        &world,
    )
    .with_scenario_def(form.scenario_def());
    if let Some(interval) = schedule.rendezvous {
        liveness = liveness
            .with_rendezvous_interval(SimDuration { ticks: interval })
            .unwrap();
    }
    let mut scheduler = SingleScheduler::new(liveness).unwrap();
    scheduler.attach_world_network_links(&world).unwrap();

    if let Some(fault) = scenario.fault {
        let vm = |name| SchedulerNodeId {
            node: node_id(name),
            kind: SchedulingNodeKind::Vm,
        };
        let (left, right) = fault.between;
        let partition = SchedulerTopologyChange::partition(
            1,
            vec![
                SchedulerLookaheadEdgeEndpoint::new(vm(left), vm(right)),
                SchedulerLookaheadEdgeEndpoint::new(vm(right), vm(left)),
            ],
        )
        .with_activation_time(SimInstant { ticks: fault.at });
        scheduler.schedule_topology_change(partition).unwrap();
    }
    scheduler
}

/// Raises each periodic cap past the committed frontier.
fn refresh_caps(
    scheduler: &mut SingleScheduler,
    schedule: &CeilingSchedule,
    next_attempt: &mut Option<u64>,
    next_branch: &mut Option<u64>,
) {
    let frontier = scheduler.frontier().ticks;
    if let (Some((interval, _)), Some(cap)) = (schedule.attempt_caps, next_attempt.as_mut()) {
        while *cap <= frontier {
            *cap += interval;
        }
        scheduler
            .set_attempt_stop_frontier(Some(VirtualTime { ticks: *cap }))
            .unwrap();
    }
    if let (Some((interval, _)), Some(cap)) = (schedule.branch_caps, next_branch.as_mut()) {
        while *cap <= frontier {
            *cap += interval;
        }
        scheduler
            .set_branch_frontier_cap(VirtualTime { ticks: *cap })
            .unwrap();
    }
}

/// Fixture behavior that a drive may deliberately break.
#[derive(Clone, Copy, Default)]
struct Faults {
    tamper: Option<Tamper>,
    ignore_exact_events: bool,
}

fn drive(
    model: StopModel,
    latency: u64,
    time_limit: u64,
    schedule: &CeilingSchedule,
) -> (Trajectory, DriveStats) {
    drive_scenario(
        model,
        &two_node_scenario(latency, time_limit),
        schedule,
        Faults::default(),
    )
    .unwrap_or_else(|error| panic!("{model:?} {schedule:?} quantum failed: {error}"))
}

fn drive_with(
    model: StopModel,
    latency: u64,
    time_limit: u64,
    schedule: &CeilingSchedule,
    tamper: Option<Tamper>,
) -> Result<(Trajectory, DriveStats), crucible::SchedulerError> {
    drive_scenario(
        model,
        &two_node_scenario(latency, time_limit),
        schedule,
        Faults {
            tamper,
            ignore_exact_events: false,
        },
    )
}

fn drive_scenario(
    model: StopModel,
    scenario: &Scenario,
    schedule: &CeilingSchedule,
    faults: Faults,
) -> Result<(Trajectory, DriveStats), crucible::SchedulerError> {
    let backend = CostedBackend {
        nodes: scenario
            .nodes
            .iter()
            .map(|spec| {
                (
                    node_id(spec.name),
                    CostedNode::new(spec.name, spec.peer, spec.program.clone(), model),
                )
            })
            .collect(),
        tamper: faults.tamper,
        ignore_exact_events: faults.ignore_exact_events,
        runs: 0,
        settled_below_ceiling: 0,
        idle_parks: 0,
    };
    let time_limit = scenario.time_limit;
    let mut adapter = BackendQuantumLoop::new(scheduler(scenario, schedule), backend);
    let mut next_attempt = schedule
        .attempt_caps
        .map(|(interval, offset)| interval + offset);
    let mut next_branch = schedule
        .branch_caps
        .map(|(interval, offset)| interval + offset);
    let mut resolved = Vec::new();
    let mut decisions = Vec::new();

    for _ in 0..1_000_000 {
        refresh_caps(
            adapter.loop_impl_mut(),
            schedule,
            &mut next_attempt,
            &mut next_branch,
        );
        let request = QuantumRequest {
            configuration: adapter.loop_impl().configuration().clone(),
            control: Vec::new(),
        };
        let round = adapter.drive_concurrent_quantum(request, scenario.nodes.len())?;
        let progressed = round
            .outcomes
            .iter()
            .any(|outcome| outcome.advanced_node.is_some());
        for outcome in round.outcomes {
            resolved.extend(outcome.resolved_events);
            decisions.extend(outcome.decisions);
        }
        if !progressed && adapter.loop_impl().frontier().ticks >= time_limit {
            break;
        }
    }
    assert!(
        adapter.loop_impl().frontier().ticks >= time_limit,
        "{model:?} {schedule:?} did not reach its time limit"
    );
    if let Some(fault) = scenario.fault {
        let applied = adapter
            .loop_impl()
            .topology_change_applications()
            .iter()
            .map(|application| application.activation_time)
            .collect::<Vec<_>>();
        assert_eq!(applied, vec![Some(SimInstant { ticks: fault.at })]);
    }

    resolved.sort_by(|left, right| left.key.cmp(&right.key));
    let backend = adapter.backend();
    let trajectory = Trajectory {
        traces: backend
            .nodes
            .values()
            .map(|node| (node.id.name.clone(), node.trace.clone()))
            .collect(),
        states: backend
            .nodes
            .values()
            .map(|node| (node.id.name.clone(), node.state()))
            .collect(),
        resolved,
        decisions,
    };
    let stats = DriveStats {
        runs: backend.runs,
        settled_below_ceiling: backend.settled_below_ceiling,
        idle_parks: backend.idle_parks,
    };
    Ok((trajectory, stats))
}

/// Reports the first event at which two trajectories diverge.
fn assert_same_trajectory(expected: &Trajectory, actual: &Trajectory, label: &str) {
    for (node, trace) in &expected.traces {
        let other = &actual.traces[node];
        if let Some(index) = trace
            .iter()
            .zip(other)
            .position(|(left, right)| left != right)
        {
            panic!(
                "{label}: {node} diverges at event {index}: expected {:?}, got {:?}",
                trace[index], other[index]
            );
        }
        assert_eq!(trace.len(), other.len(), "{label}: {node} event count");
    }
    assert_eq!(expected.states, actual.states, "{label}: final node state");
    assert_eq!(
        expected.resolved, actual.resolved,
        "{label}: resolved deliveries"
    );
    assert_eq!(
        expected.decisions, actual.decisions,
        "{label}: scheduler decisions"
    );
}

// T1: fixed ceiling schedules

const LINK_LATENCY: u64 = 250 * MICROSECOND;
const TIME_LIMIT: u64 = 3_000 * MICROSECOND;

fn t1_schedules() -> [(&'static str, CeilingSchedule); 3] {
    [
        (
            "250 µs link and rendezvous",
            CeilingSchedule::rendezvous(250 * MICROSECOND),
        ),
        (
            "10 µs rendezvous",
            CeilingSchedule::rendezvous(10 * MICROSECOND),
        ),
        (
            "attempt and branch caps every 10 µs",
            CeilingSchedule {
                rendezvous: None,
                attempt_caps: Some((10 * MICROSECOND, 0)),
                branch_caps: Some((10 * MICROSECOND, 4_999_999)),
            },
        ),
    ]
}

#[test]
fn bounded_ceilings_leave_every_guest_event_independent_of_the_schedule() {
    let runs = t1_schedules().map(|(label, schedule)| {
        let (trajectory, stats) = drive(StopModel::Bound, LINK_LATENCY, TIME_LIMIT, &schedule);
        (label, trajectory, stats)
    });

    let (baseline_label, baseline, baseline_stats) = &runs[0];
    for node in ["vm-a", "vm-b"] {
        let trace = &baseline.traces[node];
        assert!(
            trace
                .iter()
                .any(|event| matches!(event.kind, TraceKind::Receive { .. })),
            "{baseline_label}: {node} must receive frames"
        );
        assert!(
            trace.iter().any(|event| event.kind == TraceKind::Halt),
            "{baseline_label}: {node} must halt"
        );
        assert!(baseline.first_timer_raw(node).is_some());
    }
    assert!(baseline_stats.idle_parks > 0, "{baseline_stats:?}");
    for (label, trajectory, stats) in &runs[1..] {
        assert!(stats.runs > baseline_stats.runs, "{label}: {stats:?}");
        assert!(stats.settled_below_ceiling > 0, "{label}: {stats:?}");
        for node in ["vm-a", "vm-b"] {
            assert_eq!(
                baseline.first_timer_raw(node),
                trajectory.first_timer_raw(node),
                "{label}: {node} first trap"
            );
        }
        assert_same_trajectory(baseline, trajectory, label);
    }
}

#[test]
fn legacy_ceiling_credit_is_detected_as_schedule_dependent() {
    let [(_, coarse), (_, fine), _] = t1_schedules();
    let (bound, _) = drive(StopModel::Bound, LINK_LATENCY, TIME_LIMIT, &coarse);
    let (legacy_coarse, _) = drive(StopModel::LegacyCredit, LINK_LATENCY, TIME_LIMIT, &coarse);
    let (legacy_fine, _) = drive(StopModel::LegacyCredit, LINK_LATENCY, TIME_LIMIT, &fine);

    assert_ne!(
        legacy_coarse.traces, legacy_fine.traces,
        "crediting the remainder to every ceiling must perturb the guest"
    );
    assert_ne!(bound.traces, legacy_fine.traces);
}

fn assert_settlement_refused(tamper: Tamper, expected: &str) {
    let error = drive_with(
        StopModel::Bound,
        LINK_LATENCY,
        TIME_LIMIT,
        &CeilingSchedule::rendezvous(10 * MICROSECOND),
        Some(tamper),
    )
    .map(|_| ())
    .expect_err("tampered settlement must refuse");
    assert!(error.to_string().contains(expected), "{error}");
}

#[test]
fn settlement_below_a_ceiling_requires_a_completed_horizon_or_idle_park() {
    assert_settlement_refused(
        |step, _| step.physical_stop = BackendPhysicalStop::UnclassifiedPause,
        "without a completed horizon or idle park",
    );
    assert_settlement_refused(
        |step, _| step.settled_through.ticks -= 1,
        "instead of its stop",
    );
}

#[test]
fn settlement_below_a_ceiling_cannot_carry_an_output_batch() {
    assert_settlement_refused(
        |step, outputs| {
            outputs.push(BackendNetworkOutput {
                source: node_id("vm-a"),
                destination: node_id("net-router"),
                emit_icount: Icount {
                    retired: step.reached.ticks,
                },
                sequence: u64::MAX,
                payload: vec![0; 60],
                route: None,
                fault_continuation: Default::default(),
            });
        },
        "without a completed horizon or idle park",
    );
}

// T1: a fault-timed topology swap is exact only for the nodes it affects

const FAULT_LATENCY: u64 = 60 * MICROSECOND;
const FAULT_TIME_LIMIT: u64 = 800 * MICROSECOND;
/// Off every node's 10 ps retirement lattice, so no retirement can land on it.
const FAULT_AT: u64 = 333 * MICROSECOND + 37;

/// A and B are partitioned at `FAULT_AT`; C only sends frames to A.
///
/// C receives nothing from A or B, so its guest trajectory cannot depend on
/// theirs. Its RUN windows still depend on both through lookahead, and the
/// activation caps every node's ceilings, so C exercises the bound path.
fn partition_scenario(fault: Option<LinkFault>) -> Scenario {
    let (fixed, variable) = programs();
    let silent = |program: Program| Program {
        emit_every: u64::MAX,
        ..program
    };
    Scenario {
        nodes: vec![
            NodeSpec {
                name: "vm-a",
                peer: "vm-c",
                program: silent(fixed.clone()),
            },
            NodeSpec {
                name: "vm-b",
                peer: "vm-c",
                program: silent(variable.clone()),
            },
            NodeSpec {
                name: "vm-c",
                peer: "vm-a",
                program: Program {
                    timer_phase: 2 * MICROSECOND + 29,
                    emit_every: 400_007,
                    ..variable
                },
            },
        ],
        links: vec![("vm-a", "vm-b"), ("vm-a", "vm-c"), ("vm-b", "vm-c")],
        latency: FAULT_LATENCY,
        time_limit: FAULT_TIME_LIMIT,
        fault,
    }
}

const A_B_PARTITION: LinkFault = LinkFault {
    between: ("vm-a", "vm-b"),
    at: FAULT_AT,
};

fn exact_arrivals(trajectory: &Trajectory, node: &str) -> Vec<TraceEvent> {
    trajectory.traces[node]
        .iter()
        .filter(|event| matches!(event.kind, TraceKind::ExactArrival { .. }))
        .cloned()
        .collect()
}

#[test]
fn a_link_fault_is_an_exact_event_only_for_the_nodes_whose_link_it_changes() {
    let schedule = CeilingSchedule::rendezvous(250 * MICROSECOND);
    let (clean, _) = drive_scenario(
        StopModel::Bound,
        &partition_scenario(None),
        &schedule,
        Faults::default(),
    )
    .unwrap();
    let (faulted, _) = drive_scenario(
        StopModel::Bound,
        &partition_scenario(Some(A_B_PARTITION)),
        &schedule,
        Faults::default(),
    )
    .unwrap();

    // A and B take the swap exactly at the activation tick, each from a
    // clock strictly below it: the arrival is a time-only advance.
    for node in ["vm-a", "vm-b"] {
        let arrivals = exact_arrivals(&faulted, node);
        assert_eq!(arrivals.len(), 1, "{node}: {arrivals:?}");
        assert_eq!(arrivals[0].tick, FAULT_AT, "{node}");
        assert!(
            matches!(arrivals[0].kind, TraceKind::ExactArrival { from } if from < FAULT_AT),
            "{node}: {arrivals:?}"
        );
        assert!(exact_arrivals(&clean, node).is_empty());
    }

    // C settles through the activation as a bound, so its guest is unchanged.
    assert!(exact_arrivals(&faulted, "vm-c").is_empty());
    assert!(
        clean.traces["vm-c"]
            .iter()
            .any(|event| matches!(event.kind, TraceKind::Emit { .. }))
    );
    assert_eq!(clean.traces["vm-c"], faulted.traces["vm-c"]);
    assert_eq!(clean.states["vm-c"], faulted.states["vm-c"]);
}

#[test]
fn an_exact_topology_swap_is_independent_of_the_ceiling_schedule() {
    let scenario = partition_scenario(Some(A_B_PARTITION));
    let runs = t1_schedules().map(|(label, schedule)| {
        let (trajectory, stats) =
            drive_scenario(StopModel::Bound, &scenario, &schedule, Faults::default())
                .unwrap_or_else(|error| panic!("{label}: {error}"));
        (label, trajectory, stats)
    });

    let (_, baseline, _) = &runs[0];
    for (label, trajectory, stats) in &runs[1..] {
        assert!(stats.settled_below_ceiling > 0, "{label}: {stats:?}");
        assert_same_trajectory(baseline, trajectory, label);
    }
}

#[test]
fn settling_below_an_exact_topology_swap_is_refused() {
    let error = drive_scenario(
        StopModel::Bound,
        &partition_scenario(Some(A_B_PARTITION)),
        &CeilingSchedule::rendezvous(250 * MICROSECOND),
        Faults {
            tamper: None,
            ignore_exact_events: true,
        },
    )
    .map(|_| ())
    .expect_err("a node that treats the swap as a bound must be refused");

    assert!(
        error.to_string().contains("settled exact-event ceiling"),
        "{error}"
    );
}

/// Returns every exact-event settlement a node recorded.
fn exact_settlements(trajectory: &Trajectory, node: &str) -> Vec<TraceEvent> {
    trajectory.traces[node]
        .iter()
        .filter(|event| matches!(event.kind, TraceKind::ExactSettle { .. }))
        .cloned()
        .collect()
}

#[test]
fn a_running_node_settles_an_exact_topology_swap_it_cannot_land_on() {
    // Probe activation times until a partitioned node is running there. Each
    // probe is off every retirement lattice, so a running node cannot land on
    // it and must settle at its last boundary below.
    let schedules = t1_schedules();
    let (_, coarse) = &schedules[0];
    let found = (0..64_u64)
        .map(|probe| FAULT_AT + probe * (MICROSECOND + 7))
        .find_map(|at| {
            let fault = LinkFault {
                between: ("vm-a", "vm-b"),
                at,
            };
            let (trajectory, _) = drive_scenario(
                StopModel::Bound,
                &partition_scenario(Some(fault)),
                coarse,
                Faults::default(),
            )
            .unwrap_or_else(|error| panic!("swap at {at}: {error}"));
            ["vm-a", "vm-b"]
                .into_iter()
                .any(|node| !exact_settlements(&trajectory, node).is_empty())
                .then_some((fault, trajectory))
        });
    let (fault, baseline) = found.expect("some probe must meet a running node");

    for node in ["vm-a", "vm-b"] {
        let settled = exact_settlements(&baseline, node);
        let arrived = exact_arrivals(&baseline, node);
        // The swap stops each partitioned node once: by arrival if it was
        // halted, or by a settlement within one retirement if it was running.
        assert_eq!(
            settled.len() + arrived.len(),
            1,
            "{node}: {settled:?} {arrived:?}"
        );
        for event in settled {
            assert_eq!(event.kind, TraceKind::ExactSettle { ceiling: fault.at });
            assert!(event.tick < fault.at, "{node}: {event:?}");
            assert!(fault.at - event.tick < 70, "{node}: {event:?}");
        }
    }

    let scenario = partition_scenario(Some(fault));
    for (label, schedule) in &schedules[1..] {
        let (trajectory, _) =
            drive_scenario(StopModel::Bound, &scenario, schedule, Faults::default())
                .unwrap_or_else(|error| panic!("{label}: {error}"));
        assert_same_trajectory(&baseline, &trajectory, label);
    }
}

// T1: frames delivered between a receiver's retirement boundaries

/// A latency off every retirement lattice, so deliveries land between boundaries.
const OFF_LATTICE_LATENCY: u64 = LINK_LATENCY + 23;

#[test]
fn frames_delivered_between_boundaries_are_taken_at_the_next_boundary() {
    let runs = t1_schedules().map(|(label, schedule)| {
        let (trajectory, stats) =
            drive(StopModel::Bound, OFF_LATTICE_LATENCY, TIME_LIMIT, &schedule);
        (label, trajectory, stats)
    });

    // A running receiver takes each frame at its first boundary at or after
    // the delivery, never before it and never a whole retirement late.
    let (baseline_label, baseline, _) = &runs[0];
    let receives = baseline
        .traces
        .values()
        .flatten()
        .filter_map(|event| match event.kind {
            TraceKind::Receive { due, .. } => Some((event.tick, due)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        receives.iter().any(|(tick, due)| tick > due),
        "{baseline_label}: some frame must land between boundaries: {receives:?}"
    );
    for (tick, due) in &receives {
        assert!(
            tick >= due && tick - due < 70,
            "{baseline_label}: {tick} for {due}"
        );
    }

    for (label, trajectory, _) in &runs[1..] {
        assert_same_trajectory(baseline, trajectory, label);
    }
}

// T2: seeded property over random ceiling schedules

/// Minimal deterministic generator; the test needs no extra dependency.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn between(&mut self, low: u64, high: u64) -> u64 {
        low + self.next() % (high - low + 1)
    }
}

const PROPERTY_LATENCY: u64 = 60 * MICROSECOND;
const PROPERTY_TIME_LIMIT: u64 = 800 * MICROSECOND;
const PROPERTY_CASES: u64 = 256;

fn random_schedule(rng: &mut Xorshift) -> CeilingSchedule {
    // Intervals are deliberately not multiples of the 50 ps retirement cost.
    let rendezvous =
        (!rng.next().is_multiple_of(4)).then(|| rng.between(2 * MICROSECOND, 90 * MICROSECOND));
    let attempt_caps = rng.next().is_multiple_of(2).then(|| {
        (
            rng.between(MICROSECOND, 40 * MICROSECOND),
            rng.between(0, 49),
        )
    });
    let branch_caps = rng.next().is_multiple_of(3).then(|| {
        (
            rng.between(3 * MICROSECOND, 70 * MICROSECOND),
            rng.between(0, MICROSECOND),
        )
    });
    CeilingSchedule {
        rendezvous,
        attempt_caps,
        branch_caps,
    }
}

#[test]
fn seeded_random_ceiling_schedules_match_the_unconstrained_baseline() {
    let (baseline, _) = drive(
        StopModel::Bound,
        PROPERTY_LATENCY,
        PROPERTY_TIME_LIMIT,
        &CeilingSchedule::unconstrained(),
    );
    let mut rng = Xorshift(0x5c4e_d12b_0a7d_c0de);
    for case in 0..PROPERTY_CASES {
        let schedule = random_schedule(&mut rng);
        let (trajectory, _) = drive(
            StopModel::Bound,
            PROPERTY_LATENCY,
            PROPERTY_TIME_LIMIT,
            &schedule,
        );
        assert_same_trajectory(&baseline, &trajectory, &format!("case {case} {schedule:?}"));
    }
}
