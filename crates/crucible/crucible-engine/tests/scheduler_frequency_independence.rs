//! RFC-0010 SCHED-12 regression: RUN ceilings never perturb the guest.
//!
//! A ceiling is an upper bound. A running node stops at its last retirement
//! at or below the ceiling and attests settlement through the ceiling
//! separately from its actual clock; its clock never moves without a
//! retirement. It meets a frame or its own timer at its first boundary at or
//! after the delivery or deadline tick; a halted node wakes exactly there. These tests drive the real
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
//!
//! A jittery, lossy graph checks keyed link randomness (DET-25, SCHED-50):
//! every frame's loss and jitter are addressed by its link, direction and
//! producer sequence, so worker count, wall delays and ceiling schedules
//! leave the guest and the event log unchanged, and silencing one direction
//! of a link leaves the other direction's draws unchanged.

// crucible-lint: allow panic-shortcut -- deterministic fixtures use panic assertions.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible_engine::{
    AdvanceOutcome, BackendEffect, BackendError, BackendNetworkOutput, BackendPhysicalStop,
    BackendQuantumLoop, BackendSnapshot, ConcurrentBackendRun, ConcurrentBackendRunOutcome,
    ConcurrentBackendRunResult, ConcurrentQuantumLoop, ConcurrentSimulationBackend, Decision,
    FingerprintSample, Icount, LinkDef, LinkLossProbability, NodeId, NodeTemplate, Plan,
    Properties, QuantumRequest, ReadyPoint, RunCeilingStop, ScenarioDefForm, ScheduledEvent,
    SchedulerEventLogEntry, SchedulerLivenessScenario, SchedulerLookaheadEdgeEndpoint,
    SchedulerNodeId, SchedulerTopologyChange, SchedulingNodeKind, Seed, SimDuration, SimInstant,
    SimulationBackend, SingleScheduler, StepObservation, VirtualTime, WhiteBoxPolicy, World,
    WorldNode,
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
    /// The node's timer fired at this coordinate; `due` is its deadline.
    ///
    /// A halted node wakes exactly at `due`. A running node fires it at its
    /// first retirement boundary at or after `due`.
    Timer {
        fired: u64,
        due: u64,
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
    /// A RUN result produced on a host thread, awaiting canonical return.
    completed: Option<(StepObservation, Vec<BackendNetworkOutput>)>,
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
            completed: None,
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
        if self.timer <= self.now {
            let due = self.timer;
            self.timers_fired += 1;
            self.timer += self.program.timer_period;
            self.record(TraceKind::Timer {
                fired: self.timers_fired,
                due,
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
    /// ceiling (TIME-4). A running node moves its clock only by retirements. It
    /// takes frames and fires its timer at its first boundary at or after their
    /// tick, and settles an exact-event ceiling it cannot land on (TIME-30).
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

            assert!(self.timer > self.now, "timer left behind");
            // Whole cycles stop short of the timer and of a pending delivery,
            // so each is met at the first boundary at or after its tick.
            let cycle_limit = self
                .next_inbound()
                .map_or(ceiling.min(self.timer), |delivery| {
                    ceiling.min(self.timer).min(delivery)
                });
            self.retire_whole_cycles(cycle_limit);
            let next_retirement = self.now + self.cost(self.raw);
            if next_retirement <= ceiling {
                self.raw += 1;
                self.now = next_retirement;
                if self.raw == self.next_emit_raw {
                    return self.emit(ceiling_time);
                }
                continue;
            }
            // No retirement fits. A timer or frame in the gap waits for the
            // next boundary; the clock never moves without a retirement.
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
        payload[..6].copy_from_slice(&crucible_engine::deterministic_node_mac(&self.peer));
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
    /// Runs each RUN set on host threads that finish in scrambled wall order.
    threaded_delays: bool,
    runs: u64,
    settled_below_ceiling: u64,
    idle_parks: u64,
    /// Largest gap between node clocks after any dispatched RUN set.
    max_clock_spread: u64,
}

impl SimulationBackend for CostedBackend {
    fn dispatch_contract(&self) -> crucible_engine::BackendDispatchContract {
        crucible_engine::BackendDispatchContract::BoundedControl
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
        if self.threaded_delays {
            self.execute_on_delayed_threads(&runs)?;
        }
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
            let (mut step, mut network_outputs) = match node.completed.take() {
                Some(completed) => completed,
                None => node.run(run.ceiling().ticks, stop),
            };
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
        let clocks = self.nodes.values().map(|node| node.now);
        if let (Some(low), Some(high)) = (clocks.clone().min(), clocks.max()) {
            self.max_clock_spread = self.max_clock_spread.max(high - low);
        }
        Ok(results)
    }
}

impl CostedBackend {
    /// Executes one RUN set on host threads with scrambled wall delays.
    ///
    /// Each RUN first spins for a wall delay chosen so that later canonical
    /// RUNs often finish first. Results stay on their nodes and return in input order,
    /// so the scheduler sees only canonical evidence. Wall time and host
    /// completion order must not change any result (RFC-0010 PERF-5).
    fn execute_on_delayed_threads(
        &mut self,
        runs: &[ConcurrentBackendRun],
    ) -> Result<(), BackendError> {
        let stop_for = |run: &ConcurrentBackendRun| {
            if self.ignore_exact_events {
                RunCeilingStop::Bound
            } else {
                run.ceiling_stop()
            }
        };
        let mut owned = Vec::with_capacity(runs.len());
        for (position, run) in runs.iter().enumerate() {
            let node = self
                .nodes
                .remove(run.node())
                .ok_or_else(|| BackendError::Rejected {
                    message: format!("costed fixture has no node `{}`", run.node().name),
                })?;
            let delay = (runs.len() - position) as u64 * 150 + (self.runs % 7) * 40;
            owned.push((node, run.ceiling().ticks, stop_for(run), delay));
        }

        let finished = std::thread::scope(|scope| {
            let handles = owned
                .into_iter()
                .map(|(mut node, ceiling, stop, delay)| {
                    scope.spawn(move || {
                        // Busy work, not a timed wait: it only skews wall
                        // completion order between the RUN threads.
                        for _ in 0..delay * 256 {
                            std::hint::spin_loop();
                        }
                        node.completed = Some(node.run(ceiling, stop));
                        node
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("costed RUN thread"))
                .collect::<Vec<_>>()
        });
        for node in finished {
            self.nodes.insert(node.id.clone(), node);
        }
        Ok(())
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
    /// The canonical event log. Ceiling schedules change its RUN records, so
    /// only runs of one schedule compare it.
    event_log: Vec<SchedulerEventLogEntry>,
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
    /// Largest RUN set dispatched in one round.
    max_set: usize,
    /// Largest gap between node clocks after any dispatched RUN set.
    max_clock_spread: u64,
    /// Live network choices offered and settled by their default branch.
    choices: u64,
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
    /// Symmetric links with their one-way latency in picoseconds.
    links: Vec<(&'static str, &'static str, u64)>,
    time_limit: u64,
    fault: Option<LinkFault>,
    /// Jitter and loss applied to every link; `None` keeps links ideal.
    noise: Option<LinkNoise>,
}

/// Seeded per-frame link randomness, drawn from the keyed decision streams.
#[derive(Clone, Copy, Debug)]
struct LinkNoise {
    jitter: u64,
    loss_millionths: u32,
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
        links: vec![("vm-a", "vm-b", latency)],
        time_limit,
        fault: None,
        noise: None,
    }
}

fn scheduler(scenario: &Scenario, schedule: &CeilingSchedule) -> SingleScheduler {
    let links = scenario
        .links
        .iter()
        .map(|(left, right, latency)| {
            let noise = scenario.noise.unwrap_or(LinkNoise {
                jitter: 0,
                loss_millionths: 0,
            });
            LinkDef::with_transport(
                node_id(left),
                node_id(right),
                SimDuration { ticks: *latency },
                SimDuration {
                    ticks: noise.jitter,
                },
                LinkLossProbability::from_millionths(noise.loss_millionths).unwrap(),
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
    /// Host worker bound; `None` admits one worker per node.
    workers: Option<usize>,
    threaded_delays: bool,
    /// Admits network outputs one route at a time, as campaigns do.
    choice_pause: bool,
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
) -> Result<(Trajectory, DriveStats), crucible_engine::SchedulerError> {
    drive_scenario(
        model,
        &two_node_scenario(latency, time_limit),
        schedule,
        Faults {
            tamper,
            ..Faults::default()
        },
    )
}

fn drive_scenario(
    model: StopModel,
    scenario: &Scenario,
    schedule: &CeilingSchedule,
    faults: Faults,
) -> Result<(Trajectory, DriveStats), crucible_engine::SchedulerError> {
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
        threaded_delays: faults.threaded_delays,
        max_clock_spread: 0,
        runs: 0,
        settled_below_ceiling: 0,
        idle_parks: 0,
    };
    let time_limit = scenario.time_limit;
    let mut adapter = BackendQuantumLoop::new(scheduler(scenario, schedule), backend);
    adapter.set_live_network_choice_pause(faults.choice_pause);
    let mut next_attempt = schedule
        .attempt_caps
        .map(|(interval, offset)| interval + offset);
    let mut next_branch = schedule
        .branch_caps
        .map(|(interval, offset)| interval + offset);
    let mut resolved = Vec::new();
    let mut decisions = Vec::new();
    let mut max_set = 0;
    let mut choices = 0;

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
        let workers = faults.workers.unwrap_or(scenario.nodes.len());
        let round = adapter.drive_concurrent_quantum(request, workers)?;
        max_set = max_set.max(round.run_set.candidates.len());
        let progressed = round
            .outcomes
            .iter()
            .any(|outcome| outcome.advanced_node.is_some());
        for outcome in round.outcomes {
            resolved.extend(outcome.resolved_events);
            decisions.extend(outcome.decisions);
        }
        // A campaign with no selection to make takes the default branch of
        // every offered choice; the settled suffix follows the offered prefix.
        // Settlement resumes held peer publication, which may offer the next.
        while adapter.live_network_preselection().is_some() {
            for settled in adapter.settle_host_live_network_preselection()? {
                resolved.extend(settled.resolved_events);
                decisions.extend(settled.decisions);
            }
            choices += 1;
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
    // RESOLVE and EMIT publish in canonical key order across clocks, so the
    // single event log stays nondecreasing in time however far nodes skew.
    let retained = adapter.loop_impl().event_log().retained_entries().to_vec();
    for pair in retained.windows(2) {
        assert!(
            pair[0].at() <= pair[1].at(),
            "event log entry {} at {} follows {} at {}",
            pair[1].sequence(),
            pair[1].at().ticks,
            pair[0].sequence(),
            pair[0].at().ticks,
        );
    }
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
        event_log: retained,
    };
    let stats = DriveStats {
        runs: backend.runs,
        settled_below_ceiling: backend.settled_below_ceiling,
        idle_parks: backend.idle_parks,
        max_set,
        max_clock_spread: backend.max_clock_spread,
        choices,
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

/// Returns `(tick, due)` for every timer a node fired while running.
///
/// A fire that wakes a halted node is followed by its wake; every other fire
/// happened on a running node.
fn running_timer_fires(trace: &[TraceEvent]) -> Vec<(u64, u64)> {
    trace
        .iter()
        .zip(trace.iter().skip(1).map(Some).chain([None]))
        .filter_map(|(event, next)| match event.kind {
            TraceKind::Timer { due, .. }
                if next.is_none_or(|next| next.kind != TraceKind::Wake) =>
            {
                Some((event.tick, due))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn a_running_node_fires_a_timer_between_boundaries_at_its_next_boundary() {
    // Both timers run at picosecond phases off every retirement lattice. A
    // running node never moves its clock without a retirement, so it fires
    // each one at its first boundary at or after the deadline, under every
    // ceiling schedule alike.
    const LONGEST_RETIREMENT: u64 = 70;

    let runs = t1_schedules().map(|(label, schedule)| {
        let (trajectory, _) = drive(StopModel::Bound, LINK_LATENCY, TIME_LIMIT, &schedule);
        (label, trajectory)
    });

    let (baseline_label, baseline) = &runs[0];
    for node in ["vm-a", "vm-b"] {
        let fires = running_timer_fires(&baseline.traces[node]);
        assert!(
            fires.iter().any(|(tick, due)| tick != due),
            "{baseline_label}: {node} must fire a timer between boundaries"
        );
        for (tick, due) in &fires {
            assert!(
                tick >= due && tick - due < LONGEST_RETIREMENT,
                "{baseline_label}: {node} fired its {due} timer at {tick}"
            );
        }
    }
    for (label, trajectory) in &runs[1..] {
        for node in ["vm-a", "vm-b"] {
            assert_eq!(
                running_timer_fires(&baseline.traces[node]),
                running_timer_fires(&trajectory.traces[node]),
                "{label}: {node} running timer fires"
            );
        }
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
        links: vec![
            ("vm-a", "vm-b", FAULT_LATENCY),
            ("vm-a", "vm-c", FAULT_LATENCY),
            ("vm-b", "vm-c", FAULT_LATENCY),
        ],
        time_limit: FAULT_TIME_LIMIT,
        fault,
        noise: None,
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
            ignore_exact_events: true,
            ..Faults::default()
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

// T1: nodes on different graph horizons, and a disconnected component

const GRAPH_TIME_LIMIT: u64 = 900 * MICROSECOND;
const CHAIN_NEAR_LATENCY: u64 = 40 * MICROSECOND + 3;
const CHAIN_FAR_LATENCY: u64 = 170 * MICROSECOND + 11;
const PAIR_LATENCY: u64 = 25 * MICROSECOND + 7;

/// A chain `a - b - c` with unequal latencies.
fn chain_nodes() -> Vec<NodeSpec> {
    let (fixed, variable) = programs();
    vec![
        NodeSpec {
            name: "vm-a",
            peer: "vm-b",
            program: fixed.clone(),
        },
        NodeSpec {
            name: "vm-b",
            peer: "vm-c",
            program: variable,
        },
        NodeSpec {
            name: "vm-c",
            peer: "vm-b",
            program: Program {
                timer_phase: 4 * MICROSECOND + 13,
                emit_every: 900_011,
                ..fixed
            },
        },
    ]
}

/// A pair `d - e` that shares no path with the chain.
fn pair_nodes() -> Vec<NodeSpec> {
    let (fixed, variable) = programs();
    vec![
        NodeSpec {
            name: "vm-d",
            peer: "vm-e",
            program: Program {
                emit_every: 300_007,
                ..variable
            },
        },
        NodeSpec {
            name: "vm-e",
            peer: "vm-d",
            program: Program {
                timer_phase: MICROSECOND + 3,
                ..fixed
            },
        },
    ]
}

const CHAIN_LINKS: [(&str, &str, u64); 2] = [
    ("vm-a", "vm-b", CHAIN_NEAR_LATENCY),
    ("vm-b", "vm-c", CHAIN_FAR_LATENCY),
];
const PAIR_LINKS: [(&str, &str, u64); 1] = [("vm-d", "vm-e", PAIR_LATENCY)];

fn graph_scenario() -> Scenario {
    Scenario {
        nodes: chain_nodes().into_iter().chain(pair_nodes()).collect(),
        links: CHAIN_LINKS.into_iter().chain(PAIR_LINKS).collect(),
        time_limit: GRAPH_TIME_LIMIT,
        fault: None,
        noise: None,
    }
}

fn drive_graph(
    scenario: &Scenario,
    schedule: &CeilingSchedule,
    faults: Faults,
) -> (Trajectory, DriveStats) {
    drive_scenario(StopModel::Bound, scenario, schedule, faults)
        .unwrap_or_else(|error| panic!("graph {schedule:?}: {error}"))
}

#[test]
fn nodes_on_different_graph_horizons_are_independent_of_the_schedule() {
    let scenario = graph_scenario();
    let (baseline, stats) = drive_graph(
        &scenario,
        &CeilingSchedule::unconstrained(),
        Faults::default(),
    );

    // Every addressed node received frames, and nodes ran on clocks further
    // apart than the shortest link latency.
    for spec in &scenario.nodes {
        if !scenario.nodes.iter().any(|sender| sender.peer == spec.name) {
            continue;
        }
        assert!(
            baseline.traces[spec.name]
                .iter()
                .any(|event| matches!(event.kind, TraceKind::Receive { .. })),
            "{} must receive frames",
            spec.name
        );
    }
    assert!(stats.max_set >= 3, "{stats:?}");
    assert!(stats.max_clock_spread > PAIR_LATENCY, "{stats:?}");

    for (label, schedule) in t1_schedules() {
        let (trajectory, _) = drive_graph(&scenario, &schedule, Faults::default());
        assert_same_trajectory(&baseline, &trajectory, label);
    }
}

#[test]
fn a_disconnected_component_never_bounds_or_changes_the_other() {
    let (together, stats) = drive_graph(
        &graph_scenario(),
        &CeilingSchedule::unconstrained(),
        Faults::default(),
    );
    let chain = Scenario {
        nodes: chain_nodes(),
        links: CHAIN_LINKS.to_vec(),
        time_limit: GRAPH_TIME_LIMIT,
        fault: None,
        noise: None,
    };
    let pair = Scenario {
        nodes: pair_nodes(),
        links: PAIR_LINKS.to_vec(),
        time_limit: GRAPH_TIME_LIMIT,
        fault: None,
        noise: None,
    };
    let (alone_chain, _) =
        drive_graph(&chain, &CeilingSchedule::unconstrained(), Faults::default());
    let (alone_pair, _) = drive_graph(&pair, &CeilingSchedule::unconstrained(), Faults::default());

    // Nodes run more than a whole near-link latency apart. Publication in
    // canonical time order keeps the spread within one horizon window.
    assert!(stats.max_clock_spread > CHAIN_NEAR_LATENCY, "{stats:?}");
    for (alone, names) in [
        (&alone_chain, &["vm-a", "vm-b", "vm-c"][..]),
        (&alone_pair, &["vm-d", "vm-e"][..]),
    ] {
        for name in names {
            assert_eq!(together.traces[*name], alone.traces[*name], "{name} trace");
            assert_eq!(together.states[*name], alone.states[*name], "{name} state");
        }
    }
}

#[test]
fn serialized_parallel_and_wall_delayed_runs_are_bit_identical() {
    let scenario = graph_scenario();
    for (label, schedule) in [
        ("unconstrained", CeilingSchedule::unconstrained()),
        t1_schedules()[1].clone(),
    ] {
        let (parallel, _) = drive_graph(&scenario, &schedule, Faults::default());
        let (serialized, _) = drive_graph(
            &scenario,
            &schedule,
            Faults {
                workers: Some(1),
                ..Faults::default()
            },
        );
        let (delayed, _) = drive_graph(
            &scenario,
            &schedule,
            Faults {
                threaded_delays: true,
                ..Faults::default()
            },
        );

        // PERF-5: worker count, wall delays and host completion order change
        // neither the guest nor the canonical event log.
        for (variant, trajectory) in [("serialized", &serialized), ("delayed", &delayed)] {
            assert_same_trajectory(&parallel, trajectory, &format!("{label} {variant}"));
            assert_eq!(
                parallel.event_log, trajectory.event_log,
                "{label} {variant}: event log"
            );
        }
    }
}

/// The graph scenario with seeded jitter and loss on every link.
fn noisy_graph_scenario() -> Scenario {
    Scenario {
        noise: Some(LinkNoise {
            jitter: 9 * MICROSECOND + 13,
            loss_millionths: 150_000,
        }),
        ..graph_scenario()
    }
}

/// Returns `(sent, delivery offsets)` for frames `sender` addressed to `receiver`.
///
/// A delivery offset is the frame's delivery tick minus its emission tick and
/// the link latency, so it isolates the drawn jitter, which may be negative.
fn link_draw_outcomes(
    trajectory: &Trajectory,
    sender: &str,
    receiver: &str,
    latency: u64,
) -> (usize, BTreeMap<u64, i128>) {
    let emitted = trajectory.traces[sender]
        .iter()
        .filter_map(|event| match event.kind {
            TraceKind::Emit { sequence } => Some((sequence, event.tick)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let offsets = trajectory.traces[receiver]
        .iter()
        .filter_map(|event| match event.kind {
            TraceKind::Receive { sequence, due } => {
                let sent_at = emitted[&sequence];
                Some((
                    sequence,
                    i128::from(due) - i128::from(sent_at) - i128::from(latency),
                ))
            }
            _ => None,
        })
        .collect();
    (emitted.len(), offsets)
}

#[test]
fn keyed_link_draws_are_independent_of_worker_count_and_interleaving() {
    let scenario = noisy_graph_scenario();
    let (baseline, _) = drive_graph(
        &scenario,
        &CeilingSchedule::unconstrained(),
        Faults::default(),
    );

    // Both directions of the pair link draw loss and jitter, so the run
    // exercises per-frame draws from one logical link stream in both
    // directions at once.
    for (sender, receiver) in [("vm-d", "vm-e"), ("vm-e", "vm-d")] {
        let (sent, offsets) = link_draw_outcomes(&baseline, sender, receiver, PAIR_LATENCY);
        assert!(
            offsets.len() < sent,
            "{sender}->{receiver}: loss must drop a frame ({} of {sent} delivered)",
            offsets.len()
        );
        let distinct = offsets
            .values()
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        assert!(distinct > 1, "{sender}->{receiver}: jitter must vary");
    }

    // DET-25/SCHED-50: each frame's draws are keyed by its link, direction and
    // producer sequence, so neither the ceiling schedule that interleaves the
    // two directions nor worker count or host completion order changes the
    // guest or the delivery-order decisions. Ceiling schedules publish
    // different evaluation boundaries, so the canonical event log is compared
    // within one schedule across execution variants.
    let mut schedules = vec![("unconstrained", CeilingSchedule::unconstrained())];
    schedules.extend(t1_schedules());
    for (label, schedule) in schedules {
        let (parallel, _) = drive_graph(&scenario, &schedule, Faults::default());
        assert_same_trajectory(&baseline, &parallel, &format!("{label} parallel"));

        for (variant, faults) in [
            (
                "serialized",
                Faults {
                    workers: Some(1),
                    ..Faults::default()
                },
            ),
            (
                "two workers",
                Faults {
                    workers: Some(2),
                    ..Faults::default()
                },
            ),
            (
                "delayed",
                Faults {
                    threaded_delays: true,
                    ..Faults::default()
                },
            ),
        ] {
            let (trajectory, _) = drive_graph(&scenario, &schedule, faults);
            let context = format!("{label} {variant}");
            assert_same_trajectory(&parallel, &trajectory, &context);
            assert!(
                parallel.event_log == trajectory.event_log,
                "{context}: event log diverges"
            );
        }
    }
}

#[test]
fn a_link_direction_draws_independently_of_the_opposite_direction() {
    let duplex = noisy_graph_scenario();
    let mut simplex = noisy_graph_scenario();
    for spec in &mut simplex.nodes {
        if spec.name == "vm-e" {
            spec.program.emit_every = u64::MAX;
        }
    }
    let (with_reverse, _) = drive_graph(
        &duplex,
        &CeilingSchedule::unconstrained(),
        Faults::default(),
    );
    let (without_reverse, _) = drive_graph(
        &simplex,
        &CeilingSchedule::unconstrained(),
        Faults::default(),
    );

    // A cursor shared by both directions would shift every d->e draw once e
    // emits. Keyed draws give each d->e frame the same loss and jitter either
    // way.
    let (_, duplex_offsets) = link_draw_outcomes(&with_reverse, "vm-d", "vm-e", PAIR_LATENCY);
    let (_, simplex_offsets) = link_draw_outcomes(&without_reverse, "vm-d", "vm-e", PAIR_LATENCY);
    let shared = duplex_offsets
        .keys()
        .filter(|sequence| simplex_offsets.contains_key(sequence))
        .count();
    assert!(shared > 1, "both runs must deliver common d->e frames");
    for (sequence, offset) in &duplex_offsets {
        if let Some(simplex_offset) = simplex_offsets.get(sequence) {
            assert_eq!(offset, simplex_offset, "d->e frame {sequence} jitter");
        }
    }
    let delivered = |offsets: &BTreeMap<u64, i128>, below: u64| {
        offsets
            .keys()
            .filter(|sequence| **sequence < below)
            .copied()
            .collect::<Vec<_>>()
    };
    let common_horizon = duplex_offsets
        .keys()
        .last()
        .copied()
        .min(simplex_offsets.keys().last().copied())
        .unwrap();
    assert_eq!(
        delivered(&duplex_offsets, common_horizon),
        delivered(&simplex_offsets, common_horizon),
        "d->e loss decisions"
    );
}

#[test]
fn seeded_random_ceiling_schedules_match_on_different_graph_horizons() {
    let scenario = graph_scenario();
    let (baseline, _) = drive_graph(
        &scenario,
        &CeilingSchedule::unconstrained(),
        Faults::default(),
    );
    let mut rng = Xorshift(0x9a7b_1e5d_0c4f_2a61);
    for case in 0..32 {
        let schedule = random_schedule(&mut rng);
        let (trajectory, _) = drive_graph(&scenario, &schedule, Faults::default());
        assert_same_trajectory(&baseline, &trajectory, &format!("case {case} {schedule:?}"));
    }
}

// T1: an Envoy-like five-node mesh under seeded execution variants

const MESH_TIME_LIMIT: u64 = 250 * MICROSECOND;
const MESH_CASES: u64 = 200;

/// Draws one costed program whose emissions land within microseconds of
/// its peers' deliveries.
fn mesh_program(rng: &mut Xorshift) -> Program {
    let costs = (0..rng.between(1, 4))
        .map(|_| rng.between(20, 90))
        .collect::<Vec<_>>();
    Program {
        costs,
        timer_phase: rng.between(MICROSECOND, 9 * MICROSECOND),
        timer_period: rng.between(4 * MICROSECOND, 15 * MICROSECOND),
        emit_every: rng.between(60_000, 400_000),
        halt_every: rng.between(2, 6),
    }
}

/// Three routers and two traffic nodes linked like the Envoy flight.
///
/// Router `a` reaches router `c` both directly and through `b`, and each
/// traffic node hangs off one router, so deliveries and emissions on
/// different nodes interleave at nearby virtual times.
fn mesh_scenario(rng: &mut Xorshift) -> Scenario {
    let nodes = [
        ("router-a", "router-c"),
        ("router-b", "router-a"),
        ("router-c", "router-a"),
        ("traffic-east", "router-c"),
        ("traffic-west", "router-a"),
    ]
    .into_iter()
    .map(|(name, peer)| NodeSpec {
        name,
        peer,
        program: mesh_program(rng),
    })
    .collect();
    let links = [
        ("router-a", "traffic-west"),
        ("router-a", "router-b"),
        ("router-b", "router-c"),
        ("router-a", "router-c"),
        ("router-c", "traffic-east"),
    ]
    .into_iter()
    .map(|(left, right)| (left, right, rng.between(10 * MICROSECOND, 60 * MICROSECOND)))
    .collect();
    Scenario {
        nodes,
        links,
        time_limit: MESH_TIME_LIMIT,
        fault: None,
        noise: Some(LinkNoise {
            jitter: rng.between(MICROSECOND, 8 * MICROSECOND),
            loss_millionths: 100_000,
        }),
    }
}

#[test]
fn an_envoy_like_mesh_publishes_decisions_independent_of_execution_across_seeds() {
    let mut rng = Xorshift(0x3e7f_a51c_9d02_b84b);
    let mut decisions = 0;
    let mut choices = 0;
    for case in 0..MESH_CASES {
        let scenario = mesh_scenario(&mut rng);
        let serial = Faults {
            workers: Some(1),
            ..Faults::default()
        };
        let (baseline, _) = drive_graph(&scenario, &CeilingSchedule::unconstrained(), serial);
        decisions += baseline.decisions.len();

        // RFC-0010 section 8: publication order is a pure function of world
        // state. Neither the RUN partition a ceiling schedule imposes, nor
        // worker count, host completion order, or a default-settled choice
        // stop may move a decision.
        let schedule = random_schedule(&mut rng);
        let varied = Faults {
            workers: Some(usize::try_from(rng.between(2, 5)).unwrap()),
            threaded_delays: rng.next().is_multiple_of(2),
            choice_pause: rng.next().is_multiple_of(2),
            ..serial
        };
        let context = format!(
            "case {case} {schedule:?} workers {:?} pause {}",
            varied.workers, varied.choice_pause
        );
        let (concurrent, stats) = drive_graph(&scenario, &schedule, varied);
        choices += stats.choices;
        assert_same_trajectory(&baseline, &concurrent, &format!("{context} concurrent"));

        let (serialized, _) = drive_graph(
            &scenario,
            &schedule,
            Faults {
                choice_pause: varied.choice_pause,
                ..serial
            },
        );
        assert!(
            serialized.event_log == concurrent.event_log,
            "{context}: event log diverges between serial and concurrent execution"
        );
    }
    assert!(
        decisions > 100 * MESH_CASES as usize,
        "the mesh must publish link draws and delivery orders ({decisions})"
    );
    assert!(
        choices > MESH_CASES,
        "paused runs must settle offered choices"
    );
}
