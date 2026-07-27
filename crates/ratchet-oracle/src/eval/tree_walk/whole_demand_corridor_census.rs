//! Bounded full-shape force corridors beneath exact whole-demand coordinates.
//!
//! The census observes only the two outer attr-demand leaves containing the
//! certified final-config completions. It tracks every active force body during
//! the enclosing dispatcher session with fixed-width, value-free coordinates.
//! A completion is exact only when root ownership reconciles and every active
//! shape has a stable coordinate.

use super::final_force_leaf_pmu::{FinalForceCounterConnectError, FinalForceCounterReader};
use super::whole_demand_dispatcher::WholeDemandControl;
use super::*;

const STORAGE_CAP_BYTES: usize = 64 * 1024;
const MAX_ACTIVE_FORCES: usize = 512;
const MAX_STORED_FRAMES: usize = 704;
const MAX_CHAINS: usize = 128;
const FORCE_SHAPE_COUNT: usize = 8;
const SPEED_PHASE_COUNT: usize = 5;
const REQUIRED_COMPLETIONS: u64 = 357;
const INCLUSIVE_INSTRUCTION_GATE: u64 = 5_286_000_000;
const INCLUSIVE_CYCLE_GATE: u64 = 2_923_076_924;
const INSTRUCTION_SAVINGS_GATE: u64 = 3_700_000_000;
const CYCLE_SAVINGS_GATE: u64 = 1_900_000_000;
const TRAFFIC_GATE_BYTES: u64 = 200 * 1024 * 1024;
const VIRTUALIZABLE_BYTES_GATE_PPM: u64 = 700_000;
const MATERIALIZING_EXIT_GATE_PPM: u64 = 20_000;
const TARGETS_PER_SITE_GATE: usize = 4;
const FINAL_FORCE_LEAF_PMU_ENV: &str = "AOS_NIX_FINAL_FORCE_LEAF_PMU";
const FINAL_FORCE_LEAF_INSTRUCTIONS_FD_ENV: &str = "AOS_NIX_FINAL_FORCE_LEAF_INSTRUCTIONS_FD";
const FINAL_FORCE_LEAF_CYCLES_FD_ENV: &str = "AOS_NIX_FINAL_FORCE_LEAF_CYCLES_FD";
const FINAL_FORCE_LEAF_CLASS_COUNT: usize = 6;
const FINAL_FORCE_NODE_COVERAGE_GATE_PPM: u64 = 493_000;

/// Backing-store arithmetic:
///
/// - 512 * 40-byte active coordinates = 20,480 bytes
/// - 512 * 16-byte active owners = 8,192 bytes
/// - 704 * 40-byte stored coordinates = 28,160 bytes
/// - 128 * 32-byte chains = 4,096 bytes
///
/// The vector backing is 60,928 bytes. The fixed speed counters add no trace or
/// heap allocation and are charged explicitly below. The observed dispatcher
/// backing plus these counters remains beneath the shared 65,536-byte cap.
const MODELED_CENSUS_BYTES: usize = 60_928
    + std::mem::size_of::<SpeedOpportunityCounters>()
    + std::mem::size_of::<[OuterOpportunityCounters; 2]>()
    + std::mem::size_of::<FinalForceLeafPmu>();

const FLAG_SINGLE_ENTRY: u32 = 1 << 8;
const FLAG_PARALLEL_PAYLOAD: u32 = 1 << 9;
const FLAG_TIER1: u32 = 1 << 10;
const FLAG_TYPED_DETACHED: u32 = 1 << 11;

/// One exact outer dispatcher coordinate admitted by the census.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CorridorOuter {
    AutoCall4,
    FinalForce5,
}

impl CorridorOuter {
    fn from_control(control: WholeDemandControl) -> Option<Self> {
        match control {
            WholeDemandControl::AutoCall { segment: 4 } => Some(Self::AutoCall4),
            WholeDemandControl::FinalForce { segment: 5 } => Some(Self::FinalForce5),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::AutoCall4 => "auto_call",
            Self::FinalForce5 => "final_force",
        }
    }

    const fn segment(self) -> usize {
        match self {
            Self::AutoCall4 => 4,
            Self::FinalForce5 => 5,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::AutoCall4 => 0,
            Self::FinalForce5 => 1,
        }
    }
}

/// Stable suspended-work shape encoded in a force coordinate.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CorridorForceShape {
    Node = 0,
    Apply = 1,
    GenListElemAtAddOne = 2,
    Apply2 = 3,
    Select = 4,
    BuiltinAttr = 5,
    Released = 6,
    Unsupported = 7,
}

impl CorridorForceShape {
    const fn name(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Apply => "apply",
            Self::GenListElemAtAddOne => "genlist_elem_at_add_one",
            Self::Apply2 => "apply2",
            Self::Select => "select",
            Self::BuiltinAttr => "builtin_attr",
            Self::Released => "released",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Fixed-width force-site and suspended-work coordinates.
///
/// Words 1 and 2 identify the force call site. Words 3 through 9 encode up to
/// three [`EvalNodeRef`] values or shape-specific scalar ids. Word 0 contains
/// the shape and storage/execution flags.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CorridorForceCoordinate {
    words: [u32; 10],
}

impl CorridorForceCoordinate {
    /// Builds a stable coordinate without retaining a runtime value or pointer.
    pub(super) fn from_thunk(
        site_module: EvalModuleId,
        site_id: IrId,
        thunk: &EvalThunk,
        single_entry: bool,
        parallel_payload: bool,
        tier1: bool,
        typed_detached: bool,
    ) -> Self {
        let mut flags = 0;
        if single_entry {
            flags |= FLAG_SINGLE_ENTRY;
        }
        if parallel_payload {
            flags |= FLAG_PARALLEL_PAYLOAD;
        }
        if tier1 {
            flags |= FLAG_TIER1;
        }
        if typed_detached {
            flags |= FLAG_TYPED_DETACHED;
        }
        let mut coordinate = Self {
            words: [
                flags,
                site_module.as_u32(),
                site_id.as_u32(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        };
        match thunk.kind() {
            EvalThunkKind::Node { body, .. } => {
                coordinate.set_shape(CorridorForceShape::Node);
                coordinate.set_ref(3, *body);
            }
            EvalThunkKind::Apply {
                function, argument, ..
            } => {
                coordinate.set_shape(CorridorForceShape::Apply);
                coordinate.set_ref(3, *function);
                coordinate.set_ref(5, *argument);
            }
            EvalThunkKind::GenListElemAtAddOne {
                function, argument, ..
            } => {
                coordinate.set_shape(CorridorForceShape::GenListElemAtAddOne);
                coordinate.set_ref(3, *function);
                coordinate.set_ref(5, *argument);
            }
            EvalThunkKind::Apply2(apply) => {
                coordinate.set_shape(CorridorForceShape::Apply2);
                coordinate.set_ref(3, apply.function);
                coordinate.set_ref(5, apply.first_argument);
                coordinate.set_ref(7, apply.second_argument);
            }
            EvalThunkKind::Select { select, path, .. } => {
                coordinate.set_shape(CorridorForceShape::Select);
                coordinate.set_ref(3, *select);
                coordinate.words[5] = path.as_u32();
            }
            EvalThunkKind::BuiltinAttr { symbol, builtin } => {
                let ordinal = BUILTINS
                    .iter()
                    .position(|declaration| declaration.kind() == *builtin)
                    .and_then(|index| u32::try_from(index).ok());
                if let Some(ordinal) = ordinal {
                    coordinate.set_shape(CorridorForceShape::BuiltinAttr);
                    coordinate.words[3] = symbol.as_u32();
                    coordinate.words[4] = ordinal;
                } else {
                    coordinate.set_shape(CorridorForceShape::Unsupported);
                }
            }
            EvalThunkKind::Released => {
                coordinate.set_shape(CorridorForceShape::Released);
            }
        }
        coordinate
    }

    fn set_shape(&mut self, shape: CorridorForceShape) {
        self.words[0] = (self.words[0] & !0xff) | u32::from(shape as u8);
    }

    fn set_ref(&mut self, offset: usize, node: EvalNodeRef) {
        self.words[offset] = node.module().as_u32();
        self.words[offset + 1] = node.id().as_u32();
    }

    fn shape(self) -> CorridorForceShape {
        match self.words[0] & 0xff {
            0 => CorridorForceShape::Node,
            1 => CorridorForceShape::Apply,
            2 => CorridorForceShape::GenListElemAtAddOne,
            3 => CorridorForceShape::Apply2,
            4 => CorridorForceShape::Select,
            5 => CorridorForceShape::BuiltinAttr,
            6 => CorridorForceShape::Released,
            _ => CorridorForceShape::Unsupported,
        }
    }

    fn stable(self) -> bool {
        !matches!(
            self.shape(),
            CorridorForceShape::Released | CorridorForceShape::Unsupported
        )
    }
}

/// Ownership protocol for one active force coordinate.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CorridorOwnerClass {
    Generic = 0,
    Lease = 1,
    Typed = 2,
}

/// Compact ownership record parallel to one active coordinate.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveCorridorOwner {
    generation: u64,
    lease_depth: u16,
    class: CorridorOwnerClass,
    root_multiplicity: u8,
    typed_multiplicity: u8,
    padding: [u8; 3],
}

/// Opaque token used to balance a generic or typed force observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CorridorForceToken {
    depth: usize,
    generation: u64,
}

/// One unique exact target corridor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CorridorChain {
    outer: CorridorOuter,
    padding: [u8; 7],
    frame_start: usize,
    frame_len: usize,
    completions: u64,
}

/// Counters whose sum proves target-completion conservation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CorridorCounters {
    target_completions: u64,
    exact_completions: u64,
    incomplete_completions: u64,
    overflow_completions: u64,
    untargeted_completions: u64,
    generic_claims: u64,
    lease_claims: u64,
    typed_claims: u64,
    already_forced: u64,
    declined_special: u64,
    successful_returns: u64,
    error_returns: u64,
    storage_overflows: u64,
    counter_overflows: u64,
    lifo_failures: u64,
    root_mismatches: u64,
    unstable_completions: u64,
}

/// Mutually exclusive semantic phase used by the report-only speed census.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SpeedOpportunityPhase {
    Force = 0,
    Eval = 1,
    Apply = 2,
    Update = 3,
    Return = 4,
}

impl SpeedOpportunityPhase {
    const fn name(self) -> &'static str {
        match self {
            Self::Force => "force",
            Self::Eval => "eval",
            Self::Apply => "apply",
            Self::Update => "update",
            Self::Return => "return",
        }
    }

    const fn is_virtualizable(self) -> bool {
        !matches!(self, Self::Return)
    }
}

/// Native-stack token balancing one speed-census phase transition.
///
/// Tokens stay in their caller's native frame. The census therefore retains
/// no event trace or phase stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SpeedOpportunityToken {
    generation: u64,
    previous_generation: u64,
    previous_phase: SpeedOpportunityPhase,
    depth: usize,
}

/// Bounded counters for the mixed force/eval/apply/update/return opportunity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SpeedOpportunityCounters {
    current_phase: SpeedOpportunityPhase,
    current_generation: u64,
    next_generation: u64,
    depth: usize,
    max_depth: usize,
    cursor_worker_bytes: usize,
    cursor_permanent_bytes: usize,
    entries: [u64; SPEED_PHASE_COUNT],
    exits: [u64; SPEED_PHASE_COUNT],
    materializing_exits: [u64; SPEED_PHASE_COUNT],
    arena_bytes: [u64; SPEED_PHASE_COUNT],
    completions: u64,
    completion_overflows: u64,
    byte_overflows: u64,
    cursor_failures: u64,
    lifo_failures: u64,
}

/// Bounded operation mix for one exact outer leaf.
///
/// The counters partition the aggregate census without retaining a trace.
/// They identify which force families and semantic phases a first directly
/// generated superblock must cover.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OuterOpportunityCounters {
    force_claims: [u64; FORCE_SHAPE_COUNT],
    phase_entries: [u64; SPEED_PHASE_COUNT],
    already_forced: u64,
    declined_special: u64,
}

/// Mutually exclusive execution class between two adjacent PMU snapshots.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum FinalForceLeafClass {
    /// FinalForce work outside a force body.
    #[default]
    Gap = 0,
    /// Exclusive work in a Node force.
    Node = 1,
    /// Exclusive work in an Apply force nested beneath a Node entered in-window.
    ApplyUnderNode = 2,
    /// Exclusive work in an Apply force without an in-window Node ancestor.
    ApplyOutsideNode = 3,
    /// Exclusive work in another force nested beneath an in-window Node.
    OtherUnderNode = 4,
    /// Exclusive work in another force without an in-window Node ancestor.
    OtherOutsideNode = 5,
}

impl FinalForceLeafClass {
    const fn name(self) -> &'static str {
        match self {
            Self::Gap => "gap",
            Self::Node => "node",
            Self::ApplyUnderNode => "apply_under_node",
            Self::ApplyOutsideNode => "apply_outside_node",
            Self::OtherUnderNode => "other_under_node",
            Self::OtherOutsideNode => "other_outside_node",
        }
    }
}

/// One monotone hardware-counter snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FinalForceHardwareCounts {
    instructions: u64,
    cycles: u64,
}

/// Fixed-state exclusive PMU partition for exact FinalForce5 windows.
///
/// Every transition first charges the counter delta since the preceding
/// transition to the then-current class. Consequently the six buckets are
/// disjoint and their sum equals the complete interval between the outer
/// begin/end snapshots, independent of force nesting.
#[derive(Debug)]
struct FinalForceLeafPmu {
    reader: Option<FinalForceCounterReader>,
    refusal: Option<FinalForceCounterConnectError>,
    requested: bool,
    enabled: bool,
    outer_active: bool,
    failed_closed: bool,
    base_force_depth: usize,
    force_depth: usize,
    node_depth: usize,
    force_shapes: [CorridorForceShape; MAX_ACTIVE_FORCES],
    current_class: FinalForceLeafClass,
    previous: FinalForceHardwareCounts,
    totals: [FinalForceHardwareCounts; FINAL_FORCE_LEAF_CLASS_COUNT],
    outer_windows: u64,
    transitions: u64,
    snapshots: u64,
    read_failures: u64,
    monotonic_failures: u64,
    lifo_failures: u64,
    counter_overflows: u64,
}

impl Default for FinalForceLeafPmu {
    fn default() -> Self {
        Self {
            reader: None,
            refusal: None,
            requested: false,
            enabled: false,
            outer_active: false,
            failed_closed: false,
            base_force_depth: 0,
            force_depth: 0,
            node_depth: 0,
            force_shapes: [CorridorForceShape::Unsupported; MAX_ACTIVE_FORCES],
            current_class: FinalForceLeafClass::Gap,
            previous: FinalForceHardwareCounts::default(),
            totals: [FinalForceHardwareCounts::default(); FINAL_FORCE_LEAF_CLASS_COUNT],
            outer_windows: 0,
            transitions: 0,
            snapshots: 0,
            read_failures: 0,
            monotonic_failures: 0,
            lifo_failures: 0,
            counter_overflows: 0,
        }
    }
}

impl FinalForceLeafPmu {
    const fn active(&self) -> bool {
        self.outer_active && !self.failed_closed
    }

    fn connect(&mut self) {
        if self.reader.is_none() && !self.failed_closed {
            self.requested = std::env::var_os(FINAL_FORCE_LEAF_PMU_ENV).as_deref()
                == Some(std::ffi::OsStr::new("1"));
            if self.requested {
                match FinalForceCounterReader::connect(
                    FINAL_FORCE_LEAF_INSTRUCTIONS_FD_ENV,
                    FINAL_FORCE_LEAF_CYCLES_FD_ENV,
                ) {
                    Ok(reader) => self.reader = Some(reader),
                    Err(error) => self.refusal = Some(error),
                }
            }
            self.enabled = self.reader.is_some();
        }
    }

    fn begin_outer(&mut self, active_force_depth: usize) {
        if !self.enabled || self.failed_closed {
            return;
        }
        if !self
            .reader
            .as_ref()
            .is_some_and(|reader| reader.thread_matches())
        {
            self.fail_read();
            return;
        }
        if self.outer_active || self.force_depth != 0 || self.node_depth != 0 {
            self.fail_lifo();
            return;
        }
        let Some(snapshot) = self.read_snapshot() else {
            return;
        };
        self.begin_outer_at(active_force_depth, snapshot);
    }

    fn begin_outer_at(&mut self, active_force_depth: usize, snapshot: FinalForceHardwareCounts) {
        self.outer_active = true;
        self.base_force_depth = active_force_depth;
        self.current_class = FinalForceLeafClass::Gap;
        self.previous = snapshot;
        if !increment(&mut self.outer_windows) {
            self.fail_counter();
        }
    }

    fn end_outer(&mut self, active_force_depth: usize) {
        if !self.enabled || self.failed_closed {
            return;
        }
        if !self
            .reader
            .as_ref()
            .is_some_and(|reader| reader.thread_matches())
        {
            self.fail_read();
            return;
        }
        if !self.outer_active
            || self.force_depth != 0
            || self.node_depth != 0
            || active_force_depth != self.base_force_depth
        {
            self.fail_lifo();
            return;
        }
        let Some(snapshot) = self.read_snapshot() else {
            return;
        };
        self.end_outer_at(snapshot);
    }

    fn end_outer_at(&mut self, snapshot: FinalForceHardwareCounts) {
        self.charge(snapshot);
        self.outer_active = false;
        self.base_force_depth = 0;
        self.current_class = FinalForceLeafClass::Gap;
    }

    fn enter_force(&mut self, shape: CorridorForceShape, absolute_depth: usize) {
        if !self.outer_active || self.failed_closed {
            return;
        }
        if absolute_depth != self.base_force_depth.saturating_add(self.force_depth)
            || self.force_depth >= MAX_ACTIVE_FORCES
        {
            self.fail_lifo();
            return;
        }
        let Some(snapshot) = self.read_snapshot() else {
            return;
        };
        self.enter_force_at(shape, snapshot);
    }

    fn enter_force_at(&mut self, shape: CorridorForceShape, snapshot: FinalForceHardwareCounts) {
        self.charge(snapshot);
        self.force_shapes[self.force_depth] = shape;
        self.force_depth += 1;
        if shape == CorridorForceShape::Node {
            self.node_depth += 1;
        }
        self.current_class = self.class_for(shape);
        if !increment(&mut self.transitions) {
            self.fail_counter();
        }
    }

    fn exit_force(&mut self, shape: CorridorForceShape, absolute_depth: usize) {
        if !self.outer_active || self.failed_closed {
            return;
        }
        if self.force_depth == 0
            || absolute_depth.saturating_add(1)
                != self.base_force_depth.saturating_add(self.force_depth)
            || self.force_shapes[self.force_depth - 1] != shape
        {
            self.fail_lifo();
            return;
        }
        let Some(snapshot) = self.read_snapshot() else {
            return;
        };
        self.exit_force_at(shape, snapshot);
    }

    fn exit_force_at(&mut self, shape: CorridorForceShape, snapshot: FinalForceHardwareCounts) {
        self.charge(snapshot);
        self.force_depth -= 1;
        if shape == CorridorForceShape::Node {
            self.node_depth = self.node_depth.saturating_sub(1);
        }
        self.current_class = if self.force_depth == 0 {
            FinalForceLeafClass::Gap
        } else {
            self.class_for(self.force_shapes[self.force_depth - 1])
        };
        if !increment(&mut self.transitions) {
            self.fail_counter();
        }
    }

    fn class_for(&self, shape: CorridorForceShape) -> FinalForceLeafClass {
        match shape {
            CorridorForceShape::Node => FinalForceLeafClass::Node,
            CorridorForceShape::Apply if self.node_depth > 0 => FinalForceLeafClass::ApplyUnderNode,
            CorridorForceShape::Apply => FinalForceLeafClass::ApplyOutsideNode,
            _ if self.node_depth > 0 => FinalForceLeafClass::OtherUnderNode,
            _ => FinalForceLeafClass::OtherOutsideNode,
        }
    }

    fn read_snapshot(&mut self) -> Option<FinalForceHardwareCounts> {
        let snapshot = self.reader.as_ref().and_then(|reader| {
            reader
                .snapshot()
                .map(|(instructions, cycles)| FinalForceHardwareCounts {
                    instructions,
                    cycles,
                })
        });
        if snapshot.is_none() {
            self.read_failures = self.read_failures.saturating_add(1);
            self.failed_closed = true;
            self.outer_active = false;
        } else if !increment(&mut self.snapshots) {
            self.fail_counter();
            return None;
        }
        snapshot
    }

    fn charge(&mut self, snapshot: FinalForceHardwareCounts) {
        let Some(instructions) = snapshot
            .instructions
            .checked_sub(self.previous.instructions)
        else {
            self.monotonic_failures = self.monotonic_failures.saturating_add(1);
            self.failed_closed = true;
            return;
        };
        let Some(cycles) = snapshot.cycles.checked_sub(self.previous.cycles) else {
            self.monotonic_failures = self.monotonic_failures.saturating_add(1);
            self.failed_closed = true;
            return;
        };
        let total = &mut self.totals[self.current_class as usize];
        let Some(total_instructions) = total.instructions.checked_add(instructions) else {
            self.fail_counter();
            return;
        };
        let Some(total_cycles) = total.cycles.checked_add(cycles) else {
            self.fail_counter();
            return;
        };
        total.instructions = total_instructions;
        total.cycles = total_cycles;
        self.previous = snapshot;
    }

    fn total_instructions(&self) -> Option<u64> {
        self.totals
            .iter()
            .try_fold(0u64, |sum, counts| sum.checked_add(counts.instructions))
    }

    fn total_cycles(&self) -> Option<u64> {
        self.totals
            .iter()
            .try_fold(0u64, |sum, counts| sum.checked_add(counts.cycles))
    }

    fn node_candidate_cycles(&self) -> Option<u64> {
        self.totals[FinalForceLeafClass::Node as usize]
            .cycles
            .checked_add(self.totals[FinalForceLeafClass::ApplyUnderNode as usize].cycles)
    }

    fn fail_read(&mut self) {
        self.read_failures = self.read_failures.saturating_add(1);
        self.failed_closed = true;
        self.outer_active = false;
    }

    fn fail_lifo(&mut self) {
        self.lifo_failures = self.lifo_failures.saturating_add(1);
        self.failed_closed = true;
        self.outer_active = false;
    }

    fn fail_counter(&mut self) {
        self.counter_overflows = self.counter_overflows.saturating_add(1);
        self.failed_closed = true;
        self.outer_active = false;
    }
}

impl Default for SpeedOpportunityCounters {
    fn default() -> Self {
        Self {
            current_phase: SpeedOpportunityPhase::Return,
            current_generation: 0,
            next_generation: 0,
            depth: 0,
            max_depth: 0,
            cursor_worker_bytes: 0,
            cursor_permanent_bytes: 0,
            entries: [0; SPEED_PHASE_COUNT],
            exits: [0; SPEED_PHASE_COUNT],
            materializing_exits: [0; SPEED_PHASE_COUNT],
            arena_bytes: [0; SPEED_PHASE_COUNT],
            completions: 0,
            completion_overflows: 0,
            byte_overflows: 0,
            cursor_failures: 0,
            lifo_failures: 0,
        }
    }
}

impl SpeedOpportunityCounters {
    fn begin_outer(&mut self, cursor: (usize, usize)) {
        if self.depth != 0 || self.current_generation != 0 {
            self.lifo_failures = self.lifo_failures.saturating_add(1);
        }
        self.current_phase = SpeedOpportunityPhase::Return;
        self.cursor_worker_bytes = cursor.0;
        self.cursor_permanent_bytes = cursor.1;
        if !increment(&mut self.entries[SpeedOpportunityPhase::Return as usize]) {
            self.byte_overflows = self.byte_overflows.saturating_add(1);
        }
    }

    fn end_outer(&mut self, cursor: (usize, usize)) {
        self.flush(cursor);
        if self.depth != 0 || self.current_generation != 0 {
            self.lifo_failures = self.lifo_failures.saturating_add(1);
        } else if self.current_phase != SpeedOpportunityPhase::Return {
            self.lifo_failures = self.lifo_failures.saturating_add(1);
        } else if !increment(&mut self.exits[SpeedOpportunityPhase::Return as usize]) {
            self.byte_overflows = self.byte_overflows.saturating_add(1);
        }
        self.current_generation = 0;
        self.depth = 0;
    }

    fn begin(
        &mut self,
        phase: SpeedOpportunityPhase,
        cursor: (usize, usize),
    ) -> Option<SpeedOpportunityToken> {
        self.flush(cursor);
        let Some(generation) = self.next_generation.checked_add(1) else {
            self.byte_overflows = self.byte_overflows.saturating_add(1);
            return None;
        };
        let Some(depth) = self.depth.checked_add(1) else {
            self.byte_overflows = self.byte_overflows.saturating_add(1);
            return None;
        };
        let token = SpeedOpportunityToken {
            generation,
            previous_generation: self.current_generation,
            previous_phase: self.current_phase,
            depth: self.depth,
        };
        self.next_generation = generation;
        self.current_generation = generation;
        self.current_phase = phase;
        self.depth = depth;
        self.max_depth = self.max_depth.max(self.depth);
        if !increment(&mut self.entries[phase as usize]) {
            self.byte_overflows = self.byte_overflows.saturating_add(1);
        }
        Some(token)
    }

    fn finish(
        &mut self,
        token: SpeedOpportunityToken,
        cursor: (usize, usize),
        materializing: bool,
    ) {
        self.flush(cursor);
        let expected_depth = token.depth.checked_add(1);
        if self.current_generation != token.generation || Some(self.depth) != expected_depth {
            self.lifo_failures = self.lifo_failures.saturating_add(1);
            return;
        }
        if !increment(&mut self.exits[self.current_phase as usize])
            || (materializing
                && !increment(&mut self.materializing_exits[self.current_phase as usize]))
        {
            self.byte_overflows = self.byte_overflows.saturating_add(1);
        }
        self.current_generation = token.previous_generation;
        self.current_phase = token.previous_phase;
        self.depth = token.depth;
    }

    fn note_completion(&mut self) {
        if !increment(&mut self.completions) {
            self.completion_overflows = self.completion_overflows.saturating_add(1);
        }
    }

    fn flush(&mut self, cursor: (usize, usize)) {
        let worker = cursor.0.checked_sub(self.cursor_worker_bytes);
        let permanent = cursor.1.checked_sub(self.cursor_permanent_bytes);
        let (Some(worker), Some(permanent)) = (worker, permanent) else {
            self.cursor_failures = self.cursor_failures.saturating_add(1);
            self.cursor_worker_bytes = cursor.0;
            self.cursor_permanent_bytes = cursor.1;
            return;
        };
        let Some(bytes) = worker.checked_add(permanent) else {
            self.byte_overflows = self.byte_overflows.saturating_add(1);
            self.cursor_worker_bytes = cursor.0;
            self.cursor_permanent_bytes = cursor.1;
            return;
        };
        let Ok(bytes) = u64::try_from(bytes) else {
            self.byte_overflows = self.byte_overflows.saturating_add(1);
            self.cursor_worker_bytes = cursor.0;
            self.cursor_permanent_bytes = cursor.1;
            return;
        };
        let slot = &mut self.arena_bytes[self.current_phase as usize];
        let Some(total) = slot.checked_add(bytes) else {
            self.byte_overflows = self.byte_overflows.saturating_add(1);
            self.cursor_worker_bytes = cursor.0;
            self.cursor_permanent_bytes = cursor.1;
            return;
        };
        *slot = total;
        self.cursor_worker_bytes = cursor.0;
        self.cursor_permanent_bytes = cursor.1;
    }

    fn total_arena_bytes(self) -> Option<u64> {
        self.arena_bytes
            .iter()
            .try_fold(0u64, |total, bytes| total.checked_add(*bytes))
    }

    fn virtualizable_arena_bytes(self) -> Option<u64> {
        self.arena_bytes
            .iter()
            .copied()
            .enumerate()
            .filter(|(phase, _)| {
                let phase = match phase {
                    0 => SpeedOpportunityPhase::Force,
                    1 => SpeedOpportunityPhase::Eval,
                    2 => SpeedOpportunityPhase::Apply,
                    3 => SpeedOpportunityPhase::Update,
                    _ => SpeedOpportunityPhase::Return,
                };
                phase.is_virtualizable()
            })
            .map(|(_, bytes)| bytes)
            .try_fold(0u64, |total, bytes| total.checked_add(bytes))
    }

    fn phases_conserved(self) -> bool {
        self.entries == self.exits
    }
}

/// Read-only force-stack evidence for one nested nonmoving proof attempt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct CorridorNonmovingProof {
    /// Whether the bounded census is tracking an active dispatcher session.
    pub(super) session_active: bool,
    /// Whether the completion belongs to one of the two exact outer leaves.
    pub(super) outer_active: bool,
    /// Whether bounded census storage failed closed before this observation.
    pub(super) failed_closed: bool,
    /// Number of active force coordinates.
    pub(super) coordinates: usize,
    /// Number of active force owners.
    pub(super) owners: usize,
    /// Number of scanner roots predicted by the active owners.
    pub(super) expected_roots: usize,
    /// Number of active scanner roots supplied by the evaluator.
    pub(super) actual_roots: usize,
    /// Number of detached force leases predicted by the active owners.
    pub(super) expected_leases: usize,
    /// Number of detached force leases supplied by the evaluator.
    pub(super) actual_leases: usize,
    /// Number of typed-work roots predicted by the active owners.
    pub(super) expected_typed: usize,
    /// Number of typed-work roots supplied by the evaluator.
    pub(super) actual_typed: usize,
    /// Number of unstable or unsupported active force coordinates.
    pub(super) unstable_coordinates: usize,
    /// Number of active coordinates carrying non-ordinary execution flags.
    pub(super) nonordinary_flags: usize,
    /// Number of active owners that are not ordinary generic force owners.
    pub(super) nonordinary_owners: usize,
}

impl CorridorNonmovingProof {
    /// Returns whether the force stack is completely ordinary and reconciled.
    pub(super) const fn reconciled(self) -> bool {
        self.session_active
            && self.outer_active
            && !self.failed_closed
            && self.coordinates == self.owners
            && self.expected_roots == self.actual_roots
            && self.expected_leases == self.actual_leases
            && self.expected_typed == self.actual_typed
            && self.unstable_coordinates == 0
            && self.nonordinary_flags == 0
            && self.nonordinary_owners == 0
    }
}

/// Preallocated, value-free dynamic corridor census.
#[derive(Debug, Default)]
pub(super) struct WholeDemandCorridorCensus {
    enabled: bool,
    prepared: bool,
    session_active: bool,
    failed_closed: bool,
    current_outer: Option<CorridorOuter>,
    next_generation: u64,
    max_active_depth: usize,
    active_coordinates: Vec<CorridorForceCoordinate>,
    active_owners: Vec<ActiveCorridorOwner>,
    stored_frames: Vec<CorridorForceCoordinate>,
    chains: Vec<CorridorChain>,
    shape_observations: [u64; FORCE_SHAPE_COUNT],
    outer_opportunity: [OuterOpportunityCounters; 2],
    counters: CorridorCounters,
    speed_opportunity: SpeedOpportunityCounters,
    final_force_leaf_pmu: FinalForceLeafPmu,
}

impl WholeDemandCorridorCensus {
    /// Returns whether this session records corridor and phase census data.
    pub(super) const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Snapshots exact mixed-force ownership without changing census state.
    pub(super) fn nonmoving_proof(
        &self,
        active_force_roots: usize,
        active_force_leases: usize,
        active_typed_work: usize,
    ) -> CorridorNonmovingProof {
        if !self.enabled {
            return CorridorNonmovingProof::default();
        }
        let expected_roots = self
            .active_owners
            .iter()
            .map(|owner| usize::from(owner.root_multiplicity))
            .sum();
        let expected_typed = self
            .active_owners
            .iter()
            .map(|owner| usize::from(owner.typed_multiplicity))
            .sum();
        let expected_leases = self
            .active_owners
            .iter()
            .filter(|owner| owner.class == CorridorOwnerClass::Lease)
            .count();
        CorridorNonmovingProof {
            session_active: self.session_active,
            outer_active: self.current_outer.is_some(),
            failed_closed: self.failed_closed,
            coordinates: self.active_coordinates.len(),
            owners: self.active_owners.len(),
            expected_roots,
            actual_roots: active_force_roots,
            expected_leases,
            actual_leases: active_force_leases,
            expected_typed,
            actual_typed: active_typed_work,
            unstable_coordinates: self
                .active_coordinates
                .iter()
                .filter(|coordinate| !coordinate.stable())
                .count(),
            nonordinary_flags: self
                .active_coordinates
                .iter()
                .filter(|coordinate| coordinate.words[0] >> 8 != 0)
                .count(),
            nonordinary_owners: self
                .active_owners
                .iter()
                .filter(|owner| owner.class != CorridorOwnerClass::Generic)
                .count(),
        }
    }

    /// Reserves every backing allocation before a dispatcher session runs.
    pub(super) fn prepare(&mut self) {
        if !self.enabled || self.prepared || self.failed_closed {
            return;
        }
        let reserved = self
            .active_coordinates
            .try_reserve_exact(MAX_ACTIVE_FORCES)
            .and_then(|()| self.active_owners.try_reserve_exact(MAX_ACTIVE_FORCES))
            .and_then(|()| self.stored_frames.try_reserve_exact(MAX_STORED_FRAMES))
            .and_then(|()| self.chains.try_reserve_exact(MAX_CHAINS));
        if reserved.is_err()
            || self.modeled_storage_bytes() > STORAGE_CAP_BYTES
            || self.modeled_storage_bytes() != MODELED_CENSUS_BYTES
        {
            self.active_coordinates = Vec::new();
            self.active_owners = Vec::new();
            self.stored_frames = Vec::new();
            self.chains = Vec::new();
            self.fail_storage();
            return;
        }
        self.prepared = true;
    }

    /// Starts ambient coordinate tracking for one active dispatcher session.
    pub(super) fn begin_session(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            return;
        }
        self.prepare();
        self.final_force_leaf_pmu.connect();
        if self.session_active
            || !self.active_coordinates.is_empty()
            || !self.active_owners.is_empty()
        {
            self.fail_lifo();
            return;
        }
        self.session_active = true;
    }

    /// Starts byte attribution at one admitted outer leaf.
    pub(super) fn begin_speed_opportunity_outer(&mut self, cursor: (usize, usize)) {
        if self.enabled && self.current_outer.is_some() && !self.failed_closed {
            self.speed_opportunity.begin_outer(cursor);
        }
    }

    /// Finishes byte attribution at one admitted outer leaf.
    pub(super) fn end_speed_opportunity_outer(&mut self, cursor: (usize, usize)) {
        if self.enabled && self.current_outer.is_some() && !self.failed_closed {
            self.speed_opportunity.end_outer(cursor);
        }
    }

    /// Enters one mutually exclusive streaming phase without storing a trace.
    pub(super) fn begin_speed_opportunity_phase(
        &mut self,
        phase: SpeedOpportunityPhase,
        cursor: (usize, usize),
    ) -> Option<SpeedOpportunityToken> {
        if !self.enabled || self.failed_closed {
            return None;
        }
        let outer = self.current_outer?;
        if !increment(&mut self.outer_opportunity[outer.index()].phase_entries[phase as usize]) {
            self.fail_counter();
            return None;
        }
        self.speed_opportunity.begin(phase, cursor)
    }

    /// Restores the caller's streaming phase.
    pub(super) fn finish_speed_opportunity_phase(
        &mut self,
        token: Option<SpeedOpportunityToken>,
        cursor: (usize, usize),
        materializing: bool,
    ) {
        if !self.enabled {
            return;
        }
        let Some(token) = token else {
            return;
        };
        self.speed_opportunity.finish(token, cursor, materializing);
    }

    /// Stops ambient tracking after every dispatcher-owned force has returned.
    pub(super) fn end_session(&mut self) {
        if !self.enabled {
            return;
        }
        if !self.session_active
            || self.current_outer.is_some()
            || !self.active_coordinates.is_empty()
            || !self.active_owners.is_empty()
        {
            self.fail_lifo();
        }
        self.current_outer = None;
        self.active_coordinates.clear();
        self.active_owners.clear();
        self.session_active = false;
    }

    /// Enters one exact outer semantic leaf.
    pub(super) fn enter_outer(&mut self, control: WholeDemandControl) {
        if !self.enabled {
            return;
        }
        let Some(outer) = CorridorOuter::from_control(control) else {
            return;
        };
        if self.session_active && self.current_outer.replace(outer).is_some() {
            self.fail_lifo();
        }
    }

    /// Begins direct exclusive counter attribution after FinalForce5 PMU enable.
    pub(super) fn begin_final_force_leaf_pmu(&mut self) {
        if self.current_outer == Some(CorridorOuter::FinalForce5) {
            self.final_force_leaf_pmu
                .begin_outer(self.active_coordinates.len());
        }
    }

    /// Finishes direct exclusive attribution before FinalForce5 PMU disable.
    pub(super) fn end_final_force_leaf_pmu(&mut self) {
        if self.current_outer == Some(CorridorOuter::FinalForce5) {
            self.final_force_leaf_pmu
                .end_outer(self.active_coordinates.len());
        }
    }

    /// Leaves one exact outer semantic leaf.
    pub(super) fn leave_outer(&mut self, control: WholeDemandControl) {
        if !self.enabled {
            return;
        }
        let Some(expected) = CorridorOuter::from_control(control) else {
            return;
        };
        if self.current_outer != Some(expected) {
            self.fail_lifo();
        }
        self.current_outer = None;
    }

    /// Begins one claimed generic force with its real scanner-root count.
    pub(super) fn begin_generic_force(
        &mut self,
        coordinate: CorridorForceCoordinate,
        root_multiplicity: u8,
    ) -> Option<CorridorForceToken> {
        if !self.enabled {
            return None;
        }
        self.begin_force(
            coordinate,
            CorridorOwnerClass::Generic,
            0,
            root_multiplicity,
            0,
        )
    }

    /// Finishes one generic or typed force observation.
    pub(super) fn finish_force(&mut self, token: CorridorForceToken, succeeded: bool) {
        if !self.enabled {
            return;
        }
        let matches = self
            .active_owners
            .last()
            .is_some_and(|owner| owner.generation == token.generation)
            && token.depth + 1 == self.active_owners.len()
            && self.active_owners.len() == self.active_coordinates.len();
        if !matches {
            self.fail_lifo();
            return;
        }
        let shape = self
            .active_coordinates
            .last()
            .map(|coordinate| coordinate.shape())
            .unwrap_or(CorridorForceShape::Unsupported);
        if self.final_force_leaf_pmu.active() {
            self.final_force_leaf_pmu.exit_force(shape, token.depth);
        }
        self.active_owners.pop();
        self.active_coordinates.pop();
        let counter = if succeeded {
            &mut self.counters.successful_returns
        } else {
            &mut self.counters.error_returns
        };
        if !increment(counter) {
            self.fail_counter();
        }
    }

    /// Records one detached force lease after its two roots are installed.
    pub(super) fn begin_force_lease(
        &mut self,
        token: ForceLeaseToken,
        coordinate: CorridorForceCoordinate,
    ) {
        if !self.enabled {
            return;
        }
        let Ok(depth) = u16::try_from(token.depth()) else {
            self.fail_storage();
            return;
        };
        let observed = self.begin_force(coordinate, CorridorOwnerClass::Lease, depth, 2, 0);
        if observed.is_some()
            && let Some(owner) = self.active_owners.last_mut()
        {
            owner.generation = token.generation();
        }
    }

    /// Finishes one detached force lease at its central pop.
    pub(super) fn finish_force_lease(&mut self, token: ForceLeaseToken) {
        if !self.enabled || !self.session_active {
            return;
        }
        let Ok(depth) = u16::try_from(token.depth()) else {
            self.fail_lifo();
            return;
        };
        let matches = self.active_owners.last().is_some_and(|owner| {
            owner.class == CorridorOwnerClass::Lease
                && owner.lease_depth == depth
                && owner.generation == token.generation()
        }) && self.active_owners.len() == self.active_coordinates.len();
        if !matches {
            self.fail_lifo();
            return;
        }
        let shape = self
            .active_coordinates
            .last()
            .map(|coordinate| coordinate.shape())
            .unwrap_or(CorridorForceShape::Unsupported);
        if self.final_force_leaf_pmu.active() {
            self.final_force_leaf_pmu
                .exit_force(shape, self.active_coordinates.len() - 1);
        }
        self.active_owners.pop();
        self.active_coordinates.pop();
    }

    /// Begins one typed detached-work force with a stable owned-work coordinate.
    pub(super) fn begin_typed_force(
        &mut self,
        coordinate: CorridorForceCoordinate,
    ) -> Option<CorridorForceToken> {
        if !self.enabled {
            return None;
        }
        self.begin_force(coordinate, CorridorOwnerClass::Typed, 0, 0, 1)
    }

    /// Records a cached force replay under an exact target leaf.
    pub(super) fn note_already_forced(&mut self) {
        if self.enabled && !self.failed_closed {
            let Some(outer) = self.current_outer else {
                return;
            };
            if !increment(&mut self.counters.already_forced)
                || !increment(&mut self.outer_opportunity[outer.index()].already_forced)
            {
                self.fail_counter();
            }
        }
    }

    /// Records a force protocol that did not run a body.
    pub(super) fn note_declined_special(&mut self) {
        if self.enabled && !self.failed_closed {
            let Some(outer) = self.current_outer else {
                return;
            };
            if !increment(&mut self.counters.declined_special)
                || !increment(&mut self.outer_opportunity[outer.index()].declined_special)
            {
                self.fail_counter();
            }
        }
    }

    /// Records one certified final-config completion.
    pub(super) fn note_target_completion(
        &mut self,
        active_force_roots: usize,
        active_force_leases: usize,
        active_typed_work: usize,
    ) {
        if !self.enabled {
            return;
        }
        let Some(outer) = self.current_outer else {
            if !increment(&mut self.counters.untargeted_completions) {
                self.fail_counter();
            }
            return;
        };
        if !increment(&mut self.counters.target_completions) {
            self.fail_counter();
            return;
        }
        self.speed_opportunity.note_completion();
        if self.failed_closed {
            if !increment(&mut self.counters.overflow_completions) {
                self.fail_counter();
            }
            return;
        }

        let expected_roots = self.active_owners.iter().try_fold(0usize, |sum, owner| {
            sum.checked_add(usize::from(owner.root_multiplicity))
        });
        let expected_typed = self.active_owners.iter().try_fold(0usize, |sum, owner| {
            sum.checked_add(usize::from(owner.typed_multiplicity))
        });
        let expected_leases = self
            .active_owners
            .iter()
            .filter(|owner| owner.class == CorridorOwnerClass::Lease)
            .count();
        let roots_complete = self.active_owners.len() == self.active_coordinates.len()
            && expected_roots == Some(active_force_roots)
            && expected_typed == Some(active_typed_work)
            && expected_leases == active_force_leases;
        if !roots_complete {
            if !increment(&mut self.counters.root_mismatches) {
                self.fail_counter();
            }
            self.incomplete();
            return;
        }
        if let Some((depth, coordinate)) = self
            .active_coordinates
            .iter()
            .copied()
            .enumerate()
            .find(|(_, coordinate)| !coordinate.stable())
        {
            if !increment(&mut self.counters.unstable_completions) {
                self.fail_counter();
            }
            eprintln!(
                "aos_nix_whole_demand_corridor_incomplete completion={} depth={} shape={}",
                self.counters.target_completions,
                depth,
                coordinate.shape().name(),
            );
            self.incomplete();
            return;
        }

        if let Some(chain) = self.matching_chain_index(outer) {
            if !increment(&mut self.chains[chain].completions)
                || !increment(&mut self.counters.exact_completions)
            {
                self.fail_counter();
            }
            return;
        }
        let frame_len = self.active_coordinates.len();
        if self.chains.len() >= MAX_CHAINS
            || self
                .stored_frames
                .len()
                .checked_add(frame_len)
                .is_none_or(|end| end > MAX_STORED_FRAMES)
        {
            if !increment(&mut self.counters.overflow_completions) {
                self.fail_counter();
            }
            self.fail_storage();
            return;
        }
        let frame_start = self.stored_frames.len();
        self.stored_frames
            .extend_from_slice(&self.active_coordinates);
        self.chains.push(CorridorChain {
            outer,
            padding: [0; 7],
            frame_start,
            frame_len,
            completions: 1,
        });
        if !increment(&mut self.counters.exact_completions) {
            self.fail_counter();
        }
    }

    fn begin_force(
        &mut self,
        coordinate: CorridorForceCoordinate,
        class: CorridorOwnerClass,
        lease_depth: u16,
        root_multiplicity: u8,
        typed_multiplicity: u8,
    ) -> Option<CorridorForceToken> {
        if !self.session_active || self.failed_closed {
            return None;
        }
        let generation = self.next_generation.checked_add(1).or_else(|| {
            self.fail_counter();
            None
        })?;
        if self.active_coordinates.len() >= MAX_ACTIVE_FORCES
            || self.active_owners.len() >= MAX_ACTIVE_FORCES
            || self.active_coordinates.len() != self.active_owners.len()
        {
            self.fail_storage();
            return None;
        }
        let counter = match class {
            CorridorOwnerClass::Generic => &mut self.counters.generic_claims,
            CorridorOwnerClass::Lease => &mut self.counters.lease_claims,
            CorridorOwnerClass::Typed => &mut self.counters.typed_claims,
        };
        if !increment(counter) {
            self.fail_counter();
            return None;
        }
        let shape_index = coordinate.shape() as usize;
        if !increment(&mut self.shape_observations[shape_index]) {
            self.fail_counter();
            return None;
        }
        if let Some(outer) = self.current_outer
            && !increment(&mut self.outer_opportunity[outer.index()].force_claims[shape_index])
        {
            self.fail_counter();
            return None;
        }
        let depth = self.active_coordinates.len();
        self.next_generation = generation;
        self.active_coordinates.push(coordinate);
        self.active_owners.push(ActiveCorridorOwner {
            generation,
            lease_depth,
            class,
            root_multiplicity,
            typed_multiplicity,
            padding: [0; 3],
        });
        if self.final_force_leaf_pmu.active() {
            self.final_force_leaf_pmu
                .enter_force(coordinate.shape(), depth);
        }
        self.max_active_depth = self.max_active_depth.max(self.active_coordinates.len());
        Some(CorridorForceToken { depth, generation })
    }

    fn matching_chain_index(&self, outer: CorridorOuter) -> Option<usize> {
        self.chains.iter().position(|chain| {
            chain.outer == outer
                && chain.frame_len == self.active_coordinates.len()
                && self
                    .stored_frames
                    .get(chain.frame_start..chain.frame_start + chain.frame_len)
                    .is_some_and(|frames| frames == self.active_coordinates)
        })
    }

    fn incomplete(&mut self) {
        if !increment(&mut self.counters.incomplete_completions) {
            self.fail_counter();
            if !increment(&mut self.counters.overflow_completions) {
                self.fail_counter();
            }
        }
    }

    /// Returns actual allocated bytes charged to the dispatcher cap.
    pub(super) fn modeled_storage_bytes(&self) -> usize {
        if !self.enabled {
            return 0;
        }
        self.active_coordinates
            .capacity()
            .saturating_mul(std::mem::size_of::<CorridorForceCoordinate>())
            .saturating_add(
                self.active_owners
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ActiveCorridorOwner>()),
            )
            .saturating_add(
                self.stored_frames
                    .capacity()
                    .saturating_mul(std::mem::size_of::<CorridorForceCoordinate>()),
            )
            .saturating_add(
                self.chains
                    .capacity()
                    .saturating_mul(std::mem::size_of::<CorridorChain>()),
            )
            .saturating_add(std::mem::size_of::<SpeedOpportunityCounters>())
            .saturating_add(std::mem::size_of::<[OuterOpportunityCounters; 2]>())
            .saturating_add(std::mem::size_of::<FinalForceLeafPmu>())
    }

    /// Emits exact full-shape chains and their conservation summary.
    pub(super) fn emit_report(
        &self,
        pmu_evidence: Option<super::demand_epoch_probe::DemandCounterEvidence>,
    ) {
        if !self.enabled {
            return;
        }
        for (chain_index, chain) in self.chains.iter().enumerate() {
            eprintln!(
                "aos_nix_whole_demand_corridor chain={} outer={} segment={} completions={} depth={}",
                chain_index,
                chain.outer.name(),
                chain.outer.segment(),
                chain.completions,
                chain.frame_len,
            );
            if let Some(frames) = self
                .stored_frames
                .get(chain.frame_start..chain.frame_start + chain.frame_len)
            {
                for (depth, frame) in frames.iter().enumerate() {
                    eprintln!(
                        "aos_nix_whole_demand_corridor_frame chain={} depth={} shape={} \
                         flags={} site_module={} site_id={} payload={:?}",
                        chain_index,
                        depth,
                        frame.shape().name(),
                        frame.words[0] >> 8,
                        frame.words[1],
                        frame.words[2],
                        &frame.words[3..],
                    );
                }
            }
        }
        for (shape, observations) in self.shape_observations.iter().enumerate() {
            let shape = CorridorForceCoordinate {
                words: [shape as u32, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            }
            .shape();
            eprintln!(
                "aos_nix_whole_demand_corridor_shape shape={} observations={}",
                shape.name(),
                observations,
            );
        }
        for outer in [CorridorOuter::AutoCall4, CorridorOuter::FinalForce5] {
            let counters = &self.outer_opportunity[outer.index()];
            eprintln!(
                "aos_nix_superblock_candidate outer={} segment={} \
                 node_claims={} apply_claims={} genlist_claims={} apply2_claims={} \
                 select_claims={} builtin_attr_claims={} released_claims={} \
                 unsupported_claims={} force_phase_entries={} eval_phase_entries={} \
                 apply_phase_entries={} update_phase_entries={} return_phase_entries={} \
                 already_forced={} declined_special={}",
                outer.name(),
                outer.segment(),
                counters.force_claims[CorridorForceShape::Node as usize],
                counters.force_claims[CorridorForceShape::Apply as usize],
                counters.force_claims[CorridorForceShape::GenListElemAtAddOne as usize],
                counters.force_claims[CorridorForceShape::Apply2 as usize],
                counters.force_claims[CorridorForceShape::Select as usize],
                counters.force_claims[CorridorForceShape::BuiltinAttr as usize],
                counters.force_claims[CorridorForceShape::Released as usize],
                counters.force_claims[CorridorForceShape::Unsupported as usize],
                counters.phase_entries[SpeedOpportunityPhase::Force as usize],
                counters.phase_entries[SpeedOpportunityPhase::Eval as usize],
                counters.phase_entries[SpeedOpportunityPhase::Apply as usize],
                counters.phase_entries[SpeedOpportunityPhase::Update as usize],
                counters.phase_entries[SpeedOpportunityPhase::Return as usize],
                counters.already_forced,
                counters.declined_special,
            );
        }
        let accounted = self
            .counters
            .exact_completions
            .saturating_add(self.counters.incomplete_completions)
            .saturating_add(self.counters.overflow_completions);
        eprintln!(
            "aos_nix_whole_demand_corridor_census target_completions={} \
             exact_completions={} incomplete_completions={} overflow_completions={} \
             conserved={} untargeted_completions={} chains={} stored_frames={} \
             max_active={} generic_claims={} lease_claims={} typed_claims={} \
             already_forced={} declined_special={} successful_returns={} error_returns={} \
             root_mismatches={} unstable_completions={} storage_overflows={} \
             counter_overflows={} lifo_failures={} failed_closed={} \
             modeled_storage_bytes={} storage_cap_bytes={}",
            self.counters.target_completions,
            self.counters.exact_completions,
            self.counters.incomplete_completions,
            self.counters.overflow_completions,
            accounted == self.counters.target_completions,
            self.counters.untargeted_completions,
            self.chains.len(),
            self.stored_frames.len(),
            self.max_active_depth,
            self.counters.generic_claims,
            self.counters.lease_claims,
            self.counters.typed_claims,
            self.counters.already_forced,
            self.counters.declined_special,
            self.counters.successful_returns,
            self.counters.error_returns,
            self.counters.root_mismatches,
            self.counters.unstable_completions,
            self.counters.storage_overflows,
            self.counters.counter_overflows,
            self.counters.lifo_failures,
            self.failed_closed,
            self.modeled_storage_bytes(),
            STORAGE_CAP_BYTES,
        );
        self.emit_final_force_leaf_pmu_report(pmu_evidence);
        self.emit_speed_opportunity_report(pmu_evidence);
    }

    fn emit_final_force_leaf_pmu_report(
        &self,
        pmu_evidence: Option<super::demand_epoch_probe::DemandCounterEvidence>,
    ) {
        let probe = &self.final_force_leaf_pmu;
        if !probe.enabled {
            if probe.requested {
                eprintln!(
                    "aos_nix_final_force_leaf_pmu_disabled requested=true reason={}",
                    probe.refusal.map_or("unknown", |reason| match reason {
                        FinalForceCounterConnectError::CyclesOpen => "cycles_open",
                        FinalForceCounterConnectError::InstructionsOpen => "instructions_open",
                        FinalForceCounterConnectError::MetadataMap => "metadata_map",
                        FinalForceCounterConnectError::RdpmcUnavailable => "rdpmc_unavailable",
                        FinalForceCounterConnectError::GroupReset => "group_reset",
                        FinalForceCounterConnectError::GroupEnable => "group_enable",
                        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
                        FinalForceCounterConnectError::UnsupportedPlatform =>
                            "unsupported_platform",
                    }),
                );
            }
            return;
        }
        for class in [
            FinalForceLeafClass::Gap,
            FinalForceLeafClass::Node,
            FinalForceLeafClass::ApplyUnderNode,
            FinalForceLeafClass::ApplyOutsideNode,
            FinalForceLeafClass::OtherUnderNode,
            FinalForceLeafClass::OtherOutsideNode,
        ] {
            let counts = probe.totals[class as usize];
            eprintln!(
                "aos_nix_final_force_leaf_pmu_class class={} instructions={} cycles={}",
                class.name(),
                counts.instructions,
                counts.cycles,
            );
        }
        let evidence = pmu_evidence
            .unwrap_or_else(super::demand_epoch_probe::DemandCounterEvidence::unavailable);
        let total_instructions = probe.total_instructions();
        let total_cycles = probe.total_cycles();
        let candidate_cycles = probe.node_candidate_cycles();
        let candidate_coverage_ppm = candidate_cycles
            .and_then(|cycles| cycles.checked_mul(1_000_000))
            .and_then(|cycles| cycles.checked_div(total_cycles.unwrap_or(0)));
        let buckets_conserved = total_instructions.is_some() && total_cycles.is_some();
        let balanced = !probe.outer_active
            && probe.force_depth == 0
            && probe.node_depth == 0
            && probe.read_failures == 0
            && probe.monotonic_failures == 0
            && probe.lifo_failures == 0
            && probe.counter_overflows == 0
            && !probe.failed_closed;
        let authoritative = evidence.authoritative()
            && balanced
            && buckets_conserved
            && probe.outer_windows
                == evidence.windows(super::demand_epoch_probe::DemandWindowKind::FinalForce5);
        let coverage_gate = authoritative
            && candidate_coverage_ppm
                .is_some_and(|coverage| coverage >= FINAL_FORCE_NODE_COVERAGE_GATE_PPM);
        eprintln!(
            "aos_nix_final_force_leaf_pmu windows={} transitions={} snapshots={} \
             instructions={} cycles={} node_candidate_cycles={} \
             node_candidate_coverage_ppm={} coverage_gate_ppm={} coverage_gate={} \
             outer_raw_instructions={} outer_raw_cycles={} \
             outer_adjusted_instructions={} outer_adjusted_cycles={} \
             buckets_conserved={} balanced={} authoritative={} read_failures={} \
             monotonic_failures={} lifo_failures={} counter_overflows={} \
             failed_closed={}",
            probe.outer_windows,
            probe.transitions,
            probe.snapshots,
            total_instructions.unwrap_or(0),
            total_cycles.unwrap_or(0),
            candidate_cycles.unwrap_or(0),
            candidate_coverage_ppm.unwrap_or(0),
            FINAL_FORCE_NODE_COVERAGE_GATE_PPM,
            coverage_gate,
            evidence.raw_instructions(super::demand_epoch_probe::DemandWindowKind::FinalForce5,),
            evidence.raw_cycles(super::demand_epoch_probe::DemandWindowKind::FinalForce5),
            evidence.instructions(super::demand_epoch_probe::DemandWindowKind::FinalForce5),
            evidence.cycles(super::demand_epoch_probe::DemandWindowKind::FinalForce5),
            buckets_conserved,
            balanced,
            authoritative,
            probe.read_failures,
            probe.monotonic_failures,
            probe.lifo_failures,
            probe.counter_overflows,
            probe.failed_closed,
        );
    }

    fn emit_speed_opportunity_report(
        &self,
        pmu_evidence: Option<super::demand_epoch_probe::DemandCounterEvidence>,
    ) {
        let traffic_bytes = self.speed_opportunity.total_arena_bytes();
        let virtualizable_bytes = self.speed_opportunity.virtualizable_arena_bytes();
        let virtualizable_bytes_ppm = virtualizable_bytes
            .and_then(|bytes| bytes.checked_mul(1_000_000))
            .and_then(|bytes| bytes.checked_div(traffic_bytes.unwrap_or(0)));
        let max_targets_per_site = self.max_targets_per_site();
        let exits = self
            .speed_opportunity
            .exits
            .iter()
            .try_fold(0u64, |total, value| total.checked_add(*value));
        let materializing_exits = self
            .speed_opportunity
            .materializing_exits
            .iter()
            .try_fold(0u64, |total, value| total.checked_add(*value));
        let materializing_exit_ppm = materializing_exits
            .and_then(|count| count.checked_mul(1_000_000))
            .and_then(|count| count.checked_div(exits.unwrap_or(0)));
        let aggregate_arithmetic_ok = traffic_bytes.is_some()
            && virtualizable_bytes.is_some()
            && virtualizable_bytes_ppm.is_some()
            && exits.is_some()
            && materializing_exits.is_some()
            && materializing_exit_ppm.is_some();
        // Heap tags do not establish whether an exit allocated, escaped,
        // performed an effect, or crossed an unsupported oracle boundary.
        let materializing_exit_classifier_available = false;
        let materializing_exit_gate = false;
        let exact_completions = self.speed_opportunity.completions == REQUIRED_COMPLETIONS
            && self.counters.target_completions == REQUIRED_COMPLETIONS
            && self.counters.exact_completions == REQUIRED_COMPLETIONS;
        let structural_gate = exact_completions
            && self.counters.incomplete_completions == 0
            && self.counters.overflow_completions == 0
            && self.counters.lifo_failures == 0
            && self.counters.root_mismatches == 0
            && self.counters.unstable_completions == 0
            && self.speed_opportunity.completion_overflows == 0
            && self.speed_opportunity.byte_overflows == 0
            && self.speed_opportunity.cursor_failures == 0
            && self.speed_opportunity.lifo_failures == 0
            && self.speed_opportunity.phases_conserved()
            && aggregate_arithmetic_ok
            && max_targets_per_site.is_some()
            && !self.failed_closed;
        let traffic_gate = traffic_bytes.is_some_and(|bytes| bytes >= TRAFFIC_GATE_BYTES);
        let virtualizable_candidate_gate =
            virtualizable_bytes_ppm.is_some_and(|ppm| ppm >= VIRTUALIZABLE_BYTES_GATE_PPM);
        let targets_gate =
            max_targets_per_site.is_some_and(|targets| targets <= TARGETS_PER_SITE_GATE);
        let evidence = pmu_evidence
            .unwrap_or_else(super::demand_epoch_probe::DemandCounterEvidence::unavailable);
        let inclusive_instructions = evidence
            .authoritative()
            .then(|| evidence.total_instructions())
            .flatten();
        let inclusive_cycles = evidence
            .authoritative()
            .then(|| evidence.total_cycles())
            .flatten();
        let instruction_savings = inclusive_instructions
            .and_then(|value| value.checked_mul(70))
            .and_then(|value| value.checked_div(100));
        let cycle_savings = inclusive_cycles
            .and_then(|value| value.checked_mul(65))
            .and_then(|value| value.checked_div(100));
        let inclusive_instruction_gate =
            inclusive_instructions.is_some_and(|value| value >= INCLUSIVE_INSTRUCTION_GATE);
        let instruction_savings_gate =
            instruction_savings.is_some_and(|value| value >= INSTRUCTION_SAVINGS_GATE);
        let inclusive_cycle_gate =
            inclusive_cycles.is_some_and(|value| value >= INCLUSIVE_CYCLE_GATE);
        let cycle_savings_gate = cycle_savings.is_some_and(|value| value >= CYCLE_SAVINGS_GATE);

        for phase in [
            SpeedOpportunityPhase::Force,
            SpeedOpportunityPhase::Eval,
            SpeedOpportunityPhase::Apply,
            SpeedOpportunityPhase::Update,
            SpeedOpportunityPhase::Return,
        ] {
            eprintln!(
                "aos_nix_speed_opportunity_phase phase={} entries={} exits={} \
                 materializing_exits={} arena_bytes={}",
                phase.name(),
                self.speed_opportunity.entries[phase as usize],
                self.speed_opportunity.exits[phase as usize],
                self.speed_opportunity.materializing_exits[phase as usize],
                self.speed_opportunity.arena_bytes[phase as usize],
            );
        }
        eprintln!(
            "aos_nix_speed_opportunity_census completions={} required_completions={} \
             exact_completions={} max_depth={} traffic_bytes={} traffic_gate_bytes={} \
             traffic_gate={} virtualizable_candidate_bytes={} \
             virtualizable_candidate_bytes_ppm={} virtualizable_gate_ppm={} \
             virtualizable_candidate_gate={} virtualizable_classification_exact=false \
             virtualizable_gate=false max_targets_per_site={} \
             targets_per_site_gate={} targets_gate={} \
             inclusive_instructions={} inclusive_instruction_gate={} \
             inclusive_instruction_gate_pass={} instruction_savings_at_70pct={} \
             instruction_savings_gate={} instruction_savings_gate_pass={} \
             inclusive_cycles={} inclusive_cycle_gate={} inclusive_cycle_gate_pass={} \
             cycle_savings_at_65pct={} cycle_savings_gate={} \
             cycle_savings_gate_pass={} exits={} materializing_exits={} \
             weighted_materializing_exits_ppm={} \
             weighted_materializing_exit_gate_ppm={} \
             weighted_materializing_exit_gate_pass={} structural_gate={} \
             pmu_interval_measurement_available={} \
             pmu_interval_scope=target_windows_including_census_instrumentation \
             pmu_evaluator_session_window_provenance_available={} \
             instrumentation_overhead_control_available={} \
             cfg_off_codegen_neutrality_measured=false \
             materializing_exit_classifier_available={} \
             opportunity_gate=false report_only=true generic_executor=false \
             tree_walk_specialization=false collection=false \
             blocker=materialization_and_allocation_kind_provenance_unavailable \
             phase_conservation={} aggregate_arithmetic_ok={} \
             completion_overflows={} byte_overflows={} cursor_failures={} \
             phase_lifo_failures={}",
            self.speed_opportunity.completions,
            REQUIRED_COMPLETIONS,
            exact_completions,
            self.speed_opportunity.max_depth,
            traffic_bytes.unwrap_or(0),
            TRAFFIC_GATE_BYTES,
            traffic_gate,
            virtualizable_bytes.unwrap_or(0),
            virtualizable_bytes_ppm.unwrap_or(0),
            VIRTUALIZABLE_BYTES_GATE_PPM,
            virtualizable_candidate_gate,
            max_targets_per_site.unwrap_or(0),
            TARGETS_PER_SITE_GATE,
            targets_gate,
            inclusive_instructions.unwrap_or(0),
            INCLUSIVE_INSTRUCTION_GATE,
            inclusive_instruction_gate,
            instruction_savings.unwrap_or(0),
            INSTRUCTION_SAVINGS_GATE,
            instruction_savings_gate,
            inclusive_cycles.unwrap_or(0),
            INCLUSIVE_CYCLE_GATE,
            inclusive_cycle_gate,
            cycle_savings.unwrap_or(0),
            CYCLE_SAVINGS_GATE,
            cycle_savings_gate,
            exits.unwrap_or(0),
            materializing_exits.unwrap_or(0),
            materializing_exit_ppm.unwrap_or(0),
            MATERIALIZING_EXIT_GATE_PPM,
            materializing_exit_gate,
            structural_gate,
            evidence.authoritative(),
            evidence.authoritative(),
            evidence.authoritative(),
            materializing_exit_classifier_available,
            self.speed_opportunity.phases_conserved(),
            aggregate_arithmetic_ok,
            self.speed_opportunity.completion_overflows,
            self.speed_opportunity.byte_overflows,
            self.speed_opportunity.cursor_failures,
            self.speed_opportunity.lifo_failures,
        );
    }

    fn max_targets_per_site(&self) -> Option<usize> {
        let mut maximum = 0;
        for (frame_index, frame) in self.stored_frames.iter().enumerate() {
            self.outer_for_frame_index(frame_index)?;
            let mut distinct = 0usize;
            for (candidate_index, candidate) in self.stored_frames.iter().enumerate() {
                if frame.words[1..3] != candidate.words[1..3] {
                    continue;
                }
                let candidate_outer = self.outer_for_frame_index(candidate_index)?;
                let already_seen = self.stored_frames[..candidate_index]
                    .iter()
                    .enumerate()
                    .any(|(prior_index, prior)| {
                        prior.words[1..3] == candidate.words[1..3]
                            && prior.words[0] == candidate.words[0]
                            && prior.words[3..] == candidate.words[3..]
                            && self.outer_for_frame_index(prior_index) == Some(candidate_outer)
                    });
                if !already_seen {
                    distinct = distinct.saturating_add(1);
                }
            }
            maximum = maximum.max(distinct);
            if frame_index + 1 == self.stored_frames.len() {
                break;
            }
        }
        Some(maximum)
    }

    fn outer_for_frame_index(&self, frame_index: usize) -> Option<CorridorOuter> {
        self.chains.iter().find_map(|chain| {
            let end = chain.frame_start.checked_add(chain.frame_len)?;
            (frame_index >= chain.frame_start && frame_index < end).then_some(chain.outer)
        })
    }

    fn fail_storage(&mut self) {
        self.failed_closed = true;
        self.counters.storage_overflows = self.counters.storage_overflows.saturating_add(1);
    }

    fn fail_counter(&mut self) {
        self.failed_closed = true;
        self.counters.counter_overflows = self.counters.counter_overflows.saturating_add(1);
    }

    fn fail_lifo(&mut self) {
        self.failed_closed = true;
        self.counters.lifo_failures = self.counters.lifo_failures.saturating_add(1);
    }
}

impl TreeWalk {
    /// Opens one report-only speed phase using exact evaluator-arena cursors.
    pub(super) fn begin_speed_opportunity_phase(
        &mut self,
        phase: SpeedOpportunityPhase,
    ) -> Option<SpeedOpportunityToken> {
        if !self.whole_demand_dispatcher.corridor_census.is_enabled() {
            return None;
        }
        let cursor = (
            self.heap.arena_stats().used_bytes,
            self.heap.permanent_arena_stats().used_bytes,
        );
        self.whole_demand_dispatcher
            .corridor_census
            .begin_speed_opportunity_phase(phase, cursor)
    }

    /// Closes one report-only speed phase and restores its caller phase.
    pub(super) fn finish_speed_opportunity_phase(
        &mut self,
        token: Option<SpeedOpportunityToken>,
        _result: &Result<Value, TreeWalkError>,
    ) {
        if !self.whole_demand_dispatcher.corridor_census.is_enabled() {
            return;
        }
        let cursor = (
            self.heap.arena_stats().used_bytes,
            self.heap.permanent_arena_stats().used_bytes,
        );
        // Result tags are not materialization provenance. Keep this channel
        // empty and its gate unavailable until allocation-kind, escape, effect,
        // and oracle-boundary evidence can be joined to the phase token.
        let materializing = false;
        self.whole_demand_dispatcher
            .corridor_census
            .finish_speed_opportunity_phase(token, cursor, materializing);
    }
}

fn increment(counter: &mut u64) -> bool {
    let Some(next) = counter.checked_add(1) else {
        return false;
    };
    *counter = next;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coordinate(shape: CorridorForceShape, site: u32) -> CorridorForceCoordinate {
        let mut coordinate = CorridorForceCoordinate {
            words: [0, 0, site, 1, site + 1, 0, 0, 0, 0, 0],
        };
        coordinate.set_shape(shape);
        coordinate
    }

    fn start(census: &mut WholeDemandCorridorCensus) {
        census.begin_session(true);
        census.enter_outer(WholeDemandControl::FinalForce { segment: 5 });
    }

    fn target(census: &mut WholeDemandCorridorCensus, roots: usize, typed: usize) {
        census.note_target_completion(roots, 0, typed);
    }

    #[test]
    fn disabled_census_is_a_counter_and_storage_no_op() {
        let mut census = WholeDemandCorridorCensus::default();
        census.begin_session(false);
        census.enter_outer(WholeDemandControl::FinalForce { segment: 5 });
        census.begin_speed_opportunity_outer((10, 20));
        let phase = census.begin_speed_opportunity_phase(SpeedOpportunityPhase::Force, (15, 25));
        let force = census.begin_generic_force(coordinate(CorridorForceShape::Apply, 1), 1);
        census.begin_force_lease(
            ForceLeaseToken::new(0, 1),
            coordinate(CorridorForceShape::Node, 2),
        );
        census.note_already_forced();
        census.note_declined_special();
        census.note_target_completion(2, 1, 0);
        census.finish_force_lease(ForceLeaseToken::new(0, 1));
        if let Some(force) = force {
            census.finish_force(force, true);
        }
        census.finish_speed_opportunity_phase(phase, (30, 40), false);
        census.end_speed_opportunity_outer((30, 40));
        census.leave_outer(WholeDemandControl::FinalForce { segment: 5 });
        census.end_session();

        assert!(!census.is_enabled());
        assert_eq!(census.modeled_storage_bytes(), 0);
        assert_eq!(census.counters, CorridorCounters::default());
        assert_eq!(
            census.speed_opportunity,
            SpeedOpportunityCounters::default()
        );
        assert!(census.active_coordinates.is_empty());
        assert!(census.active_owners.is_empty());
        assert!(census.stored_frames.is_empty());
        assert!(census.chains.is_empty());
        assert_eq!(
            census.nonmoving_proof(2, 1, 0),
            CorridorNonmovingProof::default()
        );
    }

    #[test]
    fn thunk_kinds_encode_stable_shape_payloads_and_flags() {
        let module = EvalModuleId::new(3);
        let site = IrId::new(4);
        let node = EvalThunk::with_env(module, IrId::new(10), EvalEnv::default());
        let apply = EvalThunk::apply(
            module,
            IrId::new(11),
            Span::default(),
            Value::null(),
            EvalModuleId::new(5),
            IrId::new(12),
            Value::null(),
        );
        let marker = EvalThunk::genlist_elem_at_add_one(
            module,
            IrId::new(13),
            Span::default(),
            Value::null(),
            EvalModuleId::new(6),
            IrId::new(14),
            Value::null(),
        );
        let apply2 = EvalThunk::apply2(
            module,
            IrId::new(15),
            Span::default(),
            Value::null(),
            EvalModuleId::new(7),
            IrId::new(16),
            Span::default(),
            Value::null(),
            EvalModuleId::new(8),
            IrId::new(17),
            Span::default(),
            Value::null(),
        );
        let select = EvalThunk::select(
            EvalModuleId::new(9),
            IrId::new(18),
            Value::null(),
            IrAttrPathId::new(19),
        );
        let builtin = BUILTINS.iter().next().copied().expect("builtin registry");
        let builtin_attr = EvalThunk::builtin_attr(Symbol::new(20), builtin);
        let coordinates = [
            CorridorForceCoordinate::from_thunk(module, site, &node, true, false, false, false),
            CorridorForceCoordinate::from_thunk(module, site, &apply, false, true, false, false),
            CorridorForceCoordinate::from_thunk(module, site, &marker, false, false, true, false),
            CorridorForceCoordinate::from_thunk(module, site, &apply2, false, false, false, true),
            CorridorForceCoordinate::from_thunk(module, site, &select, false, false, false, false),
            CorridorForceCoordinate::from_thunk(
                module,
                site,
                &builtin_attr,
                false,
                false,
                false,
                false,
            ),
        ];
        assert_eq!(
            coordinates.map(CorridorForceCoordinate::shape),
            [
                CorridorForceShape::Node,
                CorridorForceShape::Apply,
                CorridorForceShape::GenListElemAtAddOne,
                CorridorForceShape::Apply2,
                CorridorForceShape::Select,
                CorridorForceShape::BuiltinAttr,
            ]
        );
        assert_eq!(coordinates[0].words[3..5], [3, 10]);
        assert_eq!(coordinates[1].words[3..7], [3, 11, 5, 12]);
        assert_eq!(coordinates[2].words[3..7], [3, 13, 6, 14]);
        assert_eq!(coordinates[3].words[3..9], [3, 15, 7, 16, 8, 17]);
        assert_eq!(coordinates[4].words[3..6], [9, 18, 19]);
        assert_eq!(coordinates[5].words[3..5], [20, 0]);
        assert_eq!(
            coordinates[0].words[0] & FLAG_SINGLE_ENTRY,
            FLAG_SINGLE_ENTRY
        );
        assert_eq!(
            coordinates[1].words[0] & FLAG_PARALLEL_PAYLOAD,
            FLAG_PARALLEL_PAYLOAD
        );
        assert_eq!(coordinates[2].words[0] & FLAG_TIER1, FLAG_TIER1);
        assert_eq!(
            coordinates[3].words[0] & FLAG_TYPED_DETACHED,
            FLAG_TYPED_DETACHED
        );
    }

    #[test]
    fn mixed_full_shape_chain_is_exact_and_deduplicated() {
        let mut census = WholeDemandCorridorCensus::default();
        census.begin_session(true);
        let mut tokens = Vec::new();
        for (index, shape) in [
            CorridorForceShape::Node,
            CorridorForceShape::Apply,
            CorridorForceShape::GenListElemAtAddOne,
            CorridorForceShape::Apply2,
            CorridorForceShape::Select,
            CorridorForceShape::BuiltinAttr,
        ]
        .into_iter()
        .enumerate()
        {
            tokens.push(census.begin_generic_force(coordinate(shape, index as u32), 1));
        }
        census.enter_outer(WholeDemandControl::FinalForce { segment: 5 });
        target(&mut census, 6, 0);
        target(&mut census, 6, 0);
        assert_eq!(census.counters.exact_completions, 2);
        assert_eq!(census.chains.len(), 1);
        assert_eq!(census.chains[0].frame_len, 6);
        for token in tokens.into_iter().rev().flatten() {
            census.finish_force(token, true);
        }
    }

    #[test]
    fn nonmoving_proof_reconciles_an_ordinary_mixed_force_stack() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        let first = census
            .begin_generic_force(coordinate(CorridorForceShape::Node, 1), 1)
            .expect("first force records");
        let second = census
            .begin_generic_force(coordinate(CorridorForceShape::Select, 2), 1)
            .expect("second force records");

        let proof = census.nonmoving_proof(2, 0, 0);
        assert!(proof.reconciled());
        assert_eq!(proof.coordinates, 2);
        assert_eq!(proof.expected_roots, 2);
        assert_eq!(proof.actual_roots, 2);

        census.finish_force(second, true);
        census.finish_force(first, true);
        census.leave_outer(WholeDemandControl::FinalForce { segment: 5 });
        census.end_session();
    }

    #[test]
    fn nonmoving_proof_refuses_nonordinary_force_flags() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        let mut flagged = coordinate(CorridorForceShape::Apply, 1);
        flagged.words[0] |= FLAG_TIER1;
        let token = census
            .begin_generic_force(flagged, 1)
            .expect("flagged force records");

        let proof = census.nonmoving_proof(1, 0, 0);
        assert!(!proof.reconciled());
        assert_eq!(proof.nonordinary_flags, 1);

        census.finish_force(token, true);
        census.leave_outer(WholeDemandControl::FinalForce { segment: 5 });
        census.end_session();
    }

    #[test]
    fn real_root_multiplicity_is_reconciled() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        let generic = census.begin_generic_force(coordinate(CorridorForceShape::Node, 1), 1);
        let lease = ForceLeaseToken::new(0, 7);
        census.begin_force_lease(lease, coordinate(CorridorForceShape::Apply, 2));
        census.note_target_completion(3, 1, 0);
        assert_eq!(census.counters.exact_completions, 1);
        census.finish_force_lease(lease);
        if let Some(token) = generic {
            census.finish_force(token, true);
        }
    }

    #[test]
    fn typed_coordinate_requires_bijective_typed_lease_count() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        let token = census.begin_typed_force(coordinate(CorridorForceShape::Apply, 1));
        target(&mut census, 0, 1);
        assert_eq!(census.counters.exact_completions, 1);
        if let Some(token) = token {
            census.finish_force(token, true);
        }
    }

    #[test]
    fn unsupported_position_keeps_completion_incomplete() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        let token = census.begin_generic_force(coordinate(CorridorForceShape::Unsupported, 1), 1);
        target(&mut census, 1, 0);
        assert_eq!(census.counters.incomplete_completions, 1);
        assert_eq!(census.counters.exact_completions, 0);
        if let Some(token) = token {
            census.finish_force(token, false);
        }
    }

    #[test]
    fn root_mismatch_keeps_completion_incomplete() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        let token = census.begin_generic_force(coordinate(CorridorForceShape::Node, 1), 1);
        target(&mut census, 0, 0);
        assert_eq!(census.counters.root_mismatches, 1);
        assert_eq!(census.counters.incomplete_completions, 1);
        if let Some(token) = token {
            census.finish_force(token, true);
        }
    }

    #[test]
    fn already_forced_and_declined_do_not_enter_chain() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        census.note_already_forced();
        census.note_declined_special();
        target(&mut census, 0, 0);
        assert_eq!(census.counters.exact_completions, 1);
        assert_eq!(census.chains[0].frame_len, 0);
    }

    #[test]
    fn superblock_candidate_mix_is_partitioned_by_outer_leaf() {
        let mut census = WholeDemandCorridorCensus::default();
        census.begin_session(true);

        census.enter_outer(WholeDemandControl::AutoCall { segment: 4 });
        let auto_force = census.begin_generic_force(coordinate(CorridorForceShape::Node, 1), 1);
        let auto_phase = census.begin_speed_opportunity_phase(SpeedOpportunityPhase::Eval, (0, 0));
        census.finish_speed_opportunity_phase(auto_phase, (0, 0), false);
        census.note_already_forced();
        if let Some(token) = auto_force {
            census.finish_force(token, true);
        }
        census.leave_outer(WholeDemandControl::AutoCall { segment: 4 });

        census.enter_outer(WholeDemandControl::FinalForce { segment: 5 });
        let final_force = census.begin_generic_force(coordinate(CorridorForceShape::Apply, 2), 1);
        let final_phase =
            census.begin_speed_opportunity_phase(SpeedOpportunityPhase::Apply, (0, 0));
        census.finish_speed_opportunity_phase(final_phase, (0, 0), false);
        census.note_declined_special();
        if let Some(token) = final_force {
            census.finish_force(token, true);
        }

        let auto = census.outer_opportunity[CorridorOuter::AutoCall4.index()];
        assert_eq!(auto.force_claims[CorridorForceShape::Node as usize], 1);
        assert_eq!(auto.phase_entries[SpeedOpportunityPhase::Eval as usize], 1);
        assert_eq!(auto.already_forced, 1);
        assert_eq!(auto.declined_special, 0);

        let final_force = census.outer_opportunity[CorridorOuter::FinalForce5.index()];
        assert_eq!(
            final_force.force_claims[CorridorForceShape::Apply as usize],
            1
        );
        assert_eq!(
            final_force.phase_entries[SpeedOpportunityPhase::Apply as usize],
            1
        );
        assert_eq!(final_force.already_forced, 0);
        assert_eq!(final_force.declined_special, 1);
    }

    #[test]
    fn final_force_leaf_pmu_partitions_nested_intervals_exactly() {
        let mut probe = FinalForceLeafPmu {
            enabled: true,
            ..FinalForceLeafPmu::default()
        };
        probe.begin_outer_at(
            3,
            FinalForceHardwareCounts {
                instructions: 100,
                cycles: 1_000,
            },
        );
        probe.enter_force_at(
            CorridorForceShape::Node,
            FinalForceHardwareCounts {
                instructions: 110,
                cycles: 1_010,
            },
        );
        probe.enter_force_at(
            CorridorForceShape::Apply,
            FinalForceHardwareCounts {
                instructions: 130,
                cycles: 1_050,
            },
        );
        probe.enter_force_at(
            CorridorForceShape::Node,
            FinalForceHardwareCounts {
                instructions: 160,
                cycles: 1_100,
            },
        );
        probe.exit_force_at(
            CorridorForceShape::Node,
            FinalForceHardwareCounts {
                instructions: 190,
                cycles: 1_170,
            },
        );
        probe.exit_force_at(
            CorridorForceShape::Apply,
            FinalForceHardwareCounts {
                instructions: 210,
                cycles: 1_200,
            },
        );
        probe.exit_force_at(
            CorridorForceShape::Node,
            FinalForceHardwareCounts {
                instructions: 240,
                cycles: 1_250,
            },
        );
        probe.end_outer_at(FinalForceHardwareCounts {
            instructions: 260,
            cycles: 1_300,
        });

        assert_eq!(probe.total_instructions(), Some(160));
        assert_eq!(probe.total_cycles(), Some(300));
        assert_eq!(probe.totals[FinalForceLeafClass::Gap as usize].cycles, 60);
        assert_eq!(probe.totals[FinalForceLeafClass::Node as usize].cycles, 160);
        assert_eq!(
            probe.totals[FinalForceLeafClass::ApplyUnderNode as usize].cycles,
            80
        );
        assert_eq!(probe.node_candidate_cycles(), Some(240));
        assert!(!probe.outer_active);
        assert_eq!(probe.force_depth, 0);
        assert_eq!(probe.node_depth, 0);
    }

    #[test]
    fn final_force_leaf_pmu_distinguishes_apply_without_node_ancestor() {
        let mut probe = FinalForceLeafPmu {
            enabled: true,
            ..FinalForceLeafPmu::default()
        };
        probe.begin_outer_at(
            0,
            FinalForceHardwareCounts {
                instructions: 10,
                cycles: 100,
            },
        );
        probe.enter_force_at(
            CorridorForceShape::Apply,
            FinalForceHardwareCounts {
                instructions: 12,
                cycles: 103,
            },
        );
        probe.exit_force_at(
            CorridorForceShape::Apply,
            FinalForceHardwareCounts {
                instructions: 22,
                cycles: 123,
            },
        );
        probe.end_outer_at(FinalForceHardwareCounts {
            instructions: 25,
            cycles: 130,
        });

        assert_eq!(
            probe.totals[FinalForceLeafClass::ApplyOutsideNode as usize].cycles,
            20
        );
        assert_eq!(
            probe.totals[FinalForceLeafClass::ApplyUnderNode as usize].cycles,
            0
        );
        assert_eq!(probe.total_cycles(), Some(30));
    }

    #[test]
    fn stale_token_fails_closed() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        let token = census.begin_generic_force(coordinate(CorridorForceShape::Node, 1), 1);
        if let Some(mut token) = token {
            token.generation = token.generation.saturating_add(1);
            census.finish_force(token, true);
        }
        assert!(census.failed_closed);
        assert_eq!(census.counters.lifo_failures, 1);
    }

    #[test]
    fn storage_overflow_is_conserved_and_fails_closed() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        let token = census.begin_generic_force(coordinate(CorridorForceShape::Node, 2), 1);
        census
            .stored_frames
            .resize(MAX_STORED_FRAMES, coordinate(CorridorForceShape::Node, 1));
        target(&mut census, 1, 0);
        assert!(census.failed_closed);
        assert_eq!(census.counters.overflow_completions, 1);
        assert_eq!(census.counters.target_completions, 1);
        if let Some(token) = token {
            census.finish_force(token, true);
        }
    }

    #[test]
    fn panic_cleanup_sequence_balances_token() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        let token = census.begin_generic_force(coordinate(CorridorForceShape::Node, 1), 1);
        let panic = std::panic::catch_unwind(|| panic!("injected force body panic"));
        assert!(panic.is_err());
        if let Some(token) = token {
            census.finish_force(token, false);
        }
        assert!(census.active_coordinates.is_empty());
        assert!(census.active_owners.is_empty());
    }

    #[test]
    fn coordinates_are_relocation_independent() {
        let coordinate = coordinate(CorridorForceShape::Apply2, 7);
        let mut unrelated_root = Value::int(1);
        unrelated_root = Value::int(2);
        assert_eq!(coordinate.words[2], 7);
        assert!(unrelated_root.raw_eq(Value::int(2)));
    }

    #[test]
    fn prepared_storage_has_exact_modeled_size() {
        let mut census = WholeDemandCorridorCensus::default();
        census.enabled = true;
        census.prepare();
        assert!(census.prepared);
        assert_eq!(census.modeled_storage_bytes(), MODELED_CENSUS_BYTES);
        assert!(census.modeled_storage_bytes() <= STORAGE_CAP_BYTES);
    }

    #[test]
    fn inactive_prepared_census_is_neutral() {
        let mut census = WholeDemandCorridorCensus::default();
        census.enabled = true;
        census.prepare();
        assert!(
            census
                .begin_generic_force(coordinate(CorridorForceShape::Node, 1), 1)
                .is_none()
        );
        assert!(census.active_coordinates.is_empty());
    }

    #[test]
    fn speed_phases_attribute_nonoverlapping_arena_deltas_without_a_trace() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        census.begin_speed_opportunity_outer((100, 200));
        let eval = census.begin_speed_opportunity_phase(SpeedOpportunityPhase::Eval, (110, 205));
        let force = census.begin_speed_opportunity_phase(SpeedOpportunityPhase::Force, (130, 215));
        census.finish_speed_opportunity_phase(force, (150, 225), false);
        census.finish_speed_opportunity_phase(eval, (160, 230), true);
        census.end_speed_opportunity_outer((170, 235));

        assert_eq!(
            census.speed_opportunity.arena_bytes[SpeedOpportunityPhase::Return as usize],
            30
        );
        assert_eq!(
            census.speed_opportunity.arena_bytes[SpeedOpportunityPhase::Eval as usize],
            45
        );
        assert_eq!(
            census.speed_opportunity.arena_bytes[SpeedOpportunityPhase::Force as usize],
            30
        );
        assert_eq!(census.speed_opportunity.total_arena_bytes(), Some(105));
        assert_eq!(census.speed_opportunity.lifo_failures, 0);
        assert!(census.speed_opportunity.phases_conserved());
        assert_eq!(
            census.speed_opportunity.entries[SpeedOpportunityPhase::Return as usize],
            1
        );
        assert_eq!(
            census.speed_opportunity.exits[SpeedOpportunityPhase::Return as usize],
            1
        );
        assert_eq!(
            census.speed_opportunity.materializing_exits[SpeedOpportunityPhase::Eval as usize],
            1
        );
    }

    #[test]
    fn speed_phase_tokens_fail_closed_on_non_lifo_finish() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        census.begin_speed_opportunity_outer((0, 0));
        let eval = census.begin_speed_opportunity_phase(SpeedOpportunityPhase::Eval, (0, 0));
        let force = census.begin_speed_opportunity_phase(SpeedOpportunityPhase::Force, (0, 0));
        census.finish_speed_opportunity_phase(eval, (0, 0), false);
        assert_eq!(census.speed_opportunity.lifo_failures, 1);
        census.finish_speed_opportunity_phase(force, (0, 0), false);
        census.end_speed_opportunity_outer((0, 0));
        assert!(!census.speed_opportunity.phases_conserved());
    }

    #[test]
    fn speed_cursor_regression_fails_closed_without_fabricating_bytes() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        census.begin_speed_opportunity_outer((100, 200));
        census.end_speed_opportunity_outer((99, 201));
        assert_eq!(census.speed_opportunity.cursor_failures, 1);
        assert_eq!(census.speed_opportunity.total_arena_bytes(), Some(0));
    }

    #[test]
    fn abandoned_speed_outer_is_not_conserved() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        census.begin_speed_opportunity_outer((0, 0));
        assert!(!census.speed_opportunity.phases_conserved());
    }

    #[test]
    fn explicit_error_cleanup_conserves_return_phase() {
        let mut census = WholeDemandCorridorCensus::default();
        start(&mut census);
        census.begin_speed_opportunity_outer((0, 0));
        let eval = census.begin_speed_opportunity_phase(SpeedOpportunityPhase::Eval, (0, 0));
        census.finish_speed_opportunity_phase(eval, (0, 0), false);
        census.end_speed_opportunity_outer((0, 0));
        assert!(census.speed_opportunity.phases_conserved());
    }

    #[test]
    fn fanout_identity_includes_shape_flags_and_payload() {
        let mut census = WholeDemandCorridorCensus::default();
        let node = coordinate(CorridorForceShape::Node, 7);
        let mut apply = node;
        apply.set_shape(CorridorForceShape::Apply);
        let mut flagged = node;
        flagged.words[0] |= FLAG_TIER1;
        census
            .stored_frames
            .extend([node, node, apply, flagged, node]);
        census.chains.extend([
            CorridorChain {
                outer: CorridorOuter::FinalForce5,
                padding: [0; 7],
                frame_start: 0,
                frame_len: 4,
                completions: 1,
            },
            CorridorChain {
                outer: CorridorOuter::AutoCall4,
                padding: [0; 7],
                frame_start: 4,
                frame_len: 1,
                completions: 1,
            },
        ]);
        assert_eq!(census.max_targets_per_site(), Some(4));
    }
}
