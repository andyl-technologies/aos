//! Validated plans for fused lazy-demand native control flow.
//!
//! A [`MixedModulePlan`] is the safe, runtime-independent contract between
//! semantic analysis and a future native fused runner. It represents force,
//! guarded application, thunk update, return, and explicit materialization as
//! control-flow edges rather than as an interpreted opcode stream.
//!
//! Plans use compact table indexes and immutable side tables:
//!
//! ```text
//! entry -> function -> block -> operations -> terminator
//!                                  |
//!                                  +-> guarded call targets
//!                                  +-> materializing statepoint
//! ```
//!
//! Construction validates every index, live set, local control-flow edge,
//! bounded resource declaration, typed SSA use, direct-call mapping, and
//! force/update ownership path before returning a plan. Version 3 deliberately
//! rejects local CFG cycles and virtual materialization without a recipe.
//! Statepoints beneath pending force ownership are admitted only when they
//! abort the complete update stack and restart an outer entry. The canonical
//! byte encoding is suitable for deterministic hashing and cache identity; it
//! is not an executable or independently versioned persistence format.

use std::collections::{HashSet, VecDeque};

use thiserror::Error;

use crate::syntax::Span;
use crate::{FrameId, IrId};

mod execution;
mod oracle_lower;

pub use execution::{
    MixedCallable, MixedExecutablePlan, MixedExecutionAdmissionError, MixedExecutionError,
    MixedExecutionOutcome, MixedExecutionRunner, MixedExecutionSideExit,
    MixedExecutionSideExitCause, MixedExecutionStats, MixedExecutionStorage, MixedForceAction,
    MixedMachineRuntime,
};
pub use oracle_lower::{
    MixedOracleCallTargetBlock, MixedOracleNodeBlock, MixedOracleNodeDecline,
    MixedOracleNodeLowerError, MixedOracleNodeLowerOutcome, MixedOraclePlanDecline,
    MixedOraclePlanLowerError, MixedOraclePlanLowerOutcome, lower_mixed_oracle_apply_force_plan,
    lower_mixed_oracle_node, lower_mixed_oracle_ready_call_plan,
};

/// Encoding and semantic-layout version of mixed-machine plans.
pub const MIXED_PLAN_FORMAT_VERSION: u32 = 3;
/// Largest guarded target population admitted at one application.
pub const MIXED_CALL_TARGET_CAP: u32 = 4;
/// Hard ceiling for value slots declared by one plan.
pub const MIXED_VALUE_SLOT_CAP: u32 = 4096;
/// Hard ceiling for simultaneously owned thunk updates.
pub const MIXED_UPDATE_DEPTH_CAP: u32 = 512;
/// Hard ceiling for virtual lexical frames retained by one activation.
pub const MIXED_VIRTUAL_FRAME_CAP: u32 = 512;

/// Stable identity of one independently cacheable mixed-machine plan.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MixedModuleKey {
    format_version: u32,
    module_digest: [u8; 32],
    semantic_digest: [u8; 32],
    capture_layout_version: u32,
}

impl MixedModuleKey {
    /// Creates a key from exact module, semantic-certificate, and capture ABI identities.
    pub const fn new(
        module_digest: [u8; 32],
        semantic_digest: [u8; 32],
        capture_layout_version: u32,
    ) -> Self {
        Self {
            format_version: MIXED_PLAN_FORMAT_VERSION,
            module_digest,
            semantic_digest,
            capture_layout_version,
        }
    }

    /// Returns the mixed-plan format version.
    pub const fn format_version(self) -> u32 {
        self.format_version
    }

    /// Returns the exact digest of the lowered module and resolver metadata.
    pub const fn module_digest(self) -> [u8; 32] {
        self.module_digest
    }

    /// Returns the exact binder-aware semantic-certificate digest.
    pub const fn semantic_digest(self) -> [u8; 32] {
        self.semantic_digest
    }

    /// Returns the capture-layout ABI version expected by the plan.
    pub const fn capture_layout_version(self) -> u32 {
        self.capture_layout_version
    }
}

macro_rules! compact_id {
    ($name:ident, $summary:literal) => {
        #[doc = $summary]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u32);

        impl $name {
            /// Creates an id from its zero-based table index.
            pub const fn new(raw: u32) -> Self {
                Self(raw)
            }

            /// Returns the zero-based table index.
            pub const fn as_u32(self) -> u32 {
                self.0
            }
        }
    };
}

compact_id!(
    MixedFunctionId,
    "Identifies one frame-specialized function in a mixed plan."
);
compact_id!(MixedBlockId, "Identifies one basic block in a mixed plan.");
compact_id!(
    MixedValueId,
    "Identifies one activation value slot in a mixed plan."
);
compact_id!(
    MixedStatepointId,
    "Identifies one materializing oracle boundary in a mixed plan."
);

impl MixedFunctionId {
    fn index(self) -> usize {
        self.0 as usize
    }
}

impl MixedBlockId {
    fn index(self) -> usize {
        self.0 as usize
    }
}

impl MixedStatepointId {
    fn index(self) -> usize {
        self.0 as usize
    }
}

/// A contiguous range in an immutable plan side table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixedTableRange {
    start: u32,
    len: u32,
}

impl MixedTableRange {
    /// Creates a range from its zero-based start and element count.
    pub const fn new(start: u32, len: u32) -> Self {
        Self { start, len }
    }

    /// Returns the first table index in the range.
    pub const fn start(self) -> u32 {
        self.start
    }

    /// Returns the number of table entries in the range.
    pub const fn len(self) -> u32 {
        self.len
    }

    /// Returns whether the range contains no entries.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    fn checked_end(self) -> Option<u32> {
        self.start.checked_add(self.len)
    }

    fn indices(self) -> Option<std::ops::Range<usize>> {
        let end = self.checked_end()?;
        Some(self.start as usize..end as usize)
    }

    fn contains(self, value: u32) -> bool {
        self.checked_end()
            .is_some_and(|end| value >= self.start && value < end)
    }
}

/// Resource bounds reserved before one mixed-machine activation begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixedPlanBounds {
    /// Maximum number of rooted runtime value slots.
    pub value_slots: u32,
    /// Maximum number of simultaneously owned thunk updates.
    pub update_depth: u32,
    /// Maximum number of virtual lexical frames.
    pub virtual_frames: u32,
}

impl MixedPlanBounds {
    /// Creates explicit activation bounds.
    pub const fn new(value_slots: u32, update_depth: u32, virtual_frames: u32) -> Self {
        Self {
            value_slots,
            update_depth,
            virtual_frames,
        }
    }
}

/// Exact source coordinate retained for diagnostics and statepoint resumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixedSource {
    /// Digest of the independently lowered module containing the source node.
    pub module_digest: [u8; 32],
    /// Original IR node id inside the module.
    pub ir: IrId,
    /// Original source span.
    pub span: Span,
}

impl MixedSource {
    /// Creates an exact source coordinate.
    pub const fn new(module_digest: [u8; 32], ir: IrId, span: Span) -> Self {
        Self {
            module_digest,
            ir,
            span,
        }
    }
}

/// Exact guarded identity of one callable code target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MixedCodeIdentity {
    /// Digest of the target's independently lowered module.
    pub module_digest: [u8; 32],
    /// Lambda definition node.
    pub definition: IrId,
    /// Lambda body node.
    pub body: IrId,
    /// Resolver frame attached to the definition.
    pub frame: Option<FrameId>,
    /// Digest of the exact versioned capture layout.
    pub capture_layout_digest: [u8; 32],
}

impl MixedCodeIdentity {
    /// Creates an exact code and capture-layout identity.
    pub const fn new(
        module_digest: [u8; 32],
        definition: IrId,
        body: IrId,
        frame: Option<FrameId>,
        capture_layout_digest: [u8; 32],
    ) -> Self {
        Self {
            module_digest,
            definition,
            body,
            frame,
            capture_layout_digest,
        }
    }
}

/// Exact pre-claim work identities admitted by one force terminator.
///
/// A thunk family is not a semantic identity: two [`MixedForceShape::Node`]
/// thunks can evaluate unrelated source bodies. The runtime must compare the
/// candidate thunk with the identity for its family before claiming it and
/// return [`MixedForceAction::Declined`] on a mismatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixedForceGuards {
    /// Exact ordinary source-node work admitted by the Node successor.
    pub node: MixedCodeIdentity,
    /// Exact synthetic application work admitted by the Apply successor.
    pub apply: MixedCodeIdentity,
    /// Exact `genList` work admitted by the specialized successor.
    pub gen_list: MixedCodeIdentity,
}

impl MixedForceGuards {
    /// Creates exact work guards for all three executable thunk families.
    pub const fn new(
        node: MixedCodeIdentity,
        apply: MixedCodeIdentity,
        gen_list: MixedCodeIdentity,
    ) -> Self {
        Self {
            node,
            apply,
            gen_list,
        }
    }

    /// Returns the identity admitted for `shape`.
    pub const fn for_shape(self, shape: MixedForceShape) -> MixedCodeIdentity {
        match shape {
            MixedForceShape::Node => self.node,
            MixedForceShape::Apply => self.apply,
            MixedForceShape::GenListElemAtAddOne => self.gen_list,
        }
    }
}

/// Outer semantic operation through which a fused plan is entered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixedEntryKind {
    /// Forces an existing runtime value to weak head normal form.
    ForceWhnf,
    /// Applies an eligible formal-set lambda before returning its value.
    AutoCallFormalSet,
}

/// One guarded outer entry into a frame-specialized function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixedEntry {
    /// Semantic operation performed by this entry.
    pub kind: MixedEntryKind,
    /// Exact source coordinate of the entry.
    pub source: MixedSource,
    /// Function receiving control after entry guards pass.
    pub function: MixedFunctionId,
    /// Resolver frame expected at entry.
    pub frame: Option<FrameId>,
    /// Digest of the exact capture layout expected at entry.
    pub capture_layout_digest: [u8; 32],
}

/// One frame-specialized function and its contiguous block population.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixedFunction {
    /// Exact source coordinate represented by the function.
    pub source: MixedSource,
    /// Activation slot receiving the function's sole lazy argument.
    pub parameter: MixedValueId,
    /// Static type required for the function argument.
    pub parameter_type: MixedValueType,
    /// Static type returned by every reachable [`MixedTerminator::Return`].
    pub return_type: MixedValueType,
    /// First block executed when the function is entered.
    pub entry: MixedBlockId,
    /// Contiguous block-table range owned by the function.
    pub blocks: MixedTableRange,
}

/// One basic block and its contiguous pure-operation population.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixedBlock {
    /// Exact source coordinate represented by the block.
    pub source: MixedSource,
    /// Contiguous operation-table range executed by the block.
    pub operations: MixedTableRange,
    /// Control transfer performed after the operations.
    pub terminator: MixedTerminator,
}

/// Static value class carried by one mixed-machine SSA slot.
///
/// [`MixedValueType::Value`] is the top type for an arbitrary encoded runtime
/// value. The remaining variants are refinements used to prove pure operations
/// and direct-call boundaries without consulting the semantic oracle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MixedValueType {
    /// An arbitrary encoded runtime value.
    Value,
    /// An already decoded integer.
    Int,
    /// An already evaluated Boolean.
    Bool,
    /// The null value.
    Null,
    /// An unpublished virtual lazy thunk.
    VirtualThunk,
    /// An unpublished virtual unary closure.
    VirtualClosure,
}

impl MixedValueType {
    fn accepts(self, actual: Self) -> bool {
        self == Self::Value || self == actual
    }
}

/// Pure data-flow operation emitted inside one mixed basic block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixedOp {
    /// Writes an integer literal into an activation slot.
    ConstInt {
        /// Destination value slot.
        destination: MixedValueId,
        /// Literal integer.
        value: i64,
    },
    /// Writes a Boolean literal into an activation slot.
    ConstBool {
        /// Destination value slot.
        destination: MixedValueId,
        /// Literal Boolean.
        value: bool,
    },
    /// Writes the null value into an activation slot.
    ConstNull {
        /// Destination value slot.
        destination: MixedValueId,
    },
    /// Copies one activation value slot into another.
    Move {
        /// Destination value slot.
        destination: MixedValueId,
        /// Source value slot.
        source: MixedValueId,
    },
    /// Loads a slot from the current virtual lexical frame.
    LoadLocal {
        /// Destination value slot.
        destination: MixedValueId,
        /// Zero-based lexical slot.
        slot: u32,
    },
    /// Loads a slot from an enclosing virtual or materialized frame.
    LoadUpvalue {
        /// Destination value slot.
        destination: MixedValueId,
        /// Number of parent frames to walk.
        depth: u32,
        /// Zero-based lexical slot.
        slot: u32,
    },
    /// Retains a virtual lazy thunk until escape or force.
    VirtualThunk {
        /// Destination value slot naming the virtual object.
        destination: MixedValueId,
        /// Function that evaluates the thunk body.
        body: MixedFunctionId,
    },
    /// Retains a virtual simple lambda closure until escape.
    VirtualClosure {
        /// Destination value slot naming the virtual object.
        destination: MixedValueId,
        /// Function entered after a guarded application.
        body: MixedFunctionId,
    },
    /// Adds two already-decoded integer operands.
    AddInt {
        /// Destination value slot.
        destination: MixedValueId,
        /// Left operand slot.
        left: MixedValueId,
        /// Right operand slot.
        right: MixedValueId,
    },
    /// Compares two already-decoded integer operands.
    LessThanInt {
        /// Destination Boolean slot.
        destination: MixedValueId,
        /// Left operand slot.
        left: MixedValueId,
        /// Right operand slot.
        right: MixedValueId,
    },
}

/// Runtime thunk-body family selected by a fused force edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixedForceShape {
    /// An ordinary source-node thunk.
    Node,
    /// A synthetic one-argument application thunk.
    Apply,
    /// The exact `genList` element-at/add-one synthetic thunk.
    GenListElemAtAddOne,
}

/// One direct guarded application destination.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MixedCallTarget {
    /// Exact closure code identity checked by the runtime guard.
    pub code: MixedCodeIdentity,
    /// Plan-local function entered when the guard succeeds.
    pub function: MixedFunctionId,
    /// Callee activation slot receiving the caller's lazy argument.
    pub argument_destination: MixedValueId,
}

/// Control transfer at the end of a mixed basic block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MixedTerminator {
    /// Transfers control unconditionally within the current function.
    Jump {
        /// Destination block.
        target: MixedBlockId,
    },
    /// Branches on an already-evaluated Boolean value.
    Branch {
        /// Condition value slot.
        condition: MixedValueId,
        /// Block entered for true.
        when_true: MixedBlockId,
        /// Block entered for false.
        when_false: MixedBlockId,
    },
    /// Forces a value and branches by its dynamic thunk family.
    Force {
        /// Value slot containing the force subject.
        subject: MixedValueId,
        /// Value slot receiving the forced result on every successful edge.
        result: MixedValueId,
        /// Static type established for the forced result.
        result_type: MixedValueType,
        /// Exact work identities checked before a runtime claim.
        guards: MixedForceGuards,
        /// Block entered when the value is already in weak head normal form.
        ready: MixedBlockId,
        /// Block entered after claiming a Node thunk.
        node: MixedBlockId,
        /// Block entered after claiming an Apply thunk.
        apply: MixedBlockId,
        /// Block entered after claiming an exact `genList` marker thunk.
        gen_list: MixedBlockId,
        /// Materializing boundary for every other force protocol.
        fallback: MixedStatepointId,
    },
    /// Applies a callable through a bounded exact target population.
    ApplyGuarded {
        /// Callable value slot.
        function: MixedValueId,
        /// Lazy argument value slot.
        argument: MixedValueId,
        /// Value slot receiving the call result.
        result: MixedValueId,
        /// Contiguous guarded-target side-table range.
        targets: MixedTableRange,
        /// Block resumed after a direct target returns.
        continuation: MixedBlockId,
        /// Materializing boundary used when no target guard matches.
        fallback: MixedStatepointId,
    },
    /// Publishes the top pending thunk update and continues.
    Update {
        /// Value slot containing the result to publish.
        value: MixedValueId,
        /// Result slot promised by the matching outstanding force.
        result: MixedValueId,
        /// Block entered after publication.
        next: MixedBlockId,
    },
    /// Returns one value to the current mixed caller or outer entry.
    Return {
        /// Returned value slot.
        value: MixedValueId,
    },
    /// Materializes all live virtual state before invoking one oracle operation.
    Materialize {
        /// Statepoint describing source, roots, and resumption.
        statepoint: MixedStatepointId,
    },
}

/// Reason a fused region must materialize and invoke the semantic oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixedStatepointReason {
    /// A valid IR form is outside the admitted fused grammar.
    Unsupported,
    /// A non-speculable effect must execute through the semantic oracle.
    Effect,
    /// Dynamic lexical scope prevents static environment resolution.
    DynamicScope,
    /// A callable did not match any bounded exact target.
    UnknownCall,
    /// A force subject uses an unsupported storage or thunk-body protocol.
    UnsupportedForce,
}

/// Continuation policy for one guarded oracle boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixedStatepointMode {
    /// The oracle supplies `result` and execution resumes at `resume`.
    Resume,
    /// Every owned force is aborted and the adapter restarts an outer entry.
    ///
    /// This mode is the fail-closed escape from a speculative guard nested
    /// beneath one or more claimed thunks. It never resumes the partially
    /// executed activation.
    RestartEntry {
        /// Entry-table index re-entered through the semantic oracle.
        entry: u32,
    },
}

/// Complete live-state contract for one materializing oracle boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixedStatepoint {
    /// Exact source coordinate delegated to the semantic oracle.
    pub source: MixedSource,
    /// Block resumed after the oracle returns a value.
    pub resume: MixedBlockId,
    /// Sorted unique activation slots that must be rooted.
    pub live_values: Box<[MixedValueId]>,
    /// Sorted unique subset of `live_values` that must first be materialized.
    pub live_virtuals: Box<[MixedValueId]>,
    /// Activation slot receiving the oracle result before `resume`.
    ///
    /// `None` is valid for a terminal materialization or
    /// [`MixedStatepointMode::RestartEntry`].
    pub result: Option<MixedValueId>,
    /// Static type of `result`, present exactly when `result` is present.
    pub result_type: Option<MixedValueType>,
    /// Whether the boundary resumes locally or rolls back to an outer entry.
    pub mode: MixedStatepointMode,
    /// Semantic reason for leaving the fused region.
    pub reason: MixedStatepointReason,
}

/// A completely validated immutable fused-demand plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixedModulePlan {
    key: MixedModuleKey,
    bounds: MixedPlanBounds,
    entries: Box<[MixedEntry]>,
    functions: Box<[MixedFunction]>,
    blocks: Box<[MixedBlock]>,
    operations: Box<[MixedOp]>,
    call_targets: Box<[MixedCallTarget]>,
    statepoints: Box<[MixedStatepoint]>,
}

impl MixedModulePlan {
    /// Validates and constructs one immutable mixed-machine plan.
    ///
    /// # Errors
    ///
    /// Returns [`MixedPlanError`] when resource declarations exceed their hard
    /// caps, a side-table reference is invalid, function/block operation
    /// ranges do not form deterministic partitions, a guarded call exceeds
    /// four targets, a statepoint live set is invalid, any block is
    /// unreachable, SSA definitions do not dominate typed uses, call mappings
    /// disagree, or force/update ownership is not balanced on every path.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: MixedModuleKey,
        bounds: MixedPlanBounds,
        entries: Vec<MixedEntry>,
        functions: Vec<MixedFunction>,
        blocks: Vec<MixedBlock>,
        operations: Vec<MixedOp>,
        call_targets: Vec<MixedCallTarget>,
        statepoints: Vec<MixedStatepoint>,
    ) -> Result<Self, MixedPlanError> {
        let plan = Self {
            key,
            bounds,
            entries: entries.into_boxed_slice(),
            functions: functions.into_boxed_slice(),
            blocks: blocks.into_boxed_slice(),
            operations: operations.into_boxed_slice(),
            call_targets: call_targets.into_boxed_slice(),
            statepoints: statepoints.into_boxed_slice(),
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Returns the exact cache identity of the plan.
    pub const fn key(&self) -> MixedModuleKey {
        self.key
    }

    /// Returns the activation resource bounds.
    pub const fn bounds(&self) -> MixedPlanBounds {
        self.bounds
    }

    /// Returns guarded outer entries.
    pub fn entries(&self) -> &[MixedEntry] {
        &self.entries
    }

    /// Returns frame-specialized functions.
    pub fn functions(&self) -> &[MixedFunction] {
        &self.functions
    }

    /// Returns basic blocks.
    pub fn blocks(&self) -> &[MixedBlock] {
        &self.blocks
    }

    /// Returns pure data-flow operations.
    pub fn operations(&self) -> &[MixedOp] {
        &self.operations
    }

    /// Returns exact guarded application targets.
    pub fn call_targets(&self) -> &[MixedCallTarget] {
        &self.call_targets
    }

    /// Returns materializing oracle boundaries.
    pub fn statepoints(&self) -> &[MixedStatepoint] {
        &self.statepoints
    }

    /// Encodes the complete validated plan into deterministic little-endian bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RMIX");
        append_u32(&mut bytes, self.key.format_version);
        bytes.extend_from_slice(&self.key.module_digest);
        bytes.extend_from_slice(&self.key.semantic_digest);
        append_u32(&mut bytes, self.key.capture_layout_version);
        append_u32(&mut bytes, self.bounds.value_slots);
        append_u32(&mut bytes, self.bounds.update_depth);
        append_u32(&mut bytes, self.bounds.virtual_frames);
        append_len(&mut bytes, self.entries.len());
        append_len(&mut bytes, self.functions.len());
        append_len(&mut bytes, self.blocks.len());
        append_len(&mut bytes, self.operations.len());
        append_len(&mut bytes, self.call_targets.len());
        append_len(&mut bytes, self.statepoints.len());

        for entry in &self.entries {
            bytes.push(match entry.kind {
                MixedEntryKind::ForceWhnf => 1,
                MixedEntryKind::AutoCallFormalSet => 2,
            });
            append_source(&mut bytes, entry.source);
            append_u32(&mut bytes, entry.function.as_u32());
            append_frame(&mut bytes, entry.frame);
            bytes.extend_from_slice(&entry.capture_layout_digest);
        }
        for function in &self.functions {
            append_source(&mut bytes, function.source);
            append_u32(&mut bytes, function.parameter.as_u32());
            append_value_type(&mut bytes, function.parameter_type);
            append_value_type(&mut bytes, function.return_type);
            append_u32(&mut bytes, function.entry.as_u32());
            append_range(&mut bytes, function.blocks);
        }
        for block in &self.blocks {
            append_source(&mut bytes, block.source);
            append_range(&mut bytes, block.operations);
            append_terminator(&mut bytes, &block.terminator);
        }
        for operation in &self.operations {
            append_operation(&mut bytes, *operation);
        }
        for target in &self.call_targets {
            append_code_identity(&mut bytes, target.code);
            append_u32(&mut bytes, target.function.as_u32());
            append_u32(&mut bytes, target.argument_destination.as_u32());
        }
        for statepoint in &self.statepoints {
            append_source(&mut bytes, statepoint.source);
            append_u32(&mut bytes, statepoint.resume.as_u32());
            append_len(&mut bytes, statepoint.live_values.len());
            for value in &statepoint.live_values {
                append_u32(&mut bytes, value.as_u32());
            }
            append_len(&mut bytes, statepoint.live_virtuals.len());
            for value in &statepoint.live_virtuals {
                append_u32(&mut bytes, value.as_u32());
            }
            append_optional_value(&mut bytes, statepoint.result);
            append_optional_value_type(&mut bytes, statepoint.result_type);
            match statepoint.mode {
                MixedStatepointMode::Resume => {
                    bytes.push(1);
                    append_u32(&mut bytes, 0);
                }
                MixedStatepointMode::RestartEntry { entry } => {
                    bytes.push(2);
                    append_u32(&mut bytes, entry);
                }
            }
            bytes.push(match statepoint.reason {
                MixedStatepointReason::Unsupported => 1,
                MixedStatepointReason::Effect => 2,
                MixedStatepointReason::DynamicScope => 3,
                MixedStatepointReason::UnknownCall => 4,
                MixedStatepointReason::UnsupportedForce => 5,
            });
        }
        bytes
    }

    fn validate(&self) -> Result<(), MixedPlanError> {
        validate_bounds(self.bounds)?;
        if self.entries.is_empty() {
            return Err(MixedPlanError::EmptyEntries);
        }
        if self.functions.is_empty() {
            return Err(MixedPlanError::EmptyFunctions);
        }
        if self.blocks.is_empty() {
            return Err(MixedPlanError::EmptyBlocks);
        }
        validate_u32_len("entries", self.entries.len())?;
        validate_u32_len("functions", self.functions.len())?;
        validate_u32_len("blocks", self.blocks.len())?;
        validate_u32_len("operations", self.operations.len())?;
        validate_u32_len("call_targets", self.call_targets.len())?;
        validate_u32_len("statepoints", self.statepoints.len())?;

        for (index, entry) in self.entries.iter().enumerate() {
            let function = self.function(entry.function, MixedReference::EntryFunction(index))?;
            if function.parameter_type != MixedValueType::Value {
                return Err(MixedPlanError::EntryParameterType {
                    entry: index,
                    function: entry.function,
                    actual: function.parameter_type,
                });
            }
        }
        validate_function_partition(&self.functions, self.blocks.len())?;
        validate_operation_partition(&self.blocks, self.operations.len())?;

        let owners = block_owners(&self.functions, self.blocks.len())?;
        for (function_index, function) in self.functions.iter().enumerate() {
            validate_value(function.parameter, self.bounds, function_index)?;
            if !function.blocks.contains(function.entry.as_u32()) {
                return Err(MixedPlanError::FunctionEntryOutsideBlocks {
                    function: function_index,
                    entry: function.entry,
                });
            }
        }
        for (block_index, block) in self.blocks.iter().enumerate() {
            let owner = owners[block_index];
            for operation_index in
                block
                    .operations
                    .indices()
                    .ok_or(MixedPlanError::RangeOverflow {
                        table: "operations",
                        owner: block_index,
                    })?
            {
                self.validate_operation(operation_index, self.operations[operation_index])?;
            }
            self.validate_terminator(block_index, owner, &block.terminator, &owners)?;
        }
        for (index, statepoint) in self.statepoints.iter().enumerate() {
            self.block(statepoint.resume, MixedReference::StatepointResume(index))?;
            if let MixedStatepointMode::RestartEntry { entry } = statepoint.mode
                && entry as usize >= self.entries.len()
            {
                return Err(MixedPlanError::RangeOutOfBounds {
                    table: "restart_entries",
                    owner: index,
                    len: self.entries.len(),
                });
            }
            validate_live_set(index, "live_values", &statepoint.live_values, self.bounds)?;
            validate_live_set(
                index,
                "live_virtuals",
                &statepoint.live_virtuals,
                self.bounds,
            )?;
            if !statepoint
                .live_virtuals
                .iter()
                .all(|value| statepoint.live_values.binary_search(value).is_ok())
            {
                return Err(MixedPlanError::VirtualLiveSetNotSubset { statepoint: index });
            }
            if !statepoint.live_virtuals.is_empty() {
                return Err(MixedPlanError::UnrepresentableMaterialization { statepoint: index });
            }
            match (statepoint.result, statepoint.result_type) {
                (Some(result), Some(_)) => validate_value(result, self.bounds, index)?,
                (None, None) => {}
                _ => return Err(MixedPlanError::IncompleteStatepointResult { statepoint: index }),
            }
            if matches!(statepoint.mode, MixedStatepointMode::RestartEntry { .. })
                && statepoint.result.is_some()
            {
                return Err(MixedPlanError::RestartStatepointHasResult { statepoint: index });
            }
        }
        self.validate_reachability(&owners)?;
        self.validate_executable_contract(&owners)?;
        self.validate_statepoint_live_set_completeness(&owners)
    }

    /// Proves that every locally resumed continuation can reconstruct its
    /// pre-existing SSA inputs from the statepoint's declared root set.
    fn validate_statepoint_live_set_completeness(
        &self,
        owners: &[usize],
    ) -> Result<(), MixedPlanError> {
        let mut live_in_by_function = Vec::with_capacity(self.functions.len());
        for function_index in 0..self.functions.len() {
            live_in_by_function.push(compute_function_live_in(self, function_index));
        }
        for (statepoint_index, statepoint) in self.statepoints.iter().enumerate() {
            if !matches!(statepoint.mode, MixedStatepointMode::Resume) {
                continue;
            }
            let resume_index = statepoint.resume.index();
            let function_index = owners[resume_index];
            let function = self.functions[function_index];
            let block_offset = resume_index - function.blocks.start() as usize;
            let live_in = &live_in_by_function[function_index][block_offset];
            for (slot, required) in live_in.iter().copied().enumerate() {
                if !required {
                    continue;
                }
                let value = MixedValueId::new(slot as u32);
                if statepoint.result == Some(value) {
                    continue;
                }
                if statepoint.live_values.binary_search(&value).is_err() {
                    return Err(MixedPlanError::IncompleteStatepointLiveSet {
                        statepoint: statepoint_index,
                        resume: statepoint.resume,
                        missing: value,
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_operation(&self, index: usize, operation: MixedOp) -> Result<(), MixedPlanError> {
        let check_value = |value| validate_value(value, self.bounds, index);
        match operation {
            MixedOp::ConstInt { destination, .. }
            | MixedOp::ConstBool { destination, .. }
            | MixedOp::ConstNull { destination }
            | MixedOp::LoadLocal { destination, .. }
            | MixedOp::LoadUpvalue { destination, .. } => check_value(destination),
            MixedOp::Move {
                destination,
                source,
            } => {
                check_value(destination)?;
                check_value(source)
            }
            MixedOp::VirtualThunk { destination, body }
            | MixedOp::VirtualClosure { destination, body } => {
                check_value(destination)?;
                self.function(body, MixedReference::OperationFunction(index))
                    .map(|_| ())
            }
            MixedOp::AddInt {
                destination,
                left,
                right,
            }
            | MixedOp::LessThanInt {
                destination,
                left,
                right,
            } => {
                check_value(destination)?;
                check_value(left)?;
                check_value(right)
            }
        }
    }

    fn validate_terminator(
        &self,
        block_index: usize,
        owner: usize,
        terminator: &MixedTerminator,
        owners: &[usize],
    ) -> Result<(), MixedPlanError> {
        let check_value = |value| validate_value(value, self.bounds, block_index);
        let local_block = |block| self.validate_local_block(block_index, owner, block, owners);
        match terminator {
            MixedTerminator::Jump { target } => local_block(*target),
            MixedTerminator::Branch {
                condition,
                when_true,
                when_false,
            } => {
                check_value(*condition)?;
                local_block(*when_true)?;
                local_block(*when_false)
            }
            MixedTerminator::Force {
                subject,
                result,
                result_type: _,
                guards: _,
                ready,
                node,
                apply,
                gen_list,
                fallback,
            } => {
                check_value(*subject)?;
                check_value(*result)?;
                local_block(*ready)?;
                local_block(*node)?;
                local_block(*apply)?;
                local_block(*gen_list)?;
                self.validate_local_statepoint(block_index, owner, *fallback, owners)
            }
            MixedTerminator::ApplyGuarded {
                function,
                argument,
                result,
                targets,
                continuation,
                fallback,
            } => {
                check_value(*function)?;
                check_value(*argument)?;
                check_value(*result)?;
                local_block(*continuation)?;
                self.validate_local_statepoint(block_index, owner, *fallback, owners)?;
                if targets.is_empty() || targets.len() > MIXED_CALL_TARGET_CAP {
                    return Err(MixedPlanError::CallTargetFanout {
                        block: block_index,
                        targets: targets.len(),
                        cap: MIXED_CALL_TARGET_CAP,
                    });
                }
                let range = validate_range(
                    "call_targets",
                    block_index,
                    *targets,
                    self.call_targets.len(),
                )?;
                let mut identities = HashSet::new();
                for target_index in range {
                    let target = self.call_targets[target_index];
                    let function = self.function(
                        target.function,
                        MixedReference::CallTargetFunction(target_index),
                    )?;
                    if target.argument_destination != function.parameter {
                        return Err(MixedPlanError::CallArgumentDestination {
                            target: target_index,
                            actual: target.argument_destination,
                            expected: function.parameter,
                        });
                    }
                    if !identities.insert(target.code) {
                        return Err(MixedPlanError::DuplicateCallTargetIdentity {
                            block: block_index,
                            target: target_index,
                        });
                    }
                }
                Ok(())
            }
            MixedTerminator::Update {
                value,
                result,
                next,
            } => {
                check_value(*value)?;
                check_value(*result)?;
                local_block(*next)
            }
            MixedTerminator::Return { value } => check_value(*value),
            MixedTerminator::Materialize { statepoint } => {
                self.validate_local_statepoint(block_index, owner, *statepoint, owners)
            }
        }
    }

    fn validate_local_block(
        &self,
        from: usize,
        owner: usize,
        target: MixedBlockId,
        owners: &[usize],
    ) -> Result<(), MixedPlanError> {
        self.block(target, MixedReference::BlockTarget(from))?;
        let target_owner = owners[target.index()];
        if target_owner == owner {
            Ok(())
        } else {
            Err(MixedPlanError::CrossFunctionBlockEdge {
                from,
                target,
                owner,
                target_owner,
            })
        }
    }

    fn validate_local_statepoint(
        &self,
        from: usize,
        owner: usize,
        statepoint: MixedStatepointId,
        owners: &[usize],
    ) -> Result<(), MixedPlanError> {
        let statepoint = self.statepoint(statepoint, MixedReference::BlockStatepoint(from))?;
        self.validate_local_block(from, owner, statepoint.resume, owners)
    }

    fn validate_reachability(&self, owners: &[usize]) -> Result<(), MixedPlanError> {
        let mut reached_blocks = vec![false; self.blocks.len()];
        let mut reached_functions = vec![false; self.functions.len()];
        let mut queue = VecDeque::new();
        for entry in &self.entries {
            reached_functions[entry.function.index()] = true;
            queue.push_back(self.functions[entry.function.index()].entry);
        }
        while let Some(block_id) = queue.pop_front() {
            if reached_blocks[block_id.index()] {
                continue;
            }
            reached_blocks[block_id.index()] = true;
            let block = &self.blocks[block_id.index()];
            for target in local_successors(&block.terminator) {
                queue.push_back(target);
            }
            for statepoint in terminator_statepoints(&block.terminator) {
                let statepoint = &self.statepoints[statepoint.index()];
                if matches!(statepoint.mode, MixedStatepointMode::Resume) {
                    queue.push_back(statepoint.resume);
                }
            }
            if let MixedTerminator::ApplyGuarded { targets, .. } = &block.terminator {
                let range = validate_range(
                    "call_targets",
                    block_id.index(),
                    *targets,
                    self.call_targets.len(),
                )?;
                for target_index in range {
                    let function = self.call_targets[target_index].function;
                    reached_functions[function.index()] = true;
                    queue.push_back(self.functions[function.index()].entry);
                }
            }
        }
        if let Some(block) = reached_blocks.iter().position(|reached| !reached) {
            return Err(MixedPlanError::UnreachableBlock { block });
        }
        if let Some(function) = reached_functions.iter().position(|reached| !reached) {
            return Err(MixedPlanError::UnreachableFunction { function });
        }
        for (block, owner) in owners.iter().copied().enumerate() {
            if reached_blocks[block] && !reached_functions[owner] {
                return Err(MixedPlanError::UnreachableFunction { function: owner });
            }
        }
        Ok(())
    }

    fn validate_executable_contract(&self, owners: &[usize]) -> Result<(), MixedPlanError> {
        let mut summaries = Vec::with_capacity(self.functions.len());
        for function_index in 0..self.functions.len() {
            summaries.push(self.validate_function_contract(function_index, owners)?);
        }

        let mut requires_zero_base = summaries
            .iter()
            .map(|summary| summary.has_statepoint)
            .collect::<Vec<_>>();
        loop {
            let mut changed = false;
            for (function_index, summary) in summaries.iter().enumerate() {
                for call in &summary.calls {
                    if !requires_zero_base[call.target.index()] {
                        continue;
                    }
                    if call.pending_depth != 0 {
                        return Err(MixedPlanError::StatepointAcrossPendingForce {
                            function: function_index,
                            block: call.block,
                            target: call.target,
                            pending_depth: call.pending_depth,
                        });
                    }
                    if !requires_zero_base[function_index] {
                        requires_zero_base[function_index] = true;
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }

        let mut maximum_entry_depth = vec![None; self.functions.len()];
        let mut queue = VecDeque::new();
        for entry in &self.entries {
            let function = entry.function.index();
            if maximum_entry_depth[function].is_none() {
                maximum_entry_depth[function] = Some(0_usize);
                queue.push_back(function);
            }
        }
        while let Some(function) = queue.pop_front() {
            let Some(base_depth) = maximum_entry_depth[function] else {
                continue;
            };
            let function_depth =
                base_depth.saturating_add(summaries[function].maximum_pending_depth);
            if function_depth > self.bounds.update_depth as usize {
                return Err(MixedPlanError::InterproceduralFunctionUpdateDepth {
                    function,
                    depth: function_depth,
                    bound: self.bounds.update_depth,
                });
            }
            for call in &summaries[function].calls {
                let depth = base_depth.saturating_add(call.pending_depth);
                if depth > self.bounds.update_depth as usize {
                    return Err(MixedPlanError::InterproceduralUpdateDepth {
                        function,
                        block: call.block,
                        target: call.target,
                        depth,
                        bound: self.bounds.update_depth,
                    });
                }
                let target = call.target.index();
                if maximum_entry_depth[target].is_none_or(|current| depth > current) {
                    maximum_entry_depth[target] = Some(depth);
                    queue.push_back(target);
                }
            }
        }
        Ok(())
    }

    fn validate_function_contract(
        &self,
        function_index: usize,
        owners: &[usize],
    ) -> Result<MixedFunctionSummary, MixedPlanError> {
        let function = self.functions[function_index];
        let block_range = function
            .blocks
            .indices()
            .ok_or(MixedPlanError::RangeOverflow {
                table: "blocks",
                owner: function_index,
            })?;
        let block_start = block_range.start;
        let block_end = block_range.end;
        let slot_count = self.bounds.value_slots as usize;
        let mut definitions = vec![None; slot_count];
        define_slot(
            &mut definitions,
            function_index,
            function.parameter,
            MixedDefinitionSite::Parameter,
        )?;
        let mut force_result_types = vec![None; slot_count];

        for block_index in block_start..block_end {
            let block = &self.blocks[block_index];
            for operation_index in
                block
                    .operations
                    .indices()
                    .ok_or(MixedPlanError::RangeOverflow {
                        table: "operations",
                        owner: block_index,
                    })?
            {
                let destination = operation_destination(self.operations[operation_index]);
                define_slot(
                    &mut definitions,
                    function_index,
                    destination,
                    MixedDefinitionSite::Operation(operation_index),
                )?;
            }
            match &block.terminator {
                MixedTerminator::Force {
                    result,
                    result_type,
                    ..
                } => {
                    define_slot(
                        &mut definitions,
                        function_index,
                        *result,
                        MixedDefinitionSite::Terminator(block_index),
                    )?;
                    force_result_types[result.as_u32() as usize] = Some(*result_type);
                }
                MixedTerminator::ApplyGuarded { result, .. } => {
                    define_slot(
                        &mut definitions,
                        function_index,
                        *result,
                        MixedDefinitionSite::Terminator(block_index),
                    )?;
                }
                MixedTerminator::Materialize { statepoint } => {
                    if let Some(result) = self.statepoints[statepoint.index()].result {
                        define_slot(
                            &mut definitions,
                            function_index,
                            result,
                            MixedDefinitionSite::Statepoint(statepoint.index()),
                        )?;
                    }
                }
                MixedTerminator::Jump { .. }
                | MixedTerminator::Branch { .. }
                | MixedTerminator::Update { .. }
                | MixedTerminator::Return { .. } => {}
            }
        }

        let mut indegree = vec![0_usize; block_end - block_start];
        for block_index in block_start..block_end {
            for successor in executable_successors(&self.blocks[block_index].terminator, self) {
                let successor_index = successor.index();
                if owners[successor_index] == function_index {
                    indegree[successor_index - block_start] =
                        indegree[successor_index - block_start].saturating_add(1);
                }
            }
        }
        let mut queue = VecDeque::new();
        for (offset, degree) in indegree.iter().copied().enumerate() {
            if degree == 0 {
                queue.push_back(block_start + offset);
            }
        }
        let mut incoming = vec![None; block_end - block_start];
        incoming[function.entry.index() - block_start] = Some(MixedFlowState::new(
            slot_count,
            function.parameter,
            function.parameter_type,
        ));
        let mut processed = 0_usize;
        let mut summary = MixedFunctionSummary::default();

        while let Some(block_index) = queue.pop_front() {
            processed = processed.saturating_add(1);
            let Some(mut state) = incoming[block_index - block_start].take() else {
                return Err(MixedPlanError::ExecutableUnreachableBlock {
                    function: function_index,
                    block: block_index,
                });
            };
            let block = &self.blocks[block_index];
            for operation_index in
                block
                    .operations
                    .indices()
                    .ok_or(MixedPlanError::RangeOverflow {
                        table: "operations",
                        owner: block_index,
                    })?
            {
                execute_operation(
                    function_index,
                    operation_index,
                    self.operations[operation_index],
                    &mut state,
                )?;
            }

            let edges = self.execute_terminator(
                function_index,
                block_index,
                function,
                &force_result_types,
                state,
                &mut summary,
            )?;
            for (successor, successor_state) in edges {
                let successor_index = successor.index();
                if owners[successor_index] != function_index {
                    continue;
                }
                merge_flow_state(
                    function_index,
                    successor_index,
                    &mut incoming[successor_index - block_start],
                    successor_state,
                )?;
                let degree = &mut indegree[successor_index - block_start];
                *degree = degree.saturating_sub(1);
                if *degree == 0 {
                    queue.push_back(successor_index);
                }
            }
        }

        if processed != block_end - block_start {
            return Err(MixedPlanError::ExecutableControlCycle {
                function: function_index,
            });
        }
        Ok(summary)
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_terminator(
        &self,
        function_index: usize,
        block_index: usize,
        function: MixedFunction,
        force_result_types: &[Option<MixedValueType>],
        state: MixedFlowState,
        summary: &mut MixedFunctionSummary,
    ) -> Result<Vec<(MixedBlockId, MixedFlowState)>, MixedPlanError> {
        let terminator = &self.blocks[block_index].terminator;
        match terminator {
            MixedTerminator::Jump { target } => Ok(vec![(*target, state)]),
            MixedTerminator::Branch {
                condition,
                when_true,
                when_false,
            } => {
                require_type(
                    function_index,
                    block_index,
                    &state,
                    *condition,
                    MixedValueType::Bool,
                )?;
                Ok(vec![(*when_true, state.clone()), (*when_false, state)])
            }
            MixedTerminator::Force {
                subject,
                result,
                result_type,
                guards: _,
                ready,
                node,
                apply,
                gen_list,
                fallback,
            } => {
                let subject_type = require_defined(function_index, block_index, &state, *subject)?;
                if !result_type.accepts(subject_type) {
                    return Err(MixedPlanError::ValueTypeMismatch {
                        function: function_index,
                        owner: block_index,
                        value: *subject,
                        expected: *result_type,
                        actual: subject_type,
                    });
                }
                let mut ready_state = state.clone();
                ready_state.define(*result, *result_type);
                let mut claimed_state = state.clone();
                claimed_state.pending_forces.push(*result);
                summary.maximum_pending_depth = summary
                    .maximum_pending_depth
                    .max(claimed_state.pending_forces.len());
                if claimed_state.pending_forces.len() > self.bounds.update_depth as usize {
                    return Err(MixedPlanError::UpdateDepthExceeded {
                        function: function_index,
                        block: block_index,
                        depth: claimed_state.pending_forces.len(),
                        bound: self.bounds.update_depth,
                    });
                }
                let statepoint = &self.statepoints[fallback.index()];
                if matches!(statepoint.mode, MixedStatepointMode::Resume) {
                    validate_statepoint_result(
                        block_index,
                        *fallback,
                        statepoint,
                        *result,
                        *result_type,
                    )?;
                }
                validate_statepoint_entry(
                    function_index,
                    block_index,
                    *fallback,
                    statepoint,
                    &state,
                )?;
                summary.has_statepoint |= matches!(statepoint.mode, MixedStatepointMode::Resume);
                let mut successors = vec![
                    (*ready, ready_state),
                    (*node, claimed_state.clone()),
                    (*apply, claimed_state.clone()),
                    (*gen_list, claimed_state),
                ];
                if matches!(statepoint.mode, MixedStatepointMode::Resume) {
                    let mut fallback_state = state;
                    fallback_state.define(*result, *result_type);
                    successors.push((statepoint.resume, fallback_state));
                }
                Ok(successors)
            }
            MixedTerminator::ApplyGuarded {
                function: callable,
                argument,
                result,
                targets,
                continuation,
                fallback,
            } => {
                require_type(
                    function_index,
                    block_index,
                    &state,
                    *callable,
                    MixedValueType::Value,
                )?;
                let argument_type =
                    require_defined(function_index, block_index, &state, *argument)?;
                let target_range = targets.indices().ok_or(MixedPlanError::RangeOverflow {
                    table: "call_targets",
                    owner: block_index,
                })?;
                let mut result_type = None;
                for target_index in target_range {
                    let target = self.call_targets[target_index];
                    let callee = self.functions[target.function.index()];
                    if !callee.parameter_type.accepts(argument_type) {
                        return Err(MixedPlanError::CallArgumentType {
                            block: block_index,
                            target: target_index,
                            expected: callee.parameter_type,
                            actual: argument_type,
                        });
                    }
                    if let Some(expected) = result_type {
                        if expected != callee.return_type {
                            return Err(MixedPlanError::CallResultTypeDisagreement {
                                block: block_index,
                                expected,
                                actual: callee.return_type,
                            });
                        }
                    } else {
                        result_type = Some(callee.return_type);
                    }
                    summary.calls.push(MixedCallEffect {
                        block: block_index,
                        target: target.function,
                        pending_depth: state.pending_forces.len(),
                    });
                }
                let Some(result_type) = result_type else {
                    return Err(MixedPlanError::CallResultTypeUnavailable { block: block_index });
                };
                let statepoint = &self.statepoints[fallback.index()];
                if matches!(statepoint.mode, MixedStatepointMode::Resume) {
                    validate_statepoint_result(
                        block_index,
                        *fallback,
                        statepoint,
                        *result,
                        result_type,
                    )?;
                }
                validate_statepoint_entry(
                    function_index,
                    block_index,
                    *fallback,
                    statepoint,
                    &state,
                )?;
                summary.has_statepoint |= matches!(statepoint.mode, MixedStatepointMode::Resume);
                let mut continuation_state = state.clone();
                continuation_state.define(*result, result_type);
                let mut successors = vec![(*continuation, continuation_state)];
                if matches!(statepoint.mode, MixedStatepointMode::Resume) {
                    let mut fallback_state = state;
                    fallback_state.define(*result, result_type);
                    successors.push((statepoint.resume, fallback_state));
                }
                Ok(successors)
            }
            MixedTerminator::Update {
                value,
                result,
                next,
            } => {
                let value_type = require_defined(function_index, block_index, &state, *value)?;
                let mut next_state = state;
                let Some(expected_result) = next_state.pending_forces.pop() else {
                    return Err(MixedPlanError::ForceUpdateUnderflow {
                        function: function_index,
                        block: block_index,
                    });
                };
                if expected_result != *result {
                    return Err(MixedPlanError::ForceUpdateResultMismatch {
                        function: function_index,
                        block: block_index,
                        expected: expected_result,
                        actual: *result,
                    });
                }
                let Some(result_type) = force_result_types[result.as_u32() as usize] else {
                    return Err(MixedPlanError::ForceUpdateUnknownResult {
                        function: function_index,
                        block: block_index,
                        result: *result,
                    });
                };
                if !result_type.accepts(value_type) {
                    return Err(MixedPlanError::ValueTypeMismatch {
                        function: function_index,
                        owner: block_index,
                        value: *value,
                        expected: result_type,
                        actual: value_type,
                    });
                }
                next_state.define(*result, result_type);
                Ok(vec![(*next, next_state)])
            }
            MixedTerminator::Return { value } => {
                let value_type = require_defined(function_index, block_index, &state, *value)?;
                if !function.return_type.accepts(value_type) {
                    return Err(MixedPlanError::ValueTypeMismatch {
                        function: function_index,
                        owner: block_index,
                        value: *value,
                        expected: function.return_type,
                        actual: value_type,
                    });
                }
                if !state.pending_forces.is_empty() {
                    return Err(MixedPlanError::UnpublishedForceAtReturn {
                        function: function_index,
                        block: block_index,
                        pending_depth: state.pending_forces.len(),
                    });
                }
                Ok(Vec::new())
            }
            MixedTerminator::Materialize { statepoint } => {
                let statepoint_data = &self.statepoints[statepoint.index()];
                validate_statepoint_entry(
                    function_index,
                    block_index,
                    *statepoint,
                    statepoint_data,
                    &state,
                )?;
                summary.has_statepoint |=
                    matches!(statepoint_data.mode, MixedStatepointMode::Resume);
                if matches!(
                    statepoint_data.mode,
                    MixedStatepointMode::RestartEntry { .. }
                ) {
                    return Ok(Vec::new());
                }
                let mut resumed = state;
                if let (Some(result), Some(result_type)) =
                    (statepoint_data.result, statepoint_data.result_type)
                {
                    resumed.define(result, result_type);
                }
                Ok(vec![(statepoint_data.resume, resumed)])
            }
        }
    }

    fn function(
        &self,
        id: MixedFunctionId,
        reference: MixedReference,
    ) -> Result<&MixedFunction, MixedPlanError> {
        self.functions
            .get(id.index())
            .ok_or(MixedPlanError::InvalidFunction { id, reference })
    }

    fn block(
        &self,
        id: MixedBlockId,
        reference: MixedReference,
    ) -> Result<&MixedBlock, MixedPlanError> {
        self.blocks
            .get(id.index())
            .ok_or(MixedPlanError::InvalidBlock { id, reference })
    }

    fn statepoint(
        &self,
        id: MixedStatepointId,
        reference: MixedReference,
    ) -> Result<&MixedStatepoint, MixedPlanError> {
        self.statepoints
            .get(id.index())
            .ok_or(MixedPlanError::InvalidStatepoint { id, reference })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MixedFlowState {
    slots: Vec<Option<MixedValueType>>,
    pending_forces: Vec<MixedValueId>,
}

impl MixedFlowState {
    fn new(slot_count: usize, parameter: MixedValueId, parameter_type: MixedValueType) -> Self {
        let mut slots = vec![None; slot_count];
        slots[parameter.as_u32() as usize] = Some(parameter_type);
        Self {
            slots,
            pending_forces: Vec::new(),
        }
    }

    fn define(&mut self, value: MixedValueId, value_type: MixedValueType) {
        self.slots[value.as_u32() as usize] = Some(value_type);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MixedCallEffect {
    block: usize,
    target: MixedFunctionId,
    pending_depth: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct MixedFunctionSummary {
    calls: Vec<MixedCallEffect>,
    has_statepoint: bool,
    maximum_pending_depth: usize,
}

/// Static location that defines one mixed-machine SSA value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixedDefinitionSite {
    /// The function's explicit argument slot.
    Parameter,
    /// A pure operation-table entry.
    Operation(usize),
    /// A value-producing block terminator.
    Terminator(usize),
    /// A direct materializing statepoint result.
    Statepoint(usize),
}

fn define_slot(
    definitions: &mut [Option<MixedDefinitionSite>],
    function: usize,
    value: MixedValueId,
    site: MixedDefinitionSite,
) -> Result<(), MixedPlanError> {
    let slot = value.as_u32() as usize;
    if let Some(previous) = definitions[slot] {
        return Err(MixedPlanError::MultipleValueDefinitions {
            function,
            value,
            first: previous,
            second: site,
        });
    }
    definitions[slot] = Some(site);
    Ok(())
}

fn operation_destination(operation: MixedOp) -> MixedValueId {
    match operation {
        MixedOp::ConstInt { destination, .. }
        | MixedOp::ConstBool { destination, .. }
        | MixedOp::ConstNull { destination }
        | MixedOp::Move { destination, .. }
        | MixedOp::LoadLocal { destination, .. }
        | MixedOp::LoadUpvalue { destination, .. }
        | MixedOp::VirtualThunk { destination, .. }
        | MixedOp::VirtualClosure { destination, .. }
        | MixedOp::AddInt { destination, .. }
        | MixedOp::LessThanInt { destination, .. } => destination,
    }
}

fn execute_operation(
    function: usize,
    operation_index: usize,
    operation: MixedOp,
    state: &mut MixedFlowState,
) -> Result<(), MixedPlanError> {
    let owner = operation_index;
    let (destination, value_type) = match operation {
        MixedOp::ConstInt {
            destination,
            value: _,
        } => (destination, MixedValueType::Int),
        MixedOp::ConstBool {
            destination,
            value: _,
        } => (destination, MixedValueType::Bool),
        MixedOp::ConstNull { destination } => (destination, MixedValueType::Null),
        MixedOp::Move {
            destination,
            source,
        } => (
            destination,
            require_defined(function, owner, state, source)?,
        ),
        MixedOp::LoadLocal {
            destination,
            slot: _,
        }
        | MixedOp::LoadUpvalue {
            destination,
            depth: _,
            slot: _,
        } => (destination, MixedValueType::Value),
        MixedOp::VirtualThunk {
            destination,
            body: _,
        } => (destination, MixedValueType::VirtualThunk),
        MixedOp::VirtualClosure {
            destination,
            body: _,
        } => (destination, MixedValueType::VirtualClosure),
        MixedOp::AddInt {
            destination,
            left,
            right,
        } => {
            require_type(function, owner, state, left, MixedValueType::Int)?;
            require_type(function, owner, state, right, MixedValueType::Int)?;
            (destination, MixedValueType::Int)
        }
        MixedOp::LessThanInt {
            destination,
            left,
            right,
        } => {
            require_type(function, owner, state, left, MixedValueType::Int)?;
            require_type(function, owner, state, right, MixedValueType::Int)?;
            (destination, MixedValueType::Bool)
        }
    };
    state.define(destination, value_type);
    Ok(())
}

fn require_defined(
    function: usize,
    owner: usize,
    state: &MixedFlowState,
    value: MixedValueId,
) -> Result<MixedValueType, MixedPlanError> {
    state.slots[value.as_u32() as usize].ok_or(MixedPlanError::ValueNotDominated {
        function,
        owner,
        value,
    })
}

fn require_type(
    function: usize,
    owner: usize,
    state: &MixedFlowState,
    value: MixedValueId,
    expected: MixedValueType,
) -> Result<MixedValueType, MixedPlanError> {
    let actual = require_defined(function, owner, state, value)?;
    if expected.accepts(actual) {
        Ok(actual)
    } else {
        Err(MixedPlanError::ValueTypeMismatch {
            function,
            owner,
            value,
            expected,
            actual,
        })
    }
}

fn validate_statepoint_result(
    block: usize,
    statepoint_id: MixedStatepointId,
    statepoint: &MixedStatepoint,
    expected_result: MixedValueId,
    expected_type: MixedValueType,
) -> Result<(), MixedPlanError> {
    if statepoint.result != Some(expected_result) || statepoint.result_type != Some(expected_type) {
        return Err(MixedPlanError::StatepointResultMismatch {
            block,
            statepoint: statepoint_id,
            expected_result,
            actual_result: statepoint.result,
            expected_type,
            actual_type: statepoint.result_type,
        });
    }
    Ok(())
}

fn validate_statepoint_entry(
    function: usize,
    block: usize,
    statepoint_id: MixedStatepointId,
    statepoint: &MixedStatepoint,
    state: &MixedFlowState,
) -> Result<(), MixedPlanError> {
    if !state.pending_forces.is_empty() && matches!(statepoint.mode, MixedStatepointMode::Resume) {
        return Err(MixedPlanError::StatepointWithPendingForce {
            function,
            block,
            statepoint: statepoint_id,
            pending_depth: state.pending_forces.len(),
        });
    }
    for value in &statepoint.live_values {
        require_defined(function, block, state, *value)?;
    }
    Ok(())
}

fn merge_flow_state(
    function: usize,
    block: usize,
    incoming: &mut Option<MixedFlowState>,
    next: MixedFlowState,
) -> Result<(), MixedPlanError> {
    let Some(current) = incoming else {
        *incoming = Some(next);
        return Ok(());
    };
    if current.pending_forces != next.pending_forces {
        return Err(MixedPlanError::ForceStackMerge {
            function,
            block,
            first: current.pending_forces.clone(),
            second: next.pending_forces,
        });
    }
    for (current_type, next_type) in current.slots.iter_mut().zip(next.slots) {
        if *current_type != next_type {
            *current_type = None;
        }
    }
    Ok(())
}

fn executable_successors(
    terminator: &MixedTerminator,
    plan: &MixedModulePlan,
) -> Vec<MixedBlockId> {
    let mut successors = local_successors(terminator);
    for statepoint in terminator_statepoints(terminator) {
        let statepoint = &plan.statepoints[statepoint.index()];
        if matches!(statepoint.mode, MixedStatepointMode::Resume) {
            successors.push(statepoint.resume);
        }
    }
    successors
}

/// Location of one invalid side-table reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixedReference {
    /// Function named by an outer entry.
    EntryFunction(usize),
    /// Function named by a pure operation.
    OperationFunction(usize),
    /// Function named by a guarded call target.
    CallTargetFunction(usize),
    /// Block named by another block's local terminator.
    BlockTarget(usize),
    /// Statepoint named by a block terminator.
    BlockStatepoint(usize),
    /// Resume block named by a statepoint.
    StatepointResume(usize),
}

/// Reports malformed or unbounded mixed-machine plan metadata.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MixedPlanError {
    /// The plan has no guarded entry.
    #[error("mixed plan has no entry")]
    EmptyEntries,
    /// The plan has no frame-specialized function.
    #[error("mixed plan has no function")]
    EmptyFunctions,
    /// The plan has no basic block.
    #[error("mixed plan has no basic block")]
    EmptyBlocks,
    /// A side table is too large for compact ids.
    #[error("mixed plan {table} table has {len} entries, exceeding u32 addressability")]
    TableTooLarge {
        /// Side-table name.
        table: &'static str,
        /// Observed length.
        len: usize,
    },
    /// One resource declaration is zero or exceeds its hard cap.
    #[error("mixed plan {resource} bound {actual} is outside 1..={cap}")]
    InvalidBound {
        /// Resource name.
        resource: &'static str,
        /// Declared bound.
        actual: u32,
        /// Hard cap.
        cap: u32,
    },
    /// A contiguous range overflowed `u32`.
    #[error("mixed plan {table} range owned by {owner} overflows u32")]
    RangeOverflow {
        /// Side-table name.
        table: &'static str,
        /// Owning table index.
        owner: usize,
    },
    /// A contiguous range lies outside its side table.
    #[error("mixed plan {table} range owned by {owner} lies outside {len} entries")]
    RangeOutOfBounds {
        /// Side-table name.
        table: &'static str,
        /// Owning table index.
        owner: usize,
        /// Side-table length.
        len: usize,
    },
    /// Function ranges do not form one ordered partition.
    #[error("mixed function {function} block range starts at {actual}, expected {expected}")]
    NonCanonicalFunctionPartition {
        /// Function index.
        function: usize,
        /// Expected start.
        expected: u32,
        /// Actual start.
        actual: u32,
    },
    /// Block operation ranges do not form one ordered partition.
    #[error("mixed block {block} operation range starts at {actual}, expected {expected}")]
    NonCanonicalOperationPartition {
        /// Block index.
        block: usize,
        /// Expected start.
        expected: u32,
        /// Actual start.
        actual: u32,
    },
    /// A function id does not exist.
    #[error("mixed plan reference {reference:?} names missing function {id:?}")]
    InvalidFunction {
        /// Invalid id.
        id: MixedFunctionId,
        /// Referring metadata.
        reference: MixedReference,
    },
    /// A block id does not exist.
    #[error("mixed plan reference {reference:?} names missing block {id:?}")]
    InvalidBlock {
        /// Invalid id.
        id: MixedBlockId,
        /// Referring metadata.
        reference: MixedReference,
    },
    /// A statepoint id does not exist.
    #[error("mixed plan reference {reference:?} names missing statepoint {id:?}")]
    InvalidStatepoint {
        /// Invalid id.
        id: MixedStatepointId,
        /// Referring metadata.
        reference: MixedReference,
    },
    /// A function entry lies outside the function's block range.
    #[error("mixed function {function} entry {entry:?} lies outside its block range")]
    FunctionEntryOutsideBlocks {
        /// Function index.
        function: usize,
        /// Invalid entry.
        entry: MixedBlockId,
    },
    /// A local control-flow edge crosses a function boundary.
    #[error(
        "mixed block {from} in function {owner} jumps to {target:?} in function {target_owner}"
    )]
    CrossFunctionBlockEdge {
        /// Source block.
        from: usize,
        /// Target block.
        target: MixedBlockId,
        /// Source owner.
        owner: usize,
        /// Target owner.
        target_owner: usize,
    },
    /// An operation or terminator names a value beyond the activation bound.
    #[error("mixed owner {owner} names value {value:?} beyond {bound} slots")]
    InvalidValue {
        /// Operation or block index.
        owner: usize,
        /// Invalid value.
        value: MixedValueId,
        /// Declared slot bound.
        bound: u32,
    },
    /// A guarded call has zero or too many targets.
    #[error("mixed block {block} has guarded fanout {targets}, cap {cap}")]
    CallTargetFanout {
        /// Block index.
        block: usize,
        /// Declared target count.
        targets: u32,
        /// Hard target cap.
        cap: u32,
    },
    /// One guarded call repeats an exact code identity.
    #[error("mixed block {block} repeats guarded target identity at target {target}")]
    DuplicateCallTargetIdentity {
        /// Block index.
        block: usize,
        /// Repeated target index.
        target: usize,
    },
    /// A statepoint live set is not strictly sorted and unique.
    #[error("mixed statepoint {statepoint} {set} is not strictly sorted and unique")]
    NonCanonicalLiveSet {
        /// Statepoint index.
        statepoint: usize,
        /// Live-set name.
        set: &'static str,
    },
    /// A locally resumed continuation needs a value absent from its root set.
    #[error("mixed statepoint {statepoint} resuming at {resume:?} omits live value {missing:?}")]
    IncompleteStatepointLiveSet {
        /// Statepoint with an incomplete spill/root contract.
        statepoint: usize,
        /// Local continuation entered after the oracle result is installed.
        resume: MixedBlockId,
        /// First continuation-live value absent from `live_values`.
        missing: MixedValueId,
    },
    /// A statepoint virtual set contains a value absent from its root set.
    #[error("mixed statepoint {statepoint} virtual live set is not a subset of live values")]
    VirtualLiveSetNotSubset {
        /// Statepoint index.
        statepoint: usize,
    },
    /// A block is not reachable from any guarded entry.
    #[error("mixed block {block} is unreachable from every entry")]
    UnreachableBlock {
        /// Unreachable block index.
        block: usize,
    },
    /// A function is not reachable from any guarded entry.
    #[error("mixed function {function} is unreachable from every entry")]
    UnreachableFunction {
        /// Unreachable function index.
        function: usize,
    },
    /// An outer entry expects a dynamically typed runtime parameter.
    #[error(
        "mixed entry {entry} function {function:?} parameter type is {actual:?}, expected Value"
    )]
    EntryParameterType {
        /// Entry index.
        entry: usize,
        /// Entered function.
        function: MixedFunctionId,
        /// Declared parameter type.
        actual: MixedValueType,
    },
    /// A guarded target does not write the callee's declared parameter slot.
    #[error("mixed call target {target} writes argument to {actual:?}, expected {expected:?}")]
    CallArgumentDestination {
        /// Target side-table index.
        target: usize,
        /// Declared destination.
        actual: MixedValueId,
        /// Callee parameter slot.
        expected: MixedValueId,
    },
    /// A statepoint result slot and type are not both present or both absent.
    #[error("mixed statepoint {statepoint} has an incomplete result mapping")]
    IncompleteStatepointResult {
        /// Statepoint index.
        statepoint: usize,
    },
    /// A rollback statepoint incorrectly declares a locally resumed result.
    #[error("mixed restart statepoint {statepoint} declares a result")]
    RestartStatepointHasResult {
        /// Invalid restart statepoint.
        statepoint: usize,
    },
    /// A statepoint requires virtual-object materialization without a recipe.
    #[error("mixed statepoint {statepoint} has live virtuals but no materialization recipe")]
    UnrepresentableMaterialization {
        /// Statepoint index.
        statepoint: usize,
    },
    /// One SSA slot has two static definition sites.
    #[error(
        "mixed function {function} value {value:?} is defined at both {first:?} and {second:?}"
    )]
    MultipleValueDefinitions {
        /// Function index.
        function: usize,
        /// Multiply defined slot.
        value: MixedValueId,
        /// First definition site.
        first: MixedDefinitionSite,
        /// Second definition site.
        second: MixedDefinitionSite,
    },
    /// Executable validation found a block without an incoming flow state.
    #[error("mixed function {function} block {block} has no executable predecessor state")]
    ExecutableUnreachableBlock {
        /// Function index.
        function: usize,
        /// Block index.
        block: usize,
    },
    /// The v2 executable subset cannot represent local cyclic SSA control flow.
    #[error("mixed function {function} contains a local control-flow cycle")]
    ExecutableControlCycle {
        /// Function index.
        function: usize,
    },
    /// A value use is not dominated by its unique definition.
    #[error("mixed function {function} owner {owner} uses undominated value {value:?}")]
    ValueNotDominated {
        /// Function index.
        function: usize,
        /// Operation or block index.
        owner: usize,
        /// Undominated value.
        value: MixedValueId,
    },
    /// A typed operation received an incompatible slot type.
    #[error(
        "mixed function {function} owner {owner} value {value:?} has type {actual:?}, expected {expected:?}"
    )]
    ValueTypeMismatch {
        /// Function index.
        function: usize,
        /// Operation or block index.
        owner: usize,
        /// Incompatible value.
        value: MixedValueId,
        /// Required type.
        expected: MixedValueType,
        /// Observed type.
        actual: MixedValueType,
    },
    /// Guarded call argument type does not satisfy one target.
    #[error(
        "mixed block {block} target {target} argument has type {actual:?}, expected {expected:?}"
    )]
    CallArgumentType {
        /// Calling block.
        block: usize,
        /// Target side-table index.
        target: usize,
        /// Callee parameter type.
        expected: MixedValueType,
        /// Caller argument type.
        actual: MixedValueType,
    },
    /// Guarded targets disagree on the type written to the caller result.
    #[error("mixed block {block} guarded results disagree: {expected:?} versus {actual:?}")]
    CallResultTypeDisagreement {
        /// Calling block.
        block: usize,
        /// First target return type.
        expected: MixedValueType,
        /// Conflicting target return type.
        actual: MixedValueType,
    },
    /// A guarded call had no result type after target validation.
    #[error("mixed block {block} has no guarded result type")]
    CallResultTypeUnavailable {
        /// Calling block.
        block: usize,
    },
    /// A force or call fallback does not write the promised result slot and type.
    #[error(
        "mixed block {block} statepoint {statepoint:?} result {actual_result:?}/{actual_type:?}, expected {expected_result:?}/{expected_type:?}"
    )]
    StatepointResultMismatch {
        /// Referring block.
        block: usize,
        /// Fallback statepoint.
        statepoint: MixedStatepointId,
        /// Expected result slot.
        expected_result: MixedValueId,
        /// Declared result slot.
        actual_result: Option<MixedValueId>,
        /// Expected result type.
        expected_type: MixedValueType,
        /// Declared result type.
        actual_type: Option<MixedValueType>,
    },
    /// A statepoint would need an unrepresented force rollback recipe.
    #[error(
        "mixed function {function} block {block} statepoint {statepoint:?} has {pending_depth} pending forces"
    )]
    StatepointWithPendingForce {
        /// Function index.
        function: usize,
        /// Referring block.
        block: usize,
        /// Statepoint requiring restoration.
        statepoint: MixedStatepointId,
        /// Pending force count.
        pending_depth: usize,
    },
    /// An update executes without a force token owned by this function.
    #[error("mixed function {function} block {block} updates without a pending force")]
    ForceUpdateUnderflow {
        /// Function index.
        function: usize,
        /// Update block.
        block: usize,
    },
    /// An update does not publish the innermost force's promised result.
    #[error(
        "mixed function {function} block {block} updates result {actual:?}, expected {expected:?}"
    )]
    ForceUpdateResultMismatch {
        /// Function index.
        function: usize,
        /// Update block.
        block: usize,
        /// Innermost promised result.
        expected: MixedValueId,
        /// Declared update result.
        actual: MixedValueId,
    },
    /// An update names a result that was not introduced by a force.
    #[error("mixed function {function} block {block} updates unknown force result {result:?}")]
    ForceUpdateUnknownResult {
        /// Function index.
        function: usize,
        /// Update block.
        block: usize,
        /// Unknown result slot.
        result: MixedValueId,
    },
    /// Control-flow paths reach a merge with different force-token stacks.
    #[error("mixed function {function} block {block} merges force stacks {first:?} and {second:?}")]
    ForceStackMerge {
        /// Function index.
        function: usize,
        /// Merge block.
        block: usize,
        /// First incoming token stack.
        first: Vec<MixedValueId>,
        /// Second incoming token stack.
        second: Vec<MixedValueId>,
    },
    /// A function returns before publishing all force tokens it claimed.
    #[error("mixed function {function} block {block} returns with {pending_depth} pending forces")]
    UnpublishedForceAtReturn {
        /// Function index.
        function: usize,
        /// Return block.
        block: usize,
        /// Pending force count.
        pending_depth: usize,
    },
    /// A callee may materialize while its caller owns a force token.
    #[error(
        "mixed function {function} block {block} calls {target:?} with {pending_depth} pending forces, but the target may statepoint"
    )]
    StatepointAcrossPendingForce {
        /// Caller function index.
        function: usize,
        /// Calling block.
        block: usize,
        /// Callee function.
        target: MixedFunctionId,
        /// Caller-owned pending force count.
        pending_depth: usize,
    },
    /// A local force path exceeds the activation's declared update capacity.
    #[error("mixed function {function} block {block} reaches update depth {depth}, bound {bound}")]
    UpdateDepthExceeded {
        /// Function index.
        function: usize,
        /// Force block.
        block: usize,
        /// Required depth.
        depth: usize,
        /// Declared bound.
        bound: u32,
    },
    /// Direct calls can exceed the update bound or grow it through recursion.
    #[error(
        "mixed function {function} block {block} enters {target:?} at update depth {depth}, bound {bound}"
    )]
    InterproceduralUpdateDepth {
        /// Caller function index.
        function: usize,
        /// Calling block.
        block: usize,
        /// Callee function.
        target: MixedFunctionId,
        /// Required absolute depth.
        depth: usize,
        /// Declared bound.
        bound: u32,
    },
    /// A callee's local claims exceed the remaining caller-owned update capacity.
    #[error("mixed function {function} reaches absolute update depth {depth}, bound {bound}")]
    InterproceduralFunctionUpdateDepth {
        /// Function index.
        function: usize,
        /// Required absolute depth.
        depth: usize,
        /// Declared bound.
        bound: u32,
    },
}

fn validate_bounds(bounds: MixedPlanBounds) -> Result<(), MixedPlanError> {
    for (resource, actual, cap) in [
        ("value_slots", bounds.value_slots, MIXED_VALUE_SLOT_CAP),
        ("update_depth", bounds.update_depth, MIXED_UPDATE_DEPTH_CAP),
        (
            "virtual_frames",
            bounds.virtual_frames,
            MIXED_VIRTUAL_FRAME_CAP,
        ),
    ] {
        if actual == 0 || actual > cap {
            return Err(MixedPlanError::InvalidBound {
                resource,
                actual,
                cap,
            });
        }
    }
    Ok(())
}

fn validate_u32_len(table: &'static str, len: usize) -> Result<(), MixedPlanError> {
    u32::try_from(len)
        .map(|_| ())
        .map_err(|_| MixedPlanError::TableTooLarge { table, len })
}

fn validate_function_partition(
    functions: &[MixedFunction],
    blocks: usize,
) -> Result<(), MixedPlanError> {
    let mut expected = 0u32;
    for (function, metadata) in functions.iter().enumerate() {
        if metadata.blocks.start() != expected {
            return Err(MixedPlanError::NonCanonicalFunctionPartition {
                function,
                expected,
                actual: metadata.blocks.start(),
            });
        }
        let range = validate_range("blocks", function, metadata.blocks, blocks)?;
        if range.is_empty() {
            return Err(MixedPlanError::RangeOutOfBounds {
                table: "blocks",
                owner: function,
                len: blocks,
            });
        }
        expected = metadata
            .blocks
            .checked_end()
            .ok_or(MixedPlanError::RangeOverflow {
                table: "blocks",
                owner: function,
            })?;
    }
    if expected as usize != blocks {
        return Err(MixedPlanError::RangeOutOfBounds {
            table: "blocks",
            owner: functions.len(),
            len: blocks,
        });
    }
    Ok(())
}

fn validate_operation_partition(
    blocks: &[MixedBlock],
    operations: usize,
) -> Result<(), MixedPlanError> {
    let mut expected = 0u32;
    for (block, metadata) in blocks.iter().enumerate() {
        if metadata.operations.start() != expected {
            return Err(MixedPlanError::NonCanonicalOperationPartition {
                block,
                expected,
                actual: metadata.operations.start(),
            });
        }
        validate_range("operations", block, metadata.operations, operations)?;
        expected = metadata
            .operations
            .checked_end()
            .ok_or(MixedPlanError::RangeOverflow {
                table: "operations",
                owner: block,
            })?;
    }
    if expected as usize != operations {
        return Err(MixedPlanError::RangeOutOfBounds {
            table: "operations",
            owner: blocks.len(),
            len: operations,
        });
    }
    Ok(())
}

fn validate_range(
    table: &'static str,
    owner: usize,
    range: MixedTableRange,
    len: usize,
) -> Result<std::ops::Range<usize>, MixedPlanError> {
    let indices = range
        .indices()
        .ok_or(MixedPlanError::RangeOverflow { table, owner })?;
    if indices.end > len {
        Err(MixedPlanError::RangeOutOfBounds { table, owner, len })
    } else {
        Ok(indices)
    }
}

fn block_owners(
    functions: &[MixedFunction],
    block_count: usize,
) -> Result<Vec<usize>, MixedPlanError> {
    let mut owners = vec![usize::MAX; block_count];
    for (function, metadata) in functions.iter().enumerate() {
        for block in validate_range("blocks", function, metadata.blocks, block_count)? {
            owners[block] = function;
        }
    }
    Ok(owners)
}

fn validate_value(
    value: MixedValueId,
    bounds: MixedPlanBounds,
    owner: usize,
) -> Result<(), MixedPlanError> {
    if value.as_u32() < bounds.value_slots {
        Ok(())
    } else {
        Err(MixedPlanError::InvalidValue {
            owner,
            value,
            bound: bounds.value_slots,
        })
    }
}

fn validate_live_set(
    statepoint: usize,
    set: &'static str,
    values: &[MixedValueId],
    bounds: MixedPlanBounds,
) -> Result<(), MixedPlanError> {
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(MixedPlanError::NonCanonicalLiveSet { statepoint, set });
    }
    for value in values {
        validate_value(*value, bounds, statepoint)?;
    }
    Ok(())
}

/// Computes exact block live-in sets for one function by monotone reverse dataflow.
fn compute_function_live_in(plan: &MixedModulePlan, function_index: usize) -> Vec<Vec<bool>> {
    let function = plan.functions[function_index];
    let block_start = function.blocks.start() as usize;
    let block_end = block_start + function.blocks.len() as usize;
    let slot_count = plan.bounds.value_slots as usize;
    let mut live_in = vec![vec![false; slot_count]; block_end - block_start];

    loop {
        let mut changed = false;
        for block_index in (block_start..block_end).rev() {
            let block = &plan.blocks[block_index];
            let mut live = vec![false; slot_count];
            for (successor, edge_definition) in liveness_successors(&block.terminator, plan) {
                let successor_live = &live_in[successor.index() - block_start];
                for (slot, required) in successor_live.iter().copied().enumerate() {
                    if required
                        && edge_definition.is_none_or(|defined| defined.as_u32() as usize != slot)
                    {
                        live[slot] = true;
                    }
                }
            }
            add_terminator_uses(&mut live, &block.terminator, plan);
            let operation_start = block.operations.start() as usize;
            let operation_end = operation_start + block.operations.len() as usize;
            for operation in plan.operations[operation_start..operation_end].iter().rev() {
                live[operation_destination(*operation).as_u32() as usize] = false;
                for value in operation_uses(*operation).into_iter().flatten() {
                    live[value.as_u32() as usize] = true;
                }
            }
            let block_live = &mut live_in[block_index - block_start];
            if *block_live != live {
                *block_live = live;
                changed = true;
            }
        }
        if !changed {
            return live_in;
        }
    }
}

/// Returns local successors and the value defined while taking each edge.
fn liveness_successors(
    terminator: &MixedTerminator,
    plan: &MixedModulePlan,
) -> Vec<(MixedBlockId, Option<MixedValueId>)> {
    match terminator {
        MixedTerminator::Jump { target } => vec![(*target, None)],
        MixedTerminator::Branch {
            when_true,
            when_false,
            ..
        } => vec![(*when_true, None), (*when_false, None)],
        MixedTerminator::Force {
            result,
            ready,
            node,
            apply,
            gen_list,
            fallback,
            ..
        } => {
            let mut successors = vec![
                (*ready, Some(*result)),
                (*node, None),
                (*apply, None),
                (*gen_list, None),
            ];
            let statepoint = &plan.statepoints[fallback.index()];
            if matches!(statepoint.mode, MixedStatepointMode::Resume) {
                successors.push((statepoint.resume, statepoint.result));
            }
            successors
        }
        MixedTerminator::ApplyGuarded {
            result,
            continuation,
            fallback,
            ..
        } => {
            let mut successors = vec![(*continuation, Some(*result))];
            let statepoint = &plan.statepoints[fallback.index()];
            if matches!(statepoint.mode, MixedStatepointMode::Resume) {
                successors.push((statepoint.resume, statepoint.result));
            }
            successors
        }
        MixedTerminator::Update { result, next, .. } => vec![(*next, Some(*result))],
        MixedTerminator::Return { .. } => Vec::new(),
        MixedTerminator::Materialize { statepoint } => {
            let statepoint = &plan.statepoints[statepoint.index()];
            if matches!(statepoint.mode, MixedStatepointMode::Resume) {
                vec![(statepoint.resume, statepoint.result)]
            } else {
                Vec::new()
            }
        }
    }
}

/// Adds values consumed by a block terminator or its oracle boundary.
fn add_terminator_uses(live: &mut [bool], terminator: &MixedTerminator, plan: &MixedModulePlan) {
    let mut add = |value: MixedValueId| live[value.as_u32() as usize] = true;
    match terminator {
        MixedTerminator::Jump { .. } => {}
        MixedTerminator::Branch { condition, .. } => add(*condition),
        MixedTerminator::Force {
            subject, fallback, ..
        } => {
            add(*subject);
            for value in &plan.statepoints[fallback.index()].live_values {
                add(*value);
            }
        }
        MixedTerminator::ApplyGuarded {
            function,
            argument,
            fallback,
            ..
        } => {
            add(*function);
            add(*argument);
            for value in &plan.statepoints[fallback.index()].live_values {
                add(*value);
            }
        }
        MixedTerminator::Update { value, .. } | MixedTerminator::Return { value } => add(*value),
        MixedTerminator::Materialize { statepoint } => {
            for value in &plan.statepoints[statepoint.index()].live_values {
                add(*value);
            }
        }
    }
}

/// Returns the at-most-two SSA operands consumed by one pure operation.
const fn operation_uses(operation: MixedOp) -> [Option<MixedValueId>; 2] {
    match operation {
        MixedOp::Move { source, .. } => [Some(source), None],
        MixedOp::AddInt { left, right, .. } | MixedOp::LessThanInt { left, right, .. } => {
            [Some(left), Some(right)]
        }
        MixedOp::ConstInt { .. }
        | MixedOp::ConstBool { .. }
        | MixedOp::ConstNull { .. }
        | MixedOp::LoadLocal { .. }
        | MixedOp::LoadUpvalue { .. }
        | MixedOp::VirtualThunk { .. }
        | MixedOp::VirtualClosure { .. } => [None, None],
    }
}

fn local_successors(terminator: &MixedTerminator) -> Vec<MixedBlockId> {
    match terminator {
        MixedTerminator::Jump { target } => vec![*target],
        MixedTerminator::Branch {
            when_true,
            when_false,
            ..
        } => vec![*when_true, *when_false],
        MixedTerminator::Force {
            ready,
            node,
            apply,
            gen_list,
            ..
        } => vec![*ready, *node, *apply, *gen_list],
        MixedTerminator::ApplyGuarded { continuation, .. } => vec![*continuation],
        MixedTerminator::Update { next, .. } => vec![*next],
        MixedTerminator::Return { .. } | MixedTerminator::Materialize { .. } => Vec::new(),
    }
}

fn terminator_statepoints(terminator: &MixedTerminator) -> Vec<MixedStatepointId> {
    match terminator {
        MixedTerminator::Force { fallback, .. }
        | MixedTerminator::ApplyGuarded { fallback, .. } => vec![*fallback],
        MixedTerminator::Materialize { statepoint } => vec![*statepoint],
        MixedTerminator::Jump { .. }
        | MixedTerminator::Branch { .. }
        | MixedTerminator::Update { .. }
        | MixedTerminator::Return { .. } => Vec::new(),
    }
}

fn append_len(bytes: &mut Vec<u8>, len: usize) {
    bytes.extend_from_slice(&(len as u64).to_le_bytes());
}

fn append_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_range(bytes: &mut Vec<u8>, range: MixedTableRange) {
    append_u32(bytes, range.start());
    append_u32(bytes, range.len());
}

fn append_source(bytes: &mut Vec<u8>, source: MixedSource) {
    bytes.extend_from_slice(&source.module_digest);
    append_u32(bytes, source.ir.as_u32());
    append_u32(bytes, source.span.start);
    append_u32(bytes, source.span.end);
}

fn append_frame(bytes: &mut Vec<u8>, frame: Option<FrameId>) {
    match frame {
        Some(frame) => {
            bytes.push(1);
            append_u32(bytes, frame.as_u32());
        }
        None => {
            bytes.push(0);
            append_u32(bytes, 0);
        }
    }
}

fn append_value_type(bytes: &mut Vec<u8>, value_type: MixedValueType) {
    bytes.push(match value_type {
        MixedValueType::Value => 1,
        MixedValueType::Int => 2,
        MixedValueType::Bool => 3,
        MixedValueType::Null => 4,
        MixedValueType::VirtualThunk => 5,
        MixedValueType::VirtualClosure => 6,
    });
}

fn append_optional_value(bytes: &mut Vec<u8>, value: Option<MixedValueId>) {
    match value {
        Some(value) => {
            bytes.push(1);
            append_u32(bytes, value.as_u32());
        }
        None => {
            bytes.push(0);
            append_u32(bytes, 0);
        }
    }
}

fn append_optional_value_type(bytes: &mut Vec<u8>, value_type: Option<MixedValueType>) {
    match value_type {
        Some(value_type) => {
            bytes.push(1);
            append_value_type(bytes, value_type);
        }
        None => {
            bytes.push(0);
            bytes.push(0);
        }
    }
}

fn append_code_identity(bytes: &mut Vec<u8>, code: MixedCodeIdentity) {
    bytes.extend_from_slice(&code.module_digest);
    append_u32(bytes, code.definition.as_u32());
    append_u32(bytes, code.body.as_u32());
    append_frame(bytes, code.frame);
    bytes.extend_from_slice(&code.capture_layout_digest);
}

fn append_operation(bytes: &mut Vec<u8>, operation: MixedOp) {
    match operation {
        MixedOp::ConstInt { destination, value } => {
            bytes.push(1);
            append_u32(bytes, destination.as_u32());
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        MixedOp::ConstBool { destination, value } => {
            bytes.push(2);
            append_u32(bytes, destination.as_u32());
            bytes.push(u8::from(value));
        }
        MixedOp::ConstNull { destination } => {
            bytes.push(3);
            append_u32(bytes, destination.as_u32());
        }
        MixedOp::Move {
            destination,
            source,
        } => {
            bytes.push(4);
            append_u32(bytes, destination.as_u32());
            append_u32(bytes, source.as_u32());
        }
        MixedOp::LoadLocal { destination, slot } => {
            bytes.push(5);
            append_u32(bytes, destination.as_u32());
            append_u32(bytes, slot);
        }
        MixedOp::LoadUpvalue {
            destination,
            depth,
            slot,
        } => {
            bytes.push(6);
            append_u32(bytes, destination.as_u32());
            append_u32(bytes, depth);
            append_u32(bytes, slot);
        }
        MixedOp::VirtualThunk { destination, body } => {
            bytes.push(7);
            append_u32(bytes, destination.as_u32());
            append_u32(bytes, body.as_u32());
        }
        MixedOp::VirtualClosure { destination, body } => {
            bytes.push(8);
            append_u32(bytes, destination.as_u32());
            append_u32(bytes, body.as_u32());
        }
        MixedOp::AddInt {
            destination,
            left,
            right,
        } => {
            bytes.push(9);
            append_u32(bytes, destination.as_u32());
            append_u32(bytes, left.as_u32());
            append_u32(bytes, right.as_u32());
        }
        MixedOp::LessThanInt {
            destination,
            left,
            right,
        } => {
            bytes.push(10);
            append_u32(bytes, destination.as_u32());
            append_u32(bytes, left.as_u32());
            append_u32(bytes, right.as_u32());
        }
    }
}

fn append_terminator(bytes: &mut Vec<u8>, terminator: &MixedTerminator) {
    match terminator {
        MixedTerminator::Jump { target } => {
            bytes.push(1);
            append_u32(bytes, target.as_u32());
        }
        MixedTerminator::Branch {
            condition,
            when_true,
            when_false,
        } => {
            bytes.push(2);
            append_u32(bytes, condition.as_u32());
            append_u32(bytes, when_true.as_u32());
            append_u32(bytes, when_false.as_u32());
        }
        MixedTerminator::Force {
            subject,
            result,
            result_type,
            guards,
            ready,
            node,
            apply,
            gen_list,
            fallback,
        } => {
            bytes.push(3);
            append_u32(bytes, subject.as_u32());
            append_u32(bytes, result.as_u32());
            append_value_type(bytes, *result_type);
            append_code_identity(bytes, guards.node);
            append_code_identity(bytes, guards.apply);
            append_code_identity(bytes, guards.gen_list);
            append_u32(bytes, ready.as_u32());
            append_u32(bytes, node.as_u32());
            append_u32(bytes, apply.as_u32());
            append_u32(bytes, gen_list.as_u32());
            append_u32(bytes, fallback.as_u32());
        }
        MixedTerminator::ApplyGuarded {
            function,
            argument,
            result,
            targets,
            continuation,
            fallback,
        } => {
            bytes.push(4);
            append_u32(bytes, function.as_u32());
            append_u32(bytes, argument.as_u32());
            append_u32(bytes, result.as_u32());
            append_range(bytes, *targets);
            append_u32(bytes, continuation.as_u32());
            append_u32(bytes, fallback.as_u32());
        }
        MixedTerminator::Update {
            value,
            result,
            next,
        } => {
            bytes.push(5);
            append_u32(bytes, value.as_u32());
            append_u32(bytes, result.as_u32());
            append_u32(bytes, next.as_u32());
        }
        MixedTerminator::Return { value } => {
            bytes.push(6);
            append_u32(bytes, value.as_u32());
        }
        MixedTerminator::Materialize { statepoint } => {
            bytes.push(7);
            append_u32(bytes, statepoint.as_u32());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(id: u32) -> MixedSource {
        MixedSource::new([7; 32], IrId::new(id), Span::new(id, id + 1))
    }

    fn code(id: u32) -> MixedCodeIdentity {
        MixedCodeIdentity::new(
            [7; 32],
            IrId::new(id),
            IrId::new(id + 1),
            Some(FrameId::new(id)),
            [id as u8; 32],
        )
    }

    fn connected_plan(target_count: u32) -> Result<MixedModulePlan, MixedPlanError> {
        let target_len = target_count as usize;
        let target_function_start = 1u32;
        let mut functions = vec![MixedFunction {
            source: source(0),
            parameter: MixedValueId::new(0),
            parameter_type: MixedValueType::Value,
            return_type: MixedValueType::Value,
            entry: MixedBlockId::new(0),
            blocks: MixedTableRange::new(0, 6),
        }];
        let mut blocks = vec![
            MixedBlock {
                source: source(0),
                operations: MixedTableRange::new(0, 1),
                terminator: MixedTerminator::ApplyGuarded {
                    function: MixedValueId::new(0),
                    argument: MixedValueId::new(1),
                    result: MixedValueId::new(2),
                    targets: MixedTableRange::new(0, target_count),
                    continuation: MixedBlockId::new(1),
                    fallback: MixedStatepointId::new(0),
                },
            },
            MixedBlock {
                source: source(1),
                operations: MixedTableRange::new(1, 0),
                terminator: MixedTerminator::Force {
                    subject: MixedValueId::new(2),
                    result: MixedValueId::new(3),
                    result_type: MixedValueType::Value,
                    guards: MixedForceGuards::new(code(30), code(31), code(32)),
                    ready: MixedBlockId::new(2),
                    node: MixedBlockId::new(3),
                    apply: MixedBlockId::new(4),
                    gen_list: MixedBlockId::new(5),
                    fallback: MixedStatepointId::new(1),
                },
            },
            MixedBlock {
                source: source(2),
                operations: MixedTableRange::new(1, 0),
                terminator: MixedTerminator::Return {
                    value: MixedValueId::new(3),
                },
            },
            MixedBlock {
                source: source(3),
                operations: MixedTableRange::new(1, 1),
                terminator: MixedTerminator::Update {
                    value: MixedValueId::new(4),
                    result: MixedValueId::new(3),
                    next: MixedBlockId::new(2),
                },
            },
            MixedBlock {
                source: source(4),
                operations: MixedTableRange::new(2, 1),
                terminator: MixedTerminator::Update {
                    value: MixedValueId::new(5),
                    result: MixedValueId::new(3),
                    next: MixedBlockId::new(2),
                },
            },
            MixedBlock {
                source: source(5),
                operations: MixedTableRange::new(3, 1),
                terminator: MixedTerminator::Update {
                    value: MixedValueId::new(6),
                    result: MixedValueId::new(3),
                    next: MixedBlockId::new(2),
                },
            },
        ];
        let mut targets = Vec::new();
        for index in 0..target_len {
            let function = MixedFunctionId::new(target_function_start + index as u32);
            targets.push(MixedCallTarget {
                code: code(20 + index as u32 * 2),
                function,
                argument_destination: MixedValueId::new(7),
            });
            let block = blocks.len() as u32;
            functions.push(MixedFunction {
                source: source(20 + index as u32),
                parameter: MixedValueId::new(7),
                parameter_type: MixedValueType::Value,
                return_type: MixedValueType::Value,
                entry: MixedBlockId::new(block),
                blocks: MixedTableRange::new(block, 1),
            });
            blocks.push(MixedBlock {
                source: source(20 + index as u32),
                operations: MixedTableRange::new(4, 0),
                terminator: MixedTerminator::Return {
                    value: MixedValueId::new(7),
                },
            });
        }
        MixedModulePlan::new(
            MixedModuleKey::new([7; 32], [9; 32], 1),
            MixedPlanBounds::new(8, 8, 8),
            vec![MixedEntry {
                kind: MixedEntryKind::ForceWhnf,
                source: source(0),
                function: MixedFunctionId::new(0),
                frame: None,
                capture_layout_digest: [0; 32],
            }],
            functions,
            blocks,
            vec![
                MixedOp::ConstInt {
                    destination: MixedValueId::new(1),
                    value: 7,
                },
                MixedOp::ConstInt {
                    destination: MixedValueId::new(4),
                    value: 40,
                },
                MixedOp::ConstInt {
                    destination: MixedValueId::new(5),
                    value: 41,
                },
                MixedOp::ConstInt {
                    destination: MixedValueId::new(6),
                    value: 42,
                },
            ],
            targets,
            vec![
                MixedStatepoint {
                    source: source(98),
                    resume: MixedBlockId::new(1),
                    live_values: Box::new([MixedValueId::new(0), MixedValueId::new(1)]),
                    live_virtuals: Box::new([]),
                    result: Some(MixedValueId::new(2)),
                    result_type: Some(MixedValueType::Value),
                    mode: MixedStatepointMode::Resume,
                    reason: MixedStatepointReason::UnknownCall,
                },
                MixedStatepoint {
                    source: source(99),
                    resume: MixedBlockId::new(2),
                    live_values: Box::new([MixedValueId::new(2)]),
                    live_virtuals: Box::new([]),
                    result: Some(MixedValueId::new(3)),
                    result_type: Some(MixedValueType::Value),
                    mode: MixedStatepointMode::Resume,
                    reason: MixedStatepointReason::UnsupportedForce,
                },
            ],
        )
    }

    fn resumable_materialize_plan(
        live_values: Box<[MixedValueId]>,
        result: Option<(MixedValueId, MixedValueType)>,
    ) -> Result<MixedModulePlan, MixedPlanError> {
        let oracle_defines_result = result.is_some();
        let (result, result_type) = result.unzip();
        let (entry_operations, continuation_operation_start, operations) = if oracle_defines_result
        {
            (MixedTableRange::new(0, 0), 0, Vec::new())
        } else {
            (
                MixedTableRange::new(0, 1),
                1,
                vec![MixedOp::Move {
                    destination: MixedValueId::new(1),
                    source: MixedValueId::new(0),
                }],
            )
        };
        MixedModulePlan::new(
            MixedModuleKey::new([31; 32], [32; 32], 1),
            MixedPlanBounds::new(2, 1, 1),
            vec![MixedEntry {
                kind: MixedEntryKind::ForceWhnf,
                source: source(100),
                function: MixedFunctionId::new(0),
                frame: None,
                capture_layout_digest: [0; 32],
            }],
            vec![MixedFunction {
                source: source(100),
                parameter: MixedValueId::new(0),
                parameter_type: MixedValueType::Value,
                return_type: MixedValueType::Value,
                entry: MixedBlockId::new(0),
                blocks: MixedTableRange::new(0, 2),
            }],
            vec![
                MixedBlock {
                    source: source(100),
                    operations: entry_operations,
                    terminator: MixedTerminator::Materialize {
                        statepoint: MixedStatepointId::new(0),
                    },
                },
                MixedBlock {
                    source: source(101),
                    operations: MixedTableRange::new(continuation_operation_start, 0),
                    terminator: MixedTerminator::Return {
                        value: MixedValueId::new(1),
                    },
                },
            ],
            operations,
            vec![],
            vec![MixedStatepoint {
                source: source(102),
                resume: MixedBlockId::new(1),
                live_values,
                live_virtuals: Box::new([]),
                result,
                result_type,
                mode: MixedStatepointMode::Resume,
                reason: MixedStatepointReason::Unsupported,
            }],
        )
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        let first = connected_plan(1).expect("sample validates");
        let second = connected_plan(1).expect("sample validates");
        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert!(first.canonical_bytes().starts_with(b"RMIX"));
        assert_eq!(
            &first.canonical_bytes()[4..8],
            &MIXED_PLAN_FORMAT_VERSION.to_le_bytes()
        );
    }

    #[test]
    fn malformed_operation_side_table_is_rejected() {
        let mut plan = connected_plan(1).expect("sample validates");
        plan.blocks[2].operations = MixedTableRange::new(1, 1);
        assert!(matches!(
            plan.validate(),
            Err(MixedPlanError::NonCanonicalOperationPartition { .. })
        ));
    }

    #[test]
    fn guarded_call_fanout_cap_is_enforced() {
        assert!(matches!(
            connected_plan(5),
            Err(MixedPlanError::CallTargetFanout {
                targets: 5,
                cap: MIXED_CALL_TARGET_CAP,
                ..
            })
        ));
    }

    #[test]
    fn statepoint_live_sets_are_sorted_unique_and_nested() {
        let mut plan = connected_plan(1).expect("sample validates");
        plan.statepoints[0].live_values = Box::new([MixedValueId::new(1), MixedValueId::new(0)]);
        assert!(matches!(
            plan.validate(),
            Err(MixedPlanError::NonCanonicalLiveSet {
                statepoint: 0,
                set: "live_values",
            })
        ));

        let mut plan = connected_plan(1).expect("sample validates");
        plan.statepoints[0].live_virtuals = Box::new([MixedValueId::new(7)]);
        assert_eq!(
            plan.validate(),
            Err(MixedPlanError::VirtualLiveSetNotSubset { statepoint: 0 })
        );
    }

    #[test]
    fn resume_statepoint_rejects_an_omitted_continuation_live_value() {
        let mut plan = connected_plan(1).expect("sample validates");
        let MixedTerminator::Force { subject, .. } = &mut plan.blocks[1].terminator else {
            panic!("sample continuation must force");
        };
        *subject = MixedValueId::new(1);
        plan.statepoints[0].live_values = Box::new([MixedValueId::new(0)]);

        assert_eq!(
            plan.validate(),
            Err(MixedPlanError::IncompleteStatepointLiveSet {
                statepoint: 0,
                resume: MixedBlockId::new(1),
                missing: MixedValueId::new(1),
            })
        );
    }

    #[test]
    fn materialize_resume_rejects_a_value_used_by_the_continuation() {
        let mut plan = resumable_materialize_plan(Box::new([MixedValueId::new(1)]), None)
            .expect("complete live set validates");
        plan.statepoints[0].live_values = Box::new([]);

        assert_eq!(
            plan.validate(),
            Err(MixedPlanError::IncompleteStatepointLiveSet {
                statepoint: 0,
                resume: MixedBlockId::new(1),
                missing: MixedValueId::new(1),
            })
        );
    }

    #[test]
    fn statepoint_result_is_defined_on_resume_and_need_not_be_live() {
        let plan = resumable_materialize_plan(
            Box::new([]),
            Some((MixedValueId::new(1), MixedValueType::Value)),
        )
        .expect("oracle-defined continuation result validates");
        let live_in = compute_function_live_in(&plan, 0);

        assert!(live_in[1][1], "the continuation consumes the result slot");
        assert!(plan.statepoints[0].live_values.is_empty());
        assert_eq!(plan.statepoints[0].result, Some(MixedValueId::new(1)));
        assert_eq!(plan.validate(), Ok(()));
    }

    #[test]
    fn reverse_liveness_unions_branched_continuation_inputs() {
        let mut plan = connected_plan(1).expect("sample validates");
        plan.blocks[1].terminator = MixedTerminator::Branch {
            condition: MixedValueId::new(1),
            when_true: MixedBlockId::new(2),
            when_false: MixedBlockId::new(3),
        };
        plan.blocks[2].terminator = MixedTerminator::Return {
            value: MixedValueId::new(0),
        };
        plan.blocks[3].operations = MixedTableRange::new(1, 0);
        plan.blocks[3].terminator = MixedTerminator::Return {
            value: MixedValueId::new(1),
        };

        let live_in = compute_function_live_in(&plan, 0);
        assert!(live_in[1][0]);
        assert!(live_in[1][1]);
        assert_eq!(live_in[1].iter().filter(|live| **live).count(), 2);
    }

    #[test]
    fn reverse_liveness_reaches_a_fixed_point_across_a_local_loop() {
        let mut plan = connected_plan(1).expect("sample validates");
        plan.blocks[1].terminator = MixedTerminator::Jump {
            target: MixedBlockId::new(2),
        };
        plan.blocks[2].terminator = MixedTerminator::Branch {
            condition: MixedValueId::new(0),
            when_true: MixedBlockId::new(1),
            when_false: MixedBlockId::new(3),
        };
        plan.blocks[3].operations = MixedTableRange::new(1, 0);
        plan.blocks[3].terminator = MixedTerminator::Return {
            value: MixedValueId::new(1),
        };

        let live_in = compute_function_live_in(&plan, 0);
        for block in [1, 2] {
            assert!(live_in[block][0]);
            assert!(live_in[block][1]);
            assert_eq!(live_in[block].iter().filter(|live| **live).count(), 2);
        }
    }

    #[test]
    fn connected_sample_covers_all_force_shapes_without_per_node_statepoints() {
        let plan = connected_plan(1).expect("sample validates");
        assert_eq!(plan.statepoints().len(), 2);
        let MixedTerminator::Force {
            node,
            apply,
            gen_list,
            ..
        } = &plan.blocks()[1].terminator
        else {
            panic!("entry block must force");
        };
        assert_ne!(node, apply);
        assert_ne!(apply, gen_list);
        assert!(
            plan.blocks()
                .iter()
                .any(|block| matches!(block.terminator, MixedTerminator::Update { .. }))
        );
        assert!(
            plan.blocks()
                .iter()
                .any(|block| matches!(block.terminator, MixedTerminator::Return { .. }))
        );
    }

    #[test]
    fn undominated_value_use_is_rejected() {
        let mut plan = connected_plan(1).expect("sample validates");
        plan.blocks[2].terminator = MixedTerminator::Return {
            value: MixedValueId::new(7),
        };
        assert_eq!(
            plan.validate(),
            Err(MixedPlanError::ValueNotDominated {
                function: 0,
                owner: 2,
                value: MixedValueId::new(7),
            })
        );
    }

    #[test]
    fn duplicate_ssa_definition_is_rejected() {
        let mut plan = connected_plan(1).expect("sample validates");
        plan.operations[1] = MixedOp::ConstInt {
            destination: MixedValueId::new(1),
            value: 40,
        };
        assert_eq!(
            plan.validate(),
            Err(MixedPlanError::MultipleValueDefinitions {
                function: 0,
                value: MixedValueId::new(1),
                first: MixedDefinitionSite::Operation(0),
                second: MixedDefinitionSite::Operation(1),
            })
        );
    }

    #[test]
    fn typed_return_mismatch_is_rejected() {
        let mut plan = connected_plan(1).expect("sample validates");
        plan.functions[0].return_type = MixedValueType::Int;
        assert!(matches!(
            plan.validate(),
            Err(MixedPlanError::ValueTypeMismatch {
                function: 0,
                owner: 2,
                expected: MixedValueType::Int,
                actual: MixedValueType::Value,
                ..
            })
        ));
    }

    #[test]
    fn guarded_argument_destination_must_match_callee_parameter() {
        let mut plan = connected_plan(1).expect("sample validates");
        plan.call_targets[0].argument_destination = MixedValueId::new(6);
        assert_eq!(
            plan.validate(),
            Err(MixedPlanError::CallArgumentDestination {
                target: 0,
                actual: MixedValueId::new(6),
                expected: MixedValueId::new(7),
            })
        );
    }

    #[test]
    fn guarded_targets_must_agree_on_return_type() {
        let mut plan = connected_plan(2).expect("sample validates");
        plan.functions[2].return_type = MixedValueType::Int;
        assert_eq!(
            plan.validate(),
            Err(MixedPlanError::CallResultTypeDisagreement {
                block: 0,
                expected: MixedValueType::Value,
                actual: MixedValueType::Int,
            })
        );
    }

    #[test]
    fn force_update_must_publish_the_innermost_result() {
        let mut plan = connected_plan(1).expect("sample validates");
        let MixedTerminator::Update { result, .. } = &mut plan.blocks[3].terminator else {
            panic!("node force branch must update");
        };
        *result = MixedValueId::new(2);
        assert_eq!(
            plan.validate(),
            Err(MixedPlanError::ForceUpdateResultMismatch {
                function: 0,
                block: 3,
                expected: MixedValueId::new(3),
                actual: MixedValueId::new(2),
            })
        );
    }

    #[test]
    fn returning_with_a_claimed_force_is_rejected() {
        let mut plan = connected_plan(1).expect("sample validates");
        plan.blocks[3].terminator = MixedTerminator::Return {
            value: MixedValueId::new(4),
        };
        assert_eq!(
            plan.validate(),
            Err(MixedPlanError::UnpublishedForceAtReturn {
                function: 0,
                block: 3,
                pending_depth: 1,
            })
        );
    }

    #[test]
    fn force_token_stacks_must_match_at_control_merge() {
        let mut plan = connected_plan(1).expect("sample validates");
        plan.blocks[4].terminator = MixedTerminator::Jump {
            target: MixedBlockId::new(2),
        };
        assert!(matches!(
            plan.validate(),
            Err(MixedPlanError::ForceStackMerge {
                function: 0,
                block: 2,
                ..
            })
        ));
    }

    #[test]
    fn force_fallback_result_mapping_is_exact() {
        let mut plan = connected_plan(1).expect("sample validates");
        plan.statepoints[1].result = Some(MixedValueId::new(2));
        assert_eq!(
            plan.validate(),
            Err(MixedPlanError::StatepointResultMismatch {
                block: 1,
                statepoint: MixedStatepointId::new(1),
                expected_result: MixedValueId::new(3),
                actual_result: Some(MixedValueId::new(2)),
                expected_type: MixedValueType::Value,
                actual_type: Some(MixedValueType::Value),
            })
        );
    }

    #[test]
    fn virtual_materialization_without_a_recipe_is_rejected() {
        let mut plan = connected_plan(1).expect("sample validates");
        plan.statepoints[0].live_virtuals = Box::new([MixedValueId::new(0)]);
        assert_eq!(
            plan.validate(),
            Err(MixedPlanError::UnrepresentableMaterialization { statepoint: 0 })
        );
    }

    #[test]
    fn statepoint_with_pending_force_requires_an_exception_recipe() {
        let mut plan = connected_plan(1).expect("sample validates");
        let MixedTerminator::Force { apply, .. } = &mut plan.blocks[1].terminator else {
            panic!("sample must force");
        };
        *apply = MixedBlockId::new(3);
        plan.operations[1] = MixedOp::LoadLocal {
            destination: MixedValueId::new(4),
            slot: 0,
        };
        plan.operations[2] = MixedOp::Move {
            destination: MixedValueId::new(7),
            source: MixedValueId::new(5),
        };
        plan.blocks[3].terminator = MixedTerminator::ApplyGuarded {
            function: MixedValueId::new(4),
            argument: MixedValueId::new(1),
            result: MixedValueId::new(5),
            targets: MixedTableRange::new(0, 1),
            continuation: MixedBlockId::new(4),
            fallback: MixedStatepointId::new(2),
        };
        plan.blocks[4].terminator = MixedTerminator::Update {
            value: MixedValueId::new(7),
            result: MixedValueId::new(3),
            next: MixedBlockId::new(2),
        };
        let mut statepoints = plan.statepoints.into_vec();
        statepoints.push(MixedStatepoint {
            source: source(100),
            resume: MixedBlockId::new(4),
            live_values: Box::new([
                MixedValueId::new(0),
                MixedValueId::new(1),
                MixedValueId::new(2),
                MixedValueId::new(4),
            ]),
            live_virtuals: Box::new([]),
            result: Some(MixedValueId::new(5)),
            result_type: Some(MixedValueType::Value),
            mode: MixedStatepointMode::Resume,
            reason: MixedStatepointReason::UnknownCall,
        });
        plan.statepoints = statepoints.into_boxed_slice();
        assert_eq!(
            plan.validate(),
            Err(MixedPlanError::StatepointWithPendingForce {
                function: 0,
                block: 3,
                statepoint: MixedStatepointId::new(2),
                pending_depth: 1,
            })
        );
    }
}
