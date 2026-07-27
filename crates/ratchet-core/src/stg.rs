//! Packed spineless-tagless G-machine node tables.
//!
//! This module owns a runtime-independent lowering boundary between evaluator
//! IR and a future explicit evaluation machine. A [`StgCodeBlock`] is an
//! immutable table of packed expression nodes, not a sequential program:
//! child operands are program counters into the same table and [`StgCodeBlock::root_pc`]
//! names the entry node. Runtime force, update, argument, and return
//! continuations deliberately remain executor-owned.
//!
//! Variable-width and diagnostic metadata stays cold. Primitive operations,
//! numeric binary operations, lambda closure sites, selection sites, literals,
//! and source locations live in side tables referenced by compact hot words.
//!
//! Lowering is deliberately conservative. It first preflights the complete
//! graph reachable from the requested body. If any node is unsupported, the
//! whole block is declined before instruction encoding begins. Callers may
//! designate selected nodes as oracle leaves; those nodes become explicit
//! continuation boundaries without exposing any oracle-owned type here.

use std::fmt;

use thiserror::Error;

use crate::syntax::{BinOpKind, Span, Symbol};
use crate::{
    FrameId, Ir, IrAttrPathId, IrAttrPathSegment, IrData, IrId, IrInlineCacheSiteId, IrKind,
    Upvalue,
};

const OPERAND_BITS: u32 = 28;
const OPERAND_MASK: u64 = (1_u64 << OPERAND_BITS) - 1;
const SECOND_OPERAND_SHIFT: u32 = 8 + OPERAND_BITS;
const MAX_OPERAND: u32 = OPERAND_MASK as u32;
const CODE_FORMAT_VERSION: u16 = 2;

/// Identifies one lowered module without depending on an evaluator's module type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StgModuleId(u64);

impl StgModuleId {
    /// Creates a module identity from a caller-owned stable value.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the caller-owned stable value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Keys a code block by module, body, and optional lexical frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StgCodeKey {
    module: StgModuleId,
    body: IrId,
    frame: Option<FrameId>,
}

impl StgCodeKey {
    /// Creates a code-block key.
    pub const fn new(module: StgModuleId, body: IrId, frame: Option<FrameId>) -> Self {
        Self {
            module,
            body,
            frame,
        }
    }

    /// Returns the module identity.
    pub const fn module(self) -> StgModuleId {
        self.module
    }

    /// Returns the IR body lowered into the block.
    pub const fn body(self) -> IrId {
        self.body
    }

    /// Returns the lexical frame expected by the body, when one exists.
    pub const fn frame(self) -> Option<FrameId> {
        self.frame
    }
}

/// A node operation encoded in the low byte of an [`StgOpWord`].
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StgOpcode {
    /// Loads an integer from the block's literal table.
    LiteralInt = 1,
    /// Produces an immediate Boolean literal.
    LiteralBool = 2,
    /// Produces the null literal.
    LiteralNull = 3,
    /// Loads a slot from the current lexical frame.
    Local = 4,
    /// Loads a slot from an enclosing lexical frame.
    Upval = 5,
    /// Constructs a one-argument lambda closure from a cold closure-site entry.
    Lambda1 = 6,
    /// Constructs a suspended node whose body is another program counter.
    Thunk = 7,
    /// Applies one argument to a function exactly once.
    Apply1 = 8,
    /// Selects an attribute path described by a cold selection-site entry.
    Select = 9,
    /// Calls a primitive operation described by a cold primitive-operation entry.
    PrimOp = 10,
    /// Evaluates a numeric binary operation described by a cold binary-site entry.
    BinaryNumeric = 11,
    /// Transfers one expression to an oracle and resumes its parent continuation.
    OracleLeaf = 12,
}

impl StgOpcode {
    /// Decodes a stable opcode byte.
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::LiteralInt),
            2 => Some(Self::LiteralBool),
            3 => Some(Self::LiteralNull),
            4 => Some(Self::Local),
            5 => Some(Self::Upval),
            6 => Some(Self::Lambda1),
            7 => Some(Self::Thunk),
            8 => Some(Self::Apply1),
            9 => Some(Self::Select),
            10 => Some(Self::PrimOp),
            11 => Some(Self::BinaryNumeric),
            12 => Some(Self::OracleLeaf),
            _ => None,
        }
    }
}

/// A fixed-width hot instruction word.
///
/// The low eight bits hold an opcode. The remaining bits hold two unsigned
/// 28-bit operands. Interpretation of the operands is opcode-specific.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StgOpWord(u64);

impl StgOpWord {
    /// Returns the decoded opcode.
    pub const fn opcode(self) -> StgOpcode {
        match StgOpcode::from_u8(self.0 as u8) {
            Some(opcode) => opcode,
            None => unreachable_opcode(),
        }
    }

    /// Returns the first unsigned operand.
    pub const fn operand_a(self) -> u32 {
        ((self.0 >> 8) & OPERAND_MASK) as u32
    }

    /// Returns the second unsigned operand.
    pub const fn operand_b(self) -> u32 {
        ((self.0 >> SECOND_OPERAND_SHIFT) & OPERAND_MASK) as u32
    }

    /// Returns the stable packed representation.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    const fn pack(opcode: StgOpcode, operand_a: u32, operand_b: u32) -> Self {
        Self(
            opcode as u64
                | ((operand_a as u64) << 8)
                | ((operand_b as u64) << SECOND_OPERAND_SHIFT),
        )
    }
}

impl fmt::Debug for StgOpWord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StgOpWord")
            .field("opcode", &self.opcode())
            .field("operand_a", &self.operand_a())
            .field("operand_b", &self.operand_b())
            .finish()
    }
}

const fn unreachable_opcode() -> ! {
    panic!("StgOpWord can only be created with a valid opcode")
}

/// A literal stored outside the hot instruction stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StgLiteral {
    /// A signed 64-bit integer.
    Int(i64),
}

/// Maps one program counter back to its source IR node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StgSourceMapEntry {
    pc: u32,
    ir: IrId,
    span: Span,
}

impl StgSourceMapEntry {
    /// Returns the program counter described by this entry.
    pub const fn pc(self) -> u32 {
        self.pc
    }

    /// Returns the originating IR node.
    pub const fn ir(self) -> IrId {
        self.ir
    }

    /// Returns the originating source span.
    pub const fn span(self) -> Span {
        self.span
    }
}

/// Describes one primitive-operation node outside the hot node table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StgPrimOpSite {
    symbol: Symbol,
    argument_pcs: Box<[u32]>,
}

impl StgPrimOpSite {
    /// Returns the statically resolved primitive-operation symbol.
    pub const fn symbol(&self) -> Symbol {
        self.symbol
    }

    /// Returns ordered argument program counters.
    pub fn argument_pcs(&self) -> &[u32] {
        &self.argument_pcs
    }
}

/// Classifies numeric binary operations admitted by packed STG lowering.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StgNumericBinOp {
    /// Applies Nix addition, including its runtime numeric/type dispatch.
    ///
    /// Membership in this arithmetic family does not prove statically that
    /// both operands are numeric.
    Add = 1,
    /// Subtracts the right operand from the left operand.
    Sub = 2,
    /// Multiplies two numeric operands.
    Mul = 3,
    /// Divides the left operand by the right operand.
    Div = 4,
}

impl StgNumericBinOp {
    const fn from_ir(op: BinOpKind) -> Option<Self> {
        match op {
            BinOpKind::Add => Some(Self::Add),
            BinOpKind::Sub => Some(Self::Sub),
            BinOpKind::Mul => Some(Self::Mul),
            BinOpKind::Div => Some(Self::Div),
            _ => None,
        }
    }
}

/// Describes one numeric binary-operation node outside the hot node table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StgBinarySite {
    op: StgNumericBinOp,
    lhs_pc: u32,
    rhs_pc: u32,
}

impl StgBinarySite {
    /// Returns the numeric operation.
    pub const fn op(self) -> StgNumericBinOp {
        self.op
    }

    /// Returns the left operand program counter.
    pub const fn lhs_pc(self) -> u32 {
        self.lhs_pc
    }

    /// Returns the right operand program counter.
    pub const fn rhs_pc(self) -> u32 {
        self.rhs_pc
    }
}

/// Describes one unary lambda closure construction outside the hot node table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StgClosureSite {
    pattern: IrId,
    body_pc: u32,
    frame: FrameId,
}

impl StgClosureSite {
    /// Returns the formal-pattern IR node retained for argument binding.
    pub const fn pattern(self) -> IrId {
        self.pattern
    }

    /// Returns the lambda body program counter.
    pub const fn body_pc(self) -> u32 {
        self.body_pc
    }

    /// Returns the lexical frame installed by the lambda.
    pub const fn frame(self) -> FrameId {
        self.frame
    }
}

/// Describes one attribute-selection node outside the hot node table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StgSelectSite {
    site: IrInlineCacheSiteId,
    receiver_pc: u32,
    path: IrAttrPathId,
    default_pc: Option<u32>,
}

impl StgSelectSite {
    /// Returns the stable inline-cache site.
    pub const fn site(self) -> IrInlineCacheSiteId {
        self.site
    }

    /// Returns the receiver program counter.
    pub const fn receiver_pc(self) -> u32 {
        self.receiver_pc
    }

    /// Returns the attribute-path side-table id.
    pub const fn path(self) -> IrAttrPathId {
        self.path
    }

    /// Returns the default-expression program counter, when one was admitted.
    pub const fn default_pc(self) -> Option<u32> {
        self.default_pc
    }
}

/// An immutable packed STG node-table block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StgCodeBlock {
    key: StgCodeKey,
    root_pc: u32,
    words: Box<[StgOpWord]>,
    literals: Box<[StgLiteral]>,
    primop_sites: Box<[StgPrimOpSite]>,
    binary_sites: Box<[StgBinarySite]>,
    closure_sites: Box<[StgClosureSite]>,
    select_sites: Box<[StgSelectSite]>,
    source_map: Box<[StgSourceMapEntry]>,
}

impl StgCodeBlock {
    /// Returns the identity used to cache this block.
    pub const fn key(&self) -> StgCodeKey {
        self.key
    }

    /// Returns the program counter of the root expression node.
    pub const fn root_pc(&self) -> u32 {
        self.root_pc
    }

    /// Returns the packed hot node words.
    pub fn words(&self) -> &[StgOpWord] {
        &self.words
    }

    /// Returns the block's cold literal table.
    pub fn literals(&self) -> &[StgLiteral] {
        &self.literals
    }

    /// Returns primitive-operation descriptors in packed-word index order.
    pub fn primop_sites(&self) -> &[StgPrimOpSite] {
        &self.primop_sites
    }

    /// Returns numeric binary-operation descriptors in packed-word index order.
    pub fn binary_sites(&self) -> &[StgBinarySite] {
        &self.binary_sites
    }

    /// Returns lambda closure descriptors in packed-word index order.
    pub fn closure_sites(&self) -> &[StgClosureSite] {
        &self.closure_sites
    }

    /// Returns selection descriptors in packed-word index order.
    pub fn select_sites(&self) -> &[StgSelectSite] {
        &self.select_sites
    }

    /// Returns the cold source map ordered by program counter.
    pub fn source_map(&self) -> &[StgSourceMapEntry] {
        &self.source_map
    }

    /// Looks up source information for one program counter.
    pub fn source_at(&self, pc: u32) -> Option<StgSourceMapEntry> {
        self.source_map
            .get(pc as usize)
            .copied()
            .filter(|entry| entry.pc == pc)
    }

    /// Encodes the complete block in a deterministic little-endian format.
    ///
    /// The encoding is suitable for hashing and equality checks. Persistence
    /// layers should additionally record their own schema and compatibility
    /// envelope.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RSTG");
        bytes.extend_from_slice(&CODE_FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.key.module.as_u64().to_le_bytes());
        bytes.extend_from_slice(&self.key.body.as_u32().to_le_bytes());
        match self.key.frame {
            Some(frame) => {
                bytes.push(1);
                bytes.extend_from_slice(&frame.as_u32().to_le_bytes());
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(&0_u32.to_le_bytes());
            }
        }
        bytes.extend_from_slice(&self.root_pc.to_le_bytes());
        append_len(&mut bytes, self.words.len());
        append_len(&mut bytes, self.literals.len());
        append_len(&mut bytes, self.primop_sites.len());
        append_len(&mut bytes, self.binary_sites.len());
        append_len(&mut bytes, self.closure_sites.len());
        append_len(&mut bytes, self.select_sites.len());
        append_len(&mut bytes, self.source_map.len());
        for word in &self.words {
            bytes.extend_from_slice(&word.as_u64().to_le_bytes());
        }
        for literal in &self.literals {
            match literal {
                StgLiteral::Int(value) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
        for site in &self.primop_sites {
            bytes.extend_from_slice(&site.symbol.as_u32().to_le_bytes());
            append_len(&mut bytes, site.argument_pcs.len());
            for pc in &site.argument_pcs {
                bytes.extend_from_slice(&pc.to_le_bytes());
            }
        }
        for site in &self.binary_sites {
            bytes.push(site.op as u8);
            bytes.extend_from_slice(&site.lhs_pc.to_le_bytes());
            bytes.extend_from_slice(&site.rhs_pc.to_le_bytes());
        }
        for site in &self.closure_sites {
            bytes.extend_from_slice(&site.pattern.as_u32().to_le_bytes());
            bytes.extend_from_slice(&site.body_pc.to_le_bytes());
            bytes.extend_from_slice(&site.frame.as_u32().to_le_bytes());
        }
        for site in &self.select_sites {
            bytes.extend_from_slice(&site.site.as_u32().to_le_bytes());
            bytes.extend_from_slice(&site.receiver_pc.to_le_bytes());
            bytes.extend_from_slice(&site.path.as_u32().to_le_bytes());
            match site.default_pc {
                Some(pc) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&pc.to_le_bytes());
                }
                None => {
                    bytes.push(0);
                    bytes.extend_from_slice(&0_u32.to_le_bytes());
                }
            }
        }
        for source in &self.source_map {
            bytes.extend_from_slice(&source.pc.to_le_bytes());
            bytes.extend_from_slice(&source.ir.as_u32().to_le_bytes());
            bytes.extend_from_slice(&source.span.start.to_le_bytes());
            bytes.extend_from_slice(&source.span.end.to_le_bytes());
        }
        bytes
    }
}

fn append_len(bytes: &mut Vec<u8>, len: usize) {
    bytes.extend_from_slice(&(len as u64).to_le_bytes());
}

/// Configures conservative boundaries accepted by STG lowering.
#[derive(Clone, Copy, Debug, Default)]
pub struct StgLowerOptions<'a> {
    oracle_leaves: &'a [IrId],
}

impl<'a> StgLowerOptions<'a> {
    /// Creates options with no oracle continuation boundaries.
    pub const fn new() -> Self {
        Self { oracle_leaves: &[] }
    }

    /// Marks exact IR nodes that an eventual executor may delegate to an oracle.
    #[must_use]
    pub const fn with_oracle_leaves(mut self, oracle_leaves: &'a [IrId]) -> Self {
        self.oracle_leaves = oracle_leaves;
        self
    }

    /// Returns the exact nodes designated as oracle continuation boundaries.
    pub const fn oracle_leaves(self) -> &'a [IrId] {
        self.oracle_leaves
    }
}

/// Explains why a well-formed IR graph was conservatively declined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StgDecline {
    id: IrId,
    kind: IrKind,
    reason: StgDeclineReason,
}

impl StgDecline {
    /// Returns the first node that prevented whole-block lowering.
    pub const fn id(self) -> IrId {
        self.id
    }

    /// Returns the kind of the first declined node.
    pub const fn kind(self) -> IrKind {
        self.kind
    }

    /// Returns the conservative decline reason.
    pub const fn reason(self) -> StgDeclineReason {
        self.reason
    }
}

/// Classifies conservative STG preflight declines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StgDeclineReason {
    /// The IR kind is outside the supported grammar.
    UnsupportedKind,
    /// The node payload does not match the supported shape.
    UnsupportedShape,
    /// A select has an `or` default.
    SelectDefault,
    /// A select path contains a dynamic segment.
    DynamicSelectPath,
    /// A lambda does not use a simple one-argument pattern.
    NonUnaryLambda,
    /// A lambda or variable access has no statically known lexical frame.
    MissingFrameContext,
    /// A lexical slot is incompatible with its statically known frame.
    InvalidFrameSlot,
    /// An upvalue is not declared by its statically known capturing frame.
    InvalidFrameCapture,
    /// One shared IR node is reachable under incompatible lexical frames.
    AmbiguousFrameContext,
    /// A binary operator is not one of the numeric operations owned by this table.
    NonNumericBinaryOperator,
    /// An instruction operand does not fit the packed 28-bit field.
    OperandTooWide,
}

/// Reports either a complete block or an atomic conservative decline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StgLowerOutcome {
    /// The complete reachable graph was lowered.
    Lowered(StgCodeBlock),
    /// The complete block was declined without producing partial code.
    Declined(StgDecline),
}

/// Reports malformed input that prevents STG preflight.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StgLowerError {
    /// The code key names a body outside the IR arena.
    #[error("STG code key references missing body {0:?}")]
    InvalidBody(IrId),
    /// The code key names a frame outside the IR frame table.
    #[error("STG code key references missing frame {0:?}")]
    InvalidFrame(FrameId),
    /// An oracle-leaf declaration names a node outside the IR arena.
    #[error("STG oracle leaf references missing node {0:?}")]
    InvalidOracleLeaf(IrId),
    /// An IR node references a child outside the IR arena.
    #[error("STG node {from:?} references missing child {child:?}")]
    InvalidChild {
        /// The node containing the invalid reference.
        from: IrId,
        /// The missing child.
        child: IrId,
    },
    /// The reachable IR graph contains a cycle.
    #[error("STG lowering found an IR cycle through node {0:?}")]
    Cycle(IrId),
}

/// Lowers a conservative IR body with no oracle continuation leaves.
///
/// Unsupported, but well-formed, nodes produce [`StgLowerOutcome::Declined`].
/// The function performs complete preflight before it encodes any instruction.
///
/// # Errors
///
/// Returns an error when the key, a child reference, or a frame references a
/// missing side-table entry, or when the reachable IR graph is cyclic.
pub fn lower_stg_code_block(ir: &Ir, key: StgCodeKey) -> Result<StgLowerOutcome, StgLowerError> {
    lower_stg_code_block_with_options(ir, key, StgLowerOptions::new())
}

/// Lowers a conservative IR body with explicit oracle continuation leaves.
///
/// Nodes named by `options` are emitted as [`StgOpcode::OracleLeaf`] without
/// traversing their children. Every other reachable node must match the
/// supported grammar or the whole block is declined.
///
/// # Errors
///
/// Returns an error when the key, a child reference, an oracle leaf, or a frame
/// references a missing side-table entry, or when the reachable IR graph is
/// cyclic.
pub fn lower_stg_code_block_with_options(
    ir: &Ir,
    key: StgCodeKey,
    options: StgLowerOptions<'_>,
) -> Result<StgLowerOutcome, StgLowerError> {
    let plan = match preflight(ir, key, options)? {
        PreflightOutcome::Plan(plan) => plan,
        PreflightOutcome::Declined(decline) => return Ok(StgLowerOutcome::Declined(decline)),
    };
    match encode(ir, key, plan) {
        Ok(block) => Ok(StgLowerOutcome::Lowered(block)),
        Err(decline) => Ok(StgLowerOutcome::Declined(decline)),
    }
}

struct PreflightPlan {
    order: Vec<IrId>,
    oracle: Vec<bool>,
}

enum PreflightOutcome {
    Plan(PreflightPlan),
    Declined(StgDecline),
}

fn preflight(
    ir: &Ir,
    key: StgCodeKey,
    options: StgLowerOptions<'_>,
) -> Result<PreflightOutcome, StgLowerError> {
    if ir.arena.node(key.body).is_none() {
        return Err(StgLowerError::InvalidBody(key.body));
    }
    if let Some(frame) = key.frame
        && ir.frames.get(frame.index()).is_none()
    {
        return Err(StgLowerError::InvalidFrame(frame));
    }

    let mut oracle = vec![false; ir.arena.nodes().len()];
    for &id in options.oracle_leaves {
        let Some(slot) = oracle.get_mut(id.index()) else {
            return Err(StgLowerError::InvalidOracleLeaf(id));
        };
        *slot = true;
    }

    let mut state = vec![0_u8; ir.arena.nodes().len()];
    let mut frames = vec![None; ir.arena.nodes().len()];
    let mut order = Vec::new();
    let mut stack = vec![(key.body, key.frame, false)];
    while let Some((id, frame, exiting)) = stack.pop() {
        let Some(node) = ir.arena.node(id) else {
            return Err(StgLowerError::InvalidBody(id));
        };
        if exiting {
            state[id.index()] = 2;
            order.push(id);
            continue;
        }
        match state[id.index()] {
            2 => {
                if frames[id.index()] != frame {
                    return Ok(PreflightOutcome::Declined(StgDecline {
                        id,
                        kind: node.kind,
                        reason: StgDeclineReason::AmbiguousFrameContext,
                    }));
                }
                continue;
            }
            1 => return Err(StgLowerError::Cycle(id)),
            _ => {}
        }
        state[id.index()] = 1;
        frames[id.index()] = frame;
        stack.push((id, frame, true));
        if oracle[id.index()] {
            continue;
        }

        let children = match supported_children(ir, frame, node.kind, node.data) {
            Ok(children) => children,
            Err(reason) => {
                return Ok(PreflightOutcome::Declined(StgDecline {
                    id,
                    kind: node.kind,
                    reason,
                }));
            }
        };
        for (child, child_frame) in children.into_iter().rev() {
            if ir.arena.node(child).is_none() {
                return Err(StgLowerError::InvalidChild { from: id, child });
            }
            if state[child.index()] == 1 {
                return Err(StgLowerError::Cycle(child));
            }
            if state[child.index()] == 0 {
                stack.push((child, child_frame, false));
            } else if frames[child.index()] != child_frame {
                return Ok(PreflightOutcome::Declined(StgDecline {
                    id: child,
                    kind: ir.arena.node(child).map_or(IrKind::Null, |node| node.kind),
                    reason: StgDeclineReason::AmbiguousFrameContext,
                }));
            }
        }
    }
    Ok(PreflightOutcome::Plan(PreflightPlan { order, oracle }))
}

fn supported_children(
    ir: &Ir,
    frame: Option<FrameId>,
    kind: IrKind,
    data: IrData,
) -> Result<Vec<(IrId, Option<FrameId>)>, StgDeclineReason> {
    let current_frame = || {
        let frame = frame.ok_or(StgDeclineReason::MissingFrameContext)?;
        let info = ir
            .frames
            .get(frame.index())
            .ok_or(StgDeclineReason::MissingFrameContext)?;
        Ok((frame, info))
    };
    match (kind, data) {
        (IrKind::Int, IrData::Int(_))
        | (IrKind::Bool, IrData::Bool(_))
        | (IrKind::Null, IrData::None) => Ok(Vec::new()),
        (IrKind::LocalVar, IrData::Local { slot }) => {
            let (_, info) = current_frame()?;
            if slot >= info.slot_count {
                return Err(StgDeclineReason::InvalidFrameSlot);
            }
            Ok(Vec::new())
        }
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
            let (_, info) = current_frame()?;
            let capture = u16::try_from(depth)
                .ok()
                .zip(u16::try_from(slot).ok())
                .map(|(depth, slot)| Upvalue { depth, slot });
            if !capture.is_some_and(|capture| info.captures.contains(&capture)) {
                return Err(StgDeclineReason::InvalidFrameCapture);
            }
            Ok(Vec::new())
        }
        (IrKind::ThunkAlloc, IrData::Node(body)) => Ok(vec![(body, frame)]),
        (IrKind::Apply, IrData::Pair { first, second }) => {
            Ok(vec![(first, frame), (second, frame)])
        }
        (IrKind::BinOp, IrData::Binary { op, lhs, rhs }) => {
            if StgNumericBinOp::from_ir(op).is_none() {
                return Err(StgDeclineReason::NonNumericBinaryOperator);
            }
            Ok(vec![(lhs, frame), (rhs, frame)])
        }
        (IrKind::PrimOp, IrData::PrimOp { args, .. }) => {
            let children = ir
                .arena
                .child_slice(args)
                .ok_or(StgDeclineReason::UnsupportedShape)?;
            Ok(children
                .iter()
                .copied()
                .map(|child| (child, frame))
                .collect())
        }
        (
            IrKind::Select,
            IrData::Select {
                receiver,
                path,
                default,
                ..
            },
        ) => {
            if default.is_some() {
                return Err(StgDeclineReason::SelectDefault);
            }
            let Some(segments) = ir.attr_paths.get(path.index()) else {
                return Err(StgDeclineReason::UnsupportedShape);
            };
            if segments.is_empty() {
                return Err(StgDeclineReason::UnsupportedShape);
            }
            if segments
                .iter()
                .any(|segment| matches!(segment, IrAttrPathSegment::Dynamic(_)))
            {
                return Err(StgDeclineReason::DynamicSelectPath);
            }
            Ok(vec![(receiver, frame)])
        }
        (
            IrKind::Lambda,
            IrData::Lambda {
                pattern,
                body,
                frame,
            },
        ) => {
            let Some(pattern_node) = ir.arena.node(pattern) else {
                return Err(StgDeclineReason::UnsupportedShape);
            };
            if !matches!(
                (pattern_node.kind, pattern_node.data),
                (IrKind::Formal, IrData::Formal { default: None, .. })
            ) {
                return Err(StgDeclineReason::NonUnaryLambda);
            }
            let frame = frame.ok_or(StgDeclineReason::MissingFrameContext)?;
            let frame_info = ir
                .frames
                .get(frame.index())
                .ok_or(StgDeclineReason::MissingFrameContext)?;
            if frame_info.slot_count != 1 {
                return Err(StgDeclineReason::InvalidFrameSlot);
            }
            Ok(vec![(body, Some(frame))])
        }
        _ if matches!(
            kind,
            IrKind::Int
                | IrKind::Bool
                | IrKind::Null
                | IrKind::LocalVar
                | IrKind::UpvalVar
                | IrKind::ThunkAlloc
                | IrKind::Apply
                | IrKind::Select
                | IrKind::Lambda
                | IrKind::BinOp
                | IrKind::PrimOp
        ) =>
        {
            Err(StgDeclineReason::UnsupportedShape)
        }
        _ => Err(StgDeclineReason::UnsupportedKind),
    }
}

fn encode(ir: &Ir, key: StgCodeKey, plan: PreflightPlan) -> Result<StgCodeBlock, StgDecline> {
    let mut pcs = vec![None; ir.arena.nodes().len()];
    for (offset, &id) in plan.order.iter().enumerate() {
        let raw_pc = u32::try_from(offset).ok();
        let Some(pc) = raw_pc.filter(|pc| *pc <= MAX_OPERAND) else {
            return Err(decline(ir, id, StgDeclineReason::OperandTooWide));
        };
        pcs[id.index()] = Some(pc);
    }
    let root_pc = match pcs[key.body.index()] {
        Some(pc) => pc,
        None => return Err(decline(ir, key.body, StgDeclineReason::UnsupportedShape)),
    };

    let mut words = Vec::with_capacity(plan.order.len());
    let mut source_map = Vec::with_capacity(plan.order.len());
    let mut tables = EncodeTables::default();
    for id in plan.order {
        let node = match ir.arena.node(id) {
            Some(node) => node,
            None => return Err(decline(ir, id, StgDeclineReason::UnsupportedShape)),
        };
        let word = if plan.oracle[id.index()] {
            StgOpWord::pack(StgOpcode::OracleLeaf, node.kind as u32, 0)
        } else {
            encode_node(ir, id, node.kind, node.data, &pcs, &mut tables)?
        };
        let pc = words.len() as u32;
        words.push(word);
        source_map.push(StgSourceMapEntry {
            pc,
            ir: id,
            span: node.span,
        });
    }

    Ok(StgCodeBlock {
        key,
        root_pc,
        words: words.into_boxed_slice(),
        literals: tables.literals.into_boxed_slice(),
        primop_sites: tables.primop_sites.into_boxed_slice(),
        binary_sites: tables.binary_sites.into_boxed_slice(),
        closure_sites: tables.closure_sites.into_boxed_slice(),
        select_sites: tables.select_sites.into_boxed_slice(),
        source_map: source_map.into_boxed_slice(),
    })
}

#[derive(Default)]
struct EncodeTables {
    literals: Vec<StgLiteral>,
    primop_sites: Vec<StgPrimOpSite>,
    binary_sites: Vec<StgBinarySite>,
    closure_sites: Vec<StgClosureSite>,
    select_sites: Vec<StgSelectSite>,
}

fn encode_node(
    ir: &Ir,
    id: IrId,
    kind: IrKind,
    data: IrData,
    pcs: &[Option<u32>],
    tables: &mut EncodeTables,
) -> Result<StgOpWord, StgDecline> {
    let packed = match (kind, data) {
        (IrKind::Int, IrData::Int(value)) => {
            let literal = table_index(ir, id, tables.literals.len())?;
            tables.literals.push(StgLiteral::Int(value));
            StgOpWord::pack(StgOpcode::LiteralInt, literal, 0)
        }
        (IrKind::Bool, IrData::Bool(value)) => {
            StgOpWord::pack(StgOpcode::LiteralBool, u32::from(value), 0)
        }
        (IrKind::Null, IrData::None) => StgOpWord::pack(StgOpcode::LiteralNull, 0, 0),
        (IrKind::LocalVar, IrData::Local { slot }) => {
            pack_checked(ir, id, StgOpcode::Local, slot, 0)?
        }
        (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
            pack_checked(ir, id, StgOpcode::Upval, depth, slot)?
        }
        (IrKind::ThunkAlloc, IrData::Node(body)) => {
            StgOpWord::pack(StgOpcode::Thunk, child_pc(ir, id, body, pcs)?, 0)
        }
        (IrKind::Apply, IrData::Pair { first, second }) => StgOpWord::pack(
            StgOpcode::Apply1,
            child_pc(ir, id, first, pcs)?,
            child_pc(ir, id, second, pcs)?,
        ),
        (
            IrKind::Select,
            IrData::Select {
                site,
                receiver,
                path,
                default,
            },
        ) => {
            let index = table_index(ir, id, tables.select_sites.len())?;
            let default_pc = default
                .map(|default| child_pc(ir, id, default, pcs))
                .transpose()?;
            tables.select_sites.push(StgSelectSite {
                site,
                receiver_pc: child_pc(ir, id, receiver, pcs)?,
                path,
                default_pc,
            });
            StgOpWord::pack(StgOpcode::Select, index, 0)
        }
        (
            IrKind::Lambda,
            IrData::Lambda {
                pattern,
                body,
                frame,
            },
        ) => {
            let Some(frame) = frame else {
                return Err(decline(ir, id, StgDeclineReason::MissingFrameContext));
            };
            let index = table_index(ir, id, tables.closure_sites.len())?;
            tables.closure_sites.push(StgClosureSite {
                pattern,
                body_pc: child_pc(ir, id, body, pcs)?,
                frame,
            });
            StgOpWord::pack(StgOpcode::Lambda1, index, 0)
        }
        (IrKind::BinOp, IrData::Binary { op, lhs, rhs }) => {
            let Some(op) = StgNumericBinOp::from_ir(op) else {
                return Err(decline(ir, id, StgDeclineReason::NonNumericBinaryOperator));
            };
            let index = table_index(ir, id, tables.binary_sites.len())?;
            tables.binary_sites.push(StgBinarySite {
                op,
                lhs_pc: child_pc(ir, id, lhs, pcs)?,
                rhs_pc: child_pc(ir, id, rhs, pcs)?,
            });
            StgOpWord::pack(StgOpcode::BinaryNumeric, index, 0)
        }
        (IrKind::PrimOp, IrData::PrimOp { symbol, args }) => {
            let children = ir
                .arena
                .child_slice(args)
                .ok_or_else(|| decline(ir, id, StgDeclineReason::UnsupportedShape))?;
            let mut argument_pcs = Vec::with_capacity(children.len());
            for &child in children {
                argument_pcs.push(child_pc(ir, id, child, pcs)?);
            }
            let index = table_index(ir, id, tables.primop_sites.len())?;
            tables.primop_sites.push(StgPrimOpSite {
                symbol,
                argument_pcs: argument_pcs.into_boxed_slice(),
            });
            StgOpWord::pack(StgOpcode::PrimOp, index, 0)
        }
        _ => return Err(decline(ir, id, StgDeclineReason::UnsupportedShape)),
    };
    Ok(packed)
}

fn table_index(ir: &Ir, id: IrId, len: usize) -> Result<u32, StgDecline> {
    u32::try_from(len)
        .ok()
        .filter(|index| *index <= MAX_OPERAND)
        .ok_or_else(|| decline(ir, id, StgDeclineReason::OperandTooWide))
}

fn pack_checked(
    ir: &Ir,
    id: IrId,
    opcode: StgOpcode,
    operand_a: u32,
    operand_b: u32,
) -> Result<StgOpWord, StgDecline> {
    if operand_a > MAX_OPERAND || operand_b > MAX_OPERAND {
        return Err(decline(ir, id, StgDeclineReason::OperandTooWide));
    }
    Ok(StgOpWord::pack(opcode, operand_a, operand_b))
}

fn child_pc(ir: &Ir, parent: IrId, child: IrId, pcs: &[Option<u32>]) -> Result<u32, StgDecline> {
    pcs.get(child.index())
        .copied()
        .flatten()
        .ok_or_else(|| decline(ir, parent, StgDeclineReason::UnsupportedShape))
}

fn decline(ir: &Ir, id: IrId, reason: StgDeclineReason) -> StgDecline {
    let kind = ir.arena.node(id).map_or(IrKind::Null, |node| node.kind);
    StgDecline { id, kind, reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::parse_str;
    use crate::{lower, resolve};

    fn lowered(source: &str) -> Ir {
        lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("IR lowers")
    }

    fn key(ir: &Ir) -> StgCodeKey {
        StgCodeKey::new(StgModuleId::new(0x1234), ir.root, None)
    }

    fn lowered_block(ir: &Ir) -> StgCodeBlock {
        match lower_stg_code_block(ir, key(ir)).expect("preflight succeeds") {
            StgLowerOutcome::Lowered(block) => block,
            StgLowerOutcome::Declined(decline) => panic!("unexpected decline: {decline:?}"),
        }
    }

    #[test]
    fn lowers_literal_to_one_node_and_explicit_root_pc() {
        let ir = lowered("42");
        let block = lowered_block(&ir);

        assert_eq!(block.root_pc(), 0);
        assert_eq!(block.words().len(), 1);
        assert_eq!(block.words()[0].opcode(), StgOpcode::LiteralInt);
        assert_eq!(block.words()[0].operand_a(), 0);
        assert_eq!(block.literals(), &[StgLiteral::Int(42)]);
        assert!(block.primop_sites().is_empty());
        assert!(block.binary_sites().is_empty());
        assert!(block.closure_sites().is_empty());
        assert!(block.select_sites().is_empty());
    }

    #[test]
    fn lowers_exact_apply_local_upval_and_unary_lambdas() {
        let ir = lowered("x: y: x y");
        let block = lowered_block(&ir);
        let opcodes = block
            .words()
            .iter()
            .map(|word| word.opcode())
            .collect::<Vec<_>>();

        assert!(opcodes.contains(&StgOpcode::Local));
        assert!(opcodes.contains(&StgOpcode::Upval));
        assert!(opcodes.contains(&StgOpcode::Apply1));
        assert_eq!(
            opcodes
                .iter()
                .filter(|opcode| **opcode == StgOpcode::Lambda1)
                .count(),
            2
        );
        assert_eq!(block.closure_sites().len(), 2);
        assert!(
            block
                .closure_sites()
                .iter()
                .all(|site| { block.words().get(site.body_pc() as usize).is_some() })
        );
    }

    #[test]
    fn keeps_source_locations_out_of_hot_words() {
        let ir = lowered("42");
        let block = lowered_block(&ir);
        let root = ir.arena.node(ir.root).expect("root exists");

        assert_eq!(block.source_map().len(), block.words().len());
        let source = block
            .source_at(block.root_pc())
            .expect("root PC has source");
        assert_eq!(source.pc(), block.root_pc());
        assert_eq!(source.ir(), ir.root);
        assert_eq!(source.span(), root.span);
        assert!(block.source_at(block.words().len() as u32).is_none());
    }

    #[test]
    fn static_select_can_resume_from_an_explicit_oracle_leaf() {
        let ir = lowered("{ a = 1; }.a");
        let root = ir.arena.node(ir.root).expect("root exists");
        let IrData::Select {
            site,
            receiver,
            path,
            ..
        } = root.data
        else {
            panic!("select expected");
        };
        let outcome = lower_stg_code_block_with_options(
            &ir,
            key(&ir),
            StgLowerOptions::new().with_oracle_leaves(&[receiver]),
        )
        .expect("preflight succeeds");
        let StgLowerOutcome::Lowered(block) = outcome else {
            panic!("select with explicit oracle receiver lowers");
        };

        assert!(
            block
                .words()
                .iter()
                .any(|word| word.opcode() == StgOpcode::OracleLeaf)
        );
        assert_eq!(
            block.words().last().map(|word| word.opcode()),
            Some(StgOpcode::Select)
        );
        let [select] = block.select_sites() else {
            panic!("one select site expected");
        };
        assert_eq!(select.site(), site);
        assert_eq!(select.path(), path);
        assert_eq!(select.default_pc(), None);
        assert_eq!(
            block.words()[select.receiver_pc() as usize].opcode(),
            StgOpcode::OracleLeaf
        );
    }

    #[test]
    fn lowers_numeric_binary_nodes_to_cold_descriptors() {
        let ir = lowered("1 + 2");
        let block = lowered_block(&ir);
        let [site] = block.binary_sites() else {
            panic!("one numeric binary site expected");
        };

        assert_eq!(
            block.words()[block.root_pc() as usize].opcode(),
            StgOpcode::BinaryNumeric
        );
        assert_eq!(site.op(), StgNumericBinOp::Add);
        assert_eq!(
            block.words()[site.lhs_pc() as usize].opcode(),
            StgOpcode::LiteralInt
        );
        assert_eq!(
            block.words()[site.rhs_pc() as usize].opcode(),
            StgOpcode::LiteralInt
        );
    }

    #[test]
    fn preserves_primop_symbol_and_ordered_argument_pcs() {
        let ir = lowered("builtins.elemAt null 0");
        let block = lowered_block(&ir);
        let [site] = block.primop_sites() else {
            panic!("one primop site expected");
        };

        assert_eq!(
            ir.symbols.resolve(site.symbol()),
            Some(b"elemAt".as_slice())
        );
        assert_eq!(site.argument_pcs().len(), 2);
        assert_eq!(
            block.words()[site.argument_pcs()[0] as usize].opcode(),
            StgOpcode::LiteralNull
        );
        assert_eq!(
            block.words()[site.argument_pcs()[1] as usize].opcode(),
            StgOpcode::LiteralInt
        );
    }

    #[test]
    fn preserves_lambda_pattern_body_and_frame_metadata() {
        let ir = lowered("x: x + 1");
        let block = lowered_block(&ir);
        let [site] = block.closure_sites() else {
            panic!("one closure site expected");
        };
        let lambda = ir.arena.node(ir.root).expect("lambda root exists");
        let IrData::Lambda {
            pattern,
            frame: Some(frame),
            ..
        } = lambda.data
        else {
            panic!("unary lambda payload expected");
        };

        assert_eq!(site.pattern(), pattern);
        assert_eq!(site.frame(), frame);
        assert_eq!(
            block.words()[site.body_pc() as usize].opcode(),
            StgOpcode::BinaryNumeric
        );
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let ir = lowered("x: builtins.elemAt null (x + 1)");
        let first = lowered_block(&ir);
        let second = lowered_block(&ir);

        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    }

    #[test]
    fn unsupported_node_declines_the_whole_block() {
        let ir = lowered("1 == 2");
        let outcome = lower_stg_code_block(&ir, key(&ir)).expect("preflight succeeds");
        let StgLowerOutcome::Declined(decline) = outcome else {
            panic!("binary operation must be declined");
        };

        assert_eq!(decline.kind(), IrKind::BinOp);
        assert_eq!(decline.reason(), StgDeclineReason::NonNumericBinaryOperator);
    }

    #[test]
    fn local_body_without_a_frame_declines_atomically() {
        let ir = lowered("x: x");
        let lambda = ir.arena.node(ir.root).expect("lambda root exists");
        let IrData::Lambda { body, .. } = lambda.data else {
            panic!("lambda payload expected");
        };
        let outcome = lower_stg_code_block(&ir, StgCodeKey::new(StgModuleId::new(7), body, None))
            .expect("preflight succeeds");
        let StgLowerOutcome::Declined(decline) = outcome else {
            panic!("frame-less local body must decline");
        };

        assert_eq!(decline.kind(), IrKind::LocalVar);
        assert_eq!(decline.reason(), StgDeclineReason::MissingFrameContext);
    }

    #[test]
    fn unary_lambda_declines_when_its_frame_cannot_hold_the_formal() {
        let mut ir = lowered("x: x");
        let lambda = *ir.arena.node(ir.root).expect("lambda root exists");
        let IrData::Lambda {
            frame: Some(frame), ..
        } = lambda.data
        else {
            panic!("lambda frame expected");
        };
        ir.frames[frame.index()].slot_count = 0;

        let outcome = lower_stg_code_block(&ir, key(&ir)).expect("preflight succeeds");
        let StgLowerOutcome::Declined(decline) = outcome else {
            panic!("incompatible lambda frame must decline");
        };
        assert_eq!(decline.kind(), IrKind::Lambda);
        assert_eq!(decline.reason(), StgDeclineReason::InvalidFrameSlot);
    }

    #[test]
    fn missing_key_frame_is_reported_as_malformed_input() {
        let ir = lowered("42");
        let error = lower_stg_code_block(
            &ir,
            StgCodeKey::new(StgModuleId::new(7), ir.root, Some(FrameId::new(u32::MAX))),
        )
        .expect_err("missing key frame must be rejected");

        assert_eq!(error, StgLowerError::InvalidFrame(FrameId::new(u32::MAX)));
    }

    #[test]
    fn select_default_declines_before_encoding_partial_tables() {
        let ir = lowered("{}.missing or 1");
        let outcome = lower_stg_code_block(&ir, key(&ir)).expect("preflight succeeds");
        let StgLowerOutcome::Declined(decline) = outcome else {
            panic!("select defaults remain outside the admitted grammar");
        };

        assert_eq!(decline.kind(), IrKind::Select);
        assert_eq!(decline.reason(), StgDeclineReason::SelectDefault);
    }

    #[test]
    fn empty_select_path_declines_before_receiver_encoding() {
        let mut ir = lowered("(1 / 0).a");
        let root = ir.arena.node(ir.root).expect("select root exists");
        let IrData::Select { path, .. } = root.data else {
            panic!("select root expected");
        };
        ir.attr_paths[path.index()] = Box::new([]);

        let outcome = lower_stg_code_block(&ir, key(&ir)).expect("preflight succeeds");
        let StgLowerOutcome::Declined(decline) = outcome else {
            panic!("empty select path must decline atomically");
        };

        assert_eq!(decline.kind(), IrKind::Select);
        assert_eq!(decline.reason(), StgDeclineReason::UnsupportedShape);
    }

    #[test]
    fn dynamic_select_path_declines_before_encoding() {
        let ir = lowered("x: x.${x}");
        let outcome = lower_stg_code_block(&ir, key(&ir)).expect("preflight succeeds");
        let StgLowerOutcome::Declined(decline) = outcome else {
            panic!("dynamic select path must decline atomically");
        };

        assert_eq!(decline.kind(), IrKind::Select);
        assert_eq!(decline.reason(), StgDeclineReason::DynamicSelectPath);
    }
}
