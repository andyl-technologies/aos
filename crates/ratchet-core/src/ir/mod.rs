//! Lowered arena IR for scope-resolved Nix expressions.
//!
//! This module owns the first concrete IR layer after scope resolution. It
//! lowers the parser arena into fixed-stride [`IrNode`] records, moves variable
//! arity payloads into side tables, and materializes conservative
//! [`IrKind::ThunkAlloc`] nodes at lazy positions.

use std::collections::BTreeMap;

use thiserror::Error;

use super::{FrameInfo, ResolvedAst};
use crate::builtins::{
    BuiltinDirect, BuiltinEffect, direct_builtin, is_known_builtin_attr, lookup_builtin,
};
use crate::syntax::{
    AstErrorKind, BinOpKind, ChildSlice, Node, NodeData, NodeId, NodeKind, Span, Symbol,
    SymbolTable, UnaryOpKind,
};

mod annotate;
mod facts;
mod render;
mod simplify;

pub use annotate::{
    IR_ANALYSIS_VERSION, IrAnalysisError, IrAnalysisReport, IrDependencyFootprint,
    IrFrameCaptureFootprint, annotate_import_ir, annotate_ir,
};
pub use render::render_ir;
pub use simplify::{
    PASS_SET_VERSION, PassOutcome, SIMPLIFY_MAX_ITERS, SimplifyError, SimplifyPass, SimplifyPhase,
    simplify_ir, simplify_with_passes,
};
pub use facts::{
    BindingLowering, CapturePlan, Cardinality, Escape, ExprFacts, FlatCaptureAccess, IrFacts,
    LambdaAttrKeys, LambdaAttrValueSummary, LambdaCallSummary, LambdaDemand, LambdaFormalSummary,
    SharedChainReason, Strictness, ThunkSharing,
};

/// Lowers a scope-resolved AST into evaluator IR.
///
/// # Errors
///
/// Returns [`IrError`] when the resolved AST contains an invalid shape for the
/// lowering contract or when an IR side table exceeds `u32` addressability.
pub fn lower(resolved: ResolvedAst) -> Result<Ir, IrError> {
    lower_with_options(resolved, IrLowerOptions::new())
}

/// Lowers a scope-resolved AST into evaluator IR with explicit options.
///
/// # Errors
///
/// Returns [`IrError`] when the resolved AST contains an invalid shape for the
/// lowering contract or when an IR side table exceeds `u32` addressability.
pub fn lower_with_options(resolved: ResolvedAst, options: IrLowerOptions) -> Result<Ir, IrError> {
    IrLowerer::new(resolved, options).lower()
}

/// The language-agnostic default node effect classifier.
///
/// The engine has no built-in knowledge of which node kinds are effectful;
/// absent a dialect-supplied classifier, every node carries a pure effect stamp.
/// A language dialect overrides this via [`IrLowerOptions::with_effect_of`] (see
/// the `Dialect` trait in `ratchet-dialect`).
pub fn all_pure(_kind: IrKind) -> EffectClass {
    EffectClass::pure()
}

/// The language-agnostic default direct-builtin effect classifier.
///
/// Direct builtin metadata is dialect vocabulary. Without a dialect-supplied
/// classifier, the engine treats those nodes as pure too.
pub fn all_pure_builtin(_name: Option<&[u8]>, _effect: BuiltinEffect) -> EffectClass {
    EffectClass::pure()
}

/// The language-agnostic default direct-builtin dialect-op classifier.
///
/// Without a dialect-supplied mapping, direct builtins never lower to dialect
/// operations.
pub fn no_builtin_dialect_op(_name: Option<&[u8]>, _direct: BuiltinDirect) -> Option<IrDialectOp> {
    None
}

/// The language-agnostic default dynamic-scope variable operation.
///
/// Without a dialect-supplied operation, unresolved names under dynamic scopes
/// are rejected during lowering.
pub fn no_dynamic_scope_var_op() -> Option<IrDialectOp> {
    None
}

/// The language-agnostic default dialect-op effect classifier.
///
/// Unknown dialect operations carry no engine-owned effect knowledge. Dialects
/// install a classifier for their operation keys when lowering.
pub fn all_pure_dialect_op(_op: IrDialectOp) -> EffectClass {
    EffectClass::pure()
}

/// Configuration for IR lowering.
#[derive(Clone, Copy, Debug)]
pub struct IrLowerOptions {
    dynamic_builtin_scope: bool,
    /// The classifier mapping each node kind to its effect class.
    ///
    /// Defaults to [`all_pure`]; a language dialect installs its own
    /// classifier so that, e.g., derivation construction is effectful.
    effect_of: fn(IrKind) -> EffectClass,
    /// The classifier mapping dialect builtin metadata to effect stamps.
    ///
    /// Defaults to [`all_pure_builtin`]; a language dialect installs its own
    /// classifier so impure builtins are not hardcoded in the engine.
    builtin_effect_of: fn(Option<&[u8]>, BuiltinEffect) -> EffectClass,
    /// The dialect-owned operation key for a direct builtin, when that builtin
    /// should lower to a dialect operation instead of a normal primop.
    builtin_dialect_op: fn(Option<&[u8]>, BuiltinDirect) -> Option<IrDialectOp>,
    /// The dialect-owned operation key used for unresolved dynamic-scope names.
    dynamic_scope_var_op: fn() -> Option<IrDialectOp>,
    /// The classifier mapping dialect operation keys to effect stamps.
    dialect_op_effect_of: fn(IrDialectOp) -> EffectClass,
}

impl PartialEq for IrLowerOptions {
    /// Compares lowering options by their flags and the address of the
    /// installed effect classifier.
    ///
    /// Function pointers have no meaningful identity guarantee, so the
    /// classifier is compared only by raw address; two options carrying
    /// distinct-but-equivalent classifiers may therefore compare unequal.
    fn eq(&self, other: &Self) -> bool {
        self.dynamic_builtin_scope == other.dynamic_builtin_scope
            && std::ptr::fn_addr_eq(self.effect_of, other.effect_of)
            && std::ptr::fn_addr_eq(self.builtin_effect_of, other.builtin_effect_of)
            && std::ptr::fn_addr_eq(self.builtin_dialect_op, other.builtin_dialect_op)
            && std::ptr::fn_addr_eq(self.dynamic_scope_var_op, other.dynamic_scope_var_op)
            && std::ptr::fn_addr_eq(self.dialect_op_effect_of, other.dialect_op_effect_of)
    }
}

impl Eq for IrLowerOptions {}

impl Default for IrLowerOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl IrLowerOptions {
    /// Creates default IR lowering options with the language-agnostic
    /// [`all_pure`] effect classifier.
    pub const fn new() -> Self {
        Self {
            dynamic_builtin_scope: false,
            effect_of: all_pure,
            builtin_effect_of: all_pure_builtin,
            builtin_dialect_op: no_builtin_dialect_op,
            dynamic_scope_var_op: no_dynamic_scope_var_op,
            dialect_op_effect_of: all_pure_dialect_op,
        }
    }

    /// Creates options for modules whose global `builtins` binding is runtime-shadowable.
    pub const fn with_dynamic_builtin_scope() -> Self {
        Self {
            dynamic_builtin_scope: true,
            effect_of: all_pure,
            builtin_effect_of: all_pure_builtin,
            builtin_dialect_op: no_builtin_dialect_op,
            dynamic_scope_var_op: no_dynamic_scope_var_op,
            dialect_op_effect_of: all_pure_dialect_op,
        }
    }

    /// Returns a copy of these options with the given effect classifier
    /// installed.
    ///
    /// A language dialect uses this to supply its effect classification (e.g.
    /// classifying derivation nodes as effectful) without the engine carrying
    /// any language-specific knowledge.
    pub const fn with_effect_of(mut self, effect_of: fn(IrKind) -> EffectClass) -> Self {
        self.effect_of = effect_of;
        self
    }

    /// Returns a copy of these options with the given direct-builtin effect
    /// classifier installed.
    ///
    /// The classifier receives the interned builtin name, when it can be resolved,
    /// plus the builtin metadata's coarse effect marker. Dialects use the name to
    /// refine effect members (for example `import` vs. `readFile`) without making
    /// the engine own a closed Nix effect enum.
    pub const fn with_builtin_effect_of(
        mut self,
        builtin_effect_of: fn(Option<&[u8]>, BuiltinEffect) -> EffectClass,
    ) -> Self {
        self.builtin_effect_of = builtin_effect_of;
        self
    }

    /// Returns a copy of these options with the given direct-builtin dialect-op
    /// classifier installed.
    ///
    /// Dialects use this hook for builtins that are not ordinary primops but
    /// still need a compact, statically locatable operation in lowered IR.
    pub const fn with_builtin_dialect_op(
        mut self,
        builtin_dialect_op: fn(Option<&[u8]>, BuiltinDirect) -> Option<IrDialectOp>,
    ) -> Self {
        self.builtin_dialect_op = builtin_dialect_op;
        self
    }

    /// Returns a copy of these options with a dynamic-scope variable operation
    /// installed.
    ///
    /// Languages with `with`-style dynamic lookup provide an operation key here;
    /// languages without dynamic scope leave the default in place and lowering
    /// rejects unresolved dynamic-scope variables.
    pub const fn with_dynamic_scope_var_op(
        mut self,
        dynamic_scope_var_op: fn() -> Option<IrDialectOp>,
    ) -> Self {
        self.dynamic_scope_var_op = dynamic_scope_var_op;
        self
    }

    /// Returns a copy of these options with the given dialect-op effect
    /// classifier installed.
    pub const fn with_dialect_op_effect_of(
        mut self,
        dialect_op_effect_of: fn(IrDialectOp) -> EffectClass,
    ) -> Self {
        self.dialect_op_effect_of = dialect_op_effect_of;
        self
    }

    /// Returns whether builtin references must remain dynamic runtime lookups.
    pub const fn dynamic_builtin_scope(&self) -> bool {
        self.dynamic_builtin_scope
    }

    /// Returns the effect classifier installed in these options.
    pub const fn effect_of(&self) -> fn(IrKind) -> EffectClass {
        self.effect_of
    }

    /// Returns the direct-builtin effect classifier installed in these options.
    pub const fn builtin_effect_of(&self) -> fn(Option<&[u8]>, BuiltinEffect) -> EffectClass {
        self.builtin_effect_of
    }

    /// Returns the direct-builtin dialect-op classifier installed in these options.
    pub const fn builtin_dialect_op(
        &self,
    ) -> fn(Option<&[u8]>, BuiltinDirect) -> Option<IrDialectOp> {
        self.builtin_dialect_op
    }

    /// Returns the dynamic-scope variable operation provider installed in these options.
    pub const fn dynamic_scope_var_op(&self) -> fn() -> Option<IrDialectOp> {
        self.dynamic_scope_var_op
    }

    /// Returns the dialect-op effect classifier installed in these options.
    pub const fn dialect_op_effect_of(&self) -> fn(IrDialectOp) -> EffectClass {
        self.dialect_op_effect_of
    }
}

/// A lowered evaluator IR artifact.
#[derive(Clone, Debug)]
pub struct Ir {
    /// The root expression node.
    pub root: IrId,
    /// The fixed-stride node arena plus child pool.
    pub arena: IrArena,
    /// Conservative or analysis-refined per-node facts indexed by [`IrId`].
    pub facts: IrFacts,
    /// File-local symbols referenced by the IR.
    pub symbols: SymbolTable,
    /// Scope frame metadata carried from resolution.
    pub frames: Box<[FrameInfo]>,
    /// Dynamic `with` chains translated to lowered scrutinee nodes.
    pub with_chains: Box<[IrWithChain]>,
    /// Attribute paths referenced by access nodes.
    pub attr_paths: Box<[Box<[IrAttrPathSegment]>]>,
    /// Binding runs referenced by `let` and attrset construction nodes.
    pub bindings: Box<[IrBinding]>,
    /// Static attribute-set shapes referenced by construction nodes.
    pub shapes: Box<[IrShape]>,
}

impl Ir {
    /// Returns the analysis facts attached to one node.
    pub fn node_facts(&self, id: IrId) -> Option<ExprFacts> {
        self.facts.get(id)
    }
}

/// A compact IR node id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IrId(u32);

impl IrId {
    /// Creates an IR id from a raw arena index.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw `u32` id.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the id as a `usize` index.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A contiguous run of child IR node ids.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IrChildSlice {
    /// The first child-pool offset.
    pub start: u32,
    /// The number of children.
    pub len: u32,
}

impl IrChildSlice {
    /// Creates a child slice from a raw start and length.
    pub const fn new(start: u32, len: u32) -> Self {
        Self { start, len }
    }

    /// Returns the slice length as a `usize`.
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Returns whether the slice is empty.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// A contiguous run of IR binding records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IrBindingSlice {
    /// The first binding-table offset.
    pub start: u32,
    /// The number of bindings.
    pub len: u32,
}

impl IrBindingSlice {
    /// Creates a binding slice from a raw start and length.
    pub const fn new(start: u32, len: u32) -> Self {
        Self { start, len }
    }

    /// Returns the slice length as a `usize`.
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Returns whether the binding slice is empty.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// An attribute-path side-table id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IrAttrPathId(u32);

impl IrAttrPathId {
    /// Creates an attribute-path id from a raw side-table index.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw `u32` id.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the id as a `usize` index.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// An attribute-set shape side-table id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IrShapeId(u32);

impl IrShapeId {
    /// Creates a shape id from a raw side-table index.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw `u32` id.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the id as a `usize` index.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A stable inline-cache site id for an attribute lookup node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IrInlineCacheSiteId(u32);

impl IrInlineCacheSiteId {
    /// Creates an inline-cache site id from a raw counter value.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw `u32` site id.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the site id as a `usize` index.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A compact dialect-owned operation key used by the generic primop escape hatch.
///
/// The engine stores and serializes the key, but the key space is owned by the
/// installed dialect. Key `0` is reserved for "no dialect operation"; dialects
/// should assign stable non-zero keys for persistent parse-cache compatibility.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct IrDialectOp(u16);

impl IrDialectOp {
    /// Creates a dialect operation key from a stable raw value.
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the raw operation key.
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// A fixed-stride IR node.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IrNode {
    /// The node taxonomy entry.
    pub kind: IrKind,
    /// The source byte span for diagnostics and deoptimization.
    pub span: Span,
    /// Whether evaluating this node can perform externally observable work.
    pub effect: EffectClass,
    /// The kind-specific node payload.
    pub data: IrData,
}

impl IrNode {
    /// Creates an IR node.
    pub const fn new(kind: IrKind, span: Span, effect: EffectClass, data: IrData) -> Self {
        Self {
            kind,
            span,
            effect,
            data,
        }
    }
}

/// The closed IR node taxonomy.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IrKind {
    /// An integer literal.
    Int,
    /// A floating-point literal.
    Float,
    /// A boolean literal.
    Bool,
    /// A null literal.
    Null,
    /// A string literal.
    Str,
    /// A path literal.
    Path,
    /// A search-path literal.
    SearchPath,
    /// A URI literal.
    Uri,
    /// A resolved local variable access.
    LocalVar,
    /// A resolved upvalue access.
    UpvalVar,
    /// A resolved global variable access.
    GlobalVar,
    /// A statically known builtin attribute value.
    BuiltinAttr,
    /// A list construction.
    List,
    /// An attribute-set construction.
    AttrSet,
    /// A lambda closure construction.
    Lambda,
    /// A formal-argument set pattern.
    FormalSet,
    /// A formal argument entry.
    Formal,
    /// A function application.
    Apply,
    /// Attribute selection.
    Select,
    /// Attribute membership test.
    HasAttr,
    /// A recursive let expression.
    Let,
    /// A `with` expression.
    With,
    /// An assertion expression.
    Assert,
    /// A conditional expression.
    If,
    /// A binary operator.
    BinOp,
    /// A unary operator.
    UnaryOp,
    /// A string interpolation operation.
    Interp,
    /// A conservative lazy thunk allocation.
    ThunkAlloc,
    /// A direct primitive operation call or dialect-owned operation.
    PrimOp,
}

/// The kind-specific payload for an IR node.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IrData {
    /// The node carries no payload.
    None,
    /// The node carries an integer literal.
    Int(i64),
    /// The node carries a floating-point literal.
    Float(f64),
    /// The node carries a boolean literal.
    Bool(bool),
    /// The node carries an interned symbol.
    Symbol(Symbol),
    /// The node represents a global-variable probe.
    GlobalVar {
        /// The stable inline-cache site for scoped-global probes.
        site: IrInlineCacheSiteId,
        /// The unresolved global symbol to probe.
        symbol: Symbol,
    },
    /// The node represents a search-path literal.
    SearchPath {
        /// The literal text, including the surrounding angle brackets.
        literal: Symbol,
        /// The optional lowered expression supplying a lexical `__nixPath`.
        search_path: Option<IrId>,
    },
    /// The node references one child.
    Node(IrId),
    /// The node references two children.
    Pair {
        /// The first child node.
        first: IrId,
        /// The second child node.
        second: IrId,
    },
    /// The node references three children.
    Triple {
        /// The first child node.
        first: IrId,
        /// The second child node.
        second: IrId,
        /// The third child node.
        third: IrId,
    },
    /// The node references a variable-length child run.
    Children(IrChildSlice),
    /// The node references a binding-table run.
    Bindings(IrBindingSlice),
    /// The node represents a binary operator.
    Binary {
        /// The operator being applied.
        op: BinOpKind,
        /// The left-hand operand.
        lhs: IrId,
        /// The right-hand operand.
        rhs: IrId,
    },
    /// The node represents a unary operator.
    Unary {
        /// The operator being applied.
        op: UnaryOpKind,
        /// The operand.
        operand: IrId,
    },
    /// The node represents an attribute selection.
    Select {
        /// The stable inline-cache site for this lookup.
        site: IrInlineCacheSiteId,
        /// The selected expression.
        receiver: IrId,
        /// The lowered attribute path.
        path: IrAttrPathId,
        /// The optional `or` default.
        default: Option<IrId>,
    },
    /// The node represents an attribute membership test.
    HasAttr {
        /// The stable inline-cache site for this lookup.
        site: IrInlineCacheSiteId,
        /// The tested expression.
        receiver: IrId,
        /// The lowered attribute path.
        path: IrAttrPathId,
    },
    /// The node represents a direct primitive operation call.
    PrimOp {
        /// The statically known primitive operation symbol.
        symbol: Symbol,
        /// The lowered argument nodes.
        args: IrChildSlice,
    },
    /// The node represents a dialect-owned operation with one strict child.
    DialectNode {
        /// The dialect-owned operation key.
        op: IrDialectOp,
        /// The operation argument.
        argument: IrId,
    },
    /// The node represents a dialect-owned dynamic-scope variable probe.
    DialectScopeVar {
        /// The dialect-owned operation key.
        op: IrDialectOp,
        /// The stable inline-cache site for dynamic-scope probes.
        site: IrInlineCacheSiteId,
        /// The unresolved symbol to probe.
        symbol: Symbol,
        /// The resolver dynamic-scope chain id.
        chain: u32,
    },
    /// The node represents a lambda closure.
    Lambda {
        /// The lowered parameter pattern.
        pattern: IrId,
        /// The lowered body expression.
        body: IrId,
        /// The resolver frame attached to the lambda.
        frame: Option<super::FrameId>,
    },
    /// The node represents a `let ... in ...` expression.
    Let {
        /// The binding run.
        bindings: IrBindingSlice,
        /// The lowered body expression.
        body: IrId,
        /// The resolver frame attached to the let.
        frame: Option<super::FrameId>,
    },
    /// The node represents an attribute set.
    AttrSet {
        /// The static hidden-class shape reference.
        shape: IrShapeId,
        /// The binding run.
        bindings: IrBindingSlice,
        /// Whether the source set was recursive.
        recursive: bool,
        /// Whether any key is dynamic.
        has_dynamic: bool,
        /// The resolver frame attached to a recursive set.
        frame: Option<super::FrameId>,
    },
    /// The node represents a formal-argument set.
    FormalSet {
        /// Formal entry nodes.
        formals: IrChildSlice,
        /// Whether the pattern accepts extra arguments.
        ellipsis: bool,
        /// The optional `@` alias.
        alias: Option<Symbol>,
    },
    /// The node represents one formal argument.
    Formal {
        /// The formal name.
        name: Symbol,
        /// The optional lazy default expression.
        default: Option<IrId>,
    },
    /// The node represents a local slot access.
    Local {
        /// The local frame slot.
        slot: u32,
    },
    /// The node represents an upvalue access.
    Upval {
        /// The number of parent frames to walk.
        depth: u32,
        /// The slot inside the target frame.
        slot: u32,
    },
}

/// A compact effect stamp carried by an IR node.
///
/// The engine stores a fixed-size stamp in [`IrNode`] and serializes the stamp in
/// the parse cache, but it does not own the lattice's member set. Dialects assign
/// stable keys and speculation behavior via [`EffectClass::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EffectClass {
    speculable: bool,
    key: u8,
}

impl EffectClass {
    /// Creates an effect stamp with a dialect-owned cache key.
    ///
    /// The `effect_key` is serialized in parse-cache IR artifacts. Dialects must
    /// keep assigned keys stable for as long as those artifacts remain readable.
    pub const fn new(effect_key: u8, speculable: bool) -> Self {
        Self {
            speculable,
            key: effect_key,
        }
    }

    /// Creates the language-agnostic pure effect stamp.
    ///
    /// Key `0` is reserved for pure, speculable nodes so old parse-cache artifacts
    /// and dialect-specific effect maps agree on the common bottom member.
    pub const fn pure() -> Self {
        Self::new(0, true)
    }

    /// Decodes an effect stamp from a parse-cache key.
    ///
    /// Key `0` is pure and speculable; every other key is conservatively decoded
    /// as non-speculable until the dialect-specific classifier revalidates it.
    pub const fn from_cache_key(effect_key: u8) -> Self {
        Self::new(effect_key, effect_key == 0)
    }

    /// Returns whether this effect stamp permits speculative evaluation.
    pub const fn is_speculable(self) -> bool {
        self.speculable
    }

    /// Returns the stable dialect-owned cache key for this effect stamp.
    pub const fn effect_key(self) -> u8 {
        self.key
    }
}

/// An effect lattice consumed by the engine's speculation and caching passes.
///
/// The engine only needs to know whether a node may be speculated and a stable
/// key for cache encoding. Dialects can assign a richer member set without
/// changing the fixed force-path storage in [`IrNode`].
pub trait Effect {
    /// Returns whether a node carrying this effect may be speculated by later
    /// passes (i.e. it performs no externally observable work).
    fn is_speculable(&self) -> bool;

    /// Returns a stable numeric key identifying this effect for cache encoding.
    fn effect_key(&self) -> u8;
}

impl Effect for EffectClass {
    fn is_speculable(&self) -> bool {
        (*self).is_speculable()
    }

    fn effect_key(&self) -> u8 {
        (*self).effect_key()
    }
}

/// A lowered attribute path segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrAttrPathSegment {
    /// A statically known interned attribute key.
    Static(Symbol),
    /// A dynamic `${...}` key expression.
    Dynamic(IrId),
}

/// One lowered binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrBinding {
    /// The lowered binding key.
    pub key: IrAttrPathSegment,
    /// The source span of the binding key, when one exists.
    pub position: Option<Span>,
    /// The lowered value expression, usually a [`IrKind::ThunkAlloc`].
    pub value: IrId,
}

/// A lowered static attribute-set shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrShape {
    /// Statically known keys in source insertion order.
    pub keys: Box<[Symbol]>,
}

impl IrShape {
    /// Creates a shape from statically known keys.
    pub fn new(keys: Box<[Symbol]>) -> Self {
        Self { keys }
    }
}

/// An innermost-first dynamic `with` probe chain in lowered IR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrWithChain {
    /// Active `with` scrutinee nodes, ordered innermost to outermost.
    pub scopes: Box<[IrId]>,
}

impl IrWithChain {
    /// Creates a `with` chain from lowered scrutinee node ids.
    pub fn new(scopes: Box<[IrId]>) -> Self {
        Self { scopes }
    }
}

/// A fixed-stride IR arena plus variable-arity child pool.
#[derive(Clone, Debug, Default)]
pub struct IrArena {
    nodes: Vec<IrNode>,
    children: Vec<IrId>,
}

mod arena;

/// An IR lowering failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{kind} at byte span {span:?}")]
pub struct IrError {
    kind: IrErrorKind,
    span: Span,
}

impl IrError {
    /// Creates an IR error.
    pub const fn new(kind: IrErrorKind, span: Span) -> Self {
        Self { kind, span }
    }

    /// Returns the error category.
    pub const fn kind(&self) -> &IrErrorKind {
        &self.kind
    }

    /// Returns the source span associated with this error.
    pub const fn span(&self) -> Span {
        self.span
    }
}

/// The category of an IR lowering failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum IrErrorKind {
    /// The source AST contained an invalid node id.
    #[error("invalid AST node id {0}")]
    InvalidNodeId(u32),
    /// A child slice did not point into the AST child pool.
    #[error("invalid AST child slice")]
    InvalidChildSlice,
    /// A with-chain side-table id did not resolve through the scope table.
    #[error("invalid with-chain id {chain}")]
    InvalidWithChain {
        /// The missing resolver with-chain id.
        chain: u32,
    },
    /// A with-chain referenced a scrutinee that has not been lowered yet.
    #[error("with-chain {chain} references unlowered scope {scope:?}")]
    UnloweredWithScope {
        /// The resolver with-chain id.
        chain: u32,
        /// The AST node id of the referenced scrutinee.
        scope: NodeId,
    },
    /// The resolved AST had a node shape that lowering cannot consume.
    #[error("invalid {kind:?} node shape, expected {expected}")]
    InvalidNodeShape {
        /// The malformed node kind.
        kind: NodeKind,
        /// The expected payload shape.
        expected: &'static str,
    },
    /// Too many IR nodes were created.
    #[error("too many IR nodes")]
    TooManyNodes,
    /// Too many child ids were created.
    #[error("too many IR children")]
    TooManyChildren,
    /// Too many side-table entries were created.
    #[error("too many IR side-table entries")]
    TooManySideTableEntries,
    /// Too many inline-cache sites were created.
    #[error("too many IR inline-cache sites")]
    TooManyInlineCacheSites,
    /// A static binding key could not be lowered.
    #[error("invalid binding key")]
    InvalidBindingKey,
    /// A resolved inherit binding had an unexpected source shape.
    #[error("invalid inherit source shape")]
    InvalidInheritSource,
    /// The resolved AST needed a dialect operation that was not registered.
    #[error("unsupported dialect operation: {operation}")]
    UnsupportedDialectOp {
        /// The unsupported operation needed by lowering.
        operation: &'static str,
    },
    /// A raw AST arena error escaped resolution.
    #[error("AST arena error: {0}")]
    Ast(AstErrorKind),
}

impl From<crate::syntax::AstError> for IrError {
    fn from(error: crate::syntax::AstError) -> Self {
        Self::new(IrErrorKind::Ast(error.kind().clone()), error.span())
    }
}

struct IrLowerer {
    resolved: ResolvedAst,
    options: IrLowerOptions,
    arena: IrArena,
    lowered_nodes: BTreeMap<NodeId, IrId>,
    attr_paths: Vec<Box<[IrAttrPathSegment]>>,
    bindings: Vec<IrBinding>,
    shapes: Vec<IrShape>,
    with_chains: Vec<IrWithChain>,
    with_chain_map: BTreeMap<u32, u32>,
    inherit_from_thunks: BTreeMap<NodeId, IrId>,
    inline_cache_sites: u32,
}

mod lowering;
mod primops;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LazySecond {
    Yes,
    No,
}

fn is_trivial_value(kind: IrKind) -> bool {
    matches!(
        kind,
        IrKind::Int | IrKind::Float | IrKind::Bool | IrKind::Null | IrKind::Str | IrKind::Uri
    )
}

#[cfg(test)]
mod tests;
