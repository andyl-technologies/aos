//! Lowered arena IR for scope-resolved Nix expressions.
//!
//! This module owns the first concrete IR layer after scope resolution. It
//! lowers the parser arena into fixed-stride [`IrNode`] records, moves variable
//! arity payloads into side tables, and materializes conservative
//! [`IrKind::ThunkAlloc`] nodes at lazy positions.

use std::collections::BTreeMap;

use thiserror::Error;

use super::{FrameInfo, ResolvedAst};
use crate::compile::builtins::{BuiltinDirect, BuiltinEffect, direct_builtin, lookup_builtin};
use crate::syntax::{
    AstErrorKind, BinOpKind, ChildSlice, Node, NodeData, NodeId, NodeKind, Span, Symbol,
    SymbolTable, UnaryOpKind,
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

/// Configuration for IR lowering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IrLowerOptions {
    dynamic_builtin_scope: bool,
}

impl IrLowerOptions {
    /// Creates default IR lowering options.
    pub const fn new() -> Self {
        Self {
            dynamic_builtin_scope: false,
        }
    }

    /// Creates options for modules whose global `builtins` binding is runtime-shadowable.
    pub const fn with_dynamic_builtin_scope() -> Self {
        Self {
            dynamic_builtin_scope: true,
        }
    }

    /// Returns whether builtin references must remain dynamic runtime lookups.
    pub const fn dynamic_builtin_scope(&self) -> bool {
        self.dynamic_builtin_scope
    }
}

/// A lowered evaluator IR artifact.
#[derive(Clone, Debug)]
pub struct Ir {
    /// The root expression node.
    pub root: IrId,
    /// The fixed-stride node arena plus child pool.
    pub arena: IrArena,
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
    /// A dynamic lookup through active `with` scopes.
    WithVar,
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
    /// A direct primitive operation call.
    PrimOp,
    /// The strict derivation boundary.
    DerivationStrict,
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
    /// The node represents a dynamic `with` lookup.
    WithVar {
        /// The unresolved symbol to probe.
        symbol: Symbol,
        /// The resolver with-chain id.
        chain: u32,
    },
}

/// Whether evaluating an IR node can perform externally observable work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EffectClass {
    /// The node is pure and may be speculated by later passes.
    Pure,
    /// The node is effectful and is a speculation barrier.
    Effectful,
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

fn effect_for(kind: IrKind) -> EffectClass {
    match kind {
        IrKind::DerivationStrict => EffectClass::Effectful,
        _ => EffectClass::Pure,
    }
}

fn is_trivial_value(kind: IrKind) -> bool {
    matches!(
        kind,
        IrKind::Int | IrKind::Float | IrKind::Bool | IrKind::Null | IrKind::Str | IrKind::Uri
    )
}

#[cfg(test)]
mod tests;
