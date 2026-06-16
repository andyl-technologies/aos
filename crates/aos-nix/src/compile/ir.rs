//! Lowered arena IR for scope-resolved Nix expressions.
//!
//! This module owns the first concrete IR layer after scope resolution. It
//! lowers the parser arena into fixed-stride [`IrNode`] records, moves variable
//! arity payloads into side tables, and materializes conservative
//! [`IrKind::ThunkAlloc`] nodes at lazy positions.

use std::collections::BTreeMap;

use thiserror::Error;

use super::{FrameInfo, ResolvedAst};
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
    IrLowerer::new(resolved).lower()
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

impl IrArena {
    /// Creates an empty IR arena.
    pub const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Creates an arena from already-decoded raw storage.
    pub(crate) fn from_raw_parts(nodes: Vec<IrNode>, children: Vec<IrId>) -> Self {
        Self { nodes, children }
    }

    /// Returns all nodes in allocation order.
    pub fn nodes(&self) -> &[IrNode] {
        &self.nodes
    }

    /// Returns all child-pool entries in allocation order.
    pub fn child_pool(&self) -> &[IrId] {
        &self.children
    }

    /// Returns one node by id.
    pub fn node(&self, id: IrId) -> Option<&IrNode> {
        self.nodes.get(id.index())
    }

    /// Returns a child-pool slice.
    pub fn child_slice(&self, slice: IrChildSlice) -> Option<&[IrId]> {
        let start = slice.start as usize;
        let end = start.checked_add(slice.len())?;
        self.children.get(start..end)
    }

    fn push_node(
        &mut self,
        kind: IrKind,
        span: Span,
        effect: EffectClass,
        data: IrData,
    ) -> Result<IrId, IrError> {
        let raw = u32::try_from(self.nodes.len())
            .map_err(|_| IrError::new(IrErrorKind::TooManyNodes, span))?;
        let id = IrId::new(raw);
        self.nodes.push(IrNode::new(kind, span, effect, data));
        Ok(id)
    }

    fn push_child_slice(&mut self, children: &[IrId], span: Span) -> Result<IrChildSlice, IrError> {
        let start = u32::try_from(self.children.len())
            .map_err(|_| IrError::new(IrErrorKind::TooManyChildren, span))?;
        let len = u32::try_from(children.len())
            .map_err(|_| IrError::new(IrErrorKind::TooManyChildren, span))?;
        start
            .checked_add(len)
            .ok_or_else(|| IrError::new(IrErrorKind::TooManyChildren, span))?;
        self.children.extend_from_slice(children);
        Ok(IrChildSlice::new(start, len))
    }
}

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

impl IrLowerer {
    fn new(resolved: ResolvedAst) -> Self {
        Self {
            resolved,
            arena: IrArena::new(),
            lowered_nodes: BTreeMap::new(),
            attr_paths: Vec::new(),
            bindings: Vec::new(),
            shapes: Vec::new(),
            with_chains: Vec::new(),
            with_chain_map: BTreeMap::new(),
            inherit_from_thunks: BTreeMap::new(),
            inline_cache_sites: 0,
        }
    }

    fn lower(mut self) -> Result<Ir, IrError> {
        let root = self.lower_expr(self.resolved.root)?;
        let frames = self.resolved.scopes.frames().to_vec().into_boxed_slice();
        Ok(Ir {
            root,
            arena: self.arena,
            symbols: self.resolved.symbols,
            frames,
            with_chains: self.with_chains.into_boxed_slice(),
            attr_paths: self.attr_paths.into_boxed_slice(),
            bindings: self.bindings.into_boxed_slice(),
            shapes: self.shapes.into_boxed_slice(),
        })
    }

    fn lower_expr(&mut self, id: NodeId) -> Result<IrId, IrError> {
        let node = self.node(id)?;
        let lowered = match node.kind {
            NodeKind::Int => {
                let NodeData::Int(value) = node.data else {
                    return Err(self.invalid_shape(node, "integer payload"));
                };
                self.push(IrKind::Int, node.span, IrData::Int(value))
            }
            NodeKind::Float => {
                let NodeData::Float(value) = node.data else {
                    return Err(self.invalid_shape(node, "float payload"));
                };
                self.push(IrKind::Float, node.span, IrData::Float(value))
            }
            NodeKind::Str => self.lower_symbol_node(node, IrKind::Str),
            NodeKind::Path => self.lower_symbol_node(node, IrKind::Path),
            NodeKind::SearchPath => self.lower_symbol_node(node, IrKind::SearchPath),
            NodeKind::Uri => self.lower_symbol_node(node, IrKind::Uri),
            NodeKind::LocalVar => {
                let NodeData::Local { slot } = node.data else {
                    return Err(self.invalid_shape(node, "local payload"));
                };
                self.push(IrKind::LocalVar, node.span, IrData::Local { slot })
            }
            NodeKind::UpvalVar => {
                let NodeData::Upval { depth, slot } = node.data else {
                    return Err(self.invalid_shape(node, "upvalue payload"));
                };
                self.push(IrKind::UpvalVar, node.span, IrData::Upval { depth, slot })
            }
            NodeKind::GlobalVar => self.lower_global(node),
            NodeKind::WithVar => self.lower_with_var(node),
            NodeKind::List => self.lower_list(node),
            NodeKind::AttrSet => self.lower_attrset(id, node, false),
            NodeKind::RecAttrSet => self.lower_attrset(id, node, true),
            NodeKind::Lambda => self.lower_lambda(id, node),
            NodeKind::FormalSet => self.lower_formal_set(node),
            NodeKind::Formal => self.lower_formal(node),
            NodeKind::Apply => self.lower_apply(node),
            NodeKind::Select => self.lower_select(node),
            NodeKind::HasAttr => self.lower_has_attr(node),
            NodeKind::LetIn => self.lower_let(id, node),
            NodeKind::With => self.lower_pair(node, IrKind::With, LazySecond::No),
            NodeKind::Assert => self.lower_pair(node, IrKind::Assert, LazySecond::No),
            NodeKind::IfThenElse => self.lower_if(node),
            NodeKind::BinOp => self.lower_binary(node),
            NodeKind::UnaryOp => self.lower_unary(node),
            NodeKind::Interp => self.lower_interp(node),
            NodeKind::Binding | NodeKind::Inherit | NodeKind::Ident | NodeKind::AttrPath => {
                Err(self.invalid_shape(node, "lowerable expression"))
            }
        }?;
        self.lowered_nodes.insert(id, lowered);
        Ok(lowered)
    }

    fn lower_symbol_node(&mut self, node: Node, kind: IrKind) -> Result<IrId, IrError> {
        let NodeData::Symbol(symbol) = node.data else {
            return Err(self.invalid_shape(node, "symbol payload"));
        };
        self.push(kind, node.span, IrData::Symbol(symbol))
    }

    fn lower_global(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Symbol(symbol) = node.data else {
            return Err(self.invalid_shape(node, "global symbol payload"));
        };
        match self.resolved.symbols.resolve(symbol) {
            Some(b"true") => self.push(IrKind::Bool, node.span, IrData::Bool(true)),
            Some(b"false") => self.push(IrKind::Bool, node.span, IrData::Bool(false)),
            Some(b"null") => self.push(IrKind::Null, node.span, IrData::None),
            _ => self.push(IrKind::GlobalVar, node.span, IrData::Symbol(symbol)),
        }
    }

    fn lower_with_var(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::WithVar { symbol, chain } = node.data else {
            return Err(self.invalid_shape(node, "with-var payload"));
        };
        let chain = self.lower_with_chain(chain, node.span)?;
        self.push(
            IrKind::WithVar,
            node.span,
            IrData::WithVar { symbol, chain },
        )
    }

    fn lower_with_chain(&mut self, chain: u32, span: Span) -> Result<u32, IrError> {
        if let Some(lowered) = self.with_chain_map.get(&chain).copied() {
            return Ok(lowered);
        }
        let raw = u32::try_from(self.with_chains.len())
            .map_err(|_| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        let resolver_chain = self
            .resolved
            .scopes
            .with_chains()
            .get(chain as usize)
            .ok_or_else(|| IrError::new(IrErrorKind::InvalidWithChain { chain }, span))?;
        let mut scopes = Vec::new();
        for scope in resolver_chain.scopes.iter().copied() {
            let lowered = self.lowered_nodes.get(&scope).copied().ok_or_else(|| {
                IrError::new(IrErrorKind::UnloweredWithScope { chain, scope }, span)
            })?;
            scopes.push(lowered);
        }
        self.with_chains
            .push(IrWithChain::new(scopes.into_boxed_slice()));
        self.with_chain_map.insert(chain, raw);
        Ok(raw)
    }

    fn is_derivation_strict_ref(&self, id: NodeId) -> Result<bool, IrError> {
        let Some(symbol) = self.direct_builtin_ref_symbol(id)? else {
            return Ok(false);
        };
        Ok(self.symbol_is(symbol, b"derivationStrict"))
    }

    fn effectful_unary_primop_ref(&self, id: NodeId) -> Result<Option<Symbol>, IrError> {
        let Some(symbol) = self.direct_builtin_ref_symbol(id)? else {
            return Ok(None);
        };
        if self.is_effectful_unary_primop(symbol) {
            Ok(Some(symbol))
        } else {
            Ok(None)
        }
    }

    fn direct_builtin_ref_symbol(&self, id: NodeId) -> Result<Option<Symbol>, IrError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::GlobalVar => {
                let NodeData::Symbol(symbol) = node.data else {
                    return Err(self.invalid_shape(node, "global symbol payload"));
                };
                Ok(Some(symbol))
            }
            NodeKind::Select => {
                let NodeData::Select {
                    receiver,
                    path,
                    default,
                } = node.data
                else {
                    return Err(self.invalid_shape(node, "select payload"));
                };
                if default.is_some() {
                    return Ok(None);
                }
                let receiver = self.node(receiver)?;
                if receiver.kind != NodeKind::GlobalVar
                    || !self.symbol_payload_is(receiver, b"builtins")
                {
                    return Ok(None);
                }
                let segments = self.child_ids(path)?;
                let Some(segment) = segments.first().copied() else {
                    return Ok(None);
                };
                if segments.len() != 1 {
                    return Ok(None);
                }
                let segment = self.node(segment)?;
                if !matches!(segment.kind, NodeKind::Ident | NodeKind::Str) {
                    return Ok(None);
                }
                let NodeData::Symbol(symbol) = segment.data else {
                    return Err(self.invalid_shape(segment, "attribute symbol payload"));
                };
                Ok(Some(symbol))
            }
            _ => Ok(None),
        }
    }

    fn symbol_payload_is(&self, node: Node, expected: &[u8]) -> bool {
        let NodeData::Symbol(symbol) = node.data else {
            return false;
        };
        self.symbol_is(symbol, expected)
    }

    fn symbol_is(&self, symbol: Symbol, expected: &[u8]) -> bool {
        self.resolved.symbols.resolve(symbol) == Some(expected)
    }

    fn is_effectful_unary_primop(&self, symbol: Symbol) -> bool {
        matches!(
            self.resolved.symbols.resolve(symbol),
            Some(
                b"getEnv" | b"import" | b"pathExists" | b"readDir" | b"readFile" | b"readFileType"
            )
        )
    }

    fn lower_list(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Children(elements) = node.data else {
            return Err(self.invalid_shape(node, "list children"));
        };
        let mut lowered = Vec::new();
        for child in self.child_ids(elements)? {
            lowered.push(self.lower_lazy(child)?);
        }
        let children = self.arena.push_child_slice(&lowered, node.span)?;
        self.push(IrKind::List, node.span, IrData::Children(children))
    }

    fn lower_attrset(
        &mut self,
        ast_id: NodeId,
        node: Node,
        recursive: bool,
    ) -> Result<IrId, IrError> {
        let NodeData::Children(bindings) = node.data else {
            return Err(self.invalid_shape(node, "attrset bindings"));
        };
        let mut has_dynamic = false;
        let bindings = self.lower_bindings(bindings, &mut has_dynamic)?;
        let shape = self.push_shape_for_bindings(bindings, node.span)?;
        let frame = if recursive {
            self.resolved.scopes.frame_for_node(ast_id)
        } else {
            None
        };
        self.push(
            IrKind::AttrSet,
            node.span,
            IrData::AttrSet {
                shape,
                bindings,
                recursive,
                has_dynamic,
                frame,
            },
        )
    }

    fn lower_lambda(&mut self, ast_id: NodeId, node: Node) -> Result<IrId, IrError> {
        let NodeData::Pair {
            first: pattern,
            second: body,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "lambda pair"));
        };
        let pattern = self.lower_pattern(pattern)?;
        let body = self.lower_expr(body)?;
        let frame = self.resolved.scopes.frame_for_node(ast_id);
        self.push(
            IrKind::Lambda,
            node.span,
            IrData::Lambda {
                pattern,
                body,
                frame,
            },
        )
    }

    fn lower_formal_set(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::FormalSet {
            formals,
            ellipsis,
            alias,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "formal-set payload"));
        };
        let mut lowered = Vec::new();
        for formal in self.child_ids(formals)? {
            lowered.push(self.lower_expr(formal)?);
        }
        let formals = self.arena.push_child_slice(&lowered, node.span)?;
        self.push(
            IrKind::FormalSet,
            node.span,
            IrData::FormalSet {
                formals,
                ellipsis,
                alias,
            },
        )
    }

    fn lower_pattern(&mut self, id: NodeId) -> Result<IrId, IrError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Ident => {
                let NodeData::Symbol(name) = node.data else {
                    return Err(self.invalid_shape(node, "identifier pattern symbol"));
                };
                self.push(
                    IrKind::Formal,
                    node.span,
                    IrData::Formal {
                        name,
                        default: None,
                    },
                )
            }
            NodeKind::FormalSet => self.lower_formal_set(node),
            _ => self.lower_expr(id),
        }
    }

    fn lower_formal(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Formal { name, default } = node.data else {
            return Err(self.invalid_shape(node, "formal payload"));
        };
        let default = default
            .map(|default| self.lower_lazy(default))
            .transpose()?;
        self.push(IrKind::Formal, node.span, IrData::Formal { name, default })
    }

    fn lower_pair(
        &mut self,
        node: Node,
        kind: IrKind,
        lazy_second: LazySecond,
    ) -> Result<IrId, IrError> {
        let NodeData::Pair { first, second } = node.data else {
            return Err(self.invalid_shape(node, "pair payload"));
        };
        let first = self.lower_expr(first)?;
        let second = if lazy_second == LazySecond::Yes {
            self.lower_lazy(second)?
        } else {
            self.lower_expr(second)?
        };
        self.push(kind, node.span, IrData::Pair { first, second })
    }

    fn lower_apply(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Pair {
            first: function,
            second: argument,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "application pair"));
        };
        if self.is_derivation_strict_ref(function)? {
            let argument = self.lower_expr(argument)?;
            return self.push(IrKind::DerivationStrict, node.span, IrData::Node(argument));
        }
        if let Some(symbol) = self.effectful_unary_primop_ref(function)? {
            let argument = self.lower_expr(argument)?;
            let args = self.arena.push_child_slice(&[argument], node.span)?;
            return self.push_with_effect(
                IrKind::PrimOp,
                node.span,
                EffectClass::Effectful,
                IrData::PrimOp { symbol, args },
            );
        }
        self.lower_pair(node, IrKind::Apply, LazySecond::Yes)
    }

    fn lower_select(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Select {
            receiver,
            path,
            default,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "select payload"));
        };
        let receiver = self.lower_expr(receiver)?;
        let path = self.lower_attr_path(path)?;
        let default = default
            .map(|default| self.lower_lazy(default))
            .transpose()?;
        let site = self.next_inline_cache_site(node.span)?;
        self.push(
            IrKind::Select,
            node.span,
            IrData::Select {
                site,
                receiver,
                path,
                default,
            },
        )
    }

    fn lower_has_attr(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::HasAttr { receiver, path } = node.data else {
            return Err(self.invalid_shape(node, "has-attr payload"));
        };
        let receiver = self.lower_expr(receiver)?;
        let path = self.lower_attr_path(path)?;
        let site = self.next_inline_cache_site(node.span)?;
        self.push(
            IrKind::HasAttr,
            node.span,
            IrData::HasAttr {
                site,
                receiver,
                path,
            },
        )
    }

    fn lower_let(&mut self, ast_id: NodeId, node: Node) -> Result<IrId, IrError> {
        let NodeData::LetIn { bindings, body } = node.data else {
            return Err(self.invalid_shape(node, "let payload"));
        };
        let mut has_dynamic = false;
        let bindings = self.lower_bindings(bindings, &mut has_dynamic)?;
        let body = self.lower_expr(body)?;
        let frame = self.resolved.scopes.frame_for_node(ast_id);
        self.push(
            IrKind::Let,
            node.span,
            IrData::Let {
                bindings,
                body,
                frame,
            },
        )
    }

    fn lower_if(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Triple {
            first,
            second,
            third,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "if payload"));
        };
        let first = self.lower_expr(first)?;
        let second = self.lower_expr(second)?;
        let third = self.lower_expr(third)?;
        self.push(
            IrKind::If,
            node.span,
            IrData::Triple {
                first,
                second,
                third,
            },
        )
    }

    fn lower_binary(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Binary { op, lhs, rhs } = node.data else {
            return Err(self.invalid_shape(node, "binary payload"));
        };
        let lhs = self.lower_expr(lhs)?;
        let rhs = self.lower_expr(rhs)?;
        self.push(IrKind::BinOp, node.span, IrData::Binary { op, lhs, rhs })
    }

    fn lower_unary(&mut self, node: Node) -> Result<IrId, IrError> {
        let NodeData::Unary { op, operand } = node.data else {
            return Err(self.invalid_shape(node, "unary payload"));
        };
        let operand = self.lower_expr(operand)?;
        self.push(IrKind::UnaryOp, node.span, IrData::Unary { op, operand })
    }

    fn lower_interp(&mut self, node: Node) -> Result<IrId, IrError> {
        match node.data {
            NodeData::Node(child) => {
                let child = self.lower_expr(child)?;
                self.push(IrKind::Interp, node.span, IrData::Node(child))
            }
            NodeData::Children(children) => {
                let mut lowered = Vec::new();
                for child in self.child_ids(children)? {
                    lowered.push(self.lower_expr(child)?);
                }
                let children = self.arena.push_child_slice(&lowered, node.span)?;
                self.push(IrKind::Interp, node.span, IrData::Children(children))
            }
            NodeData::None | NodeData::Symbol(_) => {
                self.push(IrKind::Interp, node.span, IrData::None)
            }
            _ => Err(self.invalid_shape(node, "interpolation payload")),
        }
    }

    fn lower_bindings(
        &mut self,
        slice: ChildSlice,
        has_dynamic: &mut bool,
    ) -> Result<IrBindingSlice, IrError> {
        let mut lowered = Vec::new();
        for binding in self.child_ids(slice)? {
            if let Some(binding) = self.lower_binding(binding, has_dynamic)? {
                lowered.push(binding);
            }
        }
        self.push_binding_slice(&lowered)
    }

    fn lower_binding(
        &mut self,
        id: NodeId,
        has_dynamic: &mut bool,
    ) -> Result<Option<IrBinding>, IrError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Binding => {
                let NodeData::Binding { path, value } = node.data else {
                    return Err(self.invalid_shape(node, "binding payload"));
                };
                let key = self.lower_binding_key(path)?;
                if matches!(key, IrAttrPathSegment::Dynamic(_)) {
                    *has_dynamic = true;
                }
                let value = if let Some(inherit) = self.resolved.scopes.inherit_for_node(id) {
                    let resolution = self
                        .resolved
                        .scopes
                        .inherit_resolution(inherit)
                        .ok_or_else(|| {
                            IrError::new(IrErrorKind::InvalidInheritSource, node.span)
                        })?;
                    let Some(source) = resolution.sources.first() else {
                        return Err(IrError::new(IrErrorKind::InvalidInheritSource, node.span));
                    };
                    match resolution.from {
                        Some(from) => self.lower_inherit_from_source(from, source.source)?,
                        None => self.lower_lazy(source.source)?,
                    }
                } else {
                    self.lower_lazy(value)?
                };
                Ok(Some(IrBinding { key, value }))
            }
            NodeKind::Inherit => Ok(None),
            _ => Err(self.invalid_shape(node, "binding node")),
        }
    }

    fn lower_binding_key(&mut self, path: ChildSlice) -> Result<IrAttrPathSegment, IrError> {
        let segments = self.child_ids(path)?;
        let Some(segment) = segments.first().copied() else {
            return Err(IrError::new(
                IrErrorKind::InvalidBindingKey,
                Span::default(),
            ));
        };
        if segments.len() != 1 {
            return Err(IrError::new(
                IrErrorKind::InvalidBindingKey,
                self.node(segment)?.span,
            ));
        }
        self.lower_attr_segment(segment)
    }

    fn lower_attr_path(&mut self, path: ChildSlice) -> Result<IrAttrPathId, IrError> {
        let mut segments = Vec::new();
        for segment in self.child_ids(path)? {
            segments.push(self.lower_attr_segment(segment)?);
        }
        let raw = u32::try_from(self.attr_paths.len())
            .map_err(|_| IrError::new(IrErrorKind::TooManySideTableEntries, Span::default()))?;
        let id = IrAttrPathId::new(raw);
        self.attr_paths.push(segments.into_boxed_slice());
        Ok(id)
    }

    fn lower_attr_segment(&mut self, id: NodeId) -> Result<IrAttrPathSegment, IrError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Ident | NodeKind::Str => {
                let NodeData::Symbol(symbol) = node.data else {
                    return Err(self.invalid_shape(node, "static attr symbol"));
                };
                Ok(IrAttrPathSegment::Static(symbol))
            }
            NodeKind::Interp => Ok(IrAttrPathSegment::Dynamic(self.lower_expr(id)?)),
            _ => Err(self.invalid_shape(node, "attribute path segment")),
        }
    }

    fn lower_inherit_from_source(&mut self, from: NodeId, source: NodeId) -> Result<IrId, IrError> {
        let node = self.node(source)?;
        let NodeData::Select {
            receiver,
            path,
            default,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "inherit source select"));
        };
        if receiver != from {
            return Err(IrError::new(IrErrorKind::InvalidInheritSource, node.span));
        }
        let receiver = self.lower_inherit_from_thunk(from)?;
        let path = self.lower_attr_path(path)?;
        let default = default
            .map(|default| self.lower_lazy(default))
            .transpose()?;
        let site = self.next_inline_cache_site(node.span)?;
        let select = self.push(
            IrKind::Select,
            node.span,
            IrData::Select {
                site,
                receiver,
                path,
                default,
            },
        )?;
        self.wrap_lazy(select, source)
    }

    fn lower_inherit_from_thunk(&mut self, from: NodeId) -> Result<IrId, IrError> {
        if let Some(thunk) = self.inherit_from_thunks.get(&from).copied() {
            return Ok(thunk);
        }
        let thunk = self.lower_lazy(from)?;
        self.inherit_from_thunks.insert(from, thunk);
        Ok(thunk)
    }

    fn lower_lazy(&mut self, id: NodeId) -> Result<IrId, IrError> {
        let lowered = self.lower_expr(id)?;
        self.wrap_lazy(lowered, id)
    }

    fn wrap_lazy(&mut self, lowered: IrId, ast_id: NodeId) -> Result<IrId, IrError> {
        let node = self.arena.node(lowered).copied().ok_or_else(|| {
            IrError::new(IrErrorKind::InvalidNodeId(ast_id.as_u32()), Span::default())
        })?;
        if is_trivial_value(node.kind) {
            return Ok(lowered);
        }
        self.push(IrKind::ThunkAlloc, node.span, IrData::Node(lowered))
    }

    fn next_inline_cache_site(&mut self, span: Span) -> Result<IrInlineCacheSiteId, IrError> {
        let site = IrInlineCacheSiteId::new(self.inline_cache_sites);
        self.inline_cache_sites = self
            .inline_cache_sites
            .checked_add(1)
            .ok_or_else(|| IrError::new(IrErrorKind::TooManyInlineCacheSites, span))?;
        Ok(site)
    }

    fn push(&mut self, kind: IrKind, span: Span, data: IrData) -> Result<IrId, IrError> {
        self.arena.push_node(kind, span, effect_for(kind), data)
    }

    fn push_with_effect(
        &mut self,
        kind: IrKind,
        span: Span,
        effect: EffectClass,
        data: IrData,
    ) -> Result<IrId, IrError> {
        self.arena.push_node(kind, span, effect, data)
    }

    fn push_binding_slice(&mut self, bindings: &[IrBinding]) -> Result<IrBindingSlice, IrError> {
        let span = Span::default();
        let start = u32::try_from(self.bindings.len())
            .map_err(|_| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        let len = u32::try_from(bindings.len())
            .map_err(|_| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        start
            .checked_add(len)
            .ok_or_else(|| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        self.bindings.extend_from_slice(bindings);
        Ok(IrBindingSlice::new(start, len))
    }

    fn push_shape_for_bindings(
        &mut self,
        bindings: IrBindingSlice,
        span: Span,
    ) -> Result<IrShapeId, IrError> {
        let raw = u32::try_from(self.shapes.len())
            .map_err(|_| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        let start = bindings.start as usize;
        let end = start
            .checked_add(bindings.len())
            .ok_or_else(|| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        let binding_run = self
            .bindings
            .get(start..end)
            .ok_or_else(|| IrError::new(IrErrorKind::TooManySideTableEntries, span))?;
        let keys = binding_run
            .iter()
            .filter_map(|binding| match binding.key {
                IrAttrPathSegment::Static(symbol) => Some(symbol),
                IrAttrPathSegment::Dynamic(_) => None,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let id = IrShapeId::new(raw);
        self.shapes.push(IrShape::new(keys));
        Ok(id)
    }

    fn node(&self, id: NodeId) -> Result<Node, IrError> {
        self.resolved.arena.node(id).copied().ok_or_else(|| {
            IrError::new(
                IrErrorKind::InvalidNodeId(id.as_u32()),
                Span::new(u32::MAX, u32::MAX),
            )
        })
    }

    fn child_ids(&self, slice: ChildSlice) -> Result<Vec<NodeId>, IrError> {
        Ok(self
            .resolved
            .arena
            .child_slice(slice)
            .map_err(IrError::from)?
            .to_vec())
    }

    fn invalid_shape(&self, node: Node, expected: &'static str) -> IrError {
        IrError::new(
            IrErrorKind::InvalidNodeShape {
                kind: node.kind,
                expected,
            },
            node.span,
        )
    }
}

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
        IrKind::Int | IrKind::Float | IrKind::Bool | IrKind::Null | IrKind::Str
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::resolve;
    use crate::syntax::parse_str;

    fn lowered(source: &str) -> Ir {
        lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("IR lowers")
    }

    fn node(ir: &Ir, id: IrId) -> &IrNode {
        ir.arena.node(id).expect("IR node exists")
    }

    fn root_node(ir: &Ir) -> &IrNode {
        node(ir, ir.root)
    }

    fn thunk_inner(ir: &Ir, id: IrId) -> IrId {
        assert_eq!(node(ir, id).kind, IrKind::ThunkAlloc);
        let IrData::Node(inner) = node(ir, id).data else {
            panic!("thunk payload expected");
        };
        inner
    }

    fn lookup_site(ir: &Ir, id: IrId) -> IrInlineCacheSiteId {
        match node(ir, id).data {
            IrData::Select { site, .. } | IrData::HasAttr { site, .. } => site,
            _ => panic!("lookup payload expected"),
        }
    }

    fn symbol_text<'a>(ir: &'a Ir, symbol: Symbol) -> &'a [u8] {
        ir.symbols.resolve(symbol).expect("symbol exists")
    }

    #[test]
    fn lowers_let_lambda_application_to_resolved_ir() {
        let ir = lowered("let x = 1; f = y: x + y; in f 41");
        let root = node(&ir, ir.root);
        assert_eq!(root.kind, IrKind::Let);
        let IrData::Let { bindings, body, .. } = root.data else {
            panic!("let payload expected");
        };
        assert_eq!(bindings.len(), 2);
        assert_eq!(node(&ir, body).kind, IrKind::Apply);
        let IrData::Pair { first, second } = node(&ir, body).data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::LocalVar);
        assert_eq!(node(&ir, second).kind, IrKind::Int);
    }

    #[test]
    fn lowers_global_bool_and_null_literals_after_resolution() {
        let true_ir = lowered("true");
        assert_eq!(root_node(&true_ir).kind, IrKind::Bool);
        assert_eq!(root_node(&true_ir).data, IrData::Bool(true));

        let false_ir = lowered("false");
        assert_eq!(root_node(&false_ir).kind, IrKind::Bool);
        assert_eq!(root_node(&false_ir).data, IrData::Bool(false));

        let null_ir = lowered("null");
        assert_eq!(root_node(&null_ir).kind, IrKind::Null);
        assert_eq!(root_node(&null_ir).data, IrData::None);
    }

    #[test]
    fn shadowed_bool_and_null_names_remain_lexical_variables() {
        let ir = lowered("let true = 1; null = 2; in [ true null ]");
        let root = root_node(&ir);
        let IrData::Let { body, .. } = root.data else {
            panic!("let payload expected");
        };
        let IrData::Children(elements) = node(&ir, body).data else {
            panic!("list payload expected");
        };
        let elements = ir.arena.child_slice(elements).expect("list slice exists");
        assert_eq!(
            node(&ir, thunk_inner(&ir, elements[0])).kind,
            IrKind::LocalVar
        );
        assert_eq!(
            node(&ir, thunk_inner(&ir, elements[1])).kind,
            IrKind::LocalVar
        );
    }

    #[test]
    fn with_shadowed_bool_name_remains_dynamic() {
        let ir = lowered("with { true = 1; }; true");
        let IrData::Pair { first, second } = root_node(&ir).data else {
            panic!("with payload expected");
        };
        assert_eq!(node(&ir, second).kind, IrKind::WithVar);
        let IrData::WithVar { chain, .. } = node(&ir, second).data else {
            panic!("with-var payload expected");
        };
        let chain = &ir.with_chains[chain as usize];
        assert_eq!(chain.scopes.as_ref(), &[first]);
    }

    #[test]
    fn with_var_chains_point_to_lowered_scopes_inner_first() {
        let ir = lowered("with { outer = 1; }; with { inner = 2; }; missing");
        let IrData::Pair {
            first: outer,
            second: inner_with,
        } = root_node(&ir).data
        else {
            panic!("outer with payload expected");
        };
        let IrData::Pair {
            first: inner,
            second: body,
        } = node(&ir, inner_with).data
        else {
            panic!("inner with payload expected");
        };
        let IrData::WithVar { chain, .. } = node(&ir, body).data else {
            panic!("with-var payload expected");
        };

        let chain = &ir.with_chains[chain as usize];
        assert_eq!(chain.scopes.as_ref(), &[inner, outer]);
    }

    #[test]
    fn bool_and_null_literals_are_not_thunked_in_lists() {
        let ir = lowered("[ true null false ]");
        let IrData::Children(elements) = root_node(&ir).data else {
            panic!("list payload expected");
        };
        let elements = ir.arena.child_slice(elements).expect("list slice exists");
        assert_eq!(node(&ir, elements[0]).kind, IrKind::Bool);
        assert_eq!(node(&ir, elements[1]).kind, IrKind::Null);
        assert_eq!(node(&ir, elements[2]).kind, IrKind::Bool);
    }

    #[test]
    fn lowers_direct_derivation_strict_to_effectful_boundary() {
        for source in [
            "derivationStrict { name = \"x\"; }",
            "builtins.derivationStrict { name = \"x\"; }",
        ] {
            let ir = lowered(source);
            let root = root_node(&ir);
            assert_eq!(root.kind, IrKind::DerivationStrict);
            assert_eq!(root.effect, EffectClass::Effectful);
            let IrData::Node(argument) = root.data else {
                panic!("derivationStrict payload expected");
            };
            assert_eq!(node(&ir, argument).kind, IrKind::AttrSet);
        }
    }

    #[test]
    fn shadowed_derivation_strict_stays_an_application() {
        let ir = lowered("let derivationStrict = x: x; in derivationStrict 1");
        let IrData::Let { body, .. } = root_node(&ir).data else {
            panic!("let payload expected");
        };
        assert_eq!(node(&ir, body).kind, IrKind::Apply);
        let IrData::Pair { first, .. } = node(&ir, body).data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::LocalVar);
    }

    #[test]
    fn shadowed_builtins_derivation_strict_stays_a_select_application() {
        let ir =
            lowered("let builtins = { derivationStrict = x: x; }; in builtins.derivationStrict 1");
        let IrData::Let { body, .. } = root_node(&ir).data else {
            panic!("let payload expected");
        };
        assert_eq!(node(&ir, body).kind, IrKind::Apply);
        let IrData::Pair { first, .. } = node(&ir, body).data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::Select);
    }

    #[test]
    fn with_shadowed_derivation_strict_stays_dynamic_application() {
        let ir = lowered("with { derivationStrict = x: x; }; derivationStrict 1");
        let IrData::Pair { second: body, .. } = root_node(&ir).data else {
            panic!("with payload expected");
        };
        assert_eq!(node(&ir, body).kind, IrKind::Apply);
        let IrData::Pair { first, .. } = node(&ir, body).data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::WithVar);
    }

    #[test]
    fn select_default_derivation_strict_stays_a_select_application() {
        let ir = lowered("(builtins.derivationStrict or (x: x)) { name = \"x\"; }");
        let root = root_node(&ir);
        assert_eq!(root.kind, IrKind::Apply);
        let IrData::Pair { first, .. } = root.data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::Select);
    }

    #[test]
    fn lowers_effectful_unary_primops_directly() {
        for (source, name) in [
            ("import ./foo.nix", b"import".as_slice()),
            ("builtins.readFile ./foo.txt", b"readFile".as_slice()),
            ("builtins.readDir ./foo", b"readDir".as_slice()),
            ("builtins.pathExists ./foo", b"pathExists".as_slice()),
            ("builtins.readFileType ./foo", b"readFileType".as_slice()),
            ("builtins.getEnv \"HOME\"", b"getEnv".as_slice()),
        ] {
            let ir = lowered(source);
            let root = root_node(&ir);
            assert_eq!(root.kind, IrKind::PrimOp);
            assert_eq!(root.effect, EffectClass::Effectful);
            let IrData::PrimOp { symbol, args } = root.data else {
                panic!("primop payload expected");
            };
            assert_eq!(symbol_text(&ir, symbol), name);
            let args = ir.arena.child_slice(args).expect("primop args exist");
            assert_eq!(args.len(), 1);
            assert_ne!(node(&ir, args[0]).kind, IrKind::ThunkAlloc);
        }
    }

    #[test]
    fn effectful_unary_primop_arguments_are_strict() {
        let ir = lowered("builtins.getEnv (let x = \"HOME\"; in x)");
        let root = root_node(&ir);
        assert_eq!(root.kind, IrKind::PrimOp);
        let IrData::PrimOp { args, .. } = root.data else {
            panic!("primop payload expected");
        };
        let args = ir.arena.child_slice(args).expect("primop args exist");
        assert_eq!(args.len(), 1);
        assert_eq!(node(&ir, args[0]).kind, IrKind::Let);
    }

    #[test]
    fn shadowed_effectful_primops_stay_ordinary_applications() {
        let ir = lowered("let import = x: x; in import ./foo.nix");
        let IrData::Let { body, .. } = root_node(&ir).data else {
            panic!("let payload expected");
        };
        assert_eq!(node(&ir, body).kind, IrKind::Apply);
        let IrData::Pair { first, .. } = node(&ir, body).data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::LocalVar);

        let ir = lowered("let builtins = { readFile = x: x; }; in builtins.readFile ./foo");
        let IrData::Let { body, .. } = root_node(&ir).data else {
            panic!("let payload expected");
        };
        assert_eq!(node(&ir, body).kind, IrKind::Apply);
        let IrData::Pair { first, .. } = node(&ir, body).data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::Select);
    }

    #[test]
    fn effectful_primop_select_defaults_stay_ordinary_applications() {
        let ir = lowered("(builtins.readFile or (x: x)) ./foo");
        let root = root_node(&ir);
        assert_eq!(root.kind, IrKind::Apply);
        let IrData::Pair { first, .. } = root.data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::Select);
    }

    #[test]
    fn pure_builtins_remain_apply_until_primop_strictness_is_modeled() {
        let ir = lowered("builtins.length [ 1 ]");
        let root = root_node(&ir);
        assert_eq!(root.kind, IrKind::Apply);
        let IrData::Pair { first, .. } = root.data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ir, first).kind, IrKind::Select);
    }

    #[test]
    fn materializes_thunks_at_lazy_binding_and_list_positions() {
        let ir = lowered("let x = y: y; in [ x 1 \"s\" ]");
        let root = node(&ir, ir.root);
        let IrData::Let { bindings, body, .. } = root.data else {
            panic!("let payload expected");
        };
        let binding = ir.bindings[bindings.start as usize];
        assert_eq!(node(&ir, binding.value).kind, IrKind::ThunkAlloc);
        let list = node(&ir, body);
        let IrData::Children(elements) = list.data else {
            panic!("list elements expected");
        };
        let elements = ir.arena.child_slice(elements).expect("list slice exists");
        assert_eq!(node(&ir, elements[0]).kind, IrKind::ThunkAlloc);
        assert_eq!(node(&ir, elements[1]).kind, IrKind::Int);
        assert_eq!(node(&ir, elements[2]).kind, IrKind::Str);
    }

    #[test]
    fn unsupported_literal_values_stay_lazy() {
        let ir = lowered("let p = ./foo; s = <nixpkgs>; u = http://example.test; in 1");
        let root = node(&ir, ir.root);
        let IrData::Let { bindings, .. } = root.data else {
            panic!("let payload expected");
        };
        let start = bindings.start as usize;
        let end = start + bindings.len();
        let bindings = ir.bindings[start..end]
            .iter()
            .map(|binding| binding.value)
            .collect::<Vec<_>>();

        assert_eq!(node(&ir, bindings[0]).kind, IrKind::ThunkAlloc);
        assert_eq!(node(&ir, thunk_inner(&ir, bindings[0])).kind, IrKind::Path);
        assert_eq!(node(&ir, bindings[1]).kind, IrKind::ThunkAlloc);
        assert_eq!(
            node(&ir, thunk_inner(&ir, bindings[1])).kind,
            IrKind::SearchPath
        );
        assert_eq!(node(&ir, bindings[2]).kind, IrKind::ThunkAlloc);
        assert_eq!(node(&ir, thunk_inner(&ir, bindings[2])).kind, IrKind::Uri);
    }

    #[test]
    fn lowers_dynamic_attr_paths_to_side_table_segments() {
        let ir = lowered("let name = \"x\"; in { ${name} = 1; }.${name}");
        let root = node(&ir, ir.root);
        let IrData::Let { body, .. } = root.data else {
            panic!("let payload expected");
        };
        let select = node(&ir, body);
        let IrData::Select { path, .. } = select.data else {
            panic!("select payload expected");
        };
        assert!(matches!(
            ir.attr_paths[path.index()].as_ref(),
            [IrAttrPathSegment::Dynamic(_)]
        ));
    }

    #[test]
    fn attrsets_reference_static_shapes_in_source_order() {
        let ir = lowered("{ a = 1; b = 2; c.d = 3; }");
        let root = root_node(&ir);
        let IrData::AttrSet {
            shape, has_dynamic, ..
        } = root.data
        else {
            panic!("attrset payload expected");
        };
        assert!(!has_dynamic);
        let keys = ir.shapes[shape.index()]
            .keys
            .iter()
            .map(|symbol| symbol_text(&ir, *symbol))
            .collect::<Vec<_>>();
        assert_eq!(keys, [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]);
    }

    #[test]
    fn dynamic_attrset_shapes_keep_static_keys_and_dynamic_flag() {
        let ir = lowered("let name = \"x\"; in { ${name} = 1; a = 2; }");
        let IrData::Let { body, .. } = root_node(&ir).data else {
            panic!("let payload expected");
        };
        let IrData::AttrSet {
            shape, has_dynamic, ..
        } = node(&ir, body).data
        else {
            panic!("attrset payload expected");
        };
        assert!(has_dynamic);
        let keys = ir.shapes[shape.index()]
            .keys
            .iter()
            .map(|symbol| symbol_text(&ir, *symbol))
            .collect::<Vec<_>>();
        assert_eq!(keys, [b"a".as_slice()]);
    }

    #[test]
    fn empty_attrsets_have_empty_shapes() {
        let ir = lowered("{}");
        let IrData::AttrSet {
            shape,
            has_dynamic,
            bindings,
            ..
        } = root_node(&ir).data
        else {
            panic!("attrset payload expected");
        };
        assert!(!has_dynamic);
        assert_eq!(bindings.len(), 0);
        assert!(ir.shapes[shape.index()].keys.is_empty());
    }

    #[test]
    fn recursive_attrsets_keep_shape_and_frame() {
        let ir = lowered("rec { a = 1; }");
        let IrData::AttrSet {
            shape,
            recursive,
            frame,
            ..
        } = root_node(&ir).data
        else {
            panic!("attrset payload expected");
        };
        assert!(recursive);
        assert!(frame.is_some());
        let keys = ir.shapes[shape.index()]
            .keys
            .iter()
            .map(|symbol| symbol_text(&ir, *symbol))
            .collect::<Vec<_>>();
        assert_eq!(keys, [b"a".as_slice()]);
    }

    #[test]
    fn assigns_stable_inline_cache_sites_to_lookups() {
        let ir = lowered("let x = { a = 1; b = 2; }; in [ x.a (x ? b) x.b ]");
        let root = node(&ir, ir.root);
        let IrData::Let { body, .. } = root.data else {
            panic!("let payload expected");
        };
        let IrData::Children(elements) = node(&ir, body).data else {
            panic!("list payload expected");
        };
        let elements = ir.arena.child_slice(elements).expect("list slice exists");
        let first = thunk_inner(&ir, elements[0]);
        let second = thunk_inner(&ir, elements[1]);
        let third = thunk_inner(&ir, elements[2]);

        assert_eq!(lookup_site(&ir, first).as_u32(), 0);
        assert_eq!(lookup_site(&ir, second).as_u32(), 1);
        assert_eq!(lookup_site(&ir, third).as_u32(), 2);
    }

    #[test]
    fn inherit_from_targets_share_one_source_thunk() {
        let ir =
            lowered("let src = { name = 1; version = 2; }; in { inherit (src) name version; }");
        let root = node(&ir, ir.root);
        let IrData::Let { body, .. } = root.data else {
            panic!("let payload expected");
        };
        let IrData::AttrSet { bindings, .. } = node(&ir, body).data else {
            panic!("attrset payload expected");
        };
        assert_eq!(bindings.len(), 2);

        let first = ir.bindings[bindings.start as usize];
        let second = ir.bindings[bindings.start as usize + 1];
        let first_select = thunk_inner(&ir, first.value);
        let second_select = thunk_inner(&ir, second.value);
        assert_eq!(lookup_site(&ir, first_select).as_u32(), 0);
        assert_eq!(lookup_site(&ir, second_select).as_u32(), 1);
        let IrData::Select {
            receiver: first_receiver,
            ..
        } = node(&ir, first_select).data
        else {
            panic!("select payload expected");
        };
        let IrData::Select {
            receiver: second_receiver,
            ..
        } = node(&ir, second_select).data
        else {
            panic!("select payload expected");
        };
        assert_eq!(first_receiver, second_receiver);
        assert_eq!(
            node(&ir, thunk_inner(&ir, first_receiver)).kind,
            IrKind::LocalVar
        );
    }
}
