//! Scope resolution for parsed Nix ASTs.
//!
//! The resolver walks the compact syntax arena, keeps a stack of lexical frames,
//! and rewrites expression identifiers into static environment accesses. It also
//! records the side tables needed by the later IR lowering pass:
//!
//! ```text
//! FrameInfo { slot_count, captures, rec, has_with }
//! WithChain { scopes: [innermost_with_scrutinee, ...] }
//! ```
//!
//! Attribute-key identifiers remain syntax nodes after parse-time attr-path
//! desugaring; only identifier nodes in expression position are resolved here.
//! Desugared `inherit` bindings keep their target-name syntax nodes and carry
//! side-table entries for the resolved implicit source expressions.

use std::collections::BTreeSet;
use std::convert::TryFrom;

use thiserror::Error;

use crate::builtins::{is_known_builtin_attr, is_unshadowable_global_name};
use crate::syntax::{
    AstArena, AstError, AstErrorKind, ChildSlice, Node, NodeData, NodeId, NodeKind, ParsedAst,
    Span, Symbol, SymbolTable,
};

mod state;
mod walk;

pub(crate) use self::state::{BindingResolveMode, ResolverState};

/// Resolves a parsed AST using the default resolver options.
///
/// # Errors
///
/// Returns [`ScopeError`] when the AST is malformed, a side table grows beyond
/// `u32` addressability, or strict undefined-name checking is enabled and a name
/// cannot be resolved lexically or dynamically.
pub fn resolve(parsed: ParsedAst) -> Result<ResolvedAst, ScopeError> {
    ScopeResolver::new().resolve(parsed)
}

/// A scope resolver from parsed AST into scope-annotated IR nodes.
#[derive(Clone, Debug)]
pub struct ScopeResolver {
    options: ResolverOptions,
}

impl ScopeResolver {
    /// Creates a resolver with default options.
    pub const fn new() -> Self {
        Self {
            options: ResolverOptions::new(),
        }
    }

    /// Creates a resolver with explicit options.
    pub const fn with_options(options: ResolverOptions) -> Self {
        Self { options }
    }

    /// Resolves identifiers in a parsed AST and returns the rewritten arena plus
    /// side tables.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeError`] when the AST contains an unexpected node payload,
    /// side-table ids exceed their compact integer ranges, or strict
    /// undefined-name checking rejects an unresolved symbol.
    pub fn resolve(&self, parsed: ParsedAst) -> Result<ResolvedAst, ScopeError> {
        let state = ResolverState::new(parsed, self.options);
        state.resolve_root()
    }
}

impl Default for ScopeResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for scope resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolverOptions {
    allow_unresolved_globals: bool,
}

impl ResolverOptions {
    /// Creates default resolver options.
    pub const fn new() -> Self {
        Self {
            allow_unresolved_globals: false,
        }
    }

    /// Creates resolver options that preserve unresolved names as global lookups.
    pub const fn with_unresolved_globals() -> Self {
        Self {
            allow_unresolved_globals: true,
        }
    }

    /// Returns whether unresolved identifiers are kept as runtime global lookups.
    pub const fn allow_unresolved_globals(&self) -> bool {
        self.allow_unresolved_globals
    }
}

impl Default for ResolverOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// A parsed AST after scope resolution.
#[derive(Clone, Debug)]
pub struct ResolvedAst {
    /// The expression root node.
    pub root: NodeId,
    /// The rewritten arena containing post-resolution variable nodes.
    pub arena: AstArena,
    /// File-local symbols referenced by the arena.
    pub symbols: SymbolTable,
    /// Scope-resolution side tables.
    pub scopes: ScopeTables,
}

impl ResolvedAst {
    fn new(root: NodeId, arena: AstArena, symbols: SymbolTable, scopes: ScopeTables) -> Self {
        Self {
            root,
            arena,
            symbols,
            scopes,
        }
    }
}

/// Scope side tables produced by the resolver.
#[derive(Clone, Debug, Default)]
pub struct ScopeTables {
    frames: Vec<FrameInfo>,
    node_frames: Vec<Option<FrameId>>,
    with_chains: Vec<WithChain>,
    inherit_resolutions: Vec<InheritResolution>,
    node_inherits: Vec<Option<InheritGroupId>>,
}

impl ScopeTables {
    /// Creates scope tables from already-decoded raw storage.
    pub fn from_raw_parts(
        frames: Vec<FrameInfo>,
        node_frames: Vec<Option<FrameId>>,
        with_chains: Vec<WithChain>,
        inherit_resolutions: Vec<InheritResolution>,
        node_inherits: Vec<Option<InheritGroupId>>,
    ) -> Self {
        Self {
            frames,
            node_frames,
            with_chains,
            inherit_resolutions,
            node_inherits,
        }
    }

    /// Returns all frame records in allocation order.
    pub fn frames(&self) -> &[FrameInfo] {
        &self.frames
    }

    /// Returns frame ids attached to arena nodes.
    pub fn node_frames(&self) -> &[Option<FrameId>] {
        &self.node_frames
    }

    /// Returns the frame attached to a binder node, if one exists.
    pub fn frame_for_node(&self, node: NodeId) -> Option<FrameId> {
        self.node_frames.get(node.index()).copied().flatten()
    }

    /// Returns all dynamic `with` chains in allocation order.
    pub fn with_chains(&self) -> &[WithChain] {
        &self.with_chains
    }

    /// Returns one dynamic `with` chain by id.
    pub fn with_chain(&self, id: WithChainId) -> Option<&WithChain> {
        self.with_chains.get(id.index())
    }

    /// Returns all resolved `inherit` groups in allocation order.
    pub fn inherit_resolutions(&self) -> &[InheritResolution] {
        &self.inherit_resolutions
    }

    /// Returns inherit-group ids attached to arena nodes.
    pub fn node_inherits(&self) -> &[Option<InheritGroupId>] {
        &self.node_inherits
    }

    /// Returns the resolved `inherit` group attached to a desugared binding or
    /// zero-target inherit marker node, if one exists.
    pub fn inherit_for_node(&self, node: NodeId) -> Option<InheritGroupId> {
        self.node_inherits.get(node.index()).copied().flatten()
    }

    /// Returns one resolved `inherit` group by id.
    pub fn inherit_resolution(&self, id: InheritGroupId) -> Option<&InheritResolution> {
        self.inherit_resolutions.get(id.index())
    }
}

/// A scope-frame side-table id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameId(u32);

impl FrameId {
    /// Creates a frame id from a raw side-table index.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw `u32` side-table index.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the side-table index as a `usize`.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A dynamic `with`-chain side-table id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WithChainId(u32);

impl WithChainId {
    /// Creates a with-chain id from a raw side-table index.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw `u32` side-table index.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the side-table index as a `usize`.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// An `inherit` side-table id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InheritGroupId(u32);

impl InheritGroupId {
    /// Creates an inherit-group id from a raw side-table index.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw `u32` side-table index.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the side-table index as a `usize`.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Per-frame scope metadata produced by the resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameInfo {
    /// The number of slots in the frame's environment array.
    pub slot_count: u32,
    /// Free-variable coordinates captured by this frame when it belongs to a
    /// lambda.
    pub captures: Box<[Upvalue]>,
    /// Whether the frame is self-visible while resolving its own RHS nodes.
    pub rec: bool,
    /// Whether a `with` expression is active inside the frame's body.
    pub has_with: bool,
}

/// A captured variable coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Upvalue {
    /// The number of parent frames from the capturing lambda to the binding.
    pub depth: u16,
    /// The slot in the target frame.
    pub slot: u16,
}

/// An innermost-first chain of active `with` scrutinee expressions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithChain {
    /// The active `with` scrutinee node ids, innermost first.
    pub scopes: Box<[NodeId]>,
}

/// A resolved `inherit` group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InheritResolution {
    /// The optional source expression from `inherit (expr) name`.
    pub from: Option<NodeId>,
    /// The per-name source expressions after scope resolution.
    pub sources: Box<[InheritSource]>,
}

/// One resolved inherited name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InheritSource {
    /// The target attribute symbol introduced by the inherit group.
    pub target: Symbol,
    /// The resolved implicit source expression.
    pub source: NodeId,
}

fn push_unique(symbols: &mut Vec<Symbol>, symbol: Symbol) {
    if !symbols.contains(&symbol) {
        symbols.push(symbol);
    }
}

fn is_global_name(bytes: &[u8]) -> bool {
    is_known_builtin_attr(bytes) || is_unshadowable_global_name(bytes)
}

/// A scope-resolution failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{kind} at byte span {span:?}")]
pub struct ScopeError {
    kind: ScopeErrorKind,
    span: Span,
}

impl ScopeError {
    /// Creates a scope-resolution error.
    pub const fn new(kind: ScopeErrorKind, span: Span) -> Self {
        Self { kind, span }
    }

    /// Returns the error category.
    pub const fn kind(&self) -> &ScopeErrorKind {
        &self.kind
    }

    /// Returns the source span associated with the error.
    pub const fn span(&self) -> Span {
        self.span
    }

    fn from_ast(error: AstError) -> Self {
        Self::new(ScopeErrorKind::Ast(error.kind().clone()), error.span())
    }
}

/// The category of a scope-resolution failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ScopeErrorKind {
    /// AST arena access failed.
    #[error("AST arena error: {0}")]
    Ast(AstErrorKind),
    /// A referenced AST node id does not exist.
    #[error("invalid AST node id {0}")]
    InvalidNodeId(u32),
    /// A node had a different payload than its kind requires.
    #[error("invalid {kind:?} node shape, expected {expected}")]
    InvalidNodeShape {
        /// The malformed node kind.
        kind: NodeKind,
        /// The expected payload shape.
        expected: &'static str,
    },
    /// Too many scope frames were created.
    #[error("too many scope frames")]
    TooManyFrames,
    /// Too many dynamic `with` chains were created.
    #[error("too many with chains")]
    TooManyWithChains,
    /// Too many resolved `inherit` groups were created.
    #[error("too many inherit groups")]
    TooManyInheritGroups,
    /// Too many slots were created for compact side-table coordinates.
    #[error("too many frame slots")]
    TooManySlots,
    /// Too many upvalue coordinates were created for compact side tables.
    #[error("too many upvalues")]
    TooManyUpvalues,
    /// A name was not lexical, not covered by `with`, and not allowed to become
    /// a global.
    #[error("undefined symbol {0:?}")]
    UndefinedSymbol(Symbol),
    /// A `let` binding used a computed attribute name.
    #[error("computed attribute names are not valid let bindings")]
    DynamicLetBinding,
    /// An `inherit` target used a computed attribute name.
    #[error("computed attribute names are not valid inherit targets")]
    DynamicInheritTarget,
}

#[cfg(test)]
mod tests;
