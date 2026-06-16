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
//! Attribute-key identifiers remain syntax nodes until parse-time attr-path
//! desugaring lands; only identifier nodes in expression position are resolved
//! here. `inherit` groups keep their target-name syntax nodes and carry separate
//! side-table entries for the resolved implicit source expressions.

use std::collections::BTreeSet;
use std::convert::TryFrom;

use thiserror::Error;

use crate::syntax::{
    AstArena, AstError, AstErrorKind, ChildSlice, Node, NodeData, NodeId, NodeKind, ParsedAst,
    Span, Symbol, SymbolTable,
};

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
    _future: (),
}

impl ResolverOptions {
    /// Creates default resolver options.
    pub const fn new() -> Self {
        Self { _future: () }
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
    pub(crate) fn from_raw_parts(
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
    pub(crate) fn node_frames(&self) -> &[Option<FrameId>] {
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
    pub(crate) fn node_inherits(&self) -> &[Option<InheritGroupId>] {
        &self.node_inherits
    }

    /// Returns the resolved `inherit` group attached to an `Inherit` node, if
    /// one exists.
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

#[derive(Clone, Debug)]
struct FrameBuilder {
    slots: Vec<Symbol>,
    captures: BTreeSet<Upvalue>,
    rec: bool,
    has_with: bool,
}

impl FrameBuilder {
    fn new(slots: Vec<Symbol>, rec: bool, has_with: bool) -> Self {
        Self {
            slots,
            captures: BTreeSet::new(),
            rec,
            has_with,
        }
    }

    fn finish(self) -> Result<FrameInfo, ScopeError> {
        let slot_count = u32::try_from(self.slots.len()).map_err(|_| {
            ScopeError::new(ScopeErrorKind::TooManySlots, Span::new(u32::MAX, u32::MAX))
        })?;
        Ok(FrameInfo {
            slot_count,
            captures: self.captures.into_iter().collect(),
            rec: self.rec,
            has_with: self.has_with,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ActiveFrame {
    id: FrameId,
    lambda: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BindingResolveMode {
    Full,
    ValueOnly,
    PathOnly,
}

#[derive(Clone, Debug)]
struct ResolverState {
    root: NodeId,
    arena: AstArena,
    symbols: SymbolTable,
    frames: Vec<FrameBuilder>,
    node_frames: Vec<Option<FrameId>>,
    active_frames: Vec<ActiveFrame>,
    active_withs: Vec<NodeId>,
    with_chains: Vec<WithChain>,
    inherit_resolutions: Vec<InheritResolution>,
    node_inherits: Vec<Option<InheritGroupId>>,
}

impl ResolverState {
    fn new(parsed: ParsedAst, _options: ResolverOptions) -> Self {
        let node_count = parsed.arena.len();
        Self {
            root: parsed.root,
            arena: parsed.arena,
            symbols: parsed.symbols,
            frames: Vec::new(),
            node_frames: vec![None; node_count],
            active_frames: Vec::new(),
            active_withs: Vec::new(),
            with_chains: Vec::new(),
            inherit_resolutions: Vec::new(),
            node_inherits: vec![None; node_count],
        }
    }

    fn resolve_root(mut self) -> Result<ResolvedAst, ScopeError> {
        self.resolve_node(self.root)?;
        let frames = self
            .frames
            .into_iter()
            .map(FrameBuilder::finish)
            .collect::<Result<Vec<_>, _>>()?;
        let scopes = ScopeTables {
            frames,
            node_frames: self.node_frames,
            with_chains: self.with_chains,
            inherit_resolutions: self.inherit_resolutions,
            node_inherits: self.node_inherits,
        };
        Ok(ResolvedAst::new(
            self.root,
            self.arena,
            self.symbols,
            scopes,
        ))
    }

    fn resolve_node(&mut self, id: NodeId) -> Result<(), ScopeError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Int
            | NodeKind::Float
            | NodeKind::Str
            | NodeKind::Path
            | NodeKind::SearchPath
            | NodeKind::Uri
            | NodeKind::LocalVar
            | NodeKind::UpvalVar
            | NodeKind::GlobalVar
            | NodeKind::WithVar => Ok(()),
            NodeKind::Ident => self.resolve_identifier(id, node),
            NodeKind::List => self.resolve_children_payload(node),
            NodeKind::AttrSet => self.resolve_attrset(node),
            NodeKind::RecAttrSet => self.resolve_rec_attrset(id, node),
            NodeKind::Lambda => self.resolve_lambda(id, node),
            NodeKind::FormalSet => self.resolve_formal_set_defaults(node),
            NodeKind::Formal => self.resolve_formal_default(node),
            NodeKind::Apply | NodeKind::With | NodeKind::Assert => {
                if node.kind == NodeKind::With {
                    self.resolve_with(node)
                } else {
                    self.resolve_pair_payload(node)
                }
            }
            NodeKind::IfThenElse => self.resolve_triple_payload(node),
            NodeKind::BinOp => self.resolve_binary_payload(node),
            NodeKind::UnaryOp => self.resolve_unary_payload(node),
            NodeKind::Select => self.resolve_select_payload(node),
            NodeKind::HasAttr => self.resolve_has_attr_payload(node),
            NodeKind::LetIn => self.resolve_let_in(id, node),
            NodeKind::Binding => self.resolve_binding(node, BindingResolveMode::Full),
            NodeKind::Inherit => self.resolve_inherit(id, node, BindingResolveMode::Full),
            NodeKind::Interp => self.resolve_interp_payload(node),
            NodeKind::AttrPath => self.resolve_children_payload(node),
        }
    }

    fn resolve_identifier(&mut self, id: NodeId, node: Node) -> Result<(), ScopeError> {
        let symbol = self.symbol_payload(node)?;
        if let Some((depth, slot, binding_frame)) = self.lookup_symbol(symbol) {
            self.record_captures(binding_frame, slot, node.span)?;
            let data = if depth == 0 {
                NodeData::Local { slot }
            } else {
                NodeData::Upval { depth, slot }
            };
            let kind = if depth == 0 {
                NodeKind::LocalVar
            } else {
                NodeKind::UpvalVar
            };
            return self.replace_node(id, kind, data);
        }

        if !self.active_withs.is_empty() {
            let chain = self.push_with_chain(node.span)?;
            return self.replace_node(
                id,
                NodeKind::WithVar,
                NodeData::WithVar {
                    symbol,
                    chain: chain.as_u32(),
                },
            );
        }

        if self.is_global_symbol(symbol) {
            self.replace_node(id, NodeKind::GlobalVar, NodeData::Symbol(symbol))
        } else {
            Err(ScopeError::new(
                ScopeErrorKind::UndefinedSymbol(symbol),
                node.span,
            ))
        }
    }

    fn resolve_let_in(&mut self, id: NodeId, node: Node) -> Result<(), ScopeError> {
        let NodeData::LetIn { bindings, body } = node.data else {
            return Err(self.invalid_shape(node, "let-in payload"));
        };
        let binding_ids = self.child_ids(bindings)?;
        for binding in &binding_ids {
            self.resolve_let_binding_target(*binding)?;
        }
        let slots = self.collect_binding_symbols(&binding_ids)?;
        self.push_frame(id, slots, true, false, node.span)?;
        for binding in binding_ids {
            self.resolve_binding_node(binding, BindingResolveMode::ValueOnly)?;
        }
        self.resolve_node(body)?;
        self.pop_frame();
        Ok(())
    }

    fn resolve_lambda(&mut self, id: NodeId, node: Node) -> Result<(), ScopeError> {
        let NodeData::Pair {
            first: pattern,
            second: body,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "lambda pair"));
        };
        let slots = self.collect_lambda_symbols(pattern)?;
        self.push_frame(id, slots, false, true, node.span)?;
        self.resolve_lambda_pattern(pattern)?;
        self.resolve_node(body)?;
        self.pop_frame();
        Ok(())
    }

    fn resolve_attrset(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Children(bindings) = node.data else {
            return Err(self.invalid_shape(node, "attribute-set bindings"));
        };
        for binding in self.child_ids(bindings)? {
            self.resolve_node(binding)?;
        }
        Ok(())
    }

    fn resolve_rec_attrset(&mut self, id: NodeId, node: Node) -> Result<(), ScopeError> {
        let NodeData::Children(bindings) = node.data else {
            return Err(self.invalid_shape(node, "recursive attribute-set bindings"));
        };
        let binding_ids = self.child_ids(bindings)?;
        for binding in &binding_ids {
            self.resolve_binding_node(*binding, BindingResolveMode::PathOnly)?;
        }
        let slots = self.collect_binding_symbols(&binding_ids)?;
        self.push_frame(id, slots, true, false, node.span)?;
        for binding in binding_ids {
            self.resolve_binding_node(binding, BindingResolveMode::ValueOnly)?;
        }
        self.pop_frame();
        Ok(())
    }

    fn resolve_with(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Pair {
            first: scrutinee,
            second: body,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "with pair"));
        };
        self.resolve_node(scrutinee)?;
        self.mark_with_in_active_frames();
        self.active_withs.push(scrutinee);
        self.resolve_node(body)?;
        self.active_withs.pop();
        Ok(())
    }

    fn resolve_binding_node(
        &mut self,
        id: NodeId,
        mode: BindingResolveMode,
    ) -> Result<(), ScopeError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Binding => self.resolve_binding(node, mode),
            NodeKind::Inherit => self.resolve_inherit(id, node, mode),
            _ => Err(self.invalid_shape(node, "binding or inherit group")),
        }
    }

    fn resolve_let_binding_target(&mut self, id: NodeId) -> Result<(), ScopeError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Binding => {
                let NodeData::Binding { path, .. } = node.data else {
                    return Err(self.invalid_shape(node, "binding payload"));
                };
                self.ensure_static_let_path(path)
            }
            NodeKind::Inherit => self.resolve_inherit(id, node, BindingResolveMode::PathOnly),
            _ => Err(self.invalid_shape(node, "binding or inherit group")),
        }
    }

    fn resolve_binding(&mut self, node: Node, mode: BindingResolveMode) -> Result<(), ScopeError> {
        let NodeData::Binding { path, value } = node.data else {
            return Err(self.invalid_shape(node, "binding payload"));
        };
        if matches!(
            mode,
            BindingResolveMode::Full | BindingResolveMode::PathOnly
        ) {
            self.resolve_attr_path_dynamic(path)?;
        }
        if matches!(
            mode,
            BindingResolveMode::Full | BindingResolveMode::ValueOnly
        ) {
            self.resolve_node(value)?;
        }
        Ok(())
    }

    fn resolve_inherit(
        &mut self,
        id: NodeId,
        node: Node,
        mode: BindingResolveMode,
    ) -> Result<(), ScopeError> {
        let NodeData::Inherit { from, names } = node.data else {
            return Err(self.invalid_shape(node, "inherit payload"));
        };
        self.ensure_static_inherit_names(names)?;

        match (mode, from) {
            (BindingResolveMode::Full | BindingResolveMode::PathOnly, None) => {
                self.add_bare_inherit_resolution(id, node.span, names)
            }
            (BindingResolveMode::Full | BindingResolveMode::ValueOnly, Some(from)) => {
                self.resolve_node(from)?;
                self.add_from_inherit_resolution(id, node.span, from, names)
            }
            (BindingResolveMode::PathOnly, Some(_)) | (BindingResolveMode::ValueOnly, None) => {
                Ok(())
            }
        }
    }

    fn resolve_lambda_pattern(&mut self, pattern: NodeId) -> Result<(), ScopeError> {
        let node = self.node(pattern)?;
        match node.kind {
            NodeKind::Ident => Ok(()),
            NodeKind::FormalSet => self.resolve_formal_set_defaults(node),
            _ => Err(self.invalid_shape(node, "lambda pattern")),
        }
    }

    fn resolve_formal_set_defaults(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::FormalSet { formals, .. } = node.data else {
            return Err(self.invalid_shape(node, "formal set payload"));
        };
        for formal in self.child_ids(formals)? {
            self.resolve_formal_default(self.node(formal)?)?;
        }
        Ok(())
    }

    fn resolve_formal_default(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Formal { default, .. } = node.data else {
            return Err(self.invalid_shape(node, "formal payload"));
        };
        if let Some(default) = default {
            self.resolve_node(default)?;
        }
        Ok(())
    }

    fn resolve_pair_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Pair { first, second } = node.data else {
            return Err(self.invalid_shape(node, "pair payload"));
        };
        self.resolve_node(first)?;
        self.resolve_node(second)
    }

    fn resolve_triple_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Triple {
            first,
            second,
            third,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "triple payload"));
        };
        self.resolve_node(first)?;
        self.resolve_node(second)?;
        self.resolve_node(third)
    }

    fn resolve_binary_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Binary { lhs, rhs, .. } = node.data else {
            return Err(self.invalid_shape(node, "binary payload"));
        };
        self.resolve_node(lhs)?;
        self.resolve_node(rhs)
    }

    fn resolve_unary_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Unary { operand, .. } = node.data else {
            return Err(self.invalid_shape(node, "unary payload"));
        };
        self.resolve_node(operand)
    }

    fn resolve_select_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Select {
            receiver,
            path,
            default,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "select payload"));
        };
        self.resolve_node(receiver)?;
        self.resolve_attr_path_dynamic(path)?;
        if let Some(default) = default {
            self.resolve_node(default)?;
        }
        Ok(())
    }

    fn resolve_has_attr_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::HasAttr { receiver, path } = node.data else {
            return Err(self.invalid_shape(node, "has-attr payload"));
        };
        self.resolve_node(receiver)?;
        self.resolve_attr_path_dynamic(path)
    }

    fn resolve_interp_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        match node.data {
            NodeData::Node(child) => self.resolve_node(child),
            NodeData::Children(children) => {
                for child in self.child_ids(children)? {
                    self.resolve_node(child)?;
                }
                Ok(())
            }
            NodeData::None | NodeData::Symbol(_) => Ok(()),
            _ => Err(self.invalid_shape(node, "interpolation payload")),
        }
    }

    fn resolve_children_payload(&mut self, node: Node) -> Result<(), ScopeError> {
        let NodeData::Children(children) = node.data else {
            return Err(self.invalid_shape(node, "children payload"));
        };
        for child in self.child_ids(children)? {
            self.resolve_node(child)?;
        }
        Ok(())
    }

    fn resolve_attr_path_dynamic(&mut self, path: ChildSlice) -> Result<(), ScopeError> {
        for segment in self.child_ids(path)? {
            let node = self.node(segment)?;
            if node.kind == NodeKind::Interp {
                self.resolve_interp_payload(node)?;
            }
        }
        Ok(())
    }

    fn ensure_static_let_path(&self, path: ChildSlice) -> Result<(), ScopeError> {
        for segment in self.child_ids(path)? {
            let node = self.node(segment)?;
            if node.kind == NodeKind::Interp {
                return Err(ScopeError::new(
                    ScopeErrorKind::DynamicLetBinding,
                    node.span,
                ));
            }
        }
        Ok(())
    }

    fn ensure_static_inherit_names(&self, names: ChildSlice) -> Result<(), ScopeError> {
        for name in self.child_ids(names)? {
            let node = self.node(name)?;
            if self.static_attr_symbol(name)?.is_none() {
                return Err(ScopeError::new(
                    ScopeErrorKind::DynamicInheritTarget,
                    node.span,
                ));
            }
        }
        Ok(())
    }

    fn add_bare_inherit_resolution(
        &mut self,
        node: NodeId,
        span: Span,
        names: ChildSlice,
    ) -> Result<(), ScopeError> {
        let mut sources = Vec::new();
        for name in self.child_ids(names)? {
            let name_node = self.node(name)?;
            let Some(target) = self.static_attr_symbol(name)? else {
                return Err(ScopeError::new(
                    ScopeErrorKind::DynamicInheritTarget,
                    name_node.span,
                ));
            };
            let source = self.push_synthetic_node(
                NodeKind::Ident,
                name_node.span,
                NodeData::Symbol(target),
            )?;
            self.resolve_node(source)?;
            sources.push(InheritSource { target, source });
        }
        self.push_inherit_resolution(
            node,
            InheritResolution {
                from: None,
                sources: sources.into_boxed_slice(),
            },
            span,
        )?;
        Ok(())
    }

    fn add_from_inherit_resolution(
        &mut self,
        node: NodeId,
        span: Span,
        from: NodeId,
        names: ChildSlice,
    ) -> Result<(), ScopeError> {
        let mut sources = Vec::new();
        for name in self.child_ids(names)? {
            let name_node = self.node(name)?;
            let Some(target) = self.static_attr_symbol(name)? else {
                return Err(ScopeError::new(
                    ScopeErrorKind::DynamicInheritTarget,
                    name_node.span,
                ));
            };
            let attr = self.push_synthetic_node(
                NodeKind::Ident,
                name_node.span,
                NodeData::Symbol(target),
            )?;
            let path = self
                .arena
                .push_child_slice(&[attr])
                .map_err(ScopeError::from_ast)?;
            let source = self.push_synthetic_node(
                NodeKind::Select,
                self.join_span(self.node(from)?.span, name_node.span),
                NodeData::Select {
                    receiver: from,
                    path,
                    default: None,
                },
            )?;
            sources.push(InheritSource { target, source });
        }
        self.push_inherit_resolution(
            node,
            InheritResolution {
                from: Some(from),
                sources: sources.into_boxed_slice(),
            },
            span,
        )?;
        Ok(())
    }

    fn push_inherit_resolution(
        &mut self,
        node: NodeId,
        resolution: InheritResolution,
        span: Span,
    ) -> Result<InheritGroupId, ScopeError> {
        let raw = u32::try_from(self.inherit_resolutions.len())
            .map_err(|_| ScopeError::new(ScopeErrorKind::TooManyInheritGroups, span))?;
        let id = InheritGroupId::new(raw);
        self.inherit_resolutions.push(resolution);
        let Some(slot) = self.node_inherits.get_mut(node.index()) else {
            return Err(ScopeError::new(
                ScopeErrorKind::InvalidNodeId(node.as_u32()),
                span,
            ));
        };
        *slot = Some(id);
        Ok(id)
    }

    fn collect_binding_symbols(&self, bindings: &[NodeId]) -> Result<Vec<Symbol>, ScopeError> {
        let mut slots = Vec::new();
        for binding in bindings {
            let node = self.node(*binding)?;
            match node.kind {
                NodeKind::Binding => {
                    let NodeData::Binding { path, .. } = node.data else {
                        return Err(self.invalid_shape(node, "binding payload"));
                    };
                    if let Some(symbol) = self.first_static_attr_symbol(path)? {
                        push_unique(&mut slots, symbol);
                    }
                }
                NodeKind::Inherit => {
                    let NodeData::Inherit { names, .. } = node.data else {
                        return Err(self.invalid_shape(node, "inherit payload"));
                    };
                    for name in self.child_ids(names)? {
                        if let Some(symbol) = self.static_attr_symbol(name)? {
                            push_unique(&mut slots, symbol);
                        }
                    }
                }
                _ => return Err(self.invalid_shape(node, "binding or inherit group")),
            }
        }
        Ok(slots)
    }

    fn collect_lambda_symbols(&self, pattern: NodeId) -> Result<Vec<Symbol>, ScopeError> {
        let node = self.node(pattern)?;
        match node.kind {
            NodeKind::Ident => Ok(vec![self.symbol_payload(node)?]),
            NodeKind::FormalSet => {
                let NodeData::FormalSet { formals, alias, .. } = node.data else {
                    return Err(self.invalid_shape(node, "formal set payload"));
                };
                let mut slots = Vec::new();
                for formal in self.child_ids(formals)? {
                    let formal = self.node(formal)?;
                    let NodeData::Formal { name, .. } = formal.data else {
                        return Err(self.invalid_shape(formal, "formal payload"));
                    };
                    push_unique(&mut slots, name);
                }
                if let Some(alias) = alias {
                    push_unique(&mut slots, alias);
                }
                Ok(slots)
            }
            _ => Err(self.invalid_shape(node, "lambda pattern")),
        }
    }

    fn first_static_attr_symbol(&self, path: ChildSlice) -> Result<Option<Symbol>, ScopeError> {
        let Some(first) = self.child_ids(path)?.first().copied() else {
            return Ok(None);
        };
        self.static_attr_symbol(first)
    }

    fn static_attr_symbol(&self, id: NodeId) -> Result<Option<Symbol>, ScopeError> {
        let node = self.node(id)?;
        match node.kind {
            NodeKind::Ident | NodeKind::Str => Ok(Some(self.symbol_payload(node)?)),
            _ => Ok(None),
        }
    }

    fn is_global_symbol(&self, symbol: Symbol) -> bool {
        self.symbols.resolve(symbol).is_some_and(is_global_name)
    }

    fn lookup_symbol(&self, symbol: Symbol) -> Option<(u32, u32, usize)> {
        for (depth, frame) in self.active_frames.iter().rev().enumerate() {
            let builder = &self.frames[frame.id.index()];
            if let Some(slot) = builder
                .slots
                .iter()
                .position(|candidate| *candidate == symbol)
            {
                let depth = u32::try_from(depth).ok()?;
                let slot = u32::try_from(slot).ok()?;
                let binding_frame = self.active_frames.len().checked_sub(depth as usize + 1)?;
                return Some((depth, slot, binding_frame));
            }
        }
        None
    }

    fn record_captures(
        &mut self,
        binding_frame: usize,
        slot: u32,
        span: Span,
    ) -> Result<(), ScopeError> {
        let slot =
            u16::try_from(slot).map_err(|_| ScopeError::new(ScopeErrorKind::TooManySlots, span))?;
        let mut captures = Vec::new();
        for lambda_frame in binding_frame + 1..self.active_frames.len() {
            let frame = self.active_frames[lambda_frame];
            if frame.lambda {
                let depth = u16::try_from(lambda_frame - binding_frame)
                    .map_err(|_| ScopeError::new(ScopeErrorKind::TooManyUpvalues, span))?;
                captures.push((frame.id, Upvalue { depth, slot }));
            }
        }
        for (frame, upvalue) in captures {
            self.frames[frame.index()].captures.insert(upvalue);
        }
        Ok(())
    }

    fn push_frame(
        &mut self,
        node: NodeId,
        slots: Vec<Symbol>,
        rec: bool,
        lambda: bool,
        span: Span,
    ) -> Result<(), ScopeError> {
        let raw = u32::try_from(self.frames.len())
            .map_err(|_| ScopeError::new(ScopeErrorKind::TooManyFrames, span))?;
        let id = FrameId::new(raw);
        let has_with = !self.active_withs.is_empty();
        self.frames.push(FrameBuilder::new(slots, rec, has_with));
        if let Some(slot) = self.node_frames.get_mut(node.index()) {
            *slot = Some(id);
        }
        self.active_frames.push(ActiveFrame { id, lambda });
        Ok(())
    }

    fn pop_frame(&mut self) {
        self.active_frames.pop();
    }

    fn mark_with_in_active_frames(&mut self) {
        for frame in &self.active_frames {
            self.frames[frame.id.index()].has_with = true;
        }
    }

    fn push_with_chain(&mut self, span: Span) -> Result<WithChainId, ScopeError> {
        let raw = u32::try_from(self.with_chains.len())
            .map_err(|_| ScopeError::new(ScopeErrorKind::TooManyWithChains, span))?;
        let scopes = self
            .active_withs
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.with_chains.push(WithChain { scopes });
        Ok(WithChainId::new(raw))
    }

    fn replace_node(
        &mut self,
        id: NodeId,
        kind: NodeKind,
        data: NodeData,
    ) -> Result<(), ScopeError> {
        let node = self.arena.node_mut(id).ok_or_else(|| {
            ScopeError::new(
                ScopeErrorKind::InvalidNodeId(id.as_u32()),
                Span::new(u32::MAX, u32::MAX),
            )
        })?;
        node.kind = kind;
        node.data = data;
        Ok(())
    }

    fn push_synthetic_node(
        &mut self,
        kind: NodeKind,
        span: Span,
        data: NodeData,
    ) -> Result<NodeId, ScopeError> {
        let id = self
            .arena
            .push_node(kind, span, data)
            .map_err(ScopeError::from_ast)?;
        self.node_frames.push(None);
        self.node_inherits.push(None);
        Ok(id)
    }

    fn symbol_payload(&self, node: Node) -> Result<Symbol, ScopeError> {
        let NodeData::Symbol(symbol) = node.data else {
            return Err(self.invalid_shape(node, "symbol payload"));
        };
        Ok(symbol)
    }

    fn child_ids(&self, slice: ChildSlice) -> Result<Vec<NodeId>, ScopeError> {
        Ok(self
            .arena
            .child_slice(slice)
            .map_err(ScopeError::from_ast)?
            .to_vec())
    }

    fn node(&self, id: NodeId) -> Result<Node, ScopeError> {
        self.arena.node(id).copied().ok_or_else(|| {
            ScopeError::new(
                ScopeErrorKind::InvalidNodeId(id.as_u32()),
                Span::new(u32::MAX, u32::MAX),
            )
        })
    }

    fn invalid_shape(&self, node: Node, expected: &'static str) -> ScopeError {
        ScopeError::new(
            ScopeErrorKind::InvalidNodeShape {
                kind: node.kind,
                expected,
            },
            node.span,
        )
    }

    fn join_span(&self, first: Span, second: Span) -> Span {
        Span::new(first.start.min(second.start), first.end.max(second.end))
    }
}

fn push_unique(symbols: &mut Vec<Symbol>, symbol: Symbol) {
    if !symbols.contains(&symbol) {
        symbols.push(symbol);
    }
}

fn is_global_name(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        b"abort"
            | b"add"
            | b"addDrvOutputDependencies"
            | b"addErrorContext"
            | b"all"
            | b"any"
            | b"appendContext"
            | b"attrNames"
            | b"attrValues"
            | b"baseNameOf"
            | b"bitAnd"
            | b"bitOr"
            | b"bitXor"
            | b"break"
            | b"builtins"
            | b"catAttrs"
            | b"ceil"
            | b"compareVersions"
            | b"concatLists"
            | b"concatMap"
            | b"concatStringsSep"
            | b"convertHash"
            | b"currentSystem"
            | b"currentTime"
            | b"deepSeq"
            | b"derivation"
            | b"derivationStrict"
            | b"dirOf"
            | b"div"
            | b"elem"
            | b"elemAt"
            | b"exec"
            | b"false"
            | b"fetchClosure"
            | b"fetchGit"
            | b"fetchMercurial"
            | b"fetchTarball"
            | b"fetchTree"
            | b"fetchurl"
            | b"filter"
            | b"filterSource"
            | b"findFile"
            | b"floor"
            | b"foldl'"
            | b"fromJSON"
            | b"fromTOML"
            | b"functionArgs"
            | b"genList"
            | b"genericClosure"
            | b"getAttr"
            | b"getContext"
            | b"getEnv"
            | b"getFlake"
            | b"groupBy"
            | b"hasAttr"
            | b"hasContext"
            | b"hashFile"
            | b"hashString"
            | b"head"
            | b"import"
            | b"intersectAttrs"
            | b"isAttrs"
            | b"isBool"
            | b"isFloat"
            | b"isFunction"
            | b"isInt"
            | b"isList"
            | b"isNull"
            | b"isPath"
            | b"isString"
            | b"langVersion"
            | b"length"
            | b"lessThan"
            | b"listToAttrs"
            | b"map"
            | b"mapAttrs"
            | b"match"
            | b"mul"
            | b"nixPath"
            | b"nixVersion"
            | b"null"
            | b"outputOf"
            | b"parseDrvName"
            | b"partition"
            | b"path"
            | b"pathExists"
            | b"placeholder"
            | b"readDir"
            | b"readFile"
            | b"readFileType"
            | b"removeAttrs"
            | b"replaceStrings"
            | b"scopedImport"
            | b"seq"
            | b"sort"
            | b"split"
            | b"splitVersion"
            | b"storeDir"
            | b"storePath"
            | b"stringLength"
            | b"sub"
            | b"substring"
            | b"tail"
            | b"throw"
            | b"toFile"
            | b"toHashFormat"
            | b"toJSON"
            | b"toPath"
            | b"toString"
            | b"toXML"
            | b"trace"
            | b"traceVerbose"
            | b"true"
            | b"tryEval"
            | b"typeOf"
            | b"unsafeDiscardOutputDependency"
            | b"unsafeDiscardStringContext"
            | b"unsafeGetAttrPos"
            | b"warn"
            | b"zipAttrsWith"
    )
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
mod tests {
    use super::*;
    use crate::syntax::{BinOpKind, parse_str};

    fn resolved(source: &str) -> ResolvedAst {
        resolve(parse_str(source).expect("source parses")).expect("scope resolves")
    }

    fn node(ast: &ResolvedAst, id: NodeId) -> &Node {
        ast.arena.node(id).expect("node exists")
    }

    fn child_ids(ast: &ResolvedAst, slice: ChildSlice) -> &[NodeId] {
        ast.arena.child_slice(slice).expect("child slice exists")
    }

    fn binding_value(ast: &ResolvedAst, binding: NodeId) -> NodeId {
        let NodeData::Binding { value, .. } = node(ast, binding).data else {
            panic!("binding payload expected");
        };
        value
    }

    fn local_slot(ast: &ResolvedAst, id: NodeId) -> u32 {
        let NodeData::Local { slot } = node(ast, id).data else {
            panic!("local payload expected");
        };
        slot
    }

    fn upval(ast: &ResolvedAst, id: NodeId) -> (u32, u32) {
        let NodeData::Upval { depth, slot } = node(ast, id).data else {
            panic!("upvalue payload expected");
        };
        (depth, slot)
    }

    fn inherit_resolution(ast: &ResolvedAst, id: NodeId) -> &InheritResolution {
        let group = ast
            .scopes
            .inherit_for_node(id)
            .expect("inherit group attached");
        ast.scopes
            .inherit_resolution(group)
            .expect("inherit resolution exists")
    }

    #[test]
    fn resolves_let_lambda_to_de_bruijn_slots() {
        let ast = resolved("let x = 1; f = y: x + y; in f 41");
        let root = node(&ast, ast.root);
        let NodeData::LetIn { bindings, body } = root.data else {
            panic!("let-in payload expected");
        };
        let let_frame = ast
            .scopes
            .frame_for_node(ast.root)
            .expect("let frame exists");
        let let_info = &ast.scopes.frames()[let_frame.index()];
        assert_eq!(let_info.slot_count, 2);
        assert!(let_info.rec);

        let apply = node(&ast, body);
        let NodeData::Pair { first: callee, .. } = apply.data else {
            panic!("apply payload expected");
        };
        assert_eq!(node(&ast, callee).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, callee), 1);

        let binding_ids = child_ids(&ast, bindings);
        let lambda = binding_value(&ast, binding_ids[1]);
        let lambda_frame = ast
            .scopes
            .frame_for_node(lambda)
            .expect("lambda frame exists");
        let lambda_info = &ast.scopes.frames()[lambda_frame.index()];
        assert_eq!(lambda_info.slot_count, 1);
        assert_eq!(
            lambda_info.captures.as_ref(),
            &[Upvalue { depth: 1, slot: 0 }]
        );

        let NodeData::Pair {
            second: lambda_body,
            ..
        } = node(&ast, lambda).data
        else {
            panic!("lambda payload expected");
        };
        let NodeData::Binary {
            op,
            lhs: x_ref,
            rhs: y_ref,
        } = node(&ast, lambda_body).data
        else {
            panic!("binary payload expected");
        };
        assert_eq!(op, BinOpKind::Add);
        assert_eq!(node(&ast, x_ref).kind, NodeKind::UpvalVar);
        assert_eq!(upval(&ast, x_ref), (1, 0));
        assert_eq!(node(&ast, y_ref).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, y_ref), 0);
    }

    #[test]
    fn let_frames_are_self_visible() {
        let ast = resolved("let x = y; y = 1; in x");
        let NodeData::LetIn { bindings, body } = node(&ast, ast.root).data else {
            panic!("let-in payload expected");
        };
        let binding_ids = child_ids(&ast, bindings);
        let x_value = binding_value(&ast, binding_ids[0]);
        assert_eq!(node(&ast, x_value).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, x_value), 1);
        assert_eq!(node(&ast, body).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, body), 0);
    }

    #[test]
    fn recursive_attrsets_are_self_visible_but_plain_attrsets_are_not() {
        let ast = resolved("rec { a = 1; b = a; }");
        let root = node(&ast, ast.root);
        let frame = ast
            .scopes
            .frame_for_node(ast.root)
            .expect("rec frame exists");
        assert_eq!(ast.scopes.frames()[frame.index()].slot_count, 2);
        assert!(ast.scopes.frames()[frame.index()].rec);
        let NodeData::Children(bindings) = root.data else {
            panic!("rec attrset payload expected");
        };
        let b_value = binding_value(&ast, child_ids(&ast, bindings)[1]);
        assert_eq!(node(&ast, b_value).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, b_value), 0);

        let ast = resolved("let outer = 9; in { outer = 1; b = outer; }");
        let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
            panic!("let-in payload expected");
        };
        let NodeData::Children(bindings) = node(&ast, body).data else {
            panic!("attrset payload expected");
        };
        let b_value = binding_value(&ast, child_ids(&ast, bindings)[1]);
        assert_eq!(node(&ast, b_value).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, b_value), 0);
    }

    #[test]
    fn attr_path_merges_preserve_order_sensitive_rec_scope() {
        let ast = resolved("{ a = rec { c = c; }; a.b = 1; }");
        let NodeData::Children(bindings) = node(&ast, ast.root).data else {
            panic!("attrset payload expected");
        };
        let a_value = binding_value(&ast, child_ids(&ast, bindings)[0]);
        let NodeData::Children(nested_bindings) = node(&ast, a_value).data else {
            panic!("nested attrset payload expected");
        };
        let c_value = binding_value(&ast, child_ids(&ast, nested_bindings)[0]);
        assert_eq!(node(&ast, c_value).kind, NodeKind::LocalVar);

        let error = resolve(parse_str("{ a.b = 1; a = rec { c = c; }; }").expect("source parses"))
            .expect_err("later rec attrset is merged into the earlier plain prefix");
        assert!(matches!(error.kind(), ScopeErrorKind::UndefinedSymbol(_)));
    }

    #[test]
    fn recursive_dynamic_attr_names_do_not_enter_the_rec_scope() {
        let ast = resolved("let outer = 1; in rec { ${outer} = 2; a = 3; b = a; }");
        let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
            panic!("let-in payload expected");
        };
        let NodeData::Children(bindings) = node(&ast, body).data else {
            panic!("rec attrset payload expected");
        };
        let binding_ids = child_ids(&ast, bindings);
        let NodeData::Binding { path, .. } = node(&ast, binding_ids[0]).data else {
            panic!("binding payload expected");
        };
        let dynamic_segment = child_ids(&ast, path)[0];
        let NodeData::Node(dynamic_name) = node(&ast, dynamic_segment).data else {
            panic!("dynamic attr segment expected");
        };
        assert_eq!(node(&ast, dynamic_name).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, dynamic_name), 0);

        let b_value = binding_value(&ast, binding_ids[2]);
        assert_eq!(node(&ast, b_value).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, b_value), 0);
    }

    #[test]
    fn nested_lambdas_record_transitive_capture_sets() {
        let ast = resolved("let x = 1; in y: z: x + y + z");
        let NodeData::LetIn {
            body: outer_lambda, ..
        } = node(&ast, ast.root).data
        else {
            panic!("let-in payload expected");
        };
        let NodeData::Pair {
            second: inner_lambda,
            ..
        } = node(&ast, outer_lambda).data
        else {
            panic!("outer lambda payload expected");
        };

        let outer_frame = ast
            .scopes
            .frame_for_node(outer_lambda)
            .expect("outer lambda frame exists");
        assert_eq!(
            ast.scopes.frames()[outer_frame.index()].captures.as_ref(),
            &[Upvalue { depth: 1, slot: 0 }]
        );

        let inner_frame = ast
            .scopes
            .frame_for_node(inner_lambda)
            .expect("inner lambda frame exists");
        assert_eq!(
            ast.scopes.frames()[inner_frame.index()].captures.as_ref(),
            &[Upvalue { depth: 1, slot: 0 }, Upvalue { depth: 2, slot: 0 }]
        );
    }

    #[test]
    fn lexical_bindings_beat_active_with_scopes() {
        let ast = resolved("let a = 1; xs = {}; in with xs; a");
        let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
            panic!("let-in payload expected");
        };
        let NodeData::Pair {
            first: scrutinee,
            second: with_body,
        } = node(&ast, body).data
        else {
            panic!("with payload expected");
        };
        assert_eq!(node(&ast, scrutinee).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, scrutinee), 1);
        assert_eq!(node(&ast, with_body).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, with_body), 0);

        let frame = ast
            .scopes
            .frame_for_node(ast.root)
            .expect("let frame exists");
        assert!(ast.scopes.frames()[frame.index()].has_with);
    }

    #[test]
    fn with_variables_record_innermost_first_probe_chains() {
        let ast = resolved("let outer = {}; in with outer; with inner; missing");
        let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
            panic!("let-in payload expected");
        };
        let NodeData::Pair {
            first: outer,
            second: inner_with,
        } = node(&ast, body).data
        else {
            panic!("outer with payload expected");
        };
        let NodeData::Pair {
            first: inner,
            second: missing,
        } = node(&ast, inner_with).data
        else {
            panic!("inner with payload expected");
        };
        assert_eq!(node(&ast, outer).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, outer), 0);
        assert_eq!(node(&ast, inner).kind, NodeKind::WithVar);
        assert_eq!(node(&ast, missing).kind, NodeKind::WithVar);
        let NodeData::WithVar { symbol, .. } = node(&ast, inner).data else {
            panic!("with-var payload expected");
        };
        assert_eq!(ast.symbols.resolve(symbol), Some(b"inner".as_slice()));
        let NodeData::WithVar { chain, .. } = node(&ast, missing).data else {
            panic!("with-var payload expected");
        };
        let chain = ast
            .scopes
            .with_chain(WithChainId::new(chain))
            .expect("with chain exists");
        assert_eq!(chain.scopes.as_ref(), &[inner, outer]);
    }

    #[test]
    fn lambda_parameters_shadow_active_with_scopes() {
        let ast = resolved("let outer = {}; in with outer; (x: x)");
        let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
            panic!("let-in payload expected");
        };
        let NodeData::Pair { second: lambda, .. } = node(&ast, body).data else {
            panic!("with payload expected");
        };
        let NodeData::Pair {
            second: lambda_body,
            ..
        } = node(&ast, lambda).data
        else {
            panic!("lambda payload expected");
        };
        assert_eq!(node(&ast, lambda_body).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, lambda_body), 0);
    }

    #[test]
    fn global_names_are_classified_separately_from_undefined_names() {
        let ast = resolved("true");
        assert_eq!(node(&ast, ast.root).kind, NodeKind::GlobalVar);

        let ast = resolved("foldl'");
        assert_eq!(node(&ast, ast.root).kind, NodeKind::GlobalVar);

        let error = resolve(parse_str("toLower").expect("source parses"))
            .expect_err("toLower is not global");
        assert!(matches!(error.kind(), ScopeErrorKind::UndefinedSymbol(_)));

        let error =
            resolve(parse_str("missing").expect("source parses")).expect_err("missing name errors");
        assert!(matches!(error.kind(), ScopeErrorKind::UndefinedSymbol(_)));
    }

    #[test]
    fn bare_inherit_sources_resolve_outside_the_self_frame() {
        let ast = resolved("let z = 0; x = 1; y = let inherit x; in x; in y");
        let NodeData::LetIn {
            bindings: outer_bindings,
            ..
        } = node(&ast, ast.root).data
        else {
            panic!("outer let-in payload expected");
        };
        let y_value = binding_value(&ast, child_ids(&ast, outer_bindings)[2]);
        let NodeData::LetIn {
            bindings: inner_bindings,
            body: inner_body,
        } = node(&ast, y_value).data
        else {
            panic!("inner let-in payload expected");
        };
        let inherit = child_ids(&ast, inner_bindings)[0];
        let resolution = inherit_resolution(&ast, inherit);
        assert_eq!(resolution.sources.len(), 1);
        let source = resolution.sources[0].source;
        assert_eq!(node(&ast, source).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, source), 1);
        assert_eq!(node(&ast, inner_body).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, inner_body), 0);
    }

    #[test]
    fn inherit_from_expression_records_resolved_select_sources() {
        let ast = resolved("let src = { name = 1; }; in { inherit (src) name; }");
        let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
            panic!("let-in payload expected");
        };
        let NodeData::Children(bindings) = node(&ast, body).data else {
            panic!("attrset payload expected");
        };
        let inherit = child_ids(&ast, bindings)[0];
        let resolution = inherit_resolution(&ast, inherit);
        let from = resolution.from.expect("inherit source expression exists");
        assert_eq!(node(&ast, from).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, from), 0);
        let source = resolution.sources[0].source;
        assert_eq!(node(&ast, source).kind, NodeKind::Select);
        let NodeData::Select { receiver, path, .. } = node(&ast, source).data else {
            panic!("select payload expected");
        };
        assert_eq!(receiver, from);
        assert_eq!(child_ids(&ast, path).len(), 1);
    }

    #[test]
    fn rec_inherit_targets_are_self_visible_but_sources_are_outer() {
        let ast = resolved("let x = 1; in rec { inherit x; y = x; }");
        let NodeData::LetIn { body, .. } = node(&ast, ast.root).data else {
            panic!("let-in payload expected");
        };
        let NodeData::Children(bindings) = node(&ast, body).data else {
            panic!("rec attrset payload expected");
        };
        let inherit = child_ids(&ast, bindings)[0];
        let resolution = inherit_resolution(&ast, inherit);
        let source = resolution.sources[0].source;
        assert_eq!(node(&ast, source).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, source), 0);

        let y_value = binding_value(&ast, child_ids(&ast, bindings)[1]);
        assert_eq!(node(&ast, y_value).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, y_value), 0);
    }

    #[test]
    fn rejects_computed_let_binding_names() {
        let error = resolve(parse_str("let ${name} = 1; in 1").expect("source parses"))
            .expect_err("computed let target errors");
        assert_eq!(error.kind(), &ScopeErrorKind::DynamicLetBinding);
    }

    #[test]
    fn formal_defaults_and_aliases_use_lambda_slots() {
        let ast = resolved("{ a, b ? a, ... }@args: args");
        let frame = ast
            .scopes
            .frame_for_node(ast.root)
            .expect("lambda frame exists");
        assert_eq!(ast.scopes.frames()[frame.index()].slot_count, 3);

        let NodeData::Pair {
            first: pattern,
            second: body,
        } = node(&ast, ast.root).data
        else {
            panic!("lambda payload expected");
        };
        assert_eq!(node(&ast, body).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, body), 2);

        let NodeData::FormalSet { formals, .. } = node(&ast, pattern).data else {
            panic!("formal-set payload expected");
        };
        let b_formal = child_ids(&ast, formals)[1];
        let NodeData::Formal {
            default: Some(default),
            ..
        } = node(&ast, b_formal).data
        else {
            panic!("formal default expected");
        };
        assert_eq!(node(&ast, default).kind, NodeKind::LocalVar);
        assert_eq!(local_slot(&ast, default), 0);
    }
}
