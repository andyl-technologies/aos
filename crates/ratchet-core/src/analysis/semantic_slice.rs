//! Binder-aware canonical semantic slices.
//!
//! This analysis resolves every [`crate::IrKind::LocalVar`] and
//! [`crate::IrKind::UpvalVar`] through the active lexical-frame stack. The
//! resulting byte stream names binders in first semantic-use order instead of
//! by source symbol, frame id, or physical slot. A `let` contributes only
//! bindings transitively selected by its body; recursive dependencies are
//! additionally exposed as strongly connected components.
//!
//! The representation is an analysis certificate, not executable code. It
//! deliberately retains node operations, literal data, semantic attribute
//! keys, lexical capture depth, and recursion edges while omitting spans,
//! inline-cache sites, binder names, and unrelated `let` bindings.

use std::collections::{BTreeSet, HashMap, HashSet};

use thiserror::Error;

use crate::syntax::{Symbol, SymbolTable};
use crate::{
    Ir, IrAttrPathId, IrAttrPathSegment, IrBinding, IrBindingSlice, IrChildSlice, IrData, IrId,
    IrKind,
};

/// Identifies one retained binder in canonical first-use order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticBinderId(u32);

impl SemanticBinderId {
    /// Returns the canonical numeric identity.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Describes one strongly connected component of retained binding definitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticBindingComponent {
    binders: Box<[SemanticBinderId]>,
    recursive: bool,
}

impl SemanticBindingComponent {
    /// Returns the component's binders in canonical identity order.
    pub fn binders(&self) -> &[SemanticBinderId] {
        &self.binders
    }

    /// Returns whether the component contains a recursive dependency.
    pub const fn is_recursive(&self) -> bool {
        self.recursive
    }
}

/// An alpha-normalized semantic slice rooted at one IR expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticSlice {
    canonical: Box<[u8]>,
    retained_bindings: Box<[SemanticBinderId]>,
    components: Box<[SemanticBindingComponent]>,
}

impl SemanticSlice {
    /// Returns the stable canonical byte representation.
    ///
    /// The encoding is private to the current `ratchet-core` build. Consumers
    /// may compare or hash it but must not persist it as a versionless format.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Returns every retained binding definition in canonical identity order.
    pub fn retained_bindings(&self) -> &[SemanticBinderId] {
        &self.retained_bindings
    }

    /// Returns binding dependency components in canonical component order.
    pub fn components(&self) -> &[SemanticBindingComponent] {
        &self.components
    }
}

/// Reports malformed IR that prevents sound lexical resolution.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SemanticSliceError {
    /// A referenced node does not exist.
    #[error("semantic slice references missing IR node {0:?}")]
    InvalidNode(IrId),
    /// A variable read has no corresponding active frame.
    #[error("semantic slice variable {id:?} escapes its lexical frame stack")]
    MissingFrame {
        /// The invalid variable read.
        id: IrId,
    },
    /// A frame slot is outside the frame owner's binding layout.
    #[error("semantic slice variable {id:?} references invalid slot {slot}")]
    InvalidSlot {
        /// The invalid variable read.
        id: IrId,
        /// The out-of-range slot.
        slot: u32,
    },
    /// A variable payload does not agree with its node kind.
    #[error("semantic slice node {id:?} has invalid payload for {kind:?}")]
    InvalidPayload {
        /// The malformed node.
        id: IrId,
        /// The node's declared kind.
        kind: IrKind,
    },
    /// A child side-table slice is invalid.
    #[error("semantic slice node {id:?} references an invalid child slice")]
    InvalidChildSlice {
        /// The node owning the invalid slice.
        id: IrId,
    },
    /// A binding side-table slice is invalid.
    #[error("semantic slice node {id:?} references an invalid binding slice")]
    InvalidBindingSlice {
        /// The node owning the invalid slice.
        id: IrId,
    },
    /// An attribute path side-table id is invalid.
    #[error("semantic slice node {id:?} references an invalid attribute path")]
    InvalidAttrPath {
        /// The node owning the invalid path.
        id: IrId,
    },
    /// A dynamic-scope chain id is invalid.
    #[error("semantic slice node {id:?} references an invalid dynamic-scope chain")]
    InvalidWithChain {
        /// The node owning the invalid chain.
        id: IrId,
    },
    /// A symbol cannot be resolved to semantic bytes.
    #[error("semantic slice references invalid symbol {symbol:?}")]
    InvalidSymbol {
        /// The unresolved symbol.
        symbol: Symbol,
    },
    /// The canonical binder table exceeded `u32` addressability.
    #[error("semantic slice has too many retained binders")]
    TooManyBinders,
    /// The requested subslice root is not reachable from the IR root.
    #[error("semantic subslice root {0:?} is not reachable from the IR root")]
    UnreachableRoot(IrId),
    /// The requested subslice root occurs under different lexical contexts.
    #[error("semantic subslice root {0:?} has ambiguous lexical contexts")]
    AmbiguousRootContext(IrId),
    /// A reachable child cycle prevents bounded context discovery.
    #[error("semantic subslice context discovery found an IR cycle at {0:?}")]
    IrCycle(IrId),
}

/// Produces a binder-aware canonical slice for `root`.
///
/// `let` definitions are pulled into the slice only when a retained expression
/// reads their binder. Dependencies of those definitions are retained
/// transitively. Lambda parameters and recursive attribute bindings are also
/// resolved to canonical identities, but semantic attribute keys remain in the
/// encoding.
///
/// # Errors
///
/// Returns [`SemanticSliceError`] when `root` or a reachable side-table entry
/// is malformed, a lexical coordinate cannot be resolved, or the canonical
/// binder table exceeds `u32` addressability.
pub fn analyze_semantic_slice(ir: &Ir, root: IrId) -> Result<SemanticSlice, SemanticSliceError> {
    let mut analysis = Analysis::new(ir);
    analysis.expression(root)?;
    analysis.finish()
}

/// Produces a canonical slice for a reachable node in its lexical context.
///
/// Unlike [`analyze_semantic_slice`], this entry point may start below
/// [`Ir::root`]. It discovers the unique frame stack leading to `root`, then
/// resolves the node's free lexical reads through that stack. A shared node
/// reached under different frame stacks is rejected rather than assigned an
/// arbitrary context.
///
/// # Errors
///
/// Returns [`SemanticSliceError`] when context discovery or slice analysis
/// encounters malformed IR, when `root` is unreachable, or when it has
/// ambiguous lexical contexts.
pub fn analyze_semantic_subslice(ir: &Ir, root: IrId) -> Result<SemanticSlice, SemanticSliceError> {
    let frames = locate_context(ir, root)?;
    let mut analysis = Analysis::new(ir);
    analysis.frames = frames;
    analysis.expression(root)?;
    analysis.finish()
}

/// Produces a canonical subslice using a separately owned live symbol table.
///
/// Evaluators may adopt an IR's symbol table into session-wide storage while
/// retaining the IR arena and side tables in a module. This entry point keeps
/// the same binder-aware analysis and fail-closed lexical-context discovery as
/// [`analyze_semantic_subslice`] while resolving semantic symbol bytes through
/// that adopted table.
///
/// # Errors
///
/// Returns [`SemanticSliceError`] under the same conditions as
/// [`analyze_semantic_subslice`], including when `symbols` cannot resolve a
/// symbol referenced by the IR.
pub fn analyze_semantic_subslice_with_symbols(
    ir: &Ir,
    symbols: &SymbolTable,
    root: IrId,
) -> Result<SemanticSlice, SemanticSliceError> {
    let frames = locate_context(ir, root)?;
    let mut analysis = Analysis::with_symbols(ir, symbols);
    analysis.frames = frames;
    analysis.expression(root)?;
    analysis.finish()
}

/// Returns whether a subslice transitively selects every definition node.
///
/// A definition node is the value stored in a lexical binding, including its
/// [`crate::IrKind::ThunkAlloc`] wrapper when present. This query lets
/// consumers tie separately checked semantic roles back to the binder graph
/// selected by `root`.
///
/// # Errors
///
/// Returns [`SemanticSliceError`] under the same fail-closed conditions as
/// [`analyze_semantic_subslice`].
pub fn semantic_subslice_retains_all(
    ir: &Ir,
    root: IrId,
    definitions: &[IrId],
) -> Result<bool, SemanticSliceError> {
    semantic_subslice_retains_all_with_symbols(ir, &ir.symbols, root, definitions)
}

/// Returns whether an adopted-symbol subslice retains every definition node.
///
/// This is the separately owned symbol-table counterpart to
/// [`semantic_subslice_retains_all`].
///
/// # Errors
///
/// Returns [`SemanticSliceError`] under the same conditions as
/// [`analyze_semantic_subslice_with_symbols`].
pub fn semantic_subslice_retains_all_with_symbols(
    ir: &Ir,
    symbols: &SymbolTable,
    root: IrId,
    definitions: &[IrId],
) -> Result<bool, SemanticSliceError> {
    let frames = locate_context(ir, root)?;
    let mut analysis = Analysis::with_symbols(ir, symbols);
    analysis.frames = frames;
    analysis.expression(root)?;
    Ok(definitions
        .iter()
        .all(|definition| analysis.selected_definitions.contains(definition)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct BinderKey {
    owner: IrId,
    slot: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BinderDefinition {
    Value(IrId),
    Parameter,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Frame {
    owner: IrId,
    kind: FrameKind,
    definitions: Vec<BinderDefinition>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameKind {
    Binding,
    Lambda,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DefinitionState {
    Unseen,
    Visiting,
    Complete,
}

struct Analysis<'a> {
    ir: &'a Ir,
    symbols: &'a SymbolTable,
    bytes: Vec<u8>,
    frames: Vec<Frame>,
    canonical_ids: HashMap<BinderKey, SemanticBinderId>,
    states: HashMap<BinderKey, DefinitionState>,
    selected_definitions: HashSet<IrId>,
    retained: BTreeSet<SemanticBinderId>,
    edges: Vec<BTreeSet<usize>>,
    current_definition: Vec<SemanticBinderId>,
}

impl<'a> Analysis<'a> {
    fn new(ir: &'a Ir) -> Self {
        Self::with_symbols(ir, &ir.symbols)
    }

    fn with_symbols(ir: &'a Ir, symbols: &'a SymbolTable) -> Self {
        Self {
            ir,
            symbols,
            bytes: b"ratchet-semantic-slice-v1".to_vec(),
            frames: Vec::new(),
            canonical_ids: HashMap::new(),
            states: HashMap::new(),
            selected_definitions: HashSet::new(),
            retained: BTreeSet::new(),
            edges: Vec::new(),
            current_definition: Vec::new(),
        }
    }

    fn finish(self) -> Result<SemanticSlice, SemanticSliceError> {
        let retained: Vec<_> = self.retained.iter().copied().collect();
        let components = strongly_connected_components(&retained, &self.edges);
        Ok(SemanticSlice {
            canonical: self.bytes.into_boxed_slice(),
            retained_bindings: retained.into_boxed_slice(),
            components: components.into_boxed_slice(),
        })
    }

    fn expression(&mut self, id: IrId) -> Result<(), SemanticSliceError> {
        let node = self
            .ir
            .arena
            .node(id)
            .ok_or(SemanticSliceError::InvalidNode(id))?;
        if !valid_payload(node.kind, node.data) {
            return Err(SemanticSliceError::InvalidPayload {
                id,
                kind: node.kind,
            });
        }
        if let IrData::Let { bindings, body, .. } = node.data {
            return self.let_expression(id, bindings, body);
        }
        match node.data {
            IrData::Local { slot } => return self.variable(id, 0, slot),
            IrData::Upval { depth, slot } => return self.variable(id, depth, slot),
            _ => {}
        }
        self.byte(node.kind as u8);
        match node.data {
            IrData::None => {}
            IrData::Int(value) => self.bytes.extend_from_slice(&value.to_le_bytes()),
            IrData::Float(value) => self.bytes.extend_from_slice(&value.to_bits().to_le_bytes()),
            IrData::Bool(value) => self.byte(u8::from(value)),
            IrData::Symbol(symbol) => self.symbol(symbol)?,
            IrData::GlobalVar { symbol, .. } => self.symbol(symbol)?,
            IrData::SearchPath {
                literal,
                search_path,
            } => {
                self.symbol(literal)?;
                self.optional(search_path)?;
            }
            IrData::Node(child) => self.expression(child)?,
            IrData::Pair { first, second } => {
                self.expression(first)?;
                self.expression(second)?;
            }
            IrData::Triple {
                first,
                second,
                third,
            } => {
                self.expression(first)?;
                self.expression(second)?;
                self.expression(third)?;
            }
            IrData::Children(children) => self.children(id, children)?,
            IrData::Bindings(bindings) => self.semantic_bindings(id, bindings, false)?,
            IrData::Binary { op, lhs, rhs } => {
                self.byte(op as u8);
                self.expression(lhs)?;
                self.expression(rhs)?;
            }
            IrData::Unary { op, operand } => {
                self.byte(op as u8);
                self.expression(operand)?;
            }
            IrData::Select {
                receiver,
                path,
                default,
                ..
            } => {
                self.expression(receiver)?;
                self.attr_path(id, path)?;
                self.optional(default)?;
            }
            IrData::HasAttr { receiver, path, .. } => {
                self.expression(receiver)?;
                self.attr_path(id, path)?;
            }
            IrData::PrimOp { symbol, args } => {
                self.symbol(symbol)?;
                self.children(id, args)?;
            }
            IrData::DialectNode { op, argument } => {
                self.bytes.extend_from_slice(&op.as_u16().to_le_bytes());
                self.expression(argument)?;
            }
            IrData::DialectScopeVar {
                op, symbol, chain, ..
            } => {
                self.bytes.extend_from_slice(&op.as_u16().to_le_bytes());
                self.symbol(symbol)?;
                let scopes = self
                    .ir
                    .with_chains
                    .get(chain as usize)
                    .ok_or(SemanticSliceError::InvalidWithChain { id })?
                    .scopes
                    .to_vec();
                self.length(scopes.len());
                for scope in scopes {
                    self.expression(scope)?;
                }
            }
            IrData::Lambda {
                pattern,
                body,
                frame: _,
            } => self.lambda(id, pattern, body)?,
            IrData::Let {
                bindings,
                body,
                frame: _,
            } => self.let_expression(id, bindings, body)?,
            IrData::AttrSet {
                bindings,
                recursive,
                has_dynamic,
                ..
            } => {
                self.byte(u8::from(recursive));
                self.byte(u8::from(has_dynamic));
                if recursive {
                    let frame = self.binding_frame(id, bindings, true)?;
                    self.recursive_attr_bindings(id, bindings, frame)?;
                } else {
                    self.semantic_bindings(id, bindings, true)?;
                }
            }
            IrData::FormalSet {
                formals,
                ellipsis,
                alias,
            } => {
                self.byte(u8::from(ellipsis));
                self.byte(u8::from(alias.is_some()));
                self.sorted_formals(id, formals)?;
            }
            IrData::Formal { name, default } => {
                self.symbol(name)?;
                self.optional(default)?;
            }
            IrData::Local { slot } if node.kind == IrKind::LocalVar => {
                self.variable(id, 0, slot)?;
            }
            IrData::Upval { depth, slot } if node.kind == IrKind::UpvalVar => {
                self.variable(id, depth, slot)?;
            }
            IrData::Local { .. } | IrData::Upval { .. } => {
                return Err(SemanticSliceError::InvalidPayload {
                    id,
                    kind: node.kind,
                });
            }
        }
        Ok(())
    }

    fn let_expression(
        &mut self,
        owner: IrId,
        bindings: IrBindingSlice,
        body: IrId,
    ) -> Result<(), SemanticSliceError> {
        let frame = self.binding_frame(owner, bindings, false)?;
        self.push_frame(frame);
        self.expression(body)?;
        self.pop_frame();
        Ok(())
    }

    fn lambda(&mut self, owner: IrId, pattern: IrId, body: IrId) -> Result<(), SemanticSliceError> {
        let definitions = self.lambda_definitions(pattern)?;
        self.push_frame(Frame {
            owner,
            kind: FrameKind::Lambda,
            definitions,
        });
        self.lambda_pattern(owner, pattern)?;
        self.expression(body)?;
        self.pop_frame();
        Ok(())
    }

    fn lambda_definitions(
        &self,
        pattern: IrId,
    ) -> Result<Vec<BinderDefinition>, SemanticSliceError> {
        let node = self
            .ir
            .arena
            .node(pattern)
            .ok_or(SemanticSliceError::InvalidNode(pattern))?;
        match node.data {
            IrData::Formal { .. } => Ok(vec![BinderDefinition::Parameter]),
            IrData::FormalSet { formals, alias, .. } => {
                let formals = self
                    .ir
                    .arena
                    .child_slice(formals)
                    .ok_or(SemanticSliceError::InvalidChildSlice { id: pattern })?;
                let mut definitions = vec![BinderDefinition::Parameter; formals.len()];
                definitions.extend(alias.map(|_| BinderDefinition::Parameter));
                Ok(definitions)
            }
            _ => Err(SemanticSliceError::InvalidPayload {
                id: pattern,
                kind: node.kind,
            }),
        }
    }

    fn lambda_pattern(&mut self, owner: IrId, pattern: IrId) -> Result<(), SemanticSliceError> {
        let node = self
            .ir
            .arena
            .node(pattern)
            .ok_or(SemanticSliceError::InvalidNode(pattern))?;
        self.byte(node.kind as u8);
        match node.data {
            IrData::Formal { default, .. } => {
                self.optional(default)?;
            }
            IrData::FormalSet {
                formals,
                ellipsis,
                alias,
            } => {
                self.byte(u8::from(ellipsis));
                self.byte(u8::from(alias.is_some()));
                self.lambda_formals(owner, pattern, formals, alias.is_some())?;
            }
            _ => {
                return Err(SemanticSliceError::InvalidPayload {
                    id: pattern,
                    kind: node.kind,
                });
            }
        }
        Ok(())
    }

    fn lambda_formals(
        &mut self,
        owner: IrId,
        pattern: IrId,
        slice: IrChildSlice,
        has_alias: bool,
    ) -> Result<(), SemanticSliceError> {
        let children = self
            .ir
            .arena
            .child_slice(slice)
            .ok_or(SemanticSliceError::InvalidChildSlice { id: pattern })?;
        let child_count = children.len();
        let mut keyed = Vec::with_capacity(children.len());
        for (slot, child) in children.iter().copied().enumerate() {
            let node = self
                .ir
                .arena
                .node(child)
                .ok_or(SemanticSliceError::InvalidNode(child))?;
            let IrData::Formal { name, .. } = node.data else {
                return Err(SemanticSliceError::InvalidPayload {
                    id: child,
                    kind: node.kind,
                });
            };
            let slot = u32::try_from(slot).map_err(|_| SemanticSliceError::TooManyBinders)?;
            keyed.push((self.symbol_bytes(name)?.to_vec(), child, slot));
        }
        keyed.sort_by(|left, right| left.0.cmp(&right.0));

        let mut formals = Vec::with_capacity(keyed.len());
        for (_, child, slot) in keyed {
            let binder = self.canonical_binder(BinderKey { owner, slot })?;
            formals.push((child, binder));
        }
        let alias = if has_alias {
            let slot =
                u32::try_from(child_count).map_err(|_| SemanticSliceError::TooManyBinders)?;
            Some(self.canonical_binder(BinderKey { owner, slot })?)
        } else {
            None
        };

        self.length(formals.len());
        for (child, binder) in formals {
            self.byte(0xe1);
            self.bytes.extend_from_slice(&binder.0.to_le_bytes());
            self.expression(child)?;
        }
        if let Some(binder) = alias {
            self.byte(0xe2);
            self.bytes.extend_from_slice(&binder.0.to_le_bytes());
        }
        Ok(())
    }

    fn sorted_formals(
        &mut self,
        owner: IrId,
        slice: IrChildSlice,
    ) -> Result<(), SemanticSliceError> {
        let children = self
            .ir
            .arena
            .child_slice(slice)
            .ok_or(SemanticSliceError::InvalidChildSlice { id: owner })?;
        let mut keyed = Vec::with_capacity(children.len());
        for child in children {
            let node = self
                .ir
                .arena
                .node(*child)
                .ok_or(SemanticSliceError::InvalidNode(*child))?;
            let IrData::Formal { name, .. } = node.data else {
                return Err(SemanticSliceError::InvalidPayload {
                    id: *child,
                    kind: node.kind,
                });
            };
            keyed.push((self.symbol_bytes(name)?.to_vec(), *child));
        }
        keyed.sort_by(|left, right| left.0.cmp(&right.0));
        self.length(keyed.len());
        for (_, child) in keyed {
            self.expression(child)?;
        }
        Ok(())
    }

    fn binding_frame(
        &self,
        owner: IrId,
        slice: IrBindingSlice,
        static_only: bool,
    ) -> Result<Frame, SemanticSliceError> {
        let bindings = self.bindings(owner, slice)?;
        Ok(Frame {
            owner,
            kind: FrameKind::Binding,
            definitions: bindings
                .iter()
                .filter(|binding| {
                    !static_only || matches!(binding.key, IrAttrPathSegment::Static(_))
                })
                .map(|binding| BinderDefinition::Value(binding.value))
                .collect(),
        })
    }

    fn push_frame(&mut self, frame: Frame) {
        self.frames.push(frame);
    }

    fn pop_frame(&mut self) {
        let _ = self.frames.pop();
    }

    fn variable(&mut self, id: IrId, depth: u32, slot: u32) -> Result<(), SemanticSliceError> {
        let Some(frame_index) = self.frames.len().checked_sub(depth as usize + 1) else {
            return Err(SemanticSliceError::MissingFrame { id });
        };
        let frame = &self.frames[frame_index];
        let Some(definition) = frame.definitions.get(slot as usize).copied() else {
            return Err(SemanticSliceError::InvalidSlot { id, slot });
        };
        let key = BinderKey {
            owner: frame.owner,
            slot,
        };
        let binder = self.canonical_binder(key)?;
        let lambda_depth = self.frames[frame_index + 1..]
            .iter()
            .filter(|frame| frame.kind == FrameKind::Lambda)
            .count();
        self.byte(0xe0);
        self.length(lambda_depth);
        self.bytes.extend_from_slice(&binder.0.to_le_bytes());
        if let Some(&source) = self.current_definition.last() {
            self.edges[source.0 as usize].insert(binder.0 as usize);
        }
        if let BinderDefinition::Value(value) = definition {
            self.retain_definition(key, binder, value, frame_index)?;
        }
        Ok(())
    }

    fn canonical_binder(&mut self, key: BinderKey) -> Result<SemanticBinderId, SemanticSliceError> {
        if let Some(id) = self.canonical_ids.get(&key) {
            return Ok(*id);
        }
        let raw = u32::try_from(self.canonical_ids.len())
            .map_err(|_| SemanticSliceError::TooManyBinders)?;
        let id = SemanticBinderId(raw);
        self.canonical_ids.insert(key, id);
        self.edges.push(BTreeSet::new());
        Ok(id)
    }

    fn retain_definition(
        &mut self,
        key: BinderKey,
        binder: SemanticBinderId,
        value: IrId,
        frame_index: usize,
    ) -> Result<(), SemanticSliceError> {
        match self
            .states
            .get(&key)
            .copied()
            .unwrap_or(DefinitionState::Unseen)
        {
            DefinitionState::Visiting | DefinitionState::Complete => return Ok(()),
            DefinitionState::Unseen => {}
        }
        self.states.insert(key, DefinitionState::Visiting);
        self.selected_definitions.insert(value);
        self.retained.insert(binder);
        self.byte(0xf0);
        self.bytes.extend_from_slice(&binder.0.to_le_bytes());
        self.current_definition.push(binder);
        let suffix = self.frames.split_off(frame_index.saturating_add(1));
        let result = self.expression(value);
        self.frames.extend(suffix);
        let _ = self.current_definition.pop();
        result?;
        self.states.insert(key, DefinitionState::Complete);
        self.byte(0xf1);
        Ok(())
    }

    fn semantic_bindings(
        &mut self,
        owner: IrId,
        slice: IrBindingSlice,
        include_keys: bool,
    ) -> Result<(), SemanticSliceError> {
        let bindings = self.bindings(owner, slice)?.to_vec();
        self.length(bindings.len());
        for binding in bindings {
            if include_keys {
                self.attr_segment(binding.key)?;
            }
            self.expression(binding.value)?;
        }
        Ok(())
    }

    fn recursive_attr_bindings(
        &mut self,
        owner: IrId,
        slice: IrBindingSlice,
        frame: Frame,
    ) -> Result<(), SemanticSliceError> {
        let bindings = self.bindings(owner, slice)?.to_vec();
        self.length(bindings.len());
        for binding in bindings {
            self.attr_segment(binding.key)?;
            self.push_frame(frame.clone());
            self.expression(binding.value)?;
            self.pop_frame();
        }
        Ok(())
    }

    fn bindings(
        &self,
        owner: IrId,
        slice: IrBindingSlice,
    ) -> Result<&[IrBinding], SemanticSliceError> {
        let start = slice.start as usize;
        let Some(end) = start.checked_add(slice.len()) else {
            return Err(SemanticSliceError::InvalidBindingSlice { id: owner });
        };
        self.ir
            .bindings
            .get(start..end)
            .ok_or(SemanticSliceError::InvalidBindingSlice { id: owner })
    }

    fn children(&mut self, owner: IrId, slice: IrChildSlice) -> Result<(), SemanticSliceError> {
        let children = self
            .ir
            .arena
            .child_slice(slice)
            .ok_or(SemanticSliceError::InvalidChildSlice { id: owner })?
            .to_vec();
        self.length(children.len());
        for child in children {
            self.expression(child)?;
        }
        Ok(())
    }

    fn attr_path(&mut self, owner: IrId, path: IrAttrPathId) -> Result<(), SemanticSliceError> {
        let segments = self
            .ir
            .attr_paths
            .get(path.index())
            .ok_or(SemanticSliceError::InvalidAttrPath { id: owner })?
            .to_vec();
        self.length(segments.len());
        for segment in segments {
            self.attr_segment(segment)?;
        }
        Ok(())
    }

    fn attr_segment(&mut self, segment: IrAttrPathSegment) -> Result<(), SemanticSliceError> {
        match segment {
            IrAttrPathSegment::Static(symbol) => {
                self.byte(0);
                self.symbol(symbol)?;
            }
            IrAttrPathSegment::Dynamic(expression) => {
                self.byte(1);
                self.expression(expression)?;
            }
        }
        Ok(())
    }

    fn optional(&mut self, child: Option<IrId>) -> Result<(), SemanticSliceError> {
        self.byte(u8::from(child.is_some()));
        if let Some(child) = child {
            self.expression(child)?;
        }
        Ok(())
    }

    fn symbol(&mut self, symbol: Symbol) -> Result<(), SemanticSliceError> {
        let bytes = self.symbol_bytes(symbol)?.to_vec();
        self.length(bytes.len());
        self.bytes.extend_from_slice(&bytes);
        Ok(())
    }

    fn symbol_bytes(&self, symbol: Symbol) -> Result<&[u8], SemanticSliceError> {
        self.symbols
            .resolve(symbol)
            .ok_or(SemanticSliceError::InvalidSymbol { symbol })
    }

    fn length(&mut self, length: usize) {
        self.bytes.extend_from_slice(&(length as u64).to_le_bytes());
    }

    fn byte(&mut self, byte: u8) {
        self.bytes.push(byte);
    }
}

fn locate_context(ir: &Ir, target: IrId) -> Result<Vec<Frame>, SemanticSliceError> {
    let mut found = None;
    let mut frames = Vec::new();
    let mut active = HashSet::new();
    walk_context(ir, ir.root, target, &mut frames, &mut active, &mut found)?;
    found.ok_or(SemanticSliceError::UnreachableRoot(target))
}

fn walk_context(
    ir: &Ir,
    id: IrId,
    target: IrId,
    frames: &mut Vec<Frame>,
    active: &mut HashSet<IrId>,
    found: &mut Option<Vec<Frame>>,
) -> Result<(), SemanticSliceError> {
    if id == target {
        if found.as_ref().is_some_and(|prior| prior != frames) {
            return Err(SemanticSliceError::AmbiguousRootContext(target));
        }
        if found.is_none() {
            *found = Some(frames.clone());
        }
        return Ok(());
    }
    if !active.insert(id) {
        return Err(SemanticSliceError::IrCycle(id));
    }
    let node = ir
        .arena
        .node(id)
        .ok_or(SemanticSliceError::InvalidNode(id))?;
    if !valid_payload(node.kind, node.data) {
        return Err(SemanticSliceError::InvalidPayload {
            id,
            kind: node.kind,
        });
    }
    match node.data {
        IrData::None
        | IrData::Int(_)
        | IrData::Float(_)
        | IrData::Bool(_)
        | IrData::Symbol(_)
        | IrData::GlobalVar { .. }
        | IrData::Local { .. }
        | IrData::Upval { .. }
        | IrData::DialectScopeVar { .. } => {}
        IrData::SearchPath { search_path, .. } => {
            walk_optional_context(ir, search_path, target, frames, active, found)?;
        }
        IrData::Node(child) => {
            walk_context(ir, child, target, frames, active, found)?;
        }
        IrData::Pair { first, second } => {
            for child in [first, second] {
                walk_context(ir, child, target, frames, active, found)?;
            }
        }
        IrData::Triple {
            first,
            second,
            third,
        } => {
            for child in [first, second, third] {
                walk_context(ir, child, target, frames, active, found)?;
            }
        }
        IrData::Children(children)
        | IrData::PrimOp { args: children, .. }
        | IrData::FormalSet {
            formals: children, ..
        } => {
            let children = ir
                .arena
                .child_slice(children)
                .ok_or(SemanticSliceError::InvalidChildSlice { id })?
                .to_vec();
            for child in children {
                walk_context(ir, child, target, frames, active, found)?;
            }
        }
        IrData::Bindings(bindings) => {
            walk_binding_contexts(ir, id, bindings, target, frames, active, found, false)?;
        }
        IrData::Binary { lhs, rhs, .. } => {
            for child in [lhs, rhs] {
                walk_context(ir, child, target, frames, active, found)?;
            }
        }
        IrData::Unary { operand, .. }
        | IrData::DialectNode {
            argument: operand, ..
        } => {
            walk_context(ir, operand, target, frames, active, found)?;
        }
        IrData::Select {
            receiver,
            path,
            default,
            ..
        } => {
            walk_context(ir, receiver, target, frames, active, found)?;
            walk_attr_path_context(ir, id, path, target, frames, active, found)?;
            walk_optional_context(ir, default, target, frames, active, found)?;
        }
        IrData::HasAttr { receiver, path, .. } => {
            walk_context(ir, receiver, target, frames, active, found)?;
            walk_attr_path_context(ir, id, path, target, frames, active, found)?;
        }
        IrData::Lambda { pattern, body, .. } => {
            frames.push(context_lambda_frame(ir, id, pattern)?);
            walk_context(ir, pattern, target, frames, active, found)?;
            walk_context(ir, body, target, frames, active, found)?;
            let _ = frames.pop();
        }
        IrData::Let { bindings, body, .. } => {
            frames.push(context_binding_frame(ir, id, bindings, false)?);
            walk_binding_contexts(ir, id, bindings, target, frames, active, found, false)?;
            walk_context(ir, body, target, frames, active, found)?;
            let _ = frames.pop();
        }
        IrData::AttrSet {
            bindings,
            recursive,
            ..
        } => {
            if recursive {
                walk_binding_keys(ir, id, bindings, target, frames, active, found)?;
                frames.push(context_binding_frame(ir, id, bindings, true)?);
                walk_binding_values(ir, id, bindings, target, frames, active, found)?;
                let _ = frames.pop();
            } else {
                walk_binding_contexts(ir, id, bindings, target, frames, active, found, true)?;
            }
        }
        IrData::Formal { default, .. } => {
            walk_optional_context(ir, default, target, frames, active, found)?;
        }
    }
    active.remove(&id);
    Ok(())
}

fn context_lambda_frame(ir: &Ir, owner: IrId, pattern: IrId) -> Result<Frame, SemanticSliceError> {
    let node = ir
        .arena
        .node(pattern)
        .ok_or(SemanticSliceError::InvalidNode(pattern))?;
    let definitions = match node.data {
        IrData::Formal { .. } => vec![BinderDefinition::Parameter],
        IrData::FormalSet { formals, alias, .. } => {
            let formals = ir
                .arena
                .child_slice(formals)
                .ok_or(SemanticSliceError::InvalidChildSlice { id: pattern })?;
            let mut definitions = vec![BinderDefinition::Parameter; formals.len()];
            definitions.extend(alias.map(|_| BinderDefinition::Parameter));
            definitions
        }
        _ => {
            return Err(SemanticSliceError::InvalidPayload {
                id: pattern,
                kind: node.kind,
            });
        }
    };
    Ok(Frame {
        owner,
        kind: FrameKind::Lambda,
        definitions,
    })
}

fn context_binding_frame(
    ir: &Ir,
    owner: IrId,
    slice: IrBindingSlice,
    static_only: bool,
) -> Result<Frame, SemanticSliceError> {
    let bindings = context_bindings(ir, owner, slice)?;
    Ok(Frame {
        owner,
        kind: FrameKind::Binding,
        definitions: bindings
            .iter()
            .filter(|binding| !static_only || matches!(binding.key, IrAttrPathSegment::Static(_)))
            .map(|binding| BinderDefinition::Value(binding.value))
            .collect(),
    })
}

fn context_bindings(
    ir: &Ir,
    owner: IrId,
    slice: IrBindingSlice,
) -> Result<&[IrBinding], SemanticSliceError> {
    let start = slice.start as usize;
    let Some(end) = start.checked_add(slice.len()) else {
        return Err(SemanticSliceError::InvalidBindingSlice { id: owner });
    };
    ir.bindings
        .get(start..end)
        .ok_or(SemanticSliceError::InvalidBindingSlice { id: owner })
}

fn walk_binding_contexts(
    ir: &Ir,
    owner: IrId,
    slice: IrBindingSlice,
    target: IrId,
    frames: &mut Vec<Frame>,
    active: &mut HashSet<IrId>,
    found: &mut Option<Vec<Frame>>,
    keys_in_current_context: bool,
) -> Result<(), SemanticSliceError> {
    if keys_in_current_context {
        walk_binding_keys(ir, owner, slice, target, frames, active, found)?;
    }
    walk_binding_values(ir, owner, slice, target, frames, active, found)
}

fn walk_binding_keys(
    ir: &Ir,
    owner: IrId,
    slice: IrBindingSlice,
    target: IrId,
    frames: &mut Vec<Frame>,
    active: &mut HashSet<IrId>,
    found: &mut Option<Vec<Frame>>,
) -> Result<(), SemanticSliceError> {
    for binding in context_bindings(ir, owner, slice)? {
        if let IrAttrPathSegment::Dynamic(key) = binding.key {
            walk_context(ir, key, target, frames, active, found)?;
        }
    }
    Ok(())
}

fn walk_binding_values(
    ir: &Ir,
    owner: IrId,
    slice: IrBindingSlice,
    target: IrId,
    frames: &mut Vec<Frame>,
    active: &mut HashSet<IrId>,
    found: &mut Option<Vec<Frame>>,
) -> Result<(), SemanticSliceError> {
    let values: Vec<_> = context_bindings(ir, owner, slice)?
        .iter()
        .map(|binding| binding.value)
        .collect();
    for value in values {
        walk_context(ir, value, target, frames, active, found)?;
    }
    Ok(())
}

fn walk_attr_path_context(
    ir: &Ir,
    owner: IrId,
    path: IrAttrPathId,
    target: IrId,
    frames: &mut Vec<Frame>,
    active: &mut HashSet<IrId>,
    found: &mut Option<Vec<Frame>>,
) -> Result<(), SemanticSliceError> {
    let segments = ir
        .attr_paths
        .get(path.index())
        .ok_or(SemanticSliceError::InvalidAttrPath { id: owner })?;
    for segment in segments {
        if let IrAttrPathSegment::Dynamic(child) = segment {
            walk_context(ir, *child, target, frames, active, found)?;
        }
    }
    Ok(())
}

fn walk_optional_context(
    ir: &Ir,
    child: Option<IrId>,
    target: IrId,
    frames: &mut Vec<Frame>,
    active: &mut HashSet<IrId>,
    found: &mut Option<Vec<Frame>>,
) -> Result<(), SemanticSliceError> {
    if let Some(child) = child {
        walk_context(ir, child, target, frames, active, found)?;
    }
    Ok(())
}

fn valid_payload(kind: IrKind, data: IrData) -> bool {
    match kind {
        IrKind::Int => matches!(data, IrData::Int(_)),
        IrKind::Float => matches!(data, IrData::Float(_)),
        IrKind::Bool => matches!(data, IrData::Bool(_)),
        IrKind::Null => matches!(data, IrData::None),
        IrKind::Str | IrKind::Path | IrKind::Uri | IrKind::BuiltinAttr => {
            matches!(data, IrData::Symbol(_))
        }
        IrKind::SearchPath => matches!(data, IrData::SearchPath { .. }),
        IrKind::LocalVar => matches!(data, IrData::Local { .. }),
        IrKind::UpvalVar => matches!(data, IrData::Upval { .. }),
        IrKind::GlobalVar => matches!(data, IrData::GlobalVar { .. }),
        IrKind::List => matches!(data, IrData::Children(_)),
        IrKind::AttrSet => matches!(data, IrData::AttrSet { .. }),
        IrKind::Lambda => matches!(data, IrData::Lambda { .. }),
        IrKind::FormalSet => matches!(data, IrData::FormalSet { .. }),
        IrKind::Formal => matches!(data, IrData::Formal { .. }),
        IrKind::Apply | IrKind::With | IrKind::Assert => matches!(data, IrData::Pair { .. }),
        IrKind::Select => matches!(data, IrData::Select { .. }),
        IrKind::HasAttr => matches!(data, IrData::HasAttr { .. }),
        IrKind::Let => matches!(data, IrData::Let { .. }),
        IrKind::If => matches!(data, IrData::Triple { .. }),
        IrKind::BinOp => matches!(data, IrData::Binary { .. }),
        IrKind::UnaryOp => matches!(data, IrData::Unary { .. }),
        IrKind::Interp => matches!(data, IrData::Node(_) | IrData::Children(_) | IrData::None),
        IrKind::ThunkAlloc => matches!(data, IrData::Node(_)),
        IrKind::PrimOp => matches!(
            data,
            IrData::PrimOp { .. } | IrData::DialectNode { .. } | IrData::DialectScopeVar { .. }
        ),
    }
}

fn strongly_connected_components(
    retained: &[SemanticBinderId],
    edges: &[BTreeSet<usize>],
) -> Vec<SemanticBindingComponent> {
    let retained_set: BTreeSet<_> = retained.iter().map(|id| id.0 as usize).collect();
    let mut forward_seen = BTreeSet::new();
    let mut order = Vec::new();
    for &binder in &retained_set {
        finish_order(binder, edges, &retained_set, &mut forward_seen, &mut order);
    }
    let mut reverse = vec![Vec::new(); edges.len()];
    for (source, targets) in edges.iter().enumerate() {
        for &target in targets {
            if let Some(incoming) = reverse.get_mut(target) {
                incoming.push(source);
            }
        }
    }
    let mut reverse_seen = BTreeSet::new();
    let mut components = Vec::new();
    for binder in order.into_iter().rev() {
        if reverse_seen.contains(&binder) {
            continue;
        }
        let mut members = Vec::new();
        collect_reverse(
            binder,
            &reverse,
            &retained_set,
            &mut reverse_seen,
            &mut members,
        );
        members.sort_unstable();
        let recursive = members.len() > 1
            || edges
                .get(binder)
                .is_some_and(|targets| targets.contains(&binder));
        components.push(SemanticBindingComponent {
            binders: members
                .into_iter()
                .map(|raw| SemanticBinderId(raw as u32))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            recursive,
        });
    }
    components.sort_by_key(|component| component.binders.first().map_or(u32::MAX, |id| id.0));
    components
}

fn finish_order(
    binder: usize,
    edges: &[BTreeSet<usize>],
    retained: &BTreeSet<usize>,
    seen: &mut BTreeSet<usize>,
    order: &mut Vec<usize>,
) {
    if !seen.insert(binder) {
        return;
    }
    if let Some(targets) = edges.get(binder) {
        for &target in targets {
            if retained.contains(&target) {
                finish_order(target, edges, retained, seen, order);
            }
        }
    }
    order.push(binder);
}

fn collect_reverse(
    binder: usize,
    reverse: &[Vec<usize>],
    retained: &BTreeSet<usize>,
    seen: &mut BTreeSet<usize>,
    members: &mut Vec<usize>,
) {
    if !seen.insert(binder) {
        return;
    }
    members.push(binder);
    if let Some(sources) = reverse.get(binder) {
        for &source in sources {
            if retained.contains(&source) {
                collect_reverse(source, reverse, retained, seen, members);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::parse_str;
    use crate::{lower, resolve};

    fn slice(source: &str) -> SemanticSlice {
        let parsed = parse_str(source).expect("test source parses");
        let resolved = resolve(parsed).expect("test source resolves");
        let ir = lower(resolved).expect("test source lowers");
        analyze_semantic_slice(&ir, ir.root).expect("test source has valid lexical metadata")
    }

    #[test]
    fn alpha_renaming_does_not_change_the_slice() {
        assert_eq!(
            slice("let x = 1; in x"),
            slice("let renamed = 1; in renamed")
        );
        assert_eq!(slice("x: x"), slice("argument: argument"));
        assert_eq!(
            slice("whole@{ a, b }: whole"),
            slice("renamed@{ b, a }: renamed")
        );
    }

    #[test]
    fn formal_set_binders_remain_tied_to_their_semantic_roles() {
        assert_ne!(slice("{ a, b }: a"), slice("{ a, b }: b"));
        assert_ne!(slice("whole@{ a, b }: a"), slice("whole@{ a, b }: whole"));
        assert_eq!(slice("{ a, b }: a"), slice("{ b, a }: a"));
    }

    #[test]
    fn slot_permutation_does_not_change_capture_resolution() {
        let left = slice("let x = 1; y = 2; in ignored: x + y");
        let right = slice("let y = 2; x = 1; in renamed: x + y");
        assert_eq!(left, right);

        let extra_capture_frame = slice("let x = 1; in a: b: x");
        assert_ne!(left, extra_capture_frame);
    }

    #[test]
    fn shadowing_is_not_confused_with_capture() {
        let shadowed = slice("let x = 1; in x: x");
        let captured = slice("let x = 1; in argument: x");
        assert_ne!(shadowed, captured);
        assert!(shadowed.retained_bindings().is_empty());
        assert_eq!(captured.retained_bindings().len(), 1);
    }

    #[test]
    fn mutually_recursive_bindings_form_one_recursive_component() {
        let left = slice("let a = b; b = a; in a");
        let right = slice("let second = first; first = second; in second");
        assert_eq!(left, right);
        assert_eq!(left.components().len(), 1);
        assert!(left.components()[0].is_recursive());
        assert_eq!(left.components()[0].binders().len(), 2);
    }

    #[test]
    fn unrelated_binding_insertion_is_ignored() {
        let small = slice("let x = 1; y = x; in y");
        let extended = slice("let unused = 999; x = 1; alsoUnused = 3; y = x; in y");
        assert_eq!(small, extended);
        assert_eq!(small.retained_bindings().len(), 2);
    }

    #[test]
    fn retained_definition_query_ties_roles_to_the_selected_binder_graph() {
        let parsed = parse_str("let used = 1; unused = 2; in used").expect("test source parses");
        let resolved = resolve(parsed).expect("test source resolves");
        let ir = lower(resolved).expect("test source lowers");
        let binding_value = |name: &[u8]| {
            ir.bindings
                .iter()
                .find(|binding| {
                    let IrAttrPathSegment::Static(symbol) = binding.key else {
                        return false;
                    };
                    ir.symbols.resolve(symbol) == Some(name)
                })
                .map(|binding| binding.value)
                .expect("named binding exists")
        };
        let used = binding_value(b"used");
        let unused = binding_value(b"unused");

        assert!(
            semantic_subslice_retains_all(&ir, ir.root, &[used])
                .expect("selected definition query succeeds")
        );
        assert!(
            !semantic_subslice_retains_all(&ir, ir.root, &[unused])
                .expect("unselected definition query succeeds")
        );
    }

    #[test]
    fn unused_enclosing_binding_frame_is_ignored() {
        let direct = slice("let x = 1; in argument: x");
        let nested = slice("let x = 1; in argument: let unused = 2; in x");
        assert_eq!(direct, nested);
    }

    #[test]
    fn changed_recursion_target_changes_the_slice() {
        let mutual = slice("let a = b; b = a; in a");
        let self_recursive = slice("let a = a; b = a; in a");
        assert_ne!(mutual, self_recursive);
        assert_eq!(self_recursive.components().len(), 1);
        assert!(self_recursive.components()[0].is_recursive());
        assert_eq!(self_recursive.components()[0].binders().len(), 1);
    }

    #[test]
    fn semantic_attribute_keys_are_preserved() {
        assert_ne!(slice("set: set.first"), slice("set: set.second"));
    }

    #[test]
    fn malformed_local_and_upvalue_coordinates_fail_closed() {
        for (source, kind) in [
            ("let x = 1; in x", IrKind::LocalVar),
            ("let x = 1; in argument: x", IrKind::UpvalVar),
        ] {
            let parsed = parse_str(source).expect("test source parses");
            let resolved = resolve(parsed).expect("test source resolves");
            let mut ir = lower(resolved).expect("test source lowers");
            let mut nodes = ir.arena.nodes().to_vec();
            let (index, node) = nodes
                .iter_mut()
                .enumerate()
                .find(|(_, node)| node.kind == kind)
                .expect("test source contains the requested variable");
            node.data = match kind {
                IrKind::LocalVar => IrData::Local { slot: u32::MAX },
                IrKind::UpvalVar => IrData::Upval {
                    depth: 1,
                    slot: u32::MAX,
                },
                _ => unreachable!("test only requests lexical variable kinds"),
            };
            ir.arena = crate::IrArena::from_raw_parts(nodes, ir.arena.child_pool().to_vec());
            let error = analyze_semantic_slice(&ir, ir.root)
                .expect_err("invalid lexical coordinates must decline");
            assert_eq!(
                error,
                SemanticSliceError::InvalidSlot {
                    id: IrId::new(index as u32),
                    slot: u32::MAX,
                }
            );
        }
    }

    #[test]
    fn subslice_discovers_and_canonicalizes_its_outer_context() {
        fn lambda_slice(source: &str) -> SemanticSlice {
            let parsed = parse_str(source).expect("test source parses");
            let resolved = resolve(parsed).expect("test source resolves");
            let ir = lower(resolved).expect("test source lowers");
            let lambda = ir
                .arena
                .nodes()
                .iter()
                .enumerate()
                .find_map(|(index, node)| {
                    (node.kind == IrKind::Lambda).then(|| IrId::new(index as u32))
                })
                .expect("test source contains a lambda");
            analyze_semantic_subslice(&ir, lambda).expect("lambda has a unique lexical context")
        }

        let reference =
            lambda_slice("let helper = 1; unrelated = 2; in argument: helper + argument");
        let relocated = lambda_slice("let noise = 9; renamed = 1; in value: renamed + value");
        assert_eq!(reference, relocated);
    }

    #[test]
    fn subslice_resolves_symbols_from_an_adopted_table() {
        let parsed =
            parse_str("value: builtins.concatStringsSep \".\" value").expect("source parses");
        let resolved = resolve(parsed).expect("source resolves");
        let mut ir = lower(resolved).expect("source lowers");
        let root = ir.root;
        let reference =
            analyze_semantic_subslice(&ir, root).expect("owned symbols resolve the root");
        let symbols = std::mem::take(&mut ir.symbols);
        let error = analyze_semantic_subslice(&ir, root)
            .expect_err("the adopted module IR no longer owns semantic symbols");
        assert!(matches!(error, SemanticSliceError::InvalidSymbol { .. }));
        let adopted = analyze_semantic_subslice_with_symbols(&ir, &symbols, root)
            .expect("separately owned live symbols resolve the same root");
        assert_eq!(adopted, reference);
    }
}
