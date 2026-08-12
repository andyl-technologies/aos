//! Mutable resolver state and its low-level frame, capture, and side-table
//! bookkeeping.

use super::*;

#[derive(Clone, Debug)]
pub(super) struct FrameBuilder {
    pub(super) slots: Vec<Symbol>,
    pub(super) captures: BTreeSet<Upvalue>,
    pub(super) rec: bool,
    pub(super) has_with: bool,
}

impl FrameBuilder {
    pub(super) fn new(slots: Vec<Symbol>, rec: bool, has_with: bool) -> Self {
        Self {
            slots,
            captures: BTreeSet::new(),
            rec,
            has_with,
        }
    }

    pub(super) fn finish(self) -> Result<FrameInfo, ScopeError> {
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
pub(super) struct ActiveFrame {
    pub(super) id: FrameId,
    pub(super) lambda: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindingResolveMode {
    Full,
    ValueOnly,
    PathOnly,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolverState {
    pub(super) options: ResolverOptions,
    pub(super) root: NodeId,
    pub(super) arena: AstArena,
    pub(super) symbols: SymbolTable,
    pub(super) frames: Vec<FrameBuilder>,
    pub(super) node_frames: Vec<Option<FrameId>>,
    pub(super) active_frames: Vec<ActiveFrame>,
    pub(super) active_withs: Vec<NodeId>,
    pub(super) with_chains: Vec<WithChain>,
    pub(super) inherit_resolutions: Vec<InheritResolution>,
    pub(super) node_inherits: Vec<Option<InheritGroupId>>,
}

impl ResolverState {
    pub(super) fn new(parsed: ParsedAst, options: ResolverOptions) -> Self {
        let node_count = parsed.arena.len();
        Self {
            options,
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

    pub(super) fn resolve_root(mut self) -> Result<ResolvedAst, ScopeError> {
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

    pub(super) fn is_global_symbol(&self, symbol: Symbol) -> bool {
        self.symbols.resolve(symbol).is_some_and(is_global_name)
    }

    pub(super) fn is_unshadowable_global_symbol(&self, symbol: Symbol) -> bool {
        self.symbols
            .resolve(symbol)
            .is_some_and(is_unshadowable_global_name)
    }

    pub(super) fn lookup_symbol(&self, symbol: Symbol) -> Option<(u32, u32, usize)> {
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

    pub(super) fn record_captures(
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

    pub(super) fn push_frame(
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

    pub(super) fn pop_frame(&mut self) {
        self.active_frames.pop();
    }

    pub(super) fn mark_with_in_active_frames(&mut self) {
        for frame in &self.active_frames {
            self.frames[frame.id.index()].has_with = true;
        }
    }

    pub(super) fn push_with_chain(&mut self, span: Span) -> Result<WithChainId, ScopeError> {
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

    pub(super) fn push_inherit_resolution(
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

    pub(super) fn replace_node(
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

    pub(super) fn push_synthetic_node(
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

    pub(super) fn symbol_payload(&self, node: Node) -> Result<Symbol, ScopeError> {
        let NodeData::Symbol(symbol) = node.data else {
            return Err(self.invalid_shape(node, "symbol payload"));
        };
        Ok(symbol)
    }

    pub(super) fn child_ids(&self, slice: ChildSlice) -> Result<Vec<NodeId>, ScopeError> {
        Ok(self
            .arena
            .child_slice(slice)
            .map_err(ScopeError::from_ast)?
            .to_vec())
    }

    pub(super) fn node(&self, id: NodeId) -> Result<Node, ScopeError> {
        self.arena.node(id).copied().ok_or_else(|| {
            ScopeError::new(
                ScopeErrorKind::InvalidNodeId(id.as_u32()),
                Span::new(u32::MAX, u32::MAX),
            )
        })
    }

    pub(super) fn invalid_shape(&self, node: Node, expected: &'static str) -> ScopeError {
        ScopeError::new(
            ScopeErrorKind::InvalidNodeShape {
                kind: node.kind,
                expected,
            },
            node.span,
        )
    }

    pub(super) fn join_span(&self, first: Span, second: Span) -> Span {
        Span::new(first.start.min(second.start), first.end.max(second.end))
    }
}
