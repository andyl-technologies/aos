//! Arena storage operations for the lowered IR node pool.

use super::*;

impl IrArena {
    /// Creates an empty IR arena.
    pub const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Creates an arena from already-decoded raw storage.
    pub fn from_raw_parts(nodes: Vec<IrNode>, children: Vec<IrId>) -> Self {
        Self { nodes, children }
    }

    /// Returns all nodes in allocation order.
    pub fn nodes(&self) -> &[IrNode] {
        &self.nodes
    }

    /// Returns the allocated capacity of the fixed-stride node lane.
    pub fn node_capacity(&self) -> usize {
        self.nodes.capacity()
    }

    /// Returns all child-pool entries in allocation order.
    pub fn child_pool(&self) -> &[IrId] {
        &self.children
    }

    /// Returns the allocated capacity of the variable-arity child lane.
    pub fn child_capacity(&self) -> usize {
        self.children.capacity()
    }

    /// Returns bytes allocated for the fixed node and child vectors.
    pub fn storage_bytes(&self) -> usize {
        self.nodes
            .capacity()
            .saturating_mul(std::mem::size_of::<IrNode>())
            .saturating_add(
                self.children
                    .capacity()
                    .saturating_mul(std::mem::size_of::<IrId>()),
            )
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

    pub(super) fn push_node(
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

    pub(super) fn push_child_slice(
        &mut self,
        children: &[IrId],
        span: Span,
    ) -> Result<IrChildSlice, IrError> {
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

    /// Replaces the node at `id` in place, preserving its source span.
    ///
    /// This is the arena-stable rewrite primitive for simplifier passes that fold
    /// a node to an equivalent value without changing the arena's shape: the node
    /// keeps its [`IrId`] and [`Span`], so IR-id- and span-keyed caches (the eval
    /// demand memo and the JIT compiled-body def-site key) stay coherent, while
    /// its kind, effect class, and payload are replaced. Child-pool and
    /// side-table entries the previous payload referenced are left in place; a
    /// fold that abandons them simply leaves them unreachable from `root`.
    ///
    /// Returns `false` (making no change) if `id` is out of range.
    ///
    /// This is `pub(super)`: only the `ir` module — where the simplifier driver
    /// and passes live — may mutate a lowered node, per RFC-0007 doc 30 §8 D4.
    #[must_use]
    pub(super) fn set_node(
        &mut self,
        id: IrId,
        kind: IrKind,
        effect: EffectClass,
        data: IrData,
    ) -> bool {
        match self.nodes.get_mut(id.index()) {
            Some(node) => {
                let span = node.span;
                *node = IrNode::new(kind, span, effect, data);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_node_arena() -> (IrArena, IrId) {
        let mut arena = IrArena::new();
        let id = arena
            .push_node(
                IrKind::Int,
                Span::new(4, 9),
                EffectClass::pure(),
                IrData::Int(1),
            )
            .expect("node pushes");
        (arena, id)
    }

    #[test]
    fn set_node_replaces_payload_and_preserves_span_and_id() {
        let (mut arena, id) = one_node_arena();
        assert!(arena.set_node(id, IrKind::Bool, EffectClass::pure(), IrData::Bool(true)));

        let node = arena.node(id).expect("node still present at the same id");
        assert_eq!(node.kind, IrKind::Bool);
        assert_eq!(node.data, IrData::Bool(true));
        assert_eq!(
            node.span,
            Span::new(4, 9),
            "span is preserved across the rewrite"
        );
        assert_eq!(arena.nodes().len(), 1, "no node is added or removed");
    }

    #[test]
    fn set_node_out_of_range_makes_no_change() {
        let (mut arena, _id) = one_node_arena();
        let before = arena.nodes().to_vec();
        assert!(!arena.set_node(
            IrId::new(7),
            IrKind::Null,
            EffectClass::pure(),
            IrData::None
        ));
        assert_eq!(
            arena.nodes(),
            before.as_slice(),
            "an out-of-range id is a no-op"
        );
    }
}
