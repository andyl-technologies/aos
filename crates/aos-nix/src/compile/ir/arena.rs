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
}
