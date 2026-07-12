//! Tree-walk diagnostics for heap-owned active scalar values.
//!
//! Candidate C needs an evaluator reservation to construct or decode boxed
//! integers and floats. These helpers attach source-node context to that heap
//! boundary while the active 16-byte representation remains allocation-free.

use super::*;

impl TreeWalk {
    /// Constructs one integer through the active heap-owned value boundary.
    #[inline(always)]
    pub(super) fn runtime_int_value(
        &mut self,
        id: IrId,
        span: Span,
        value: i64,
    ) -> Result<Value, TreeWalkError> {
        self.heap
            .alloc_int_value(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    /// Constructs one float through the active heap-owned value boundary.
    #[inline(always)]
    pub(super) fn runtime_float_value(
        &mut self,
        id: IrId,
        span: Span,
        value: f64,
    ) -> Result<Value, TreeWalkError> {
        self.heap
            .alloc_float_value(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    /// Decodes one integer through the active heap-owned value boundary.
    #[inline(always)]
    pub(super) fn runtime_int_payload(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<i64, TreeWalkError> {
        self.heap
            .decode_int_value(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }

    /// Decodes one float through the active heap-owned value boundary.
    #[inline(always)]
    pub(super) fn runtime_float_payload(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<f64, TreeWalkError> {
        self.heap
            .decode_float_value(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
    }
}
