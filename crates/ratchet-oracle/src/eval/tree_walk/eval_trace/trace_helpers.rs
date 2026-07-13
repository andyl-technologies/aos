//! `TreeWalk` methods (trace_helpers), split from the parent for the §2 line cap.

use super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn append_context_base_string(
        &self,
        string_id: IrId,
        string_span: Span,
        string_value: Value,
    ) -> Result<(Vec<u8>, StringContext), TreeWalkError> {
        if string_value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: string_id,
                    expected: "string",
                    actual: string_value.tag(),
                },
                string_span,
            ));
        }

        let string = self.heap.get_string(string_value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: string_id,
                    source,
                },
                string_span,
            )
        })?;
        let bytes = Self::copy_bytes_for_node(string_id, string_span, string.bytes())?;
        let base_context = string
            .context()
            .union(&StringContext::empty())
            .map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::String {
                        id: string_id,
                        source,
                    },
                    string_span,
                )
            })?;
        Ok((bytes, base_context))
    }

    pub(in crate::eval::tree_walk) fn finish_append_context_primop(
        &mut self,
        id: IrId,
        span: Span,
        bytes: Vec<u8>,
        base_context: StringContext,
        context_id: IrId,
        context_span: Span,
        context_value: Value,
    ) -> Result<Value, TreeWalkError> {
        let context_value =
            self.force_lazy_foldl_initial_value(context_id, context_span, context_value)?;
        if context_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: context_id,
                    expected: "attrs",
                    actual: context_value.tag(),
                },
                context_span,
            ));
        }

        let appended_context =
            self.context_from_reflected_attrs(context_id, context_span, context_value)?;
        let context = base_context
            .union(&appended_context)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        let result = NixString::new(bytes, context);
        self.alloc_tree_walk_string(id, span, result)
    }
}
