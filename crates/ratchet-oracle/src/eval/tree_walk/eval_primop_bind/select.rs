//! Attribute binding inheritance and select evaluation helpers.

use crate::compile::IrInlineCacheSiteId;

use super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn eval_attr_binding_value(
        &mut self,
        id: IrId,
        span: Span,
        value: IrId,
        inherit_source_thunks: &mut BTreeMap<u32, Value>,
    ) -> Result<Value, TreeWalkError> {
        let Some((select_id, receiver, path)) = self.inherit_source_select(value)? else {
            return self.eval_lazy_node(value);
        };

        let receiver_key = receiver.as_u32();
        let receiver_value = if let Some(receiver_value) = inherit_source_thunks.get(&receiver_key)
        {
            *receiver_value
        } else {
            let receiver_value = self.eval_lazy_node(receiver)?;
            inherit_source_thunks.insert(receiver_key, receiver_value);
            receiver_value
        };

        self.alloc_select_thunk(id, span, select_id, receiver_value, path)
    }

    pub(in crate::eval::tree_walk) fn inherit_source_select(
        &self,
        value: IrId,
    ) -> Result<Option<(IrId, IrId, IrAttrPathId)>, TreeWalkError> {
        // `inherit (e) name...` lowers each target to a lazy select whose receiver
        // is the same thunked source expression. Sharing that receiver at runtime
        // preserves Nix's one-evaluation source behavior without caching all
        // `ThunkAlloc` nodes globally across lexical environments.
        let value_node = self.node(value)?;
        if value_node.kind != IrKind::ThunkAlloc {
            return Ok(None);
        }
        let IrData::Node(select_id) = value_node.data else {
            return Err(self.invalid_payload(value, value_node, "thunk body"));
        };
        let select_node = self.node(select_id)?;
        if select_node.kind != IrKind::Select {
            return Ok(None);
        }
        let IrData::Select {
            receiver,
            path,
            default,
            ..
        } = select_node.data
        else {
            return Err(self.invalid_payload(select_id, select_node, "select payload"));
        };
        if default.is_some() || self.node(receiver)?.kind != IrKind::ThunkAlloc {
            return Ok(None);
        }
        if self
            .attr_path(select_id, path, select_node.span)?
            .iter()
            .any(|segment| matches!(segment, IrAttrPathSegment::Dynamic(_)))
        {
            return Ok(None);
        }

        Ok(Some((select_id, receiver, path)))
    }

    pub(in crate::eval::tree_walk) fn eval_select(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::Select {
            receiver,
            path: path_id,
            default,
            ..
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "select payload"));
        };
        self.reject_empty_attr_path(id, path_id, node.span)?;
        if let Some(value) =
            self.eval_builtin_static_select(id, node, receiver, path_id, default)?
        {
            return Ok(value);
        }
        let current = self.eval_node(receiver)?;
        self.eval_select_from_value(id, node.span, current, path_id, default, false)
    }

    pub(in crate::eval::tree_walk) fn eval_select_from_value(
        &mut self,
        id: IrId,
        span: Span,
        mut current: Value,
        path_id: IrAttrPathId,
        default: Option<IrId>,
        force_receiver: bool,
    ) -> Result<Value, TreeWalkError> {
        let segments = self.attr_path_len(id, path_id, span)?;
        self.reject_empty_attr_path_len(id, path_id, span, segments)?;

        if force_receiver {
            current = self.force_value(id, span, current)?;
        }
        current = self.force_lazy_foldl_initial_value(id, span, current)?;
        for index in 0..segments {
            let segment = self.attr_path_segment(id, path_id, index, span)?;
            let key = self
                .eval_attr_name(id, segment, DynamicAttrNullPolicy::RejectNull, span)?
                .ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "string",
                            actual: ValueTag::Null,
                        },
                        span,
                    )
                })?;
            if current.tag() != ValueTag::Attrs {
                return match default {
                    Some(default) => self.eval_node(default),
                    None => Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "attrs",
                            actual: current.tag(),
                        },
                        span,
                    )),
                };
            }
            let selected = {
                let attrs = self.heap.get_attrs(current).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
                attrs.get(key)
            };
            let Some(value) = selected else {
                return match default {
                    Some(default) => self.eval_node(default),
                    None => Err(TreeWalkError::new(
                        TreeWalkErrorKind::MissingAttribute { id, symbol: key },
                        span,
                    )),
                };
            };
            if index + 1 == segments {
                return Ok(value);
            }
            current = self.force_value(id, span, value)?;
            current = self.force_lazy_foldl_initial_value(id, span, current)?;
        }

        Err(TreeWalkError::new(
            TreeWalkErrorKind::InvalidAttrPath { id, path: path_id },
            span,
        ))
    }

    /// Selects one attr from an already-forced attrset value.
    ///
    /// Callers own WHNF forcing and lazy-foldl normalization before entering this
    /// select-IC helper boundary; this routine only checks the receiver shape and
    /// performs the key lookup.
    pub(crate) fn select_attr_value(
        &mut self,
        id: IrId,
        span: Span,
        attrs_value: Value,
        symbol: Symbol,
        _site: IrInlineCacheSiteId,
    ) -> Result<Value, TreeWalkError> {
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                span,
            ));
        }
        let attrs = self
            .heap
            .get_attrs(attrs_value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        attrs.get(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::MissingAttribute { id, symbol }, span)
        })
    }

    /// Returns whether an already-forced attrset value contains one static attr.
    ///
    /// Callers own WHNF forcing and lazy-foldl normalization before entering this
    /// helper boundary; this routine only checks the receiver shape and probes key
    /// presence.
    pub(crate) fn has_attr_value(
        &mut self,
        id: IrId,
        span: Span,
        attrs_value: Value,
        symbol: Symbol,
        _site: IrInlineCacheSiteId,
    ) -> Result<Value, TreeWalkError> {
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                span,
            ));
        }
        let attrs = self
            .heap
            .get_attrs(attrs_value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        Ok(Value::bool(attrs.contains_key(symbol)))
    }
}
