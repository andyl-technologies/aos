//! Trace/warning emission, `tryEval`, deep forcing, and value-output writers.

use super::*;

impl TreeWalk {
    pub(super) fn write_trace_value(
        &self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        visited: &mut Vec<(ValueTag, u64)>,
        top_level: bool,
    ) -> Result<(), TreeWalkError> {
        let tag = value.tag();
        let entered = if Self::trace_recursive_value_tag(tag) {
            let key = (tag, value.payload_bits());
            if visited.contains(&key) {
                return Self::extend_bytes_for_node(id, span, out, "«repeated»".as_bytes());
            }
            let len = visited.len() + 1;
            visited.try_reserve_exact(1).map_err(|_| {
                TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
            })?;
            visited.push(key);
            true
        } else {
            false
        };

        let result = match tag {
            ValueTag::Null => Self::extend_bytes_for_node(id, span, out, b"null"),
            ValueTag::Bool => {
                if self.expect_bool(value_id, value, value_span)? {
                    Self::extend_bytes_for_node(id, span, out, b"true")
                } else {
                    Self::extend_bytes_for_node(id, span, out, b"false")
                }
            }
            ValueTag::Int => {
                let bytes = Self::raw_int_bytes(value.payload_bits() as i64);
                Self::extend_bytes_for_node(id, span, out, &bytes)
            }
            ValueTag::Float => {
                let bytes = Self::raw_float_bytes(f64::from_bits(value.payload_bits()));
                Self::extend_bytes_for_node(id, span, out, &bytes)
            }
            ValueTag::String => {
                self.write_trace_string(id, span, value_id, value_span, value, out, top_level)
            }
            ValueTag::Path => self.write_trace_path(id, span, value_id, value_span, value, out),
            ValueTag::List => {
                self.write_trace_list(id, span, value_id, value_span, value, out, visited)
            }
            ValueTag::Attrs => {
                self.write_trace_attrs(id, span, value_id, value_span, value, out, visited)
            }
            ValueTag::Lambda => Self::extend_bytes_for_node(id, span, out, "«lambda»".as_bytes()),
            ValueTag::Primop => self.write_trace_primop(id, span, value_id, value_span, value, out),
            ValueTag::External => {
                Self::extend_bytes_for_node(id, span, out, "«external»".as_bytes())
            }
            ValueTag::Thunk => self.write_trace_thunk(
                id, span, value_id, value_span, value, out, visited, top_level,
            ),
        };

        if entered {
            visited.pop();
        }
        result
    }

    pub(super) fn trace_recursive_value_tag(tag: ValueTag) -> bool {
        matches!(tag, ValueTag::List | ValueTag::Attrs | ValueTag::Thunk)
    }

    pub(super) fn write_trace_thunk(
        &self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        visited: &mut Vec<(ValueTag, u64)>,
        top_level: bool,
    ) -> Result<(), TreeWalkError> {
        let thunk = self.heap.get_thunk(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: value_id,
                    source,
                },
                value_span,
            )
        })?;
        let body = thunk.body_ref();
        let cached = thunk
            .cell()
            .cached_value()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?;
        if let Some(cached) = cached {
            self.write_trace_value(
                id, span, value_id, value_span, cached, out, visited, top_level,
            )
        } else if let Some(body) = body {
            if self.write_trace_literal_thunk_body(id, span, body, out, top_level)? {
                Ok(())
            } else {
                Self::extend_bytes_for_node(id, span, out, "«thunk»".as_bytes())
            }
        } else {
            Self::extend_bytes_for_node(id, span, out, "«thunk»".as_bytes())
        }
    }

    pub(super) fn write_trace_literal_thunk_body(
        &self,
        id: IrId,
        span: Span,
        body: EvalNodeRef,
        out: &mut Vec<u8>,
        top_level: bool,
    ) -> Result<bool, TreeWalkError> {
        let body_id = body.id();
        let node = *self.node_in_module(body.module(), body_id)?;
        match node.kind {
            IrKind::Int => {
                let IrData::Int(value) = node.data else {
                    return Err(self.invalid_payload(body_id, &node, "integer payload"));
                };
                let bytes = Self::raw_int_bytes(value);
                Self::extend_bytes_for_node(id, span, out, &bytes)?;
            }
            IrKind::Float => {
                let IrData::Float(value) = node.data else {
                    return Err(self.invalid_payload(body_id, &node, "float payload"));
                };
                let bytes = Self::raw_float_bytes(value);
                Self::extend_bytes_for_node(id, span, out, &bytes)?;
            }
            IrKind::Bool => {
                let IrData::Bool(value) = node.data else {
                    return Err(self.invalid_payload(body_id, &node, "boolean payload"));
                };
                if value {
                    Self::extend_bytes_for_node(id, span, out, b"true")?;
                } else {
                    Self::extend_bytes_for_node(id, span, out, b"false")?;
                }
            }
            IrKind::Null => {
                if node.data != IrData::None {
                    return Err(self.invalid_payload(body_id, &node, "empty payload"));
                }
                Self::extend_bytes_for_node(id, span, out, b"null")?;
            }
            IrKind::Str | IrKind::Uri => {
                let IrData::Symbol(symbol) = node.data else {
                    return Err(self.invalid_payload(body_id, &node, "string symbol payload"));
                };
                let bytes = self.symbols.resolve(symbol).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidSymbol {
                            id: body_id,
                            symbol,
                        },
                        node.span,
                    )
                })?;
                if top_level {
                    Self::extend_bytes_for_node(id, span, out, bytes)?;
                } else {
                    Self::write_trace_escaped_string(id, span, bytes, out)?;
                }
            }
            IrKind::Path => {
                let IrData::Symbol(symbol) = node.data else {
                    return Err(self.invalid_payload(body_id, &node, "path symbol payload"));
                };
                let bytes = self.symbols.resolve(symbol).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidSymbol {
                            id: body_id,
                            symbol,
                        },
                        node.span,
                    )
                })?;
                let path = self.path_literal_bytes_for_module_node(
                    body.module(),
                    body_id,
                    node.span,
                    bytes,
                )?;
                Self::extend_bytes_for_node(id, span, out, &path)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub(super) fn write_trace_string(
        &self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        top_level: bool,
    ) -> Result<(), TreeWalkError> {
        let string = self.heap.get_string(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: value_id,
                    source,
                },
                value_span,
            )
        })?;
        if top_level {
            Self::extend_bytes_for_node(id, span, out, string.bytes())
        } else {
            Self::write_trace_escaped_string(id, span, string.bytes(), out)
        }
    }

    pub(super) fn write_trace_path(
        &self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
        out: &mut Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        let path = self.heap.get_path(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: value_id,
                    source,
                },
                value_span,
            )
        })?;
        Self::extend_bytes_for_node(id, span, out, path.bytes())
    }

    pub(super) fn write_trace_list(
        &self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        visited: &mut Vec<(ValueTag, u64)>,
    ) -> Result<(), TreeWalkError> {
        let elements = {
            let list = self.heap.get_list(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            let mut elements = Vec::new();
            elements.try_reserve_exact(list.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: list_id,
                        len: list.len(),
                    },
                    list_span,
                )
            })?;
            elements.extend_from_slice(list.as_slice());
            elements
        };

        if elements.is_empty() {
            return Self::extend_bytes_for_node(id, span, out, b"[ ]");
        }

        Self::extend_bytes_for_node(id, span, out, b"[ ")?;
        for (index, element) in elements.into_iter().enumerate() {
            if index > 0 {
                Self::extend_bytes_for_node(id, span, out, b" ")?;
            }
            self.write_trace_value(id, span, list_id, list_span, element, out, visited, false)?;
        }
        Self::extend_bytes_for_node(id, span, out, b" ]")
    }

    pub(super) fn write_trace_attrs(
        &self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        attrs_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        visited: &mut Vec<(ValueTag, u64)>,
    ) -> Result<(), TreeWalkError> {
        let entries = {
            let attrs = self.heap.get_attrs(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(attrs.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Attr {
                        id,
                        source: AttrError::AllocationFailed {
                            entries: attrs.len(),
                        },
                    },
                    span,
                )
            })?;
            for entry in attrs.iter_lexicographic() {
                let key = self.symbols.resolve(entry.key).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidSymbol {
                            id: attrs_id,
                            symbol: entry.key,
                        },
                        attrs_span,
                    )
                })?;
                entries.push((Self::copy_bytes_for_node(id, span, key)?, entry.value));
            }
            entries
        };

        if entries.is_empty() {
            return Self::extend_bytes_for_node(id, span, out, b"{ }");
        }

        Self::extend_bytes_for_node(id, span, out, b"{ ")?;
        for (key, value) in entries {
            Self::write_trace_attr_key(id, span, &key, out)?;
            Self::extend_bytes_for_node(id, span, out, b" = ")?;
            self.write_trace_value(id, span, attrs_id, attrs_span, value, out, visited, false)?;
            Self::extend_bytes_for_node(id, span, out, b"; ")?;
        }
        Self::extend_bytes_for_node(id, span, out, b"}")
    }

    pub(super) fn write_trace_primop(
        &self,
        id: IrId,
        span: Span,
        primop_id: IrId,
        primop_span: Span,
        value: Value,
        out: &mut Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        let primop = self.heap.get_primop(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: primop_id,
                    source,
                },
                primop_span,
            )
        })?;
        let name = self.symbols.resolve(primop.symbol()).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol {
                    id: primop_id,
                    symbol: primop.symbol(),
                },
                primop_span,
            )
        })?;
        Self::extend_bytes_for_node(id, span, out, "«primop ".as_bytes())?;
        Self::extend_bytes_for_node(id, span, out, name)?;
        Self::extend_bytes_for_node(id, span, out, "»".as_bytes())
    }

    pub(super) fn write_trace_attr_key(
        id: IrId,
        span: Span,
        key: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        if Self::trace_attr_key_can_be_unquoted(key) {
            Self::extend_bytes_for_node(id, span, out, key)
        } else {
            Self::write_trace_escaped_string(id, span, key, out)
        }
    }

    pub(super) fn trace_attr_key_can_be_unquoted(key: &[u8]) -> bool {
        let Some(first) = key.first() else {
            return false;
        };
        if !first.is_ascii_alphabetic() && *first != b'_' {
            return false;
        }
        key.iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'\''))
    }

    pub(super) fn write_trace_escaped_string(
        id: IrId,
        span: Span,
        bytes: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        Self::extend_bytes_for_node(id, span, out, b"\"")?;
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            match byte {
                b'"' => Self::extend_bytes_for_node(id, span, out, b"\\\"")?,
                b'\\' => Self::extend_bytes_for_node(id, span, out, b"\\\\")?,
                b'\n' => Self::extend_bytes_for_node(id, span, out, b"\\n")?,
                b'\r' => Self::extend_bytes_for_node(id, span, out, b"\\r")?,
                b'\t' => Self::extend_bytes_for_node(id, span, out, b"\\t")?,
                b'$' if bytes.get(index + 1) == Some(&b'{') => {
                    Self::extend_bytes_for_node(id, span, out, b"\\${")?;
                    index += 1;
                }
                byte => Self::extend_bytes_for_node(id, span, out, &[byte])?,
            }
            index += 1;
        }
        Self::extend_bytes_for_node(id, span, out, b"\"")
    }

    pub(super) fn eval_try_eval_direct(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
    ) -> Result<Value, TreeWalkError> {
        match self.eval_node(argument) {
            Ok(value) => self.alloc_try_eval_result(id, span, true, value),
            Err(error) => self.handle_try_eval_error(id, span, error),
        }
    }

    pub(super) fn eval_try_eval_value(
        &mut self,
        id: IrId,
        span: Span,
        argument: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        match self.force_value(argument.id(), argument.span(), argument.value()) {
            Ok(value) => self.alloc_try_eval_result(id, span, true, value),
            Err(error) => self.handle_try_eval_error(id, span, error),
        }
    }

    pub(super) fn handle_try_eval_error(
        &mut self,
        id: IrId,
        span: Span,
        error: TreeWalkError,
    ) -> Result<Value, TreeWalkError> {
        match error.kind() {
            TreeWalkErrorKind::Thrown { .. }
            | TreeWalkErrorKind::AssertionFailed { .. }
            | TreeWalkErrorKind::SearchPathNotFound { .. } => {
                self.alloc_try_eval_result(id, span, false, Value::bool(false))
            }
            _ => Err(error),
        }
    }

    pub(super) fn alloc_try_eval_result(
        &mut self,
        id: IrId,
        span: Span,
        success: bool,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let success_key = self.intern_builtin_attr_symbol(id, b"success", span)?;
        let value_key = self.intern_builtin_attr_symbol(id, b"value", span)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(2).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len: 2 }, span)
        })?;
        entries.push(AttrEntry::new(success_key, Value::bool(success)));
        entries.push(AttrEntry::new(value_key, value));
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn eval_float_to_int_primop(
        &self,
        id: IrId,
        span: Span,
        argument: IrId,
        value: Value,
        op: fn(f64) -> f64,
        arithmetic_op: ArithmeticOp,
    ) -> Result<Value, TreeWalkError> {
        let argument_span = self.node(argument)?.span;
        let value = match self.expect_number(argument, value, argument_span)? {
            Number::Int(value) => value,
            Number::Float(value) => {
                let rounded = op(value);
                if rounded.is_nan() {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::ArithmeticOverflow {
                            id,
                            op: arithmetic_op,
                        },
                        span,
                    ));
                }
                if rounded <= i64::MIN as f64 {
                    i64::MIN
                } else if rounded >= I64_MAX_EXCLUSIVE_AS_F64 {
                    i64::MAX
                } else {
                    rounded as i64
                }
            }
        };
        Ok(Value::int(value))
    }

    pub(super) fn eval_seq_primop(
        &mut self,
        first: IrId,
        second: IrId,
    ) -> Result<Value, TreeWalkError> {
        let first_span = self.node(first)?.span;
        let value = self.eval_node(first)?;
        self.consume_suspended_lazy_identity_thunk(first, first_span, value)?;
        self.eval_lazy_node(second)
    }

    pub(super) fn eval_deep_seq_primop(
        &mut self,
        first: IrId,
        second: IrId,
    ) -> Result<Value, TreeWalkError> {
        let first_span = self.node(first)?.span;
        let value = self.eval_node(first)?;
        if !self.consume_suspended_lazy_identity_thunk(first, first_span, value)? {
            let mut visited = Vec::new();
            self.deep_force_value(first, first_span, value, &mut visited)?;
        }
        self.eval_lazy_node(second)
    }

    pub(crate) fn deep_force_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        visited: &mut Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let value = self.with_deep_force_visited_roots(id, span, visited, |eval, _| {
            eval.force_value(id, span, value)
        })?;
        let tag = value.tag();
        if !matches!(tag, ValueTag::List | ValueTag::Attrs) {
            return Ok(value);
        }

        let mut roots = [value];
        self.with_indexed_transient_value_stack_roots(id, span, &mut roots, |eval, slots| {
            let slot = slots.start;
            let value = eval
                .current_transient_value_stack_root(slot)
                .ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                        span,
                    )
                })?;
            eval.deep_force_container_value(id, span, value, visited)
        })?;
        Ok(roots[0])
    }

    fn deep_force_container_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        visited: &mut Vec<Value>,
    ) -> Result<(), TreeWalkError> {
        let tag = value.tag();
        if Self::deep_force_visited_contains(visited, value) {
            return Ok(());
        }
        let len = visited.len() + 1;
        visited.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
        })?;
        visited.push(value);

        match tag {
            ValueTag::List => {
                let mut elements = {
                    let list = self.heap.get_list(value).map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })?;
                    Self::clone_list_elements(id, span, list)?
                };
                self.deep_force_child_values(id, span, &mut elements, visited)?;
            }
            ValueTag::Attrs => {
                let mut values = {
                    let attrs = self.heap.get_attrs(value).map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })?;
                    let mut values = Vec::new();
                    values.try_reserve_exact(attrs.len()).map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ListAllocationFailed {
                                id,
                                len: attrs.len(),
                            },
                            span,
                        )
                    })?;
                    for entry in attrs.iter_source_order() {
                        values.push(entry.value);
                    }
                    values
                };
                self.deep_force_child_values(id, span, &mut values, visited)?;
            }
            _ => unreachable!("deepSeq only traverses list and attrset values"),
        }

        Ok(())
    }

    fn deep_force_child_values(
        &mut self,
        id: IrId,
        span: Span,
        values: &mut [Value],
        visited: &mut Vec<Value>,
    ) -> Result<(), TreeWalkError> {
        self.with_indexed_transient_value_stack_roots(id, span, values, |eval, slots| {
            eval.with_deep_force_visited_roots(id, span, visited, |eval, visited| {
                for slot in slots {
                    let value = eval
                        .current_transient_value_stack_root(slot)
                        .ok_or_else(|| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                                span,
                            )
                        })?;
                    eval.deep_force_value(id, span, value, visited)?;
                }
                Ok(())
            })
        })
    }

    /// Publishes the current deep-force visited set as transient roots.
    ///
    /// Moving-GC stress can relocate containers that have already been visited
    /// before a later recursive edge reaches them again.
    pub(in crate::eval::tree_walk) fn with_deep_force_visited_roots<T>(
        &mut self,
        id: IrId,
        span: Span,
        visited: &mut Vec<Value>,
        body: impl FnOnce(&mut Self, &mut Vec<Value>) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        if visited.is_empty() {
            return body(self, visited);
        }

        let rooted = visited.len();
        let mut roots = Vec::new();
        roots.try_reserve_exact(rooted).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed { id, len: rooted },
                span,
            )
        })?;
        roots.extend_from_slice(visited);
        let result =
            self.with_transient_value_stack_roots(id, span, roots.as_mut_slice(), |eval| {
                body(eval, visited)
            });
        for (visited, root) in visited.iter_mut().take(rooted).zip(roots) {
            *visited = root;
        }
        result
    }

    fn deep_force_visited_contains(visited: &[Value], value: Value) -> bool {
        visited.iter().any(|entry| entry.raw_eq(value))
    }

    pub(super) fn eval_has_context_primop(
        &self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "string",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }
        let string = self.heap.get_string(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: argument,
                    source,
                },
                argument_span,
            )
        })?;
        Ok(Value::bool(string.has_context()))
    }

    pub(super) fn eval_get_context_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "string",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }
        let groups = {
            let string = self.heap.get_string(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let mut groups: Vec<ReflectedContextGroup> = Vec::new();
            groups
                .try_reserve_exact(string.context().len())
                .map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Attr {
                            id,
                            source: AttrError::AllocationFailed {
                                entries: string.context().len(),
                            },
                        },
                        span,
                    )
                })?;
            for element in string.context() {
                let path = Self::copy_bytes_for_node(id, span, element.path())?;
                let group_index = if groups
                    .last()
                    .is_some_and(|group| group.path.as_slice() == path.as_slice())
                {
                    groups.len() - 1
                } else {
                    groups.push(ReflectedContextGroup::new(path));
                    groups.len() - 1
                };
                let Some(group) = groups.get_mut(group_index) else {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::InvalidStringContext { id },
                        span,
                    ));
                };
                match element.kind() {
                    ContextKind::OpaquePath => group.path_flag = true,
                    ContextKind::SingleOutput => {
                        let output = element.output().ok_or_else(|| {
                            TreeWalkError::new(TreeWalkErrorKind::InvalidStringContext { id }, span)
                        })?;
                        let len = group.outputs.len().checked_add(1).ok_or_else(|| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::List {
                                    id,
                                    source: NixListError::LengthOverflow {
                                        left: group.outputs.len(),
                                        right: 1,
                                    },
                                },
                                span,
                            )
                        })?;
                        group.outputs.try_reserve_exact(1).map_err(|_| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::ListAllocationFailed { id, len },
                                span,
                            )
                        })?;
                        group
                            .outputs
                            .push(Self::copy_bytes_for_node(id, span, output)?);
                    }
                    ContextKind::DeepDerivation => group.all_outputs = true,
                }
            }
            groups
        };

        let mut entries = Vec::new();
        entries.try_reserve_exact(groups.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: groups.len(),
                    },
                },
                span,
            )
        })?;
        for group in groups {
            let symbol = self.intern_symbol_for_eval(&group.path).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SymbolIntern {
                        id,
                        source: source.kind().clone(),
                    },
                    span,
                )
            })?;
            let value = self.alloc_reflected_context_group(id, span, group)?;
            entries.push(AttrEntry::new(symbol, value));
        }
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn eval_append_context_primop(
        &mut self,
        id: IrId,
        span: Span,
        string: IrId,
        context: IrId,
    ) -> Result<Value, TreeWalkError> {
        let string_span = self.node(string)?.span;
        let string_value = self.eval_node(string)?;
        let (bytes, base_context) =
            self.append_context_base_string(string, string_span, string_value)?;
        let context_span = self.node(context)?.span;
        let context_value = self.eval_node(context)?;
        self.finish_append_context_primop(
            id,
            span,
            bytes,
            base_context,
            context,
            context_span,
            context_value,
        )
    }

    pub(super) fn eval_append_context_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        string: EvalPrimOpArg,
        context: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let string_value = self.force_value(string.id(), string.span(), string.value())?;
        let (bytes, base_context) =
            self.append_context_base_string(string.id(), string.span(), string_value)?;
        let context_value = self.force_value(context.id(), context.span(), context.value())?;
        self.finish_append_context_primop(
            id,
            span,
            bytes,
            base_context,
            context.id(),
            context.span(),
            context_value,
        )
    }

    pub(super) fn append_context_base_string(
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

    pub(super) fn finish_append_context_primop(
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
