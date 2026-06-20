//! Numeric builtins, instantiation evaluation, and value reflection.

use super::*;

impl TreeWalk {
    pub(super) fn eval_instantiation_attr_path(
        &mut self,
        id: IrId,
        span: Span,
        mut current: Value,
        attr_path: &[Vec<u8>],
    ) -> Result<Value, TreeWalkError> {
        if attr_path.is_empty() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "non-empty attr path",
                    actual: current.tag(),
                },
                span,
            ));
        }

        for segment in attr_path {
            current = self.auto_call_formal_set_lambda(id, span, current)?;
            current = self.force_value(id, span, current)?;
            if attr_path_segment_is_list_index(segment) {
                current = self.eval_instantiation_list_index(id, span, current, segment)?;
                continue;
            }
            if current.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id,
                        expected: "attrs",
                        actual: current.tag(),
                    },
                    span,
                ));
            }
            let key = self.intern_attr_name_bytes(id, segment)?;
            let selected = {
                let attrs = self.heap.get_attrs(current).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
                attrs.get(key)
            };
            current = selected.ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::MissingAttribute { id, symbol: key },
                    span,
                )
            })?;
        }

        self.force_node_result(id, span, current)
    }

    pub(super) fn eval_instantiation_list_index(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        segment: &[u8],
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "list",
                    actual: value.tag(),
                },
                span,
            ));
        }
        let list = self
            .heap
            .get_list(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let index = parse_attr_path_list_index(segment);
        let diagnostic_index = parse_attr_path_list_index_diagnostic(segment);
        let Some(value) = index.and_then(|index| list.get(index)) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::ListIndexOutOfBounds {
                    id,
                    index: diagnostic_index,
                    len: list.len(),
                },
                span,
            ));
        };
        Ok(value)
    }

    pub(super) fn auto_call_formal_set_lambda(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.force_value(id, span, value)?;
        if value.tag() != ValueTag::Lambda {
            return Ok(value);
        }
        let lambda = self
            .heap
            .clone_lambda(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if !self.lambda_uses_formal_set_pattern(id, span, &lambda)? {
            return Ok(value);
        }
        let argument = self
            .heap
            .alloc_attrs(0, FlatAttrs::empty())
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        self.apply_lambda_value(id, span, id, value, span, id, argument)
    }

    pub(super) fn lambda_uses_formal_set_pattern(
        &mut self,
        id: IrId,
        span: Span,
        lambda: &EvalLambda,
    ) -> Result<bool, TreeWalkError> {
        self.with_current_module(lambda.module(), |eval| {
            let pattern_node = *eval.node(lambda.pattern())?;
            match pattern_node.kind {
                IrKind::Formal => Ok(false),
                IrKind::FormalSet => Ok(true),
                kind => Err(TreeWalkError::new(
                    TreeWalkErrorKind::UnsupportedLambdaPattern {
                        id,
                        pattern: lambda.pattern(),
                        kind,
                    },
                    span,
                )),
            }
        })
    }

    pub(super) fn eval_builtin_static_select(
        &mut self,
        id: IrId,
        node: &IrNode,
        receiver: IrId,
        path_id: IrAttrPathId,
        default: Option<IrId>,
    ) -> Result<Option<Value>, TreeWalkError> {
        if !self.scoped_globals.is_empty() {
            return Ok(None);
        }
        let receiver_node = self.node(receiver)?;
        let IrData::Symbol(receiver_symbol) = receiver_node.data else {
            return Ok(None);
        };
        if receiver_node.kind != IrKind::GlobalVar
            || self.symbols.resolve(receiver_symbol) != Some(b"builtins")
        {
            return Ok(None);
        }

        let path = self.attr_path(id, path_id, node.span)?;
        let Some(IrAttrPathSegment::Static(symbol)) = path.first() else {
            return Ok(None);
        };
        let name = self.symbols.resolve(*symbol).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol {
                    id,
                    symbol: *symbol,
                },
                node.span,
            )
        })?;
        let Some(builtin) = lookup_builtin(name) else {
            return match default {
                Some(default) => self.eval_node(default).map(Some),
                None => Err(TreeWalkError::new(
                    TreeWalkErrorKind::MissingAttribute {
                        id,
                        symbol: *symbol,
                    },
                    node.span,
                )),
            };
        };
        if !builtin.is_available(self) {
            if self.reject_unconfigured_impure_builtin_constant(builtin) {
                return Err(self.unsupported_ambient_builtin_constant(id, node.span));
            }
            return match default {
                Some(default) => self.eval_node(default).map(Some),
                None => Err(TreeWalkError::new(
                    TreeWalkErrorKind::MissingAttribute {
                        id,
                        symbol: *symbol,
                    },
                    node.span,
                )),
            };
        }
        if path.len() == 1 {
            return builtin.select(self, id, node.span, *symbol).map(Some);
        }

        match default {
            Some(default) => self.eval_node(default).map(Some),
            None => {
                let value = builtin.select(self, id, node.span, *symbol)?;
                Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id,
                        expected: "attrs",
                        actual: value.tag(),
                    },
                    node.span,
                ))
            }
        }
    }

    pub(super) fn eval_has_attr(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::HasAttr {
            receiver,
            path: path_id,
            ..
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "has-attr payload"));
        };
        self.reject_empty_attr_path(id, path_id, node.span)?;
        if let Some(value) = self.eval_builtin_static_has_attr(id, node, receiver, path_id)? {
            return Ok(value);
        }
        let segments = self.attr_path_len(id, path_id, node.span)?;
        let mut current = self.eval_node(receiver)?;
        self.reject_empty_attr_path_len(id, path_id, node.span, segments)?;

        for index in 0..segments {
            let segment = self.attr_path_segment(id, path_id, index, node.span)?;
            let key = self
                .eval_attr_name(id, segment, DynamicAttrNullPolicy::RejectNull, node.span)?
                .ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "string",
                            actual: ValueTag::Null,
                        },
                        node.span,
                    )
                })?;
            if current.tag() != ValueTag::Attrs {
                return Ok(Value::bool(false));
            }
            let selected = {
                let attrs = self.heap.get_attrs(current).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
                })?;
                attrs.get(key)
            };
            let Some(value) = selected else {
                return Ok(Value::bool(false));
            };
            if index + 1 == segments {
                return Ok(Value::bool(true));
            }
            current = self.force_value(id, node.span, value)?;
        }

        Ok(Value::bool(false))
    }

    pub(super) fn eval_builtin_static_has_attr(
        &mut self,
        id: IrId,
        node: &IrNode,
        receiver: IrId,
        path_id: IrAttrPathId,
    ) -> Result<Option<Value>, TreeWalkError> {
        if !self.scoped_globals.is_empty() {
            return Ok(None);
        }
        let receiver_node = self.node(receiver)?;
        let IrData::Symbol(receiver_symbol) = receiver_node.data else {
            return Ok(None);
        };
        if receiver_node.kind != IrKind::GlobalVar
            || self.symbols.resolve(receiver_symbol) != Some(b"builtins")
        {
            return Ok(None);
        }

        let path = self.attr_path(id, path_id, node.span)?;
        let Some(IrAttrPathSegment::Static(symbol)) = path.first() else {
            return Ok(None);
        };
        let name = self.symbols.resolve(*symbol).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidSymbol {
                    id,
                    symbol: *symbol,
                },
                node.span,
            )
        })?;
        let Some(builtin) = lookup_builtin(name) else {
            return Ok(Some(Value::bool(false)));
        };
        if !builtin.is_available(self) && self.reject_unconfigured_impure_builtin_constant(builtin)
        {
            return Err(self.unsupported_ambient_builtin_constant(id, node.span));
        }
        Ok(Some(Value::bool(
            path.len() == 1 && builtin.is_available(self),
        )))
    }

    pub(super) fn reject_unconfigured_impure_builtin_constant(&self, builtin: Builtin) -> bool {
        self.options.reject_unconfigured_impure_builtin_constants()
            && self.options.eval_mode() != EvalMode::Pure
            && matches!(
                builtin.availability(),
                BuiltinAvailability::ImpureCurrentSystem | BuiltinAvailability::ImpureCurrentTime
            )
    }

    pub(super) fn unsupported_ambient_builtin_constant(
        &self,
        id: IrId,
        span: Span,
    ) -> TreeWalkError {
        TreeWalkError::new(
            TreeWalkErrorKind::UnsupportedAmbientBuiltinConstant {
                id,
                feature: "CLI-sensitive builtin evaluation",
            },
            span,
        )
    }

    pub(super) fn eval_add(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let forced_break_left = self.consume_suspended_lazy_identity_thunk(lhs, lhs_span, left)?;
        let left = if forced_break_left {
            self.force_value(lhs, lhs_span, left)?
        } else {
            left
        };
        match left.tag() {
            ValueTag::Int | ValueTag::Float if !forced_break_left => {
                let rhs_span = self.node(rhs)?.span;
                let right = self.eval_node(rhs)?;
                let left = self.expect_number(lhs, left, lhs_span)?;
                let right = self.expect_number(rhs, right, rhs_span)?;
                self.eval_numeric_values(id, node, BinaryArithmeticOp::Add, left, right)
            }
            ValueTag::String => {
                let rhs_span = self.node(rhs)?.span;
                let right = self.eval_node(rhs)?;
                let right = self.force_demanded_value(rhs, rhs_span, right)?;
                let right = self.coerce_to_interpolation_string(rhs, right, rhs_span)?;
                self.concat_strings(id, node, left, right)
            }
            ValueTag::Path => self.eval_path_add(id, node, lhs, lhs_span, left, rhs),
            ValueTag::Attrs => self.eval_attrs_add(id, node, lhs, lhs_span, left, rhs),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: lhs,
                    expected: "number, string, or path",
                    actual,
                },
                lhs_span,
            )),
        }
    }

    pub(super) fn eval_path_add(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        lhs_span: Span,
        left: Value,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let right = self.force_demanded_value(rhs, rhs_span, right)?;
        let right = self.coerce_to_string(rhs, right, rhs_span)?;
        let left = self.heap.get_path(left).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id: lhs, source }, lhs_span)
        })?;
        let right = self.heap.get_string(right).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id: rhs, source }, rhs_span)
        })?;
        if right.has_context() {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::StringContextNotAllowed {
                    id: rhs,
                    op: "path addition",
                },
                rhs_span,
            ));
        }

        let len = left.len().checked_add(right.len()).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: usize::MAX,
                },
                node.span,
            )
        })?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed { id, len },
                node.span,
            )
        })?;
        bytes.extend_from_slice(left.bytes());
        bytes.extend_from_slice(right.bytes());
        let bytes = Self::absolute_path_bytes_for_node(id, node.span, &bytes)?;
        self.heap
            .alloc_path(NixString::from_bytes(bytes))
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    pub(super) fn eval_attrs_add(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        lhs_span: Span,
        left: Value,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let left = self.coerce_to_string(lhs, left, lhs_span)?;
        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let right = self.force_demanded_value(rhs, rhs_span, right)?;
        let right = self.coerce_to_string(rhs, right, rhs_span)?;
        self.concat_strings(id, node, left, right)
    }

    pub(super) fn eval_equality(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
        invert: bool,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let left = self.force_demanded_value(lhs, lhs_span, left)?;
        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let right = self.force_demanded_value(rhs, rhs_span, right)?;
        let equal = self.values_equal(id, node, left, right, EqualityContext::Direct)?;
        Ok(Value::bool(if invert { !equal } else { equal }))
    }

    pub(super) fn values_equal(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
        _context: EqualityContext,
    ) -> Result<bool, TreeWalkError> {
        match (left.tag(), right.tag()) {
            (ValueTag::Int, ValueTag::Int) => {
                Ok((left.payload_bits() as i64) == (right.payload_bits() as i64))
            }
            (ValueTag::Float, ValueTag::Float) => {
                Ok(f64::from_bits(left.payload_bits()) == f64::from_bits(right.payload_bits()))
            }
            (ValueTag::Int, ValueTag::Float) => {
                Ok((left.payload_bits() as i64) as f64 == f64::from_bits(right.payload_bits()))
            }
            (ValueTag::Float, ValueTag::Int) => {
                Ok(f64::from_bits(left.payload_bits()) == (right.payload_bits() as i64) as f64)
            }
            (ValueTag::Bool, ValueTag::Bool) => Ok(left.payload_bits() == right.payload_bits()),
            (ValueTag::Null, ValueTag::Null) => Ok(true),
            (ValueTag::String, ValueTag::String) => self.strings_equal(id, node, left, right),
            (ValueTag::Path, ValueTag::Path) => self.paths_equal(id, node, left, right),
            (ValueTag::List, ValueTag::List) => self.lists_equal(id, node, left, right),
            (ValueTag::Attrs, ValueTag::Attrs) => self.attrsets_equal(id, node, left, right),
            (ValueTag::Lambda | ValueTag::Primop, ValueTag::Lambda | ValueTag::Primop) => Ok(false),
            (left_tag, right_tag) if left_tag == right_tag => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedEqualityType {
                    id,
                    left: left_tag,
                    right: right_tag,
                },
                node.span,
            )),
            _ => Ok(false),
        }
    }

    pub(super) fn values_equal_nested_lazy(
        &mut self,
        id: IrId,
        node: &IrNode,
        left_id: IrId,
        left_span: Span,
        left: Value,
        right_id: IrId,
        right_span: Span,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left_identity = self.nested_identity_value(id, node.span, left)?;
        let right_identity = self.nested_identity_value(id, node.span, right)?;
        let shared_heap_identity =
            left_identity.raw_eq(right_identity) && left_identity.tag().is_heap();
        if shared_heap_identity && left_identity.tag() != ValueTag::Thunk {
            return Ok(true);
        }

        let left = self.force_value(left_id, left_span, left_identity)?;
        let right = self.force_value(right_id, right_span, right_identity)?;
        if shared_heap_identity
            && left.raw_eq(right)
            && left.tag().is_heap()
            && left.tag() != ValueTag::Thunk
        {
            return Ok(true);
        }
        if shared_heap_identity
            && left.tag() == ValueTag::Float
            && right.tag() == ValueTag::Float
            && f64::from_bits(left.payload_bits()).is_nan()
            && f64::from_bits(right.payload_bits()).is_nan()
        {
            return Ok(true);
        }
        self.values_equal(id, node, left, right, EqualityContext::Nested)
    }

    pub(super) fn nested_identity_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::Thunk {
            return Ok(value);
        }
        let thunk = self
            .heap
            .clone_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let Some(body) = thunk.body_ref() else {
            return Ok(value);
        };
        let body_node = *self.node_in_module(body.module(), body.id())?;
        if !matches!(
            body_node.kind,
            IrKind::LocalVar | IrKind::UpvalVar | IrKind::ThunkAlloc
        ) {
            return Ok(value);
        }

        let Some(env) = thunk.env() else {
            return Ok(value);
        };
        let Some(with_env) = thunk.with_scope_env() else {
            return Ok(value);
        };
        let thunk_env = self.clone_env_frames(id, env, span)?;
        let thunk_with_env = self.clone_with_scopes(id, with_env, span)?;
        let saved_env = std::mem::replace(&mut self.env, thunk_env);
        let saved_with_scopes = std::mem::replace(&mut self.with_scopes, thunk_with_env);
        let result = self.with_current_module(body.module(), |eval| {
            eval.eval_nested_equality_operand(body.id())
        });
        self.env = saved_env;
        self.with_scopes = saved_with_scopes;
        result
    }

    pub(super) fn strings_equal(
        &self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left = self.heap.get_string(left).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        let right = self.heap.get_string(right).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        Ok(left.bytes() == right.bytes())
    }

    pub(super) fn paths_equal(
        &self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left = self.heap.get_path(left).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        let right = self.heap.get_path(right).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
        })?;
        Ok(left.bytes() == right.bytes())
    }

    pub(super) fn lists_equal(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left_elements = {
            let list = self.heap.get_list(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        let right_elements = {
            let list = self.heap.get_list(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_list_elements(id, node.span, list)?
        };
        if left_elements.len() != right_elements.len() {
            return Ok(false);
        }

        for (left, right) in left_elements.into_iter().zip(right_elements) {
            if !self
                .values_equal_nested_lazy(id, node, id, node.span, left, id, node.span, right)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn attrsets_equal(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let left_entries = {
            let attrs = self.heap.get_attrs(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_attr_entries(id, node.span, attrs)?
        };
        let right_entries = {
            let attrs = self.heap.get_attrs(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            Self::clone_attr_entries(id, node.span, attrs)?
        };
        if left_entries.len() != right_entries.len() {
            return Ok(false);
        }

        for (left, right) in left_entries.iter().zip(&right_entries) {
            if left.key != right.key {
                return Ok(false);
            }
        }
        for (left, right) in left_entries.into_iter().zip(right_entries) {
            if !self.values_equal_nested_lazy(
                id,
                node,
                id,
                node.span,
                left.value,
                id,
                node.span,
                right.value,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn eval_numeric_negation(
        &mut self,
        _id: IrId,
        _node: &IrNode,
        operand: IrId,
    ) -> Result<Value, TreeWalkError> {
        match self.eval_number_node(operand)? {
            Number::Int(value) => Ok(Value::int(value.wrapping_neg())),
            Number::Float(value) => Ok(Value::float(-value)),
        }
    }

    pub(super) fn eval_numeric_binary(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: BinaryArithmeticOp,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let left = self.force_demanded_value(lhs, lhs_span, left)?;
        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let right = self.force_demanded_value(rhs, rhs_span, right)?;
        let left = self.expect_number(lhs, left, lhs_span)?;
        let right = self.expect_number(rhs, right, rhs_span)?;
        self.eval_numeric_values(id, node, op, left, right)
    }

    pub(super) fn eval_bitwise_primop(
        &mut self,
        op: BitwiseOp,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let left = self.eval_int_node(lhs)?;
        let right = self.eval_int_node(rhs)?;

        Ok(Value::int(op.apply(left, right)))
    }

    pub(super) fn eval_numeric_values(
        &self,
        id: IrId,
        node: &IrNode,
        op: BinaryArithmeticOp,
        left: Number,
        right: Number,
    ) -> Result<Value, TreeWalkError> {
        match (left, right) {
            (Number::Int(left), Number::Int(right)) => {
                self.eval_integer_binary(id, node, op, left, right)
            }
            (left, right) => {
                self.eval_float_binary(id, node, op, left.to_float(), right.to_float())
            }
        }
    }

    pub(super) fn concat_strings(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        let concatenated = {
            let left = self.heap.get_string(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            let right = self.heap.get_string(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            left.concat(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::String { id, source }, node.span)
            })?
        };
        self.heap
            .alloc_string(concatenated)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    pub(super) fn eval_list_concat(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let left = self.force_demanded_value(lhs, lhs_span, left)?;
        if left.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: lhs,
                    expected: "list",
                    actual: left.tag(),
                },
                lhs_span,
            ));
        }

        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let right = self.force_demanded_value(rhs, rhs_span, right)?;
        if right.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: rhs,
                    expected: "list",
                    actual: right.tag(),
                },
                rhs_span,
            ));
        }

        self.concat_lists(id, node, left, right)
    }

    pub(super) fn eval_attr_update(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        if left.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: lhs,
                    expected: "attrs",
                    actual: left.tag(),
                },
                lhs_span,
            ));
        }
        let left_entries = {
            let attrs = self.heap.get_attrs(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, lhs_span)
            })?;
            Self::clone_attr_entries(id, lhs_span, attrs)?
        };

        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        if right.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: rhs,
                    expected: "attrs",
                    actual: right.tag(),
                },
                rhs_span,
            ));
        }
        let right_entries = {
            let attrs = self.heap.get_attrs(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, rhs_span)
            })?;
            Self::clone_attr_entries(id, rhs_span, attrs)?
        };

        let capacity = left_entries
            .len()
            .checked_add(right_entries.len())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Attr {
                        id,
                        source: AttrError::TooManyEntries { len: usize::MAX },
                    },
                    node.span,
                )
            })?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(capacity).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed { entries: capacity },
                },
                node.span,
            )
        })?;
        for entry in left_entries {
            if !right_entries.iter().any(|right| right.key == entry.key) {
                entries.push(entry);
            }
        }
        entries.extend(right_entries);

        let attrs = FlatAttrs::new(entries, &self.symbols).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, node.span)
        })?;
        self.heap
            .alloc_attrs(0, attrs)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    pub(super) fn concat_lists(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        let concatenated = {
            let left = self.heap.get_list(left).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            let right = self.heap.get_list(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span)
            })?;
            left.concat(right).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::List { id, source }, node.span)
            })?
        };
        self.heap
            .alloc_list(concatenated)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, node.span))
    }

    pub(super) fn eval_comparison(
        &mut self,
        id: IrId,
        node: &IrNode,
        op: ComparisonOp,
        lhs: IrId,
        rhs: IrId,
    ) -> Result<Value, TreeWalkError> {
        match op {
            ComparisonOp::Lt => self.eval_less_than_comparison(id, node, lhs, rhs, false),
            ComparisonOp::Gt => self.eval_less_than_comparison(id, node, rhs, lhs, false),
            ComparisonOp::Le => self.eval_less_than_comparison(id, node, rhs, lhs, true),
            ComparisonOp::Ge => self.eval_less_than_comparison(id, node, lhs, rhs, true),
        }
    }

    pub(super) fn eval_less_than_comparison(
        &mut self,
        id: IrId,
        node: &IrNode,
        lhs: IrId,
        rhs: IrId,
        invert: bool,
    ) -> Result<Value, TreeWalkError> {
        let lhs_span = self.node(lhs)?.span;
        let left = self.eval_node(lhs)?;
        let rhs_span = self.node(rhs)?.span;
        let right = self.eval_node(rhs)?;
        let value = self.eval_comparison_values(
            id,
            node,
            ComparisonOp::Lt,
            lhs,
            lhs_span,
            left,
            rhs,
            rhs_span,
            right,
        )?;
        if invert {
            Ok(Value::bool(!self.expect_bool(id, value, node.span)?))
        } else {
            Ok(value)
        }
    }
}
