//! XML and raw-value serialization writers (`toXML` and friends).

use super::*;

impl TreeWalk {
    pub(super) fn eval_to_xml_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let mut bytes = Vec::new();
        let mut context = StringContext::empty();
        let mut drvs_seen = Vec::new();
        let value = self.force_value(argument, argument_span, value)?;

        Self::extend_bytes_for_node(
            id,
            span,
            &mut bytes,
            b"<?xml version='1.0' encoding='utf-8'?>\n",
        )?;
        Self::write_xml_open_element(id, span, &mut bytes, 0, b"expr", &[])?;
        self.write_xml_value(
            id,
            span,
            argument,
            argument_span,
            value,
            1,
            &mut bytes,
            &mut context,
            &mut drvs_seen,
        )?;
        Self::write_xml_close_element(id, span, &mut bytes, 0, b"expr")?;

        self.alloc_tree_walk_string(id, span, NixString::new(bytes, context))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_xml_value(
        &mut self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
        depth: usize,
        out: &mut Vec<u8>,
        context: &mut StringContext,
        drvs_seen: &mut Vec<Vec<u8>>,
    ) -> Result<(), TreeWalkError> {
        let value = self.force_value(value_id, value_span, value)?;
        match value.tag() {
            ValueTag::Int => {
                let value = self
                    .heap
                    .decode_int_value(value)
                    .map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::Heap {
                                id: value_id,
                                source,
                            },
                            value_span,
                        )
                    })?
                    .to_string()
                    .into_bytes();
                Self::write_xml_empty_element(
                    id,
                    span,
                    out,
                    depth,
                    b"int",
                    &[(b"value".as_slice(), value.as_slice())],
                )
            }
            ValueTag::Float => {
                let scalar = self.heap.decode_float_value(value).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: value_id,
                            source,
                        },
                        value_span,
                    )
                })?;
                let value = Self::xml_float_bytes(scalar);
                Self::write_xml_empty_element(
                    id,
                    span,
                    out,
                    depth,
                    b"float",
                    &[(b"value".as_slice(), value.as_slice())],
                )
            }
            ValueTag::Bool => {
                let value = if self.expect_bool(value_id, value, value_span)? {
                    b"true".as_slice()
                } else {
                    b"false".as_slice()
                };
                Self::write_xml_empty_element(
                    id,
                    span,
                    out,
                    depth,
                    b"bool",
                    &[(b"value".as_slice(), value)],
                )
            }
            ValueTag::String => self
                .write_xml_string_value(id, span, value_id, value_span, value, depth, out, context),
            ValueTag::Path => {
                self.write_xml_path_value(id, span, value_id, value_span, value, depth, out)
            }
            ValueTag::Null => Self::write_xml_empty_element(id, span, out, depth, b"null", &[]),
            ValueTag::Attrs => self.write_xml_attrs(
                id, span, value_id, value_span, value, depth, out, context, drvs_seen,
            ),
            ValueTag::List => self.write_xml_list(
                id, span, value_id, value_span, value, depth, out, context, drvs_seen,
            ),
            ValueTag::Lambda => {
                self.write_xml_lambda(id, span, value_id, value_span, value, depth, out)
            }
            ValueTag::Primop | ValueTag::Thunk | ValueTag::External => {
                Self::write_xml_empty_element(id, span, out, depth, b"unevaluated", &[])
            }
        }
    }

    pub(super) fn write_xml_string_value(
        &self,
        id: IrId,
        span: Span,
        string_id: IrId,
        string_span: Span,
        value: Value,
        depth: usize,
        out: &mut Vec<u8>,
        context: &mut StringContext,
    ) -> Result<(), TreeWalkError> {
        let string = self.heap.get_string_view(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: string_id,
                    source,
                },
                string_span,
            )
        })?;
        Self::write_xml_empty_element(
            id,
            span,
            out,
            depth,
            b"string",
            &[(b"value".as_slice(), string.bytes())],
        )?;
        *context = context
            .union(&string.context().try_to_owned().map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
            })?)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        Ok(())
    }

    pub(super) fn write_xml_path_value(
        &self,
        id: IrId,
        span: Span,
        path_id: IrId,
        path_span: Span,
        value: Value,
        depth: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        let path = self.heap.get_path_view(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: path_id,
                    source,
                },
                path_span,
            )
        })?;
        Self::write_xml_empty_element(
            id,
            span,
            out,
            depth,
            b"path",
            &[(b"value".as_slice(), path.bytes())],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_xml_list(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        value: Value,
        depth: usize,
        out: &mut Vec<u8>,
        context: &mut StringContext,
        drvs_seen: &mut Vec<Vec<u8>>,
    ) -> Result<(), TreeWalkError> {
        let elements = {
            let list = self.heap.get_list_view(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            Self::clone_list_elements(list_id, list_span, list)?
        };

        Self::write_xml_open_element(id, span, out, depth, b"list", &[])?;
        for element in elements {
            self.write_xml_value(
                id,
                span,
                list_id,
                list_span,
                element,
                depth + 1,
                out,
                context,
                drvs_seen,
            )?;
        }
        Self::write_xml_close_element(id, span, out, depth, b"list")
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_xml_attrs(
        &mut self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        attrs_span: Span,
        value: Value,
        depth: usize,
        out: &mut Vec<u8>,
        context: &mut StringContext,
        drvs_seen: &mut Vec<Vec<u8>>,
    ) -> Result<(), TreeWalkError> {
        if self.xml_attrs_is_derivation(attrs_id, attrs_span, value)? {
            return self.write_xml_derivation(
                id, span, attrs_id, attrs_span, value, depth, out, context, drvs_seen,
            );
        }

        Self::write_xml_open_element(id, span, out, depth, b"attrs", &[])?;
        self.write_xml_attr_entries(
            id,
            span,
            attrs_id,
            attrs_span,
            value,
            depth + 1,
            out,
            context,
            drvs_seen,
        )?;
        Self::write_xml_close_element(id, span, out, depth, b"attrs")
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_xml_derivation(
        &mut self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        attrs_span: Span,
        value: Value,
        depth: usize,
        out: &mut Vec<u8>,
        context: &mut StringContext,
        drvs_seen: &mut Vec<Vec<u8>>,
    ) -> Result<(), TreeWalkError> {
        let drv_path =
            self.xml_forced_string_attr_bytes(attrs_id, attrs_span, value, DRV_PATH_ATTR)?;
        let out_path =
            self.xml_forced_string_attr_bytes(attrs_id, attrs_span, value, OUT_PATH_ATTR)?;

        let mut attrs = Vec::new();
        attrs
            .try_reserve_exact(usize::from(drv_path.is_some()) + usize::from(out_path.is_some()))
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Attr {
                        id,
                        source: AttrError::AllocationFailed { entries: 2 },
                    },
                    span,
                )
            })?;
        if let Some(bytes) = drv_path.as_deref() {
            attrs.push((b"drvPath".as_slice(), bytes));
        }
        if let Some(bytes) = out_path.as_deref() {
            attrs.push((b"outPath".as_slice(), bytes));
        }

        Self::write_xml_open_element(id, span, out, depth, b"derivation", &attrs)?;
        if let Some(drv_path) = drv_path.as_ref() {
            if !drv_path.is_empty() && !drvs_seen.iter().any(|seen| seen == drv_path) {
                drvs_seen.push(drv_path.clone());
                self.write_xml_attr_entries(
                    id,
                    span,
                    attrs_id,
                    attrs_span,
                    value,
                    depth + 1,
                    out,
                    context,
                    drvs_seen,
                )?;
            } else {
                Self::write_xml_empty_element(id, span, out, depth + 1, b"repeated", &[])?;
            }
        } else {
            Self::write_xml_empty_element(id, span, out, depth + 1, b"repeated", &[])?;
        }
        Self::write_xml_close_element(id, span, out, depth, b"derivation")
    }

    pub(super) fn xml_attrs_is_derivation(
        &mut self,
        attrs_id: IrId,
        attrs_span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        let Some(type_value) = self.attr_value_by_name(attrs_id, value, TYPE_ATTR, attrs_span)?
        else {
            return Ok(false);
        };
        let type_value = self.force_value(attrs_id, attrs_span, type_value)?;
        if type_value.tag() != ValueTag::String {
            return Ok(false);
        }
        let string = self.heap.get_string_view(type_value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: attrs_id,
                    source,
                },
                attrs_span,
            )
        })?;
        Ok(string.bytes() == b"derivation")
    }

    pub(super) fn xml_forced_string_attr_bytes(
        &mut self,
        attrs_id: IrId,
        attrs_span: Span,
        value: Value,
        name: &[u8],
    ) -> Result<Option<Vec<u8>>, TreeWalkError> {
        let Some(attr) = self.attr_value_by_name(attrs_id, value, name, attrs_span)? else {
            return Ok(None);
        };
        let attr = self.force_value(attrs_id, attrs_span, attr)?;
        if attr.tag() != ValueTag::String {
            return Ok(None);
        }
        let string = self.heap.get_string_view(attr).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: attrs_id,
                    source,
                },
                attrs_span,
            )
        })?;
        Ok(Some(Self::copy_bytes_for_node(
            attrs_id,
            attrs_span,
            string.bytes(),
        )?))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_xml_attr_entries(
        &mut self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        attrs_span: Span,
        value: Value,
        depth: usize,
        out: &mut Vec<u8>,
        context: &mut StringContext,
        drvs_seen: &mut Vec<Vec<u8>>,
    ) -> Result<(), TreeWalkError> {
        let entries = {
            let attrs = self.heap.get_attrs_view(value).map_err(|source| {
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

        for (key, value) in entries {
            Self::write_xml_open_element(
                id,
                span,
                out,
                depth,
                b"attr",
                &[(b"name".as_slice(), key.as_slice())],
            )?;
            let value = self.force_value(attrs_id, attrs_span, value)?;
            self.write_xml_value(
                id,
                span,
                attrs_id,
                attrs_span,
                value,
                depth + 1,
                out,
                context,
                drvs_seen,
            )?;
            Self::write_xml_close_element(id, span, out, depth, b"attr")?;
        }
        Ok(())
    }

    pub(super) fn write_xml_lambda(
        &self,
        id: IrId,
        span: Span,
        lambda_id: IrId,
        lambda_span: Span,
        value: Value,
        depth: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        let lambda = self.heap.clone_lambda(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: lambda_id,
                    source,
                },
                lambda_span,
            )
        })?;
        Self::write_xml_open_element(id, span, out, depth, b"function", &[])?;
        self.write_xml_lambda_pattern(id, span, lambda.module(), lambda.pattern(), depth + 1, out)?;
        Self::write_xml_close_element(id, span, out, depth, b"function")
    }

    pub(super) fn write_xml_lambda_pattern(
        &self,
        id: IrId,
        span: Span,
        module: EvalModuleId,
        pattern: IrId,
        depth: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        let pattern_node = *self.node_in_module(module, pattern)?;
        match pattern_node.kind {
            IrKind::Formal => {
                let IrData::Formal { name, .. } = pattern_node.data else {
                    return Err(self.invalid_payload(pattern, &pattern_node, "formal payload"));
                };
                let name = self.symbols.resolve(name).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidSymbol {
                            id: pattern,
                            symbol: name,
                        },
                        pattern_node.span,
                    )
                })?;
                Self::write_xml_empty_element(
                    id,
                    span,
                    out,
                    depth,
                    b"varpat",
                    &[(b"name".as_slice(), name)],
                )
            }
            IrKind::FormalSet => {
                let IrData::FormalSet {
                    formals,
                    ellipsis,
                    alias,
                } = pattern_node.data
                else {
                    return Err(self.invalid_payload(pattern, &pattern_node, "formal-set payload"));
                };
                let mut attrs = Vec::new();
                attrs
                    .try_reserve_exact(usize::from(ellipsis) + usize::from(alias.is_some()))
                    .map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::Attr {
                                id,
                                source: AttrError::AllocationFailed { entries: 2 },
                            },
                            span,
                        )
                    })?;
                if ellipsis {
                    attrs.push((b"ellipsis".as_slice(), b"1".as_slice()));
                }
                let alias_name = alias
                    .map(|symbol| {
                        self.symbols.resolve(symbol).ok_or_else(|| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::InvalidSymbol {
                                    id: pattern,
                                    symbol,
                                },
                                pattern_node.span,
                            )
                        })
                    })
                    .transpose()?;
                if let Some(name) = alias_name {
                    attrs.push((b"name".as_slice(), name));
                }

                let mut formal_names =
                    self.xml_formal_names(id, span, module, pattern, pattern_node.span, formals)?;
                formal_names.sort_by(|left, right| left.as_slice().cmp(right.as_slice()));

                Self::write_xml_open_element(id, span, out, depth, b"attrspat", &attrs)?;
                for name in formal_names {
                    Self::write_xml_empty_element(
                        id,
                        span,
                        out,
                        depth + 1,
                        b"attr",
                        &[(b"name".as_slice(), name.as_slice())],
                    )?;
                }
                Self::write_xml_close_element(id, span, out, depth, b"attrspat")
            }
            kind => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedLambdaPattern { id, pattern, kind },
                pattern_node.span,
            )),
        }
    }

    pub(super) fn xml_formal_names(
        &self,
        id: IrId,
        span: Span,
        module: EvalModuleId,
        pattern: IrId,
        pattern_span: Span,
        formals: IrChildSlice,
    ) -> Result<Vec<Vec<u8>>, TreeWalkError> {
        let formal_slice = self
            .module_ir(module)?
            .arena
            .child_slice(formals)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidChildSlice {
                        id: pattern,
                        slice: formals,
                    },
                    pattern_span,
                )
            })?;
        let mut names = Vec::new();
        names.try_reserve_exact(formal_slice.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: formal_slice.len(),
                },
                span,
            )
        })?;
        for formal in formal_slice {
            let formal_node = *self.node_in_module(module, *formal)?;
            let IrData::Formal { name, .. } = formal_node.data else {
                return Err(self.invalid_payload(*formal, &formal_node, "formal payload"));
            };
            let name_bytes = self.symbols.resolve(name).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidSymbol {
                        id: *formal,
                        symbol: name,
                    },
                    formal_node.span,
                )
            })?;
            names.push(Self::copy_bytes_for_node(id, span, name_bytes)?);
        }
        Ok(names)
    }

    pub(super) fn write_xml_open_element(
        id: IrId,
        span: Span,
        out: &mut Vec<u8>,
        depth: usize,
        name: &[u8],
        attrs: &[(&[u8], &[u8])],
    ) -> Result<(), TreeWalkError> {
        Self::write_xml_indent(id, span, out, depth)?;
        Self::extend_bytes_for_node(id, span, out, b"<")?;
        Self::extend_bytes_for_node(id, span, out, name)?;
        Self::write_xml_attrs_bytes(id, span, out, attrs)?;
        Self::extend_bytes_for_node(id, span, out, b">\n")
    }

    pub(super) fn write_xml_close_element(
        id: IrId,
        span: Span,
        out: &mut Vec<u8>,
        depth: usize,
        name: &[u8],
    ) -> Result<(), TreeWalkError> {
        Self::write_xml_indent(id, span, out, depth)?;
        Self::extend_bytes_for_node(id, span, out, b"</")?;
        Self::extend_bytes_for_node(id, span, out, name)?;
        Self::extend_bytes_for_node(id, span, out, b">\n")
    }

    pub(super) fn write_xml_empty_element(
        id: IrId,
        span: Span,
        out: &mut Vec<u8>,
        depth: usize,
        name: &[u8],
        attrs: &[(&[u8], &[u8])],
    ) -> Result<(), TreeWalkError> {
        Self::write_xml_indent(id, span, out, depth)?;
        Self::extend_bytes_for_node(id, span, out, b"<")?;
        Self::extend_bytes_for_node(id, span, out, name)?;
        Self::write_xml_attrs_bytes(id, span, out, attrs)?;
        Self::extend_bytes_for_node(id, span, out, b" />\n")
    }

    pub(super) fn write_xml_indent(
        id: IrId,
        span: Span,
        out: &mut Vec<u8>,
        depth: usize,
    ) -> Result<(), TreeWalkError> {
        for _ in 0..depth {
            Self::extend_bytes_for_node(id, span, out, b"  ")?;
        }
        Ok(())
    }

    pub(super) fn write_xml_attrs_bytes(
        id: IrId,
        span: Span,
        out: &mut Vec<u8>,
        attrs: &[(&[u8], &[u8])],
    ) -> Result<(), TreeWalkError> {
        for (name, value) in attrs {
            Self::extend_bytes_for_node(id, span, out, b" ")?;
            Self::extend_bytes_for_node(id, span, out, name)?;
            Self::extend_bytes_for_node(id, span, out, b"=\"")?;
            Self::write_xml_attr_value(id, span, out, value)?;
            Self::extend_bytes_for_node(id, span, out, b"\"")?;
        }
        Ok(())
    }

    pub(super) fn write_xml_attr_value(
        id: IrId,
        span: Span,
        out: &mut Vec<u8>,
        value: &[u8],
    ) -> Result<(), TreeWalkError> {
        for byte in value {
            match *byte {
                b'"' => Self::extend_bytes_for_node(id, span, out, b"&quot;")?,
                b'<' => Self::extend_bytes_for_node(id, span, out, b"&lt;")?,
                b'>' => Self::extend_bytes_for_node(id, span, out, b"&gt;")?,
                b'&' => Self::extend_bytes_for_node(id, span, out, b"&amp;")?,
                b'\n' => Self::extend_bytes_for_node(id, span, out, b"&#xA;")?,
                byte => Self::extend_bytes_for_node(id, span, out, &[byte])?,
            }
        }
        Ok(())
    }

    pub(super) fn raw_number_bytes(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Vec<u8>, TreeWalkError> {
        match value.tag() {
            ValueTag::Int => Ok(Self::raw_int_bytes(
                self.heap.decode_int_value(value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?,
            )),
            ValueTag::Float => Ok(Self::raw_float_bytes(
                self.heap.decode_float_value(value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?,
            )),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "number",
                    actual,
                },
                span,
            )),
        }
    }

    pub(super) fn raw_int_bytes(value: i64) -> Vec<u8> {
        value.to_string().into_bytes()
    }

    pub(super) fn raw_float_bytes(value: f64) -> Vec<u8> {
        Self::xml_float_bytes(value)
    }

    pub(super) fn xml_float_bytes(value: f64) -> Vec<u8> {
        if value.is_nan() {
            return b"nan".to_vec();
        }
        if value == f64::INFINITY {
            return b"inf".to_vec();
        }
        if value == f64::NEG_INFINITY {
            return b"-inf".to_vec();
        }
        let value = if value == 0.0 { 0.0 } else { value };
        let scientific = format!("{value:.5e}");
        let Some((mantissa, exponent)) = scientific.split_once('e') else {
            return scientific.into_bytes();
        };
        let Ok(exponent) = exponent.parse::<i32>() else {
            return scientific.into_bytes();
        };
        if !(-4..6).contains(&exponent) {
            return Self::xml_scientific_float_bytes(mantissa, exponent);
        }
        Self::xml_fixed_float_bytes(mantissa, exponent)
    }

    pub(super) fn xml_scientific_float_bytes(mantissa: &str, exponent: i32) -> Vec<u8> {
        let mut out = mantissa.as_bytes().to_vec();
        if let Some(point) = out.iter().position(|byte| *byte == b'.') {
            while matches!(out.last(), Some(b'0')) {
                let _ = out.pop();
            }
            if out.len() == point + 1 {
                let _ = out.pop();
            }
        }
        let sign = if exponent < 0 { b'-' } else { b'+' };
        let magnitude = exponent.unsigned_abs();
        out.push(b'e');
        out.push(sign);
        if magnitude < 10 {
            out.push(b'0');
        }
        out.extend_from_slice(magnitude.to_string().as_bytes());
        out
    }

    pub(super) fn xml_fixed_float_bytes(mantissa: &str, exponent: i32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut digits = Vec::new();
        let mut body = mantissa.as_bytes();
        if body.first() == Some(&b'-') {
            out.push(b'-');
            body = &body[1..];
        }
        digits.extend(body.iter().copied().filter(|byte| *byte != b'.'));

        let decimal_at = exponent.saturating_add(1);
        if decimal_at <= 0 {
            out.extend_from_slice(b"0.");
            out.resize(out.len() + decimal_at.unsigned_abs() as usize, b'0');
            out.extend_from_slice(&digits);
        } else {
            let decimal_at = usize::try_from(decimal_at).unwrap_or(usize::MAX);
            if decimal_at >= digits.len() {
                out.extend_from_slice(&digits);
                out.resize(out.len() + decimal_at.saturating_sub(digits.len()), b'0');
            } else {
                out.extend_from_slice(&digits[..decimal_at]);
                out.push(b'.');
                out.extend_from_slice(&digits[decimal_at..]);
            }
        }

        if let Some(point) = out.iter().position(|byte| *byte == b'.') {
            while matches!(out.last(), Some(b'0')) {
                let _ = out.pop();
            }
            if out.len() == point + 1 {
                let _ = out.pop();
            }
        }
        out
    }
}
