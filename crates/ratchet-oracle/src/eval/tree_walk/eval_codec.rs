//! Base16/base32/base64 and other byte-codec builtin evaluation.

use super::*;

impl TreeWalk {
    pub(super) fn check_hash_digest_len(
        &self,
        id: IrId,
        span: Span,
        hash: &[u8],
        algorithm: HashStringAlgorithm,
        digest: Vec<u8>,
    ) -> Result<NixHashDigest, TreeWalkError> {
        NixHashDigest::new(algorithm, digest).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::HashWrongLength {
                    id,
                    hash: hash.to_vec(),
                    algorithm: algorithm.name().to_vec(),
                },
                span,
            )
        })
    }

    pub(super) fn decode_base16_hash(
        id: IrId,
        span: Span,
        hash: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        let mut out = Vec::new();
        out.try_reserve_exact(payload.len() / 2).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: payload.len() / 2,
                },
                span,
            )
        })?;
        for pair in payload.chunks_exact(2) {
            let high = Self::hex_digit(pair[0]).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidBase16Hash {
                        id,
                        hash: hash.to_vec(),
                    },
                    span,
                )
            })?;
            let low = Self::hex_digit(pair[1]).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidBase16Hash {
                        id,
                        hash: hash.to_vec(),
                    },
                    span,
                )
            })?;
            out.push((high << 4) | low);
        }
        Ok(out)
    }

    pub(super) fn hex_digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    pub(super) fn decode_nix_base32_hash(
        id: IrId,
        span: Span,
        hash: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        Self::decode_nix_base32(id, span, payload)?.ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidNix32Hash {
                    id,
                    hash: hash.to_vec(),
                },
                span,
            )
        })
    }

    pub(super) fn decode_nix_base32(
        id: IrId,
        span: Span,
        encoded: &[u8],
    ) -> Result<Option<Vec<u8>>, TreeWalkError> {
        let len = encoded
            .len()
            .checked_mul(5)
            .map(|bits| bits / 8)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: usize::MAX,
                    },
                    span,
                )
            })?;
        let mut out = Vec::new();
        out.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
        })?;
        out.resize(len, 0);
        for (n, byte) in encoded.iter().rev().enumerate() {
            let Some(digit) = NIX_BASE32.iter().position(|digit| digit == byte) else {
                return Ok(None);
            };
            let digit = digit as u16;
            let bit = n * 5;
            let i = bit / 8;
            let j = bit % 8;
            let Some(current) = out.get_mut(i) else {
                return Ok(None);
            };
            *current |= (digit << j) as u8;
            let carry = digit >> (8 - j);
            match out.get_mut(i + 1) {
                Some(next) => *next |= carry as u8,
                None if carry != 0 => return Ok(None),
                None => {}
            }
        }
        Ok(Some(out))
    }

    pub(super) fn encode_convert_hash_digest(
        id: IrId,
        span: Span,
        format: ConvertHashFormat,
        digest: &NixHashDigest,
    ) -> Result<Vec<u8>, TreeWalkError> {
        match format {
            ConvertHashFormat::Base16 => Self::lower_hex_bytes(id, span, digest.bytes()),
            ConvertHashFormat::Nix32 => Self::encode_nix_base32(id, span, digest.bytes()),
            ConvertHashFormat::Base64 => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(digest.bytes());
                Self::copy_bytes_for_node(id, span, encoded.as_bytes())
            }
            ConvertHashFormat::Sri => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(digest.bytes());
                let len = digest
                    .algorithm()
                    .name()
                    .len()
                    .checked_add(1)
                    .and_then(|len| len.checked_add(encoded.len()))
                    .ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ByteAllocationFailed {
                                id,
                                len: usize::MAX,
                            },
                            span,
                        )
                    })?;
                let mut out = Vec::new();
                out.try_reserve_exact(len).map_err(|_| {
                    TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
                })?;
                out.extend_from_slice(digest.algorithm().name());
                out.push(b'-');
                out.extend_from_slice(encoded.as_bytes());
                Ok(out)
            }
        }
    }

    pub(super) fn encode_nix_base32(
        id: IrId,
        span: Span,
        bytes: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let len = Self::nix_base32_encoded_len(bytes.len());
        let mut out = Vec::new();
        out.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
        })?;
        for n in (0..len).rev() {
            let bit = n * 5;
            let i = bit / 8;
            let j = bit % 8;
            let mut c = (bytes[i] >> j) as u16;
            if i + 1 < bytes.len() {
                c |= (bytes[i + 1] as u16) << (8 - j);
            }
            out.push(NIX_BASE32[usize::from(c & 0x1f)]);
        }
        Ok(out)
    }

    pub(super) fn nix_base32_encoded_len(byte_len: usize) -> usize {
        byte_len.saturating_mul(8).div_ceil(5)
    }

    pub(super) fn base64_encoded_len(byte_len: usize) -> usize {
        byte_len.div_ceil(3).saturating_mul(4)
    }

    pub(super) fn base64_unpadded_encoded_len(byte_len: usize) -> usize {
        let len = (byte_len / 3).saturating_mul(4);
        match byte_len % 3 {
            0 => len,
            1 => len.saturating_add(2),
            2 => len.saturating_add(3),
            _ => len,
        }
    }

    #[cfg(test)]
    pub(super) fn eval_hash_string_primop_with_string_value(
        &mut self,
        id: IrId,
        span: Span,
        algorithm_id: IrId,
        string_id: IrId,
        string_span: Span,
        string: Value,
    ) -> Result<Value, TreeWalkError> {
        let algorithm_span = self.node(algorithm_id)?.span;
        let algorithm = self.eval_node(algorithm_id)?;
        let algorithm =
            self.eval_hash_algorithm(algorithm_id, algorithm_span, algorithm, "hashString")?;
        self.eval_hash_string_value(id, span, string_id, string_span, string, algorithm)
    }

    pub(super) fn lower_hex_bytes(
        id: IrId,
        span: Span,
        digest: &[u8],
    ) -> Result<Vec<u8>, TreeWalkError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let len = digest.len().checked_mul(2).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ByteAllocationFailed { id, len }, span)
        })?;
        for byte in digest {
            bytes.push(HEX[usize::from(byte >> 4)]);
            bytes.push(HEX[usize::from(byte & 0x0f)]);
        }
        Ok(bytes)
    }

    #[cfg(test)]
    pub(super) fn eval_compare_versions_values(
        &self,
        left_id: IrId,
        left_span: Span,
        left: Value,
        right_id: IrId,
        right_span: Span,
        right: Value,
    ) -> Result<Value, TreeWalkError> {
        let left = self.context_free_string_bytes(left_id, left_span, left, "compareVersions")?;
        let right =
            self.context_free_string_bytes(right_id, right_span, right, "compareVersions")?;
        Ok(Value::int(compare_version_bytes(&left, &right)))
    }

    pub(super) fn eval_from_json_primop(
        &mut self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let bytes = self.context_free_string_bytes(argument, argument_span, value, "fromJSON")?;
        let json: JsonValue = serde_json::from_slice(&bytes).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::JsonParse {
                    id: argument,
                    message: source.to_string(),
                },
                argument_span,
            )
        })?;
        self.value_from_json(argument, argument_span, json)
    }

    pub(super) fn eval_from_toml_primop(
        &mut self,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let bytes = self.context_free_string_bytes(argument, argument_span, value, "fromTOML")?;
        let source = std::str::from_utf8(&bytes).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::TomlParse {
                    id: argument,
                    message: source.to_string(),
                },
                argument_span,
            )
        })?;
        let normalized = normalize_toml_numeric_overflows(source);
        let toml: TomlValue = normalized
            .as_str()
            .parse()
            .map_err(|source: toml::de::Error| {
                TreeWalkError::new(
                    TreeWalkErrorKind::TomlParse {
                        id: argument,
                        message: source.to_string(),
                    },
                    argument_span,
                )
            })?;
        self.value_from_toml(argument, argument_span, toml)
    }

    pub(super) fn value_from_json(
        &mut self,
        id: IrId,
        span: Span,
        value: JsonValue,
    ) -> Result<Value, TreeWalkError> {
        match value {
            JsonValue::Null => Ok(Value::null()),
            JsonValue::Bool(value) => Ok(Value::bool(value)),
            JsonValue::Number(value) => {
                if let Some(value) = value.as_i64() {
                    self.runtime_int_value(id, span, value)
                } else if let Some(value) = value.as_u64() {
                    self.runtime_int_value(id, span, value as i64)
                } else if let Some(value) = value.as_f64() {
                    self.runtime_float_value(id, span, value)
                } else {
                    Err(TreeWalkError::new(
                        TreeWalkErrorKind::JsonNumberUnsupported { id },
                        span,
                    ))
                }
            }
            JsonValue::String(value) => self.alloc_static_string(id, span, value.as_bytes()),
            JsonValue::Array(values) => {
                let mut elements = Vec::new();
                elements.try_reserve_exact(values.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ListAllocationFailed {
                            id,
                            len: values.len(),
                        },
                        span,
                    )
                })?;
                for value in values {
                    elements.push(self.value_from_json(id, span, value)?);
                }
                self.alloc_tree_walk_list(id, span, NixList::new(elements))
            }
            JsonValue::Object(values) => {
                let mut entries = Vec::new();
                entries.try_reserve_exact(values.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Attr {
                            id,
                            source: AttrError::AllocationFailed {
                                entries: values.len(),
                            },
                        },
                        span,
                    )
                })?;
                for (key, value) in values {
                    let symbol = self
                        .intern_symbol_for_eval(key.as_bytes())
                        .map_err(|source| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::SymbolIntern {
                                    id,
                                    source: source.kind().clone(),
                                },
                                span,
                            )
                        })?;
                    let value = self.value_from_json(id, span, value)?;
                    entries.push(AttrEntry::new(symbol, value));
                }
                let attrs = FlatAttrs::new(entries, &self.symbols).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span)
                })?;
                self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
            }
        }
    }

    pub(super) fn value_from_toml(
        &mut self,
        id: IrId,
        span: Span,
        value: TomlValue,
    ) -> Result<Value, TreeWalkError> {
        match value {
            TomlValue::String(value) => self.alloc_static_string(id, span, value.as_bytes()),
            TomlValue::Integer(value) => self.runtime_int_value(id, span, value),
            TomlValue::Float(value) => self.runtime_float_value(id, span, value),
            TomlValue::Boolean(value) => Ok(Value::bool(value)),
            TomlValue::Datetime(value) => {
                if self.options.parse_toml_timestamps() {
                    self.alloc_toml_timestamp_value(id, span, value)
                } else {
                    Err(TreeWalkError::new(
                        TreeWalkErrorKind::TomlUnsupportedValue {
                            id,
                            kind: "datetime",
                        },
                        span,
                    ))
                }
            }
            TomlValue::Array(values) => {
                let mut elements = Vec::new();
                elements.try_reserve_exact(values.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ListAllocationFailed {
                            id,
                            len: values.len(),
                        },
                        span,
                    )
                })?;
                for value in values {
                    elements.push(self.value_from_toml(id, span, value)?);
                }
                self.alloc_tree_walk_list(id, span, NixList::new(elements))
            }
            TomlValue::Table(values) => {
                let mut entries = Vec::new();
                entries.try_reserve_exact(values.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Attr {
                            id,
                            source: AttrError::AllocationFailed {
                                entries: values.len(),
                            },
                        },
                        span,
                    )
                })?;
                for (key, value) in values {
                    let symbol = self
                        .intern_symbol_for_eval(key.as_bytes())
                        .map_err(|source| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::SymbolIntern {
                                    id,
                                    source: source.kind().clone(),
                                },
                                span,
                            )
                        })?;
                    let value = self.value_from_toml(id, span, value)?;
                    entries.push(AttrEntry::new(symbol, value));
                }
                let attrs = FlatAttrs::new(entries, &self.symbols).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span)
                })?;
                self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
            }
        }
    }

    fn alloc_toml_timestamp_value(
        &mut self,
        id: IrId,
        span: Span,
        timestamp: TomlDatetime,
    ) -> Result<Value, TreeWalkError> {
        let type_symbol = self
            .symbols
            .intern(TOML_TIMESTAMP_TYPE_ATTR)
            .map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SymbolIntern {
                        id,
                        source: source.kind().clone(),
                    },
                    span,
                )
            })?;
        let value_symbol = self.intern_symbol_for_eval(VALUE_ATTR).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::SymbolIntern {
                    id,
                    source: source.kind().clone(),
                },
                span,
            )
        })?;
        let timestamp_type = self.alloc_static_string(id, span, TOML_TIMESTAMP_TYPE_VALUE)?;
        let timestamp_value = timestamp.to_string();
        let timestamp_value = self.alloc_static_string(id, span, timestamp_value.as_bytes())?;
        let attrs = FlatAttrs::new(
            vec![
                AttrEntry::new(type_symbol, timestamp_type),
                AttrEntry::new(value_symbol, timestamp_value),
            ],
            &self.symbols,
        )
        .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn eval_to_string_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string = self.coerce_to_string_value(id, span, argument, argument_span, value)?;
        self.alloc_tree_walk_string(id, span, string)
    }

    pub(super) fn coerce_to_string_value(
        &mut self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        if value.tag() == ValueTag::List {
            return self.list_to_string_value(id, span, value_id, value_span, value);
        }
        self.scalar_to_string_value(id, span, value_id, value_span, value)
    }

    pub(super) fn derivation_to_string_value(
        &mut self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        if value.tag() == ValueTag::List {
            return self.derivation_list_to_string_value(id, span, value_id, value_span, value);
        }
        self.derivation_scalar_to_string_value(id, span, value_id, value_span, value)
    }

    pub(super) fn list_to_string_value(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        let mut bytes = Vec::new();
        let mut context = StringContext::empty();
        let mut fields = 0usize;
        self.append_list_to_string_fields(
            id,
            span,
            list_id,
            list_span,
            value,
            &mut bytes,
            &mut context,
            &mut fields,
        )?;
        Ok(NixString::new(bytes, context))
    }

    pub(super) fn derivation_list_to_string_value(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        let mut bytes = Vec::new();
        let mut context = StringContext::empty();
        let mut fields = 0usize;
        self.append_derivation_list_to_string_fields(
            id,
            span,
            list_id,
            list_span,
            value,
            &mut bytes,
            &mut context,
            &mut fields,
        )?;
        Ok(NixString::new(bytes, context))
    }

    pub(super) fn append_list_to_string_fields(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        value: Value,
        bytes: &mut Vec<u8>,
        context: &mut StringContext,
        fields: &mut usize,
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

        for element in elements {
            self.append_to_string_list(
                id, span, list_id, list_span, element, bytes, context, fields,
            )?;
        }
        Ok(())
    }

    pub(super) fn append_derivation_list_to_string_fields(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        value: Value,
        bytes: &mut Vec<u8>,
        context: &mut StringContext,
        fields: &mut usize,
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
            Self::clone_list_elements(list_id, list_span, list)?
        };

        for element in elements {
            self.append_derivation_to_string_list(
                id, span, list_id, list_span, element, bytes, context, fields,
            )?;
        }
        Ok(())
    }

    pub(super) fn append_to_string_list(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        value: Value,
        bytes: &mut Vec<u8>,
        context: &mut StringContext,
        fields: &mut usize,
    ) -> Result<(), TreeWalkError> {
        let value = self.force_value(list_id, list_span, value)?;
        if value.tag() == ValueTag::List {
            return self.append_list_to_string_fields(
                id, span, list_id, list_span, value, bytes, context, fields,
            );
        }

        let rendered = self.scalar_to_string_value(id, span, list_id, list_span, value)?;
        Self::append_to_string_field(id, span, bytes, context, fields, rendered)
    }

    pub(super) fn append_derivation_to_string_list(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        value: Value,
        bytes: &mut Vec<u8>,
        context: &mut StringContext,
        fields: &mut usize,
    ) -> Result<(), TreeWalkError> {
        let value = self.force_value(list_id, list_span, value)?;
        if value.tag() == ValueTag::List {
            return self.append_derivation_list_to_string_fields(
                id, span, list_id, list_span, value, bytes, context, fields,
            );
        }

        let rendered =
            self.derivation_scalar_to_string_value(id, span, list_id, list_span, value)?;
        Self::append_to_string_field(id, span, bytes, context, fields, rendered)
    }

    pub(super) fn append_to_string_field(
        id: IrId,
        span: Span,
        bytes: &mut Vec<u8>,
        context: &mut StringContext,
        fields: &mut usize,
        field: NixString,
    ) -> Result<(), TreeWalkError> {
        if *fields > 0 {
            Self::extend_bytes_for_node(id, span, bytes, b" ")?;
        }
        *fields = fields.checked_add(1).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListLengthOverflow {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })?;
        Self::extend_bytes_for_node(id, span, bytes, field.bytes())?;
        *context = context
            .union(field.context())
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        Ok(())
    }

    pub(super) fn scalar_to_string_value(
        &mut self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
    ) -> Result<NixString, TreeWalkError> {
        match value.tag() {
            ValueTag::String => self.clone_string_value(value_id, value_span, value),
            ValueTag::Path => self.clone_path_value(value_id, value_span, value),
            ValueTag::Int => Ok(NixString::from_bytes(
                self.heap
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
                    .into_bytes(),
            )),
            ValueTag::Float => Ok(NixString::from_bytes(Self::to_string_float_bytes(
                self.heap.decode_float_value(value).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: value_id,
                            source,
                        },
                        value_span,
                    )
                })?,
            ))),
            ValueTag::Bool => {
                if self.expect_bool(value_id, value, value_span)? {
                    Ok(NixString::from_bytes(b"1".to_vec()))
                } else {
                    Ok(NixString::default())
                }
            }
            ValueTag::Null => Ok(NixString::default()),
            ValueTag::Attrs => self.attrs_to_string_value(id, span, value_id, value_span, value),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: value_id,
                    expected: "string",
                    actual,
                },
                value_span,
            )),
        }
    }
}
