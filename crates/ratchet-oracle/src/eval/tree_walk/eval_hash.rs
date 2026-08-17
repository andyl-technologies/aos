//! Hash builtins: `hashString`/`hashFile`, conversion, and concatenation.

use super::*;

type SplitConvertHashTypedInput<'a> = (HashStringAlgorithm, ConvertHashInputFormat, &'a [u8]);

impl TreeWalk {
    pub(super) fn force_replace_string(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<ReplaceStringReplacement, TreeWalkError> {
        let value = self.force_value(id, span, value)?;
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "string",
                    actual: value.tag(),
                },
                span,
            ));
        }
        let string = self
            .heap
            .get_string_view(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let bytes = Self::copy_bytes_for_node(id, span, string.bytes())?;
        let context = string
            .context()
            .try_to_owned()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span))?;
        Ok(ReplaceStringReplacement { bytes, context })
    }

    pub(super) fn eval_concat_strings_sep_primop(
        &mut self,
        id: IrId,
        span: Span,
        separator_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let separator_span = self.node(separator_id)?.span;
        let separator_value = self.eval_node(separator_id)?;
        // C++ Nix forces both arguments to WHNF (`forceString` /
        // `forceList`) before type-checking; a thunked argument must be
        // evaluated here rather than reported as a type error.
        let separator_value = self.force_value(separator_id, separator_span, separator_value)?;
        if separator_value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: separator_id,
                    expected: "string",
                    actual: separator_value.tag(),
                },
                separator_span,
            ));
        }
        let (separator_bytes, separator_context) = {
            let separator = self
                .heap
                .get_string_view(separator_value)
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: separator_id,
                            source,
                        },
                        separator_span,
                    )
                })?;
            let bytes = Self::copy_bytes_for_node(separator_id, separator_span, separator.bytes())?;
            let context = separator.context().try_to_owned().map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::String {
                        id: separator_id,
                        source,
                    },
                    separator_span,
                )
            })?;
            (bytes, context)
        };

        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list_view(list_value).map_err(|source| {
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
            elements.extend(list.iter());
            elements
        };

        let result = self.concat_strings_sep_values(
            id,
            span,
            list_id,
            list_span,
            &separator_bytes,
            separator_context,
            &elements,
        )?;
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(super) fn concat_strings_sep_values(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        separator: &[u8],
        mut context: StringContext,
        elements: &[Value],
    ) -> Result<NixString, TreeWalkError> {
        let mut bytes = Vec::new();
        for (index, element) in elements.iter().copied().enumerate() {
            #[cfg(feature = "collection_poll_probe")]
            let root_count = elements.len().checked_add(1).unwrap_or(usize::MAX);
            #[cfg(feature = "collection_poll_probe")]
            let element = self.with_bounded_native_root_manifest(
                super::native_continuation_shadow::NativeContinuationKind::ConcatStringElementForce,
                list_id,
                root_count,
                super::native_continuation_shadow::NativeContinuationEdge::ForceValue,
                |roots| {
                    roots.push(element);
                    roots.extend_from_slice(elements);
                },
                |eval| eval.force_value(list_id, list_span, element),
            )?;
            #[cfg(not(feature = "collection_poll_probe"))]
            let element = self.force_value(list_id, list_span, element)?;
            let element = self.coerce_to_string(list_id, element, list_span)?;
            let (element_bytes, element_context) = {
                let string = self.heap.get_string_view(element).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: list_id,
                            source,
                        },
                        list_span,
                    )
                })?;
                let bytes = Self::copy_bytes_for_node(list_id, list_span, string.bytes())?;
                let context = string.context().try_to_owned().map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: list_id,
                            source,
                        },
                        list_span,
                    )
                })?;
                (bytes, context)
            };
            if index > 0 {
                Self::extend_bytes_for_node(id, span, &mut bytes, separator)?;
            }
            Self::extend_bytes_for_node(id, span, &mut bytes, &element_bytes)?;
            context = context.union(&element_context).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::String { id, source }, span)
            })?;
        }

        Ok(NixString::new(bytes, context))
    }

    pub(super) fn eval_base_name_of_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let string = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string_view(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let (start, len) = base_name_range(string.bytes());
            string
                .try_to_owned()
                .and_then(|string| string.substring_preserve_context(start, len))
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?
        };
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(super) fn eval_dir_of_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() == ValueTag::Path {
            let path = self.clone_path_value(argument, argument_span, value)?;
            let result = match dir_name_range(path.bytes()) {
                Some((start, len)) => {
                    path.substring_preserve_context(start, len)
                        .map_err(|source| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::String {
                                    id: argument,
                                    source,
                                },
                                argument_span,
                            )
                        })?
                }
                None => context_free_dot_string(argument, argument_span)?,
            };
            return self.alloc_tree_walk_path(id, span, result);
        }

        let string = self.coerce_to_string(argument, value, argument_span)?;
        let result = {
            let string = self.heap.get_string_view(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            match dir_name_range(string.bytes()) {
                Some((start, len)) => string
                    .try_to_owned()
                    .and_then(|string| string.substring_preserve_context(start, len))
                    .map_err(|source| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::String {
                                id: argument,
                                source,
                            },
                            argument_span,
                        )
                    })?,
                None => context_free_dot_string(argument, argument_span)?,
            }
        };
        self.alloc_tree_walk_string(id, span, result)
    }

    pub(super) fn eval_parse_drv_name_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let bytes =
            self.context_free_string_bytes(argument, argument_span, value, "parseDrvName")?;
        let (name_end, version_start) = parse_drv_name_split(&bytes);
        let name = self.alloc_static_string(id, span, &bytes[..name_end])?;
        let version = self.alloc_static_string(id, span, &bytes[version_start..])?;
        let name_key = self.intern_builtin_attr_symbol(id, b"name", span)?;
        let version_key = self.intern_builtin_attr_symbol(id, b"version", span)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(2).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len: 2 }, span)
        })?;
        entries.push(AttrEntry::new(name_key, name));
        entries.push(AttrEntry::new(version_key, version));
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn eval_split_version_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let bytes =
            self.context_free_string_bytes(argument, argument_span, value, "splitVersion")?;
        let len = SplitVersionRanges::new(&bytes).count();
        let mut elements = Vec::new();
        elements.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
        })?;
        for (start, end) in SplitVersionRanges::new(&bytes) {
            elements.push(self.alloc_static_string(id, span, &bytes[start..end])?);
        }
        self.alloc_tree_walk_list(id, span, NixList::new(elements))
    }

    pub(super) fn eval_compare_versions_primop(
        &mut self,
        left_id: IrId,
        right_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let left_span = self.node(left_id)?.span;
        let left = self.eval_node(left_id)?;
        let left = self.context_free_string_bytes(left_id, left_span, left, "compareVersions")?;
        let right_span = self.node(right_id)?.span;
        let right = self.eval_node(right_id)?;
        let right =
            self.context_free_string_bytes(right_id, right_span, right, "compareVersions")?;
        self.runtime_int_value(left_id, left_span, compare_version_bytes(&left, &right))
    }

    pub(super) fn eval_hash_string_primop(
        &mut self,
        id: IrId,
        span: Span,
        algorithm_id: IrId,
        string_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let algorithm_span = self.node(algorithm_id)?.span;
        let algorithm = self.eval_node(algorithm_id)?;
        let algorithm =
            self.eval_hash_algorithm(algorithm_id, algorithm_span, algorithm, "hashString")?;

        let string_span = self.node(string_id)?.span;
        let string = self.eval_node(string_id)?;
        if string.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: string_id,
                    expected: "string",
                    actual: string.tag(),
                },
                string_span,
            ));
        }
        self.eval_hash_string_value(id, span, string_id, string_span, string, algorithm)
    }

    pub(super) fn eval_hash_string_value(
        &mut self,
        id: IrId,
        span: Span,
        string_id: IrId,
        string_span: Span,
        string: Value,
        algorithm: HashStringAlgorithm,
    ) -> Result<Value, TreeWalkError> {
        let digest = {
            let string = self.heap.get_string_view(string).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: string_id,
                        source,
                    },
                    string_span,
                )
            })?;
            Self::hash_bytes(string.bytes(), algorithm)
        };
        self.alloc_hash_digest(id, span, &digest)
    }

    pub(super) fn eval_placeholder_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let output =
            self.context_free_string_bytes(argument, argument_span, value, "placeholder")?;
        let input_len = PLACEHOLDER_HASH_PREFIX
            .len()
            .checked_add(output.len())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id: argument,
                        len: usize::MAX,
                    },
                    argument_span,
                )
            })?;
        let mut input = Vec::new();
        input.try_reserve_exact(input_len).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id: argument,
                    len: input_len,
                },
                argument_span,
            )
        })?;
        input.extend_from_slice(PLACEHOLDER_HASH_PREFIX);
        input.extend_from_slice(&output);

        let digest = Self::nix_sha256_digest(&input);
        let bytes = Self::slash_prefixed_nix_base32_sha256_digest(id, span, digest)?;

        self.alloc_tree_walk_string(id, span, NixString::from_bytes(bytes))
    }

    pub(super) fn eval_hash_file_primop(
        &mut self,
        id: IrId,
        span: Span,
        algorithm_id: IrId,
        path_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let algorithm_span = self.node(algorithm_id)?.span;
        let algorithm = self.eval_node(algorithm_id)?;
        let algorithm =
            self.eval_hash_algorithm(algorithm_id, algorithm_span, algorithm, "hashFile")?;

        let path_span = self.node(path_id)?.span;
        let path_value = self.eval_node(path_id)?;
        self.eval_hash_file_path_value(id, span, path_id, path_span, path_value, algorithm)
    }

    pub(super) fn eval_hash_file_path_value(
        &mut self,
        id: IrId,
        span: Span,
        path_id: IrId,
        path_span: Span,
        path_value: Value,
        algorithm: HashStringAlgorithm,
    ) -> Result<Value, TreeWalkError> {
        let (path, is_text_store) = self.coerce_to_filesystem_or_text_store_path_bytes(
            path_id, path_span, path_value, "hashFile",
        )?;
        let contents = if is_text_store {
            self.text_store
                .get(&path)
                .cloned()
                .ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::FileRead {
                            id: path_id,
                            path: path.clone(),
                            message: "text store path is missing".to_owned(),
                        },
                        path_span,
                    )
                })?
                .contents
        } else {
            let contents = fs::read(Path::new(OsStr::from_bytes(&path))).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::FileRead {
                        id: path_id,
                        path: path.clone(),
                        message: source.to_string(),
                    },
                    path_span,
                )
            })?;
            self.record_impure_input_result(ImpureInputFingerprint::hash_file(&path, &contents));
            contents
        };
        let digest = Self::hash_bytes(&contents, algorithm);
        self.alloc_hash_digest(id, span, &digest)
    }

    pub(super) fn eval_convert_hash_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "attrs",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }

        let hash_value =
            self.required_attr_value_by_name(argument, value, HASH_ATTR, argument_span)?;
        let hash_value = self.force_value(argument, argument_span, hash_value)?;
        let hash =
            self.context_free_string_bytes(argument, argument_span, hash_value, "convertHash")?;

        let expected_algorithm = if let Some(algorithm_value) =
            self.attr_value_by_name(argument, value, HASH_ALGO_ATTR, argument_span)?
        {
            let algorithm_value = self.force_value(argument, argument_span, algorithm_value)?;
            Some(self.eval_hash_algorithm(
                argument,
                argument_span,
                algorithm_value,
                "convertHash",
            )?)
        } else {
            None
        };

        let format_value =
            self.required_attr_value_by_name(argument, value, TO_HASH_FORMAT_ATTR, argument_span)?;
        let format_value = self.force_value(argument, argument_span, format_value)?;
        let format =
            self.eval_convert_hash_format(argument, argument_span, format_value, "convertHash")?;

        let digest =
            self.decode_convert_hash(argument, argument_span, &hash, expected_algorithm)?;
        let bytes = Self::encode_convert_hash_digest(id, span, format, &digest)?;
        self.alloc_tree_walk_string(id, span, NixString::from_bytes(bytes))
    }

    pub(super) fn hash_bytes(bytes: &[u8], algorithm: HashStringAlgorithm) -> NixHashDigest {
        let digest = match algorithm {
            HashStringAlgorithm::Md5 => Md5::digest(bytes).to_vec(),
            HashStringAlgorithm::Sha1 => Sha1::digest(bytes).to_vec(),
            HashStringAlgorithm::Sha256 => Self::sha256_array(bytes).to_vec(),
            HashStringAlgorithm::Sha512 => Sha512::digest(bytes).to_vec(),
        };
        match NixHashDigest::new(algorithm, digest) {
            Some(digest) => digest,
            None => unreachable!("hash implementations emit the selected algorithm's digest size"),
        }
    }

    pub(super) fn alloc_hash_digest(
        &mut self,
        id: IrId,
        span: Span,
        digest: &NixHashDigest,
    ) -> Result<Value, TreeWalkError> {
        let bytes = Self::lower_hex_bytes(id, span, digest.bytes())?;
        self.alloc_tree_walk_string(id, span, NixString::from_bytes(bytes))
    }

    pub(super) fn eval_hash_algorithm(
        &self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<HashStringAlgorithm, TreeWalkError> {
        let algorithm_bytes = self.context_free_string_bytes(id, span, value, op)?;
        HashStringAlgorithm::from_bytes(&algorithm_bytes).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::UnknownHashAlgorithm {
                    id,
                    algorithm: algorithm_bytes,
                },
                span,
            )
        })
    }

    pub(super) fn required_attr_value_by_name(
        &mut self,
        id: IrId,
        attrs_value: Value,
        name: &[u8],
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        let symbol = self.intern_builtin_attr_symbol(id, name, span)?;
        let attrs = self
            .heap
            .get_attrs_view(attrs_value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        attrs.get(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::MissingAttribute { id, symbol }, span)
        })
    }

    pub(super) fn eval_convert_hash_format(
        &self,
        id: IrId,
        span: Span,
        value: Value,
        op: &'static str,
    ) -> Result<ConvertHashFormat, TreeWalkError> {
        let format_bytes = self.context_free_string_bytes(id, span, value, op)?;
        ConvertHashFormat::from_bytes(&format_bytes).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::UnknownHashFormat {
                    id,
                    format: format_bytes,
                },
                span,
            )
        })
    }

    pub(super) fn decode_convert_hash(
        &self,
        argument: IrId,
        argument_span: Span,
        hash: &[u8],
        expected_algorithm: Option<HashStringAlgorithm>,
    ) -> Result<NixHashDigest, TreeWalkError> {
        if let Some((algorithm, input_format, payload)) =
            Self::split_convert_hash_typed_input(argument, argument_span, hash)?
        {
            if let Some(expected) = expected_algorithm
                && algorithm != expected
            {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::HashAlgorithmMismatch {
                        id: argument,
                        hash: Self::copy_bytes_for_node(argument, argument_span, hash)?,
                        expected: Self::copy_bytes_for_node(
                            argument,
                            argument_span,
                            expected.name(),
                        )?,
                    },
                    argument_span,
                ));
            }

            return match input_format {
                ConvertHashInputFormat::Sri => {
                    self.decode_sri_hash_payload(argument, argument_span, hash, algorithm, payload)
                }
                ConvertHashInputFormat::Typed => {
                    self.decode_hash_payload(argument, argument_span, hash, algorithm, payload)
                }
            };
        }

        let Some(algorithm) = expected_algorithm else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::HashAlgorithmRequired {
                    id: argument,
                    hash: Self::copy_bytes_for_node(argument, argument_span, hash)?,
                },
                argument_span,
            ));
        };
        self.decode_hash_payload(argument, argument_span, hash, algorithm, hash)
    }

    pub(super) fn split_convert_hash_typed_input(
        id: IrId,
        span: Span,
        hash: &[u8],
    ) -> Result<Option<SplitConvertHashTypedInput<'_>>, TreeWalkError> {
        let sri_separator = hash.iter().position(|byte| *byte == b'-');
        let typed_separator = hash.iter().position(|byte| *byte == b':');
        let Some((separator, input_format)) = (match (sri_separator, typed_separator) {
            (Some(sri), Some(typed)) if sri < typed => Some((sri, ConvertHashInputFormat::Sri)),
            (Some(_), Some(typed)) => Some((typed, ConvertHashInputFormat::Typed)),
            (Some(sri), None) => Some((sri, ConvertHashInputFormat::Sri)),
            (None, Some(typed)) => Some((typed, ConvertHashInputFormat::Typed)),
            (None, None) => None,
        }) else {
            return Ok(None);
        };
        let algorithm = HashStringAlgorithm::from_bytes(&hash[..separator]).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::UnknownHashAlgorithm {
                    id,
                    algorithm: hash[..separator].to_vec(),
                },
                span,
            )
        })?;
        Ok(Some((algorithm, input_format, &hash[separator + 1..])))
    }

    pub(super) fn decode_sri_hash_payload(
        &self,
        id: IrId,
        span: Span,
        hash: &[u8],
        algorithm: HashStringAlgorithm,
        payload: &[u8],
    ) -> Result<NixHashDigest, TreeWalkError> {
        let digest_len = algorithm.digest_len();
        let padded_len = Self::base64_encoded_len(digest_len);
        let unpadded_len = Self::base64_unpadded_encoded_len(digest_len);
        let decoded = if payload.len() == padded_len {
            base64::engine::general_purpose::STANDARD.decode(payload)
        } else if payload.len() == unpadded_len {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(payload)
        } else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidSriHash {
                    id,
                    hash: hash.to_vec(),
                },
                span,
            ));
        }
        .map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::InvalidSriHash {
                    id,
                    hash: hash.to_vec(),
                },
                span,
            )
        })?;
        self.check_hash_digest_len(id, span, hash, algorithm, decoded)
    }

    pub(super) fn decode_hash_payload(
        &self,
        id: IrId,
        span: Span,
        hash: &[u8],
        algorithm: HashStringAlgorithm,
        payload: &[u8],
    ) -> Result<NixHashDigest, TreeWalkError> {
        let digest_len = algorithm.digest_len();
        if payload.len()
            == digest_len.checked_mul(2).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: usize::MAX,
                    },
                    span,
                )
            })?
        {
            let decoded = Self::decode_base16_hash(id, span, hash, payload)?;
            return self.check_hash_digest_len(id, span, hash, algorithm, decoded);
        }
        if payload.len() == Self::nix_base32_encoded_len(digest_len) {
            let decoded = Self::decode_nix_base32_hash(id, span, hash, payload)?;
            return self.check_hash_digest_len(id, span, hash, algorithm, decoded);
        }
        let base64_len = Self::base64_encoded_len(digest_len);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|_| {
                if payload.len() == base64_len {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidBase64Hash {
                            id,
                            hash: hash.to_vec(),
                        },
                        span,
                    )
                } else {
                    TreeWalkError::new(
                        TreeWalkErrorKind::HashWrongLength {
                            id,
                            hash: hash.to_vec(),
                            algorithm: algorithm.name().to_vec(),
                        },
                        span,
                    )
                }
            })?;
        self.check_hash_digest_len(id, span, hash, algorithm, decoded)
    }
}
